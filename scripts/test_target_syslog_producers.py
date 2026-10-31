"""Pure source/schema/ELF corruption controls; no target, daemon or mount."""
import copy
import errno
import json
import os
import subprocess
import tempfile
import types
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parent))
import check_target_syslog_producers as gate


def rows():
 result=[]
 for name in gate.CASE_NAMES:
  symbol=name==gate.CASE_NAMES[-1];fatal=name=='lanauth-central';whole=name.startswith('busybox-logger');info=name=='busybox-info-central'
  result.append(dict(case=name,role='actual-image-dynsym' if symbol else 'actual-shipped-logger' if whole else 'actual-central-functions',queue_full=None if symbol else True,normal_marker=None if symbol else True,recovery_marker=None if symbol else True,calls=[] if symbol else [1,1 if whole or fatal else 128,1],exit_codes=[] if symbol else [1 if fatal else 0]*3,elapsed_ms=[] if symbol else [10]*3,fd_balanced=None if symbol or fatal or whole else True,errno_preserved=None if symbol or fatal or whole or info else True,errno_trace=[[dict(call=i,entry=13,transport_entry=0,transport_exit=0,final=0)for i in range(n)]for n in (1,128,1)]if info else None))
 return result


def symbols(provided,undefined):
 # Minimal ELF32LE with one dynsym linked to a bounded strtab.
 strings=b'\0';entries=b'\0'*16
 for name,index in [(x,1)for x in provided]+[(x,0)for x in undefined]:
  offset=len(strings);strings+=name.encode()+b'\0';entries+=struct.pack('<IIIBBH',offset,0,0,0x12,0,index)
 data=bytearray(52+3*40);data[:7]=b'\x7fELF\x01\x01\x01'
 struct.pack_into('<HH',data,16,3,8);struct.pack_into('<I',data,32,52)
 struct.pack_into('<HHHHHH',data,40,52,0,0,40,3,0)
 offset=len(data);data.extend(strings);syms=len(data);data.extend(entries)
 struct.pack_into('<10I',data,52+40,0,3,0,0,offset,len(strings),0,0,1,0)
 struct.pack_into('<10I',data,52+80,0,11,0,0,syms,len(entries),1,0,4,16)
 return bytes(data)


class SyslogProducerControls(unittest.TestCase):
 def test_exact_twenty_cases_and_roles(self):
  self.assertEqual(len(gate.CASE_NAMES),20);self.assertTrue(gate.validate_records(rows()))
  for bad in (rows()[:-1],rows()[::-1],rows()+[rows()[0]]):
   with self.assertRaises(RuntimeError):gate.validate_records(bad)

 def test_pressure_calls_fatal_status_cleanup_and_not_whole_daemon(self):
  for key,bad in [('role','whole daemon'),('queue_full',False),('calls',[1,0,1]),('calls',[True,128,1]),('exit_codes',[0,0,1]),('elapsed_ms',[1,5001,1]),('fd_balanced',False),('errno_preserved',False),('normal_marker',False),('recovery_marker',False)]:
   v=rows();v[2][key]=bad
   with self.subTest(key=key),self.assertRaises(RuntimeError):gate.validate_records(v)
  v=rows();v[gate.CASE_NAMES.index('lanauth-central')]['exit_codes']=[0]*3
  with self.assertRaises(RuntimeError):gate.validate_records(v)

 def test_datagram_nul_priority_literal_body_controls(self):
  packet=b'<13>Oct 31 10:00:00 K2P_BB: literal %n %s %%\0'
  self.assertTrue(gate.validate_frame(packet,b'literal %n %s %%',13))
  for bad in (packet[:-1],packet+b'\0',packet.replace(b'<13>',b'<14>'),packet.replace(b'%n',b'0'),b'<13>'+b'x'*1023+b'\0'):
   with self.assertRaises(RuntimeError):gate.validate_frame(bad,b'literal %n %s %%',13)

 def test_pure_generator_rejects_side_effects_or_replaced_source_map(self):
  good='import json\nimport re\ndef function(text,name):return text\ndef generate_source(inputs,endpoint):return endpoint\n'
  self.assertEqual(gate.pure_generator(good,'downloaded')({},'fixture'),'fixture')
  for bad in (good+'\nopen("bad","w")',good.replace('import re','import os'),good+'\ndef extra():pass\n',good.replace('def function','@danger\ndef function')):
   with self.assertRaises(RuntimeError):gate.pure_generator(bad,'downloaded')
  wrong='SOURCE_PATHS={}\ndef mask(x):pass\ndef function(x,n):pass\ndef declaration(x,n):pass\ndef without_includes(x):pass\ndef generate_source(x):pass\n'
  with self.assertRaises(RuntimeError):gate.pure_generator(wrong,'central')

 def test_patch_target_cannot_escape_or_modify_extra_package_files(self):
  for bad in ('+++ b/../../outside\n','+++ b/log.c\n+++ b/other\n','+++ /absolute\n'):
   values={key+'_patch':bad for key in gate.PACKAGE_PATHS}
   values.update({key+'_fixture':'fixture'for key in gate.PACKAGE_PATHS})
   with self.assertRaises(RuntimeError):gate.apply_patches(values)

 def test_sequential_single_target_package_patches_missing_and_drift_rejected(self):
  def change(path,old,new):return '--- a/'+path+'\n+++ b/'+path+'\n@@ -1 +1 @@\n-'+old+'\n+'+new+'\n'
  inputs={}
  for package,(_,path)in gate.PACKAGE_PATHS.items():
   inputs[package+'_fixture']='old-'+package+'\n'
   inputs[package+'_patch']=change(path,'old-'+package,'new-'+package)
  inputs['openvpn_ps_fixture']='old-ps\n'
  inputs['openvpn_ps_patch']=change('src/openvpn/ps.c','old-ps','new-ps')
  self.assertEqual(gate.apply_patches(inputs),{package:'new-'+package+'\n'for package in gate.PACKAGE_PATHS})
  for role in ('missing-fixture','missing-patch','unknown-target','multi-target','drift','already-patched','swapped-patches'):
   bad=copy.deepcopy(inputs)
   if role=='missing-fixture':del bad['openvpn_ps_fixture']
   elif role=='missing-patch':del bad['openvpn_ps_patch']
   elif role=='unknown-target':bad['openvpn_ps_patch']=bad['openvpn_ps_patch'].replace('b/src/openvpn/ps.c','b/src/openvpn/unknown.c')
   elif role=='multi-target':bad['openvpn_patch']+=bad['openvpn_ps_patch']
   elif role=='drift':bad['openvpn_ps_fixture']='unrelated-drift\n'
   elif role=='already-patched':bad['openvpn_ps_fixture']='new-ps\n'
   else:bad['openvpn_patch'],bad['openvpn_ps_patch']=bad['openvpn_ps_patch'],bad['openvpn_patch']
   with self.subTest(role=role),self.assertRaises(RuntimeError):gate.apply_patches(bad)
  self.assertEqual(gate.SOURCE_PATHS['openvpn_ps_fixture'],'tests/fixtures/downloaded-log-sources/openvpn-2.6.23-ps.c')
  self.assertEqual(gate.SOURCE_PATHS['openvpn_ps_patch'],'trunk/user/openvpn/openvpn-bounded-port-share.patch')

 def test_wrapper_preserves_central_main_and_checks_fd_balance(self):
  source='int main(int argc,char **argv) { (void)argc;(void)argv;return 0; }'
  actual=gate.wrap_descriptors(source)
  self.assertIn('static int component_main(',actual);self.assertIn('before==after?result:94',actual)
  self.assertIn('"literal %%m | %m"',actual);self.assertIn('errno!=ENOENT',actual)
  for bad in ('',source+source):
   with self.assertRaises(RuntimeError):gate.wrap_descriptors(bad)

 def test_dynamic_symbols_parse_actual_exports_and_undefined(self):
  value=gate.dynamic_symbols(symbols(gate.PPP_EXPORTS,['socket']))
  self.assertEqual(set(value['provided']),set(gate.PPP_EXPORTS));self.assertEqual(value['undefined'],['socket'])
  for bad in (b'notelf',symbols([],[])[:-1],symbols([],[])[:32]+b'\xff'*4+symbols([],[])[36:]):
   with self.assertRaises((RuntimeError,ValueError,struct.error)):gate.dynamic_symbols(bad)

 def test_plugin_resolution_rejects_old_libc_logging_or_missing_exports(self):
  class Fake:
   def __init__(self,key=''):self.key=key
   def __truediv__(self,value):return Fake(value)
   def read_bytes(self):
    if self.key.endswith('/pppd'):return symbols(gate.PPP_EXPORTS,[])
    return symbols([],['ppp_syslog'])
  value=gate.plugin_closure(Fake());self.assertEqual(value['pppd']['logger_exports'],sorted(gate.PPP_EXPORTS))
  with mock.patch.object(gate,'dynamic_symbols',return_value={'provided':[],'undefined':['syslog']}):
   with self.assertRaises(RuntimeError):gate.plugin_closure(Fake())

 def test_namespace_identity_and_root_worker_required(self):
  iso=dict(namespaces={key:dict(parent_inode=10,worker_inode=20)for key in ('mnt','net','pid')},worker_pid=1,loopback_only=True,private_mount_propagation=True,anchors_cloexec=True,namespace_exit_confirmed=True,private_dev_log=True)
  self.assertTrue(gate.validate_isolation(iso))
  for field,value in [('worker_pid',True),('namespace_exit_confirmed',False),('private_dev_log',False)]:
   bad=copy.deepcopy(iso);bad[field]=value
   with self.assertRaises(RuntimeError):gate.validate_isolation(bad)
  iso['namespaces']['net']['worker_inode']=10
  with self.assertRaises(RuntimeError):gate.validate_isolation(iso)

 def test_openssl_or_crypto_single_remaining_libc_log_import_fails_closed(self):
  with tempfile.TemporaryDirectory(prefix='k2p-openssl-import-control-') as temporary:
   root=Path(temporary)
   for relative in gate.PROGRAMS.values():
    path=root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(symbols([],[]))
   self.assertEqual(set(gate.import_proof(root)['undefined']),set(gate.PROGRAMS))
   for key in ('openssl','libcrypto'):
    for api in gate.FORBIDDEN_LOG_IMPORTS:
     path=root/gate.PROGRAMS[key];path.write_bytes(symbols([],[api]))
     with self.subTest(program=key,api=api),self.assertRaises(RuntimeError):gate.import_proof(root)
     path.write_bytes(symbols([],[]))

 def test_openssl_and_crypto_are_mandatory_real_image_import_checks(self):
  self.assertEqual(gate.PROGRAMS['openssl'],'usr/bin/openssl')
  self.assertEqual(gate.PROGRAMS['libcrypto'],'lib/libcrypto.so.3')
  self.assertEqual(len(gate.PROGRAMS),23)

 def test_shipped_metadata_paths_exact_and_source_closure(self):
  self.assertEqual(gate.PROGRAMS['rp-pppoe'],'usr/lib/pppd/rp-pppoe.so')
  self.assertEqual(gate.PROGRAMS['pptp'],'usr/lib/pppd/pptp.so')
  self.assertIn('central_generator',gate.SOURCE_PATHS);self.assertIn('downloaded_generator',gate.SOURCE_PATHS)
  for path in ('user/pppd/pppd/options.c','user/pppd/pppd/plugins/rp-pppoe/pppoe.h'):
   self.assertEqual(gate.SOURCE_PATHS[path],'trunk/'+path)
  for name in ('openssh','openvpn','smartdns'):
   self.assertIn(name+'_fixture',gate.SOURCE_PATHS);self.assertIn(name+'_patch',gate.SOURCE_PATHS)

 def test_full_report_binds_sources_image_probes_imports_and_isolation(self):
  iso=dict(namespaces={key:dict(parent_inode=10,worker_inode=20)for key in ('mnt','net','pid')},worker_pid=1,loopback_only=True,private_mount_propagation=True,anchors_cloexec=True,namespace_exit_confirmed=True,private_dev_log=True)
  generated={'central':'C','downloaded':'D'};sources={'source':'a'*64};shipped={'busybox':{'sha256':'b'*64}}
  report=dict(schema_version=1,status='PASS',profile='k2p-4.4',execution_role=gate.ROLE,source_sha256=sources,shipped=shipped,required_cases=list(gate.CASE_NAMES),checks=rows(),filesystem_limits=gate.FILESYSTEM_LIMITS,limits=gate.LIMITS,contract=gate.CONTRACT,isolation=iso,failure=None,
   probes={key:dict(source_sha256=gate.sha(text.encode()),sha256='c'*64,bytes=1000,elf=dict(elf_class=32,byte_order='little',e_machine=8,e_type=2))for key,text in generated.items()},
   patched_sources={key:'d'*64 for key in gate.PACKAGE_PATHS},import_check=dict(forbidden_symbols=list(gate.FORBIDDEN_LOG_IMPORTS),undefined={key:[]for key in gate.PROGRAMS}),
   plugin_closure={key:dict(logger_exports=sorted(gate.PPP_EXPORTS)if key=='pppd'else [],logger_imports=[]if key=='pppd'else ['ppp_syslog'])for key in ('pppd','rp-pppoe','pptp')})
  self.assertTrue(gate.validate_report(report,sources,shipped,generated))
  for key,bad in [('status','SKIP'),('schema_version',True),('failure','ignored'),('source_sha256',{}),('shipped',{}),('required_cases',[]),('execution_role',{}),('limits',{}),('contract',{}),('filesystem_limits',{})]:
   value=copy.deepcopy(report);value[key]=bad
   with self.subTest(key=key),self.assertRaises(RuntimeError):gate.validate_report(value,sources,shipped,generated)
  for field,bad in [('source_sha256','0'*64),('bytes',True),('elf',dict(elf_class=64,byte_order='little',e_machine=62,e_type=2))]:
   value=copy.deepcopy(report);value['probes']['central'][field]=bad
   with self.assertRaises(RuntimeError):gate.validate_report(value,sources,shipped,generated)
  value=copy.deepcopy(report);value['import_check']['undefined']['libssh']=['syslog']
  with self.assertRaises(RuntimeError):gate.validate_report(value,sources,shipped,generated)

 def test_actual_object_import_check_includes_weak_log_symbols(self):
  class Fake:
   def __init__(self,path=''):self.path=path
   def __truediv__(self,path):return Fake(path)
   def read_bytes(self):return symbols([],['syslog'])
  with self.assertRaises(RuntimeError):gate.import_proof(Fake())
  data=bytearray(symbols([],['syslog']))
  # Last entry binding becomes weak, still an unresolved libc logging path.
  data[-4]=0x22
  self.assertIn('syslog',gate.dynamic_symbols(bytes(data))['undefined'])

 def test_info_formatter_errno_layers_do_not_waive_any_transport(self):
  value=rows();index=gate.CASE_NAMES.index('busybox-info-central')
  self.assertTrue(gate.validate_records(value));self.assertIsNone(value[index]['errno_preserved'])
  for field,bad in [('transport_exit',1),('call',True),('entry',-1),('final',4096)]:
   damaged=copy.deepcopy(value);damaged[index]['errno_trace'][1][3][field]=bad
   with self.subTest(field=field),self.assertRaises(RuntimeError):gate.validate_records(damaged)
  damaged=copy.deepcopy(value);damaged[index]['errno_trace'][1].pop()
  with self.assertRaises(RuntimeError):gate.validate_records(damaged)
  # A genuine formatter may clobber errno outside transport; unrelated old
  # cases still require the whole transport API errno witness and no trace.
  damaged=copy.deepcopy(value);damaged[gate.CASE_NAMES.index('busybox-central')]['errno_preserved']=None
  with self.assertRaises(RuntimeError):gate.validate_records(damaged)
  wire=b'ERRNO_TRACE call=0 entry=13 transport_entry=0 transport_exit=0 final=0\n'
  self.assertEqual(gate.parse_errno_trace(wire,1),[dict(call=0,entry=13,transport_entry=0,transport_exit=0,final=0)])
  for bad in (wire.replace(b'transport_exit=0',b'transport_exit=13'),wire+wire,wire.replace(b'final=0',b'final=-1'),b''):
   with self.assertRaises(RuntimeError):gate.parse_errno_trace(bad,1)

 def test_source_only_exact_seventeen_cannot_replace_image_twenty(self):
  subset=[row for row in rows()if row['case']in gate.ADAPTER_CASE_NAMES]
  self.assertEqual(len(subset),17);self.assertTrue(gate.validate_records(subset,source_only=True))
  with self.assertRaises(RuntimeError):gate.validate_records(subset)
  with self.assertRaises(RuntimeError):gate.validate_records(rows(),source_only=True)
  with self.assertRaises(RuntimeError):gate.validate_records(subset,source_only='True')
  iso=dict(namespaces={key:dict(parent_inode=10,worker_inode=20)for key in ('mnt','net','pid')},worker_pid=1,loopback_only=True,private_mount_propagation=True,anchors_cloexec=True,namespace_exit_confirmed=True,private_dev_log=True)
  sources={'locked':'a'*64};probes={'central':'bound','downloaded':'bound'}
  report=dict(schema_version=1,status='PASS',profile='k2p-4.4',execution_role=gate.ADAPTER_ROLE,source_sha256=sources,required_cases=list(gate.ADAPTER_CASE_NAMES),checks=subset,filesystem_limits=gate.FILESYSTEM_LIMITS,limits=gate.LIMITS,contract=gate.ADAPTER_CONTRACT,isolation=iso,probes=probes,failure=None)
  self.assertTrue(gate.validate_adapter_report(report,sources,probes))
  for field,bad in [('execution_role',gate.ROLE),('execution_role',gate.COMPILE_ROLE),('checks',rows()),('required_cases',list(gate.CASE_NAMES)),('source_sha256',{}),('probes',{}),('status','COMPILED')]:
   value=copy.deepcopy(report);value[field]=bad
   with self.subTest(field=field),self.assertRaises(RuntimeError):gate.validate_adapter_report(value,sources,probes)

 def test_reuse_exact_compiled_c_and_static_elf_not_metadata_alone(self):
  data=bytearray(100);data[:7]=b'\x7fELF\x01\x01\x01';struct.pack_into('<HH',data,16,2,8)
  struct.pack_into('<II',data,24,0x400000,52);struct.pack_into('<HH',data,42,32,1)
  struct.pack_into('<8I',data,52,1,0,0x400000,0,len(data),len(data),5,4096);binary=bytes(data)
  code={'central':'public-C','downloaded':'public-D'};sources={'locked':'a'*64}
  meta={key:dict(source_sha256=gate.sha(text.encode()),sha256=gate.sha(binary),bytes=len(binary),elf=gate.base.elf(binary))for key,text in code.items()}
  original=dict(status='COMPILED',execution_role=gate.COMPILE_ROLE,source_sha256=sources,probes=meta)
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary);report=root/'result.json'
   for key,text in code.items():
    (root/('target-syslog-'+key+'-probe.c')).write_text(text);(root/('target-syslog-'+key+'-probe')).write_bytes(binary)
   report.write_text(json.dumps(original))
   with mock.patch.object(gate,'source_hashes',return_value=sources),mock.patch.object(gate,'generate_sources',return_value=code):
    result,paths=gate.reuse_compiled_probes(report,{})
    self.assertEqual(result,meta);self.assertEqual(set(paths),set(code))
    for role in ('source','C','ELF','role'):
     report.write_text(json.dumps(original));(root/'target-syslog-central-probe.c').write_text(code['central']);(root/'target-syslog-central-probe').write_bytes(binary)
     if role=='source':v=copy.deepcopy(original);v['source_sha256']={};report.write_text(json.dumps(v))
     elif role=='C':(root/'target-syslog-central-probe.c').write_text('wrong-C')
     elif role=='ELF':(root/'target-syslog-central-probe').write_bytes(binary[:-1]+b'x')
     else:v=copy.deepcopy(original);v['execution_role']=gate.ADAPTER_ROLE;report.write_text(json.dumps(v))
     with self.subTest(role=role),self.assertRaises(RuntimeError):gate.reuse_compiled_probes(report,{})

 def test_preflight_reader_refuses_link_fifo_empty_or_oversized(self):
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary);regular=root/'data';regular.write_bytes(b'public')
   self.assertEqual(gate.read_preflight_file(regular,6),b'public')
   with self.assertRaises(RuntimeError):gate.read_preflight_file(regular,5)
   link=root/'link';link.symlink_to(regular)
   with self.assertRaises(OSError):gate.read_preflight_file(link,100)
   fifo=root/'fifo';os.mkfifo(fifo)
   with self.assertRaises(RuntimeError):gate.read_preflight_file(fifo,100)
   empty=root/'empty';empty.touch()
   with self.assertRaises(RuntimeError):gate.read_preflight_file(empty,100)
   alias=root/'alias';os.link(regular,alias)
   with self.assertRaises(RuntimeError):gate.read_preflight_file(regular,100)

 def test_runtime_failure_diagnostic_keeps_actual_rc_and_component(self):
  command=['qemu-mipsel','probe','busybox-info','1','normal']
  result=types.SimpleNamespace(returncode=92,stdout=b'FD_BALANCE before=4 after=4\n',stderr=b'')
  with mock.patch.object(gate.subprocess,'run',return_value=result):
   with self.assertRaisesRegex(RuntimeError,'rc=92 expected=0.*busybox-info'):gate.run_program(command)
  with mock.patch.object(gate.subprocess,'run',side_effect=subprocess.TimeoutExpired(command,5)):
   with self.assertRaisesRegex(RuntimeError,'timeout.*busybox-info'):gate.run_program(command)
  result.returncode=0
  with mock.patch.object(gate.subprocess,'run',return_value=result):
   out,_,status=gate.run_program(command);self.assertEqual(status,0);self.assertIn(b'FD_BALANCE',out)

 def test_explicit_cli_source_only_does_not_compile_or_claim_shipped(self):
  argv=['checker','--adapter-preflight','--trunk','/tmp/trunk','--output','/tmp/out.json','--preflight-result','/tmp/compiled.json']
  with mock.patch.object(gate.sys,'argv',argv),mock.patch.object(gate,'adapter_preflight')as runtime,mock.patch.object(gate,'compile_probes')as compiler,mock.patch.object(gate,'shipped_proof')as image:
   gate.main();runtime.assert_called_once();compiler.assert_not_called();image.assert_not_called()
  with mock.patch.object(gate.sys,'argv',argv+['--preflight']),mock.patch('sys.stderr'):
   with self.assertRaises(SystemExit):gate.main()
  # Exercise the real CLI normalization and reader together. Resolving the
  # leaf first would turn this into a regular file and defeat O_NOFOLLOW.
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary);target=root/'compiled.json';target.write_text('{}')
   alias=root/'compiled-alias.json';alias.symlink_to(target)
   arguments=['checker','--adapter-preflight','--trunk',str(root),'--output',str(root/'result.json'),'--preflight-result',str(alias)]
   with mock.patch.object(gate.sys,'platform','linux'),mock.patch.object(gate.sys,'argv',arguments),mock.patch.object(gate,'source_inputs',return_value={}),mock.patch.object(gate.subprocess,'run')as launcher,mock.patch.object(gate.base,'prepare_output')as output:
    with self.assertRaises(OSError)as failure:gate.main()
    self.assertEqual(failure.exception.errno,errno.ELOOP);launcher.assert_not_called();output.assert_not_called()


if __name__=='__main__':unittest.main()
