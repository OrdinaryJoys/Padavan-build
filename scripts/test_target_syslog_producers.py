"""Pure source/schema/ELF corruption controls; no target, daemon or mount."""
import copy
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
  symbol=name==gate.CASE_NAMES[-1];fatal=name=='lanauth-central';whole=name.startswith('busybox-logger')
  result.append(dict(case=name,role='actual-image-dynsym' if symbol else 'actual-shipped-logger' if whole else 'actual-central-functions',queue_full=None if symbol else True,normal_marker=None if symbol else True,recovery_marker=None if symbol else True,calls=[] if symbol else [1,1 if whole or fatal else 128,1],exit_codes=[] if symbol else [1 if fatal else 0]*3,elapsed_ms=[] if symbol else [10]*3,fd_balanced=None if symbol or fatal or whole else True,errno_preserved=None if symbol or fatal or whole else True))
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
 def test_exact_nineteen_cases_and_roles(self):
  self.assertEqual(len(gate.CASE_NAMES),19);self.assertTrue(gate.validate_records(rows()))
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

if __name__=='__main__':unittest.main()
