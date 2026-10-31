"""Pure raw/schema/namespace/ELF-negative controls, no target program or mounts."""
from pathlib import Path
import base64,copy,json,os,struct,sys,tempfile,types,unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parent))
import check_target_openssl_log as gate
from test_target_ntp import dynamic_elf

def packet(pri,tag,body,pid=111):return ('<'+str(pri)+'>Jan  1 00:00:00 '+tag+'['+str(pid)+']: ').encode()+body+b'\0'
def rows():
 frames=[[packet(156,'bio-a',b'literal %n %s %%')],[packet(156,'bio-a',b'ONE'),packet(166,'bio-b',b'TWO'),packet(156,'bio-a',b'THREE')],[],[gate.FILLER]*3,[packet(156,'bio-a',b'literal %n %s %%')],[packet(172,'owned-name',b'OWNED'),packet(156,'updated-name',b'UPDATED')],[packet(172,'bio-child',b'CHILD',222),packet(156,'bio-a',b'PARENT',111)],[]]
 prefix=packet(158,'bio-a',b'')[:-1];frames[2]=[prefix+b'[truncated] '+b'x'*(1024-len(prefix)-len(b'[truncated] ')-1)+b'\0']
 out=[]
 for i,name in enumerate(gate.CASE_NAMES):
  r=dict(schema_version=1,mode=gate.OPERATIONS[i],calls=[dict(input=n,accepted=n)for n in gate.INPUT_LENGTHS[i]],fd_before=4,fd_after=4,errno_entry=33,errno_after_write=11,child_status=0 if i==6 else-1)
  out.append(dict(case=name,operation=gate.OPERATIONS[i],elapsed_ms=25,queue_full_errno=11 if i==3 else None,queue_filler_datagrams=3 if i==3 else 0,probe_result=r,stdout=json.dumps(r)+'\n',stderr='',datagrams_base64=[base64.b64encode(x).decode()for x in frames[i]]))
 return out

def report():
 sources={k:'a'*64 for k in gate.SOURCE_PATHS};shipped={'synthetic':'image'};libraries={'synthetic':'libraries'}
 r=dict(schema_version=1,status='PASS',profile='k2p-4.4',execution_role=gate.ROLE,source_sha256=sources,shipped=shipped,runtime_libraries=libraries,required_cases=list(gate.CASE_NAMES),checks=rows(),filesystem_limits=gate.FILESYSTEM_LIMITS,limits=gate.LIMITS,contract=gate.CONTRACT,probe=dict(source_sha256='a'*64,sha256='b'*64,bytes=1024,elf=dict(elf_class=32,byte_order='little',e_machine=8,e_type=2),dynamic=dict(interpreter='/lib/ld-uClibc.so.0',needed=['libcrypto.so.3','libc.so.0'])),compiler=dict(path='/private/cross-gcc',version='synthetic-control'),isolation=dict(namespaces={n:dict(parent_inode=i,worker_inode=i+10)for i,n in enumerate(('mnt','net','pid'),1)},worker_pid=1,loopback_only=True,private_mount_propagation=True,anchors_cloexec=True,namespace_exit_confirmed=True,private_dev_log=True),failure=None)
 return r,sources,shipped,libraries

class OpenSSLLogGateControls(unittest.TestCase):
 def test_fixed_eight_cases_and_strict_final_versus_partial(self):
  self.assertEqual(len(gate.CASE_NAMES),8);self.assertTrue(gate.validate_records(rows()));self.assertTrue(gate.validate_records(rows()[:2],partial=True))
  for bad in (rows()[:-1],rows()[::-1],rows()+[rows()[0]],[]):
   with self.assertRaises(RuntimeError):gate.validate_records(bad)
 def test_whole_report_roles_bindings_and_all_constants(self):
  r,s,p,l=report();self.assertTrue(gate.validate_report(r,s,p,l))
  for key,bad in [('status','FAIL'),('execution_role','whole OCSP daemon'),('required_cases',list(gate.CASE_NAMES)[:-1]),('limits',{}),('runtime_libraries',{}),('source_sha256',{}),('contract',{})]:
   v=copy.deepcopy(r);v[key]=bad
   with self.subTest(key=key),self.assertRaises(RuntimeError):gate.validate_report(v,s,p,l)
 def test_raw_stdout_exact_result_and_stderr_exit_evidence(self):
  for key,value in [('stdout','{}'),('stderr','unexpected'),('elapsed_ms',5001),('elapsed_ms',True)]:
   v=rows();v[0][key]=value
   with self.subTest(key=key),self.assertRaises((RuntimeError,ValueError)):gate.validate_records(v)
  v=rows();v[0]['stdout']=v[0]['stdout'].replace('"schema_version": 1','"schema_version": 1,"schema_version": 1')
  with self.assertRaises(RuntimeError):gate.validate_records(v)
 def test_accepted_lengths_actual_calls_and_types_not_self_reported_pass(self):
  for value in (0,True,-1,1048575):
   v=rows();v[2]['probe_result']['calls'][0]['accepted']=value;v[2]['stdout']=json.dumps(v[2]['probe_result'])
   with self.subTest(value=value),self.assertRaises(RuntimeError):gate.validate_records(v)
  v=rows();v[3]['probe_result']['calls'].pop();v[3]['stdout']=json.dumps(v[3]['probe_result'])
  with self.assertRaises(RuntimeError):gate.validate_records(v)
 def test_pressure_requires_actual_eagain_and_unchanged_raw_fillers(self):
  for key,value in [('queue_full_errno',None),('queue_full_errno',True),('queue_full_errno',105),('queue_filler_datagrams',0),('queue_filler_datagrams',2),('datagrams_base64',[base64.b64encode(packet(156,'bio-a',b'LEAK')).decode()])]:
   v=rows();v[3][key]=value
   with self.subTest(key=key),self.assertRaises(RuntimeError):gate.validate_records(v)
 def test_frames_priority_owned_identity_literal_nul_and_base64(self):
  good=rows()[0]['datagrams_base64'][0];raw=base64.b64decode(good)
  for bad in (raw[:-1],raw+b'\0',raw.replace(b'<156>',b'<158>'),raw.replace(b'bio-a[',b'bio-b['),raw.replace(b'%n',b'00'),raw.replace(b'[111]',b'[0]')):
   v=rows();v[0]['datagrams_base64']=[base64.b64encode(bad).decode()]
   with self.assertRaises(RuntimeError):gate.validate_records(v)
  with self.assertRaises(ValueError):gate.decode_frames(['%%%'])
 def test_large_input_truncation_and_local3_info158(self):
  raw=base64.b64decode(rows()[2]['datagrams_base64'][0])
  for bad in (raw.replace(b'<158>',b'<166>'),raw.replace(b'[truncated]',b'[unchanged]'),raw.replace(b'xxx',b'xyx',1),raw[:-2]+b'\0'):
   v=rows();v[2]['datagrams_base64']=[base64.b64encode(bad).decode()]
   with self.assertRaises(RuntimeError):gate.validate_records(v)
 def test_per_bio_context_control_and_fork_pid_must_differ(self):
  for index,replacement in [(1,packet(156,'bio-a',b'TWO')),(5,packet(172,'zzzz-name',b'OWNED')),(6,packet(172,'bio-child',b'CHILD',111))]:
   v=rows();position=1 if index==1 else 0;v[index]['datagrams_base64'][position]=base64.b64encode(replacement).decode()
   with self.subTest(index=index),self.assertRaises(RuntimeError):gate.validate_records(v)
 def test_errno_observation_fd_lifecycle_and_fork_status(self):
  for key,value in [('fd_after',5),('fd_before',True),('errno_entry',11),('errno_after_write',4096),('child_status',1)]:
   v=rows();v[6]['probe_result'][key]=value;v[6]['stdout']=json.dumps(v[6]['probe_result'])
   with self.subTest(key=key),self.assertRaises(RuntimeError):gate.validate_records(v)
  v=rows();v[0]['probe_result']['errno_after_write']=13;v[0]['stdout']=json.dumps(v[0]['probe_result']);self.assertTrue(gate.validate_records(v))
 def test_namespace_guard_precedes_any_mount_or_socket(self):
  args=types.SimpleNamespace(anchor_fds='{}')
  with mock.patch.object(gate.base,'namespace_guard',side_effect=RuntimeError('unsafe')),mock.patch.object(gate.producers,'private_filesystems')as mounts,mock.patch.object(gate,'report_shell')as report:
   with self.assertRaises(RuntimeError):gate.worker(args)
   mounts.assert_not_called();report.assert_not_called()
 def test_safe_source_and_export_reject_alias_existing_and_wrong_input_set(self):
  with tempfile.TemporaryDirectory()as td:
   path=Path(td)/'data';gate.create_export(path,b'bytes',0o600);self.assertEqual(gate.read_file(path,10),b'bytes')
   alias=Path(td)/'alias';alias.symlink_to(path)
   for target in (path,alias):
    with self.assertRaises(FileExistsError):gate.create_export(target,b'bad',0o600)
   with self.assertRaises(OSError):gate.read_file(alias,10)
  with self.assertRaises(RuntimeError):gate.generate_source({})
 def test_dynamic_probe_library_closure_and_isolation_metadata_not_static(self):
  r,s,p,l=report()
  for key,value in [('elf',dict(elf_class=64,byte_order='little',e_machine=8,e_type=2)),('dynamic',dict(interpreter=None,needed=[])),('source_sha256','not-a-hash')]:
   v=copy.deepcopy(r);v['probe'][key]=value
   with self.subTest(key=key),self.assertRaises(RuntimeError):gate.validate_report(v,s,p,l)
  for key,value in [('worker_pid',2),('private_dev_log',False),('namespace_exit_confirmed',False)]:
   v=copy.deepcopy(r);v['isolation'][key]=value
   with self.subTest(key=key),self.assertRaises(RuntimeError):gate.validate_report(v,s,p,l)

 def test_compile_uses_pinned_public_c_actual_stage_headers_and_dynamic_libraries(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);output=root/'result.json';trunk=root/'trunk';trunk.mkdir();prefix=root/'romfs';prefix.mkdir()
   args=types.SimpleNamespace(output=output,trunk=trunk,compiler=Path('/private/cross-gcc'),sysroot=prefix)
   inputs={name:'' for name in gate.SOURCE_PATHS};inputs['probe']='#include <openssl/bio.h>\n/* BIO_s_log() */\n'
   binary=dynamic_elf(needed=('libcrypto.so.3','libc.so.0'))
   commands=[]
   def compile_or_version(command,**kwargs):
    commands.append(command)
    if '--version'in command:return types.SimpleNamespace(returncode=0,stdout=b'fixture cross compiler\n',stderr=b'')
    Path(command[-1]).write_bytes(binary);return types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
   with mock.patch.object(gate.subprocess,'run',side_effect=compile_or_version):metadata,path,compiler=gate.compile_probe(args,inputs)
   self.assertEqual(path.read_bytes(),binary);self.assertEqual(path.with_suffix('.c').read_text(),inputs['probe']);self.assertEqual(metadata['source_sha256'],gate.sha(inputs['probe'].encode()))
   self.assertIn('-I'+str(trunk/'libs/libssl/openssl-3.5.9/include'),commands[0]);self.assertIn('-L'+str(trunk/'stage/lib'),commands[0]);self.assertIn('-Wl,-rpath-link,'+str(prefix/'lib'),commands[0]);self.assertNotIn('-static',commands[0]);self.assertEqual(metadata['dynamic']['needed'],['libcrypto.so.3','libc.so.0'])
   with mock.patch.object(gate.subprocess,'run',side_effect=compile_or_version),self.assertRaises(RuntimeError):gate.compile_probe(args,inputs)
 def test_five_runtime_aliases_bind_actual_image_bytes_and_closed_needed_set(self):
  images=Path('/image');prefix=Path('/prefix')
  def payloads(root,name):
   needed=('libatomic.so.1','libc.so.0') if name=='lib/libcrypto.so.3' else (('libc.so.0',)if name=='lib/libatomic.so.1'else())
   body=bytes(dynamic_elf(needed=needed,interpreter=None,kind=3));identity=dict(resolved=name,sha256=gate.sha(body),bytes=len(body),elf_class=32,byte_order='little',e_machine=8,e_type=3)
   return identity,body
  with mock.patch.object(gate.ntp,'_runtime_library',side_effect=payloads):self.assertEqual(set(gate.runtime_libraries(images,prefix)),set(gate.RUNTIME_PATHS))
  for mismatch in ('bytes','identity','unknown-needed'):
   def bad(root,name):
    identity,body=payloads(root,name)
    if mismatch=='bytes' and root==prefix and name=='lib/libatomic.so.1':body=body[:-1]+b'X'
    if mismatch=='identity' and root==prefix:identity=dict(identity,sha256='0'*64)
    if mismatch=='unknown-needed' and name=='lib/libatomic.so.1':
     body=bytes(dynamic_elf(needed=('unknown.so',),interpreter=None,kind=3));identity=dict(identity,bytes=len(body),sha256=gate.sha(body))
    return identity,body
   with self.subTest(mismatch=mismatch),mock.patch.object(gate.ntp,'_runtime_library',side_effect=bad),self.assertRaises(RuntimeError):gate.runtime_libraries(images,prefix)

 def test_probe_entry_must_be_file_backed_executable_not_shared_library_rule(self):
  original=dynamic_elf(needed=('libcrypto.so.3','libc.so.0'));self.assertTrue(gate.validate_probe_entry(original))
  for mode in ('zero','outside','nonexec','bss-only'):
   body=bytearray(original)
   if mode=='zero':struct.pack_into('<I',body,24,0)
   elif mode=='outside':struct.pack_into('<I',body,24,0x500000)
   elif mode=='nonexec':struct.pack_into('<I',body,52+24,4)
   else:struct.pack_into('<I',body,52+20,len(body)+4096);struct.pack_into('<I',body,24,0x400000+len(body)+16)
   with self.subTest(mode=mode),self.assertRaises((RuntimeError,ValueError)):gate.validate_probe_entry(bytes(body))
