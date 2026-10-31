"""Host corruption controls for the syslogd fixture. No MIPS/daemon is executed."""
from pathlib import Path
import contextlib,copy,json,os,stat,struct,subprocess,sys,tempfile,types,unittest
from unittest import mock
import check_target_syslogd_file as gate


def snap(body=b'',mode=0o644,uid=0,links=1,inode=10,kind='regular',target=None):
 return dict(type=kind,uid=uid,gid=uid,mode=mode,nlink=links,device=7,inode=inode,size=len(body)if kind=='regular'else len(target)if kind=='symlink'else 0,
  bytes_base64=gate.encode(body)if kind=='regular'else None,link_target=target,
  device_major=1 if kind=='character'else None,device_minor=3 if kind=='character'else None)


def observed(alias=None,target=None):return dict(alias=alias,target=target,rotation=None)


def daemon(index,position=0):
 ident=dict(pid=100+index*2+position,starttime=1000+index*2+position)
 return dict(options=['-s','0','-O','/dev/null'if position==0 else'-']if index==8 else['-s','1'if index==1 else'0','-O',str(gate.DEFAULT)],
  before=ident.copy(),after=ident.copy(),returncode=-15,forced_stop=False,stopped=True,
  stdout_base64=gate.encode((gate.marker(index,'STDOUT')+'\n').encode())if index==8 and position==1 else'',stderr_base64='')


def rows():
 result=[]
 for index,name in enumerate(gate.CASE_NAMES):
  suffixes=('FILL1','FILL2','FILL3','TAIL')if index==1 else('REJECTED','RECOVERY')if 4<=index<=7 else('NULL','STDOUT')if index==8 else('ONE','TWO')
  clients=[dict(message=gate.marker(index,suffix)+('x'*300 if suffix.startswith('FILL')else''),returncode=0,stdout_base64='',stderr_base64='',elapsed_ms=1)for suffix in suffixes]
  row=dict(case=name,status='PASS',failure=None,before=observed(),checkpoint=observed(),after=observed(),clients=clients,
   daemons=[daemon(index)]+([daemon(index,1)]if index==8 else[]),fifo_reader=None,fifo_bytes_base64=None,
   fixture_removed_alias=4<=index<=7,rotation_scale_bytes=1024 if index==1 else None,null_device=snap(mode=0o666,inode=999,kind='character')if index==8 else None)
  if index==8:result.append(row);continue
  if index==1:
   row['checkpoint']=observed(snap(('\n'.join('Oct31 01:02:03 k2p-default: '+value['message']for value in clients[:3])).encode()))
   row['after']=observed(snap(clients[-1]['message'].encode(),inode=11))
  elif 4<=index<=7:
   if index==4:row['before']=observed(snap(mode=0o777,kind='symlink',target=str(gate.TARGET)),snap(gate.SEED,0o600,inode=50))
   elif index==5:row['before']=observed(snap(gate.SEED,0o600,links=2,inode=50),snap(gate.SEED,0o600,links=2,inode=50))
   elif index==6:
    row['before']=observed(snap(mode=0o600,kind='fifo'))
    row['fifo_reader']={key:row['before']['alias'][key]for key in('device','inode','uid','mode','type')};row['fifo_bytes_base64']=''
   else:row['before']=observed(snap(gate.SEED,0o666,uid=99))
   row['checkpoint']=copy.deepcopy(row['before']);target=copy.deepcopy(row['before']['target'])
   if index==5:target['nlink']=1
   row['after']=observed(snap(clients[-1]['message'].encode(),inode=11),target)
  else:
   if index in(2,3):row['before']=observed(snap(gate.SEED,0o666 if index==2 else 0o600))
   mode=0o600 if index==3 else 0o644
   row['checkpoint']=observed(snap(clients[0]['message'].encode(),mode))
   row['after']=observed(snap(('\n'.join(value['message']for value in clients)).encode(),mode))
  result.append(row)
 return result


def iso():return dict(namespaces={key:dict(parent_inode=i+1,worker_inode=i+11)for i,key in enumerate(('mnt','net','pid'))},worker_pid=1,loopback_only=True,private_mount_propagation=True,anchors_cloexec=True,namespace_exit_confirmed=True,private_dev_log=True)


def report():
 sources={key:'a'*64 for key in gate.SOURCE_PATHS};shipped={'busybox':dict(path='bin/busybox',bytes=96,sha256='b'*64,elf=dict(elf_class=32,byte_order='little',e_machine=8,e_type=2))}
 dynamic=dict(interpreter='/lib/ld-uClibc.so.0',needed=['libc.so.0']);libraries={'lib/libc.so.0':{'public':'synthetic-parser-control'}}
 value=dict(schema_version=1,status='PASS',profile='k2p-4.4',execution_role=gate.ROLE,source_sha256=sources,shipped=shipped,busybox_dynamic=dynamic,runtime_libraries=libraries,required_cases=list(gate.CASE_NAMES),checks=rows(),filesystem_limits=copy.deepcopy(gate.FILESYSTEM_LIMITS),limits=copy.deepcopy(gate.LIMITS),contract=copy.deepcopy(gate.CONTRACT),isolation=iso(),failure=None)
 return value,sources,shipped,dynamic,libraries


class SyslogdFileGateTests(unittest.TestCase):
 def test_all_nine_and_completed_prefix_are_required(self):
  self.assertEqual(len(gate.CASE_NAMES),9);self.assertTrue(gate.validate_records(rows()));self.assertTrue(gate.validate_records(rows()[:3],partial=True))
  for value in ([],rows()[:-1],rows()+[rows()[0]],rows()[::-1]):
   with self.subTest(count=len(value)),self.assertRaises(RuntimeError):gate.validate_records(value)
  with self.assertRaises(RuntimeError):gate.validate_records(rows(),partial='yes')

 def test_owned666_migration_and600_non_broadening_preserve_inode(self):
  for index,mode in ((2,0o666),(3,0o644)):
   value=rows();value[index]['after']['alias']['mode']=mode
   with self.subTest(index=index),self.assertRaises(RuntimeError):gate.validate_records(value)
  value=rows();value[2]['after']['alias']['inode']+=1
  with self.assertRaises(RuntimeError):gate.validate_records(value)

 def test_new644_file_must_continue_appending_same_inode(self):
  for mutation in ('missing','different-inode','mode'):
   value=rows();entry=value[0]['after']['alias']
   if mutation=='missing':entry.update(size=0,bytes_base64='')
   elif mutation=='different-inode':entry['inode']+=1
   else:entry['mode']=0o666
   with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):gate.validate_records(value)

 def test_b0_rotation_requires_over_threshold_purge_new_inode_and_no_backup(self):
  for mutation in ('not-over','same-inode','backup','old-marker'):
   value=rows();entry=value[1]
   if mutation=='not-over':entry['checkpoint']['alias']=snap(b'x')
   elif mutation=='same-inode':entry['after']['alias']['inode']=entry['checkpoint']['alias']['inode']
   elif mutation=='backup':entry['after']['rotation']=snap(b'old')
   else:
    body=gate.decode(entry['after']['alias']['bytes_base64'])+gate.marker(1,'FILL1').encode();entry['after']['alias'].update(size=len(body),bytes_base64=gate.encode(body))
   with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):gate.validate_records(value)

 def test_each_unsafe_alias_must_remain_unchanged_before_fixture_removes_it(self):
  for index in range(4,8):
   for key,value in (('mode',0o644),('uid',42),('inode',99)):
    records=rows();records[index]['checkpoint']['alias'][key]=value
    with self.subTest(index=index,key=key),self.assertRaises(RuntimeError):gate.validate_records(records)
   records=rows();records[index]['fixture_removed_alias']=False
   with self.assertRaises(RuntimeError):gate.validate_records(records)

 def test_root_owned_symlink_target_and_hardlink_identity_are_proven(self):
  for index,key,value in ((4,'uid',99),(4,'link_target','/private/other'),(5,'nlink',1),(5,'device',8)):
   records=rows();records[index]['before']['alias'][key]=value;records[index]['checkpoint']=copy.deepcopy(records[index]['before'])
   with self.subTest(index=index,key=key),self.assertRaises(RuntimeError):gate.validate_records(records)
  records=rows();records[4]['after']['target']['bytes_base64']=gate.encode(b'changed');records[4]['after']['target']['size']=7
  with self.assertRaises(RuntimeError):gate.validate_records(records)

 def test_fifo_has_active_reader_exact_inode_and_no_received_bytes(self):
  for mutation in ('no-reader','wrong-inode','boolean-inode','data'):
   records=rows();entry=records[6]
   if mutation=='no-reader':entry['fifo_reader']=None
   elif mutation=='wrong-inode':entry['fifo_reader']['inode']+=1
   elif mutation=='boolean-inode':entry['fifo_reader']['inode']=True
   else:entry['fifo_bytes_base64']=gate.encode(b'disallowed')
   with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):gate.validate_records(records)

 def test_foreign_owner_is_really99_and_preserves_seed_mode_and_links(self):
  for key,value in (('uid',0),('mode',0o644),('nlink',2)):
   records=rows();records[7]['before']['alias'][key]=value;records[7]['checkpoint']=copy.deepcopy(records[7]['before'])
   with self.subTest(key=key),self.assertRaises(RuntimeError):gate.validate_records(records)

 def test_recovery_requires_same_daemon_and_rejected_marker_stays_absent(self):
  for index in range(4,8):
   records=rows();records[index]['daemons'][0]['after']['starttime']+=1
   with self.assertRaises(RuntimeError):gate.validate_records(records)
   records=rows();entry=records[index]['after']['alias'];data=gate.decode(entry['bytes_base64'])+gate.marker(index,'REJECTED').encode();entry.update(size=len(data),bytes_base64=gate.encode(data))
   with self.assertRaises(RuntimeError):gate.validate_records(records)

 def test_no_default_file_fallback_stdout_or_stderr_is_accepted(self):
  for key in ('stdout_base64','stderr_base64'):
   for index in (0,4,5,6,7):
    records=rows();records[index]['daemons'][0][key]=gate.encode(b'forbidden fallback')
    with self.subTest(key=key,index=index),self.assertRaises(RuntimeError):gate.validate_records(records)

 def test_explicit_null_and_stdout_use_two_bounded_daemons_and_private_null_device(self):
  for mutation in ('one-daemon','default-file','missing-stdout','wrong-null','wrong-options'):
   records=rows();entry=records[8]
   if mutation=='one-daemon':entry['daemons'].pop()
   elif mutation=='default-file':entry['after']['alias']=snap(b'unexpected')
   elif mutation=='missing-stdout':entry['daemons'][1]['stdout_base64']=''
   elif mutation=='wrong-null':entry['null_device']['device_minor']=5
   else:entry['daemons'][0]['options']=['-s','0']
   with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):gate.validate_records(records)

 def test_client_failures_output_timeout_and_noncanonical_capture_are_rejected(self):
  for key,value in (('returncode',1),('stdout_base64',gate.encode(b'unexpected')),('stderr_base64','!'),('elapsed_ms',5001),('elapsed_ms',True)):
   records=rows();records[0]['clients'][0][key]=value
   with self.subTest(key=key),self.assertRaises((RuntimeError,ValueError)):gate.validate_records(records)

 def test_daemon_must_stop_without_forced_kill_and_keep_real_integer_identity(self):
  for key,value in (('forced_stop',True),('returncode',-9),('stopped',False)):
   records=rows();records[0]['daemons'][0][key]=value
   with self.subTest(key=key),self.assertRaises(RuntimeError):gate.validate_records(records)
  records=rows();records[0]['daemons'][0]['before']['pid']=True
  with self.assertRaises(RuntimeError):gate.validate_records(records)

 def test_report_exact_sources_image_closure_isolation_and_all_rows_are_bound(self):
  value,sources,shipped,dynamic,libraries=report();self.assertTrue(gate.validate_report(value,sources,shipped,dynamic,libraries))
  for key,replacement in (('status','FAIL'),('source_sha256',{}),('shipped',{}),('busybox_dynamic',{}),('runtime_libraries',{}),('checks',rows()[:-1]),('limits',{})):
   bad=copy.deepcopy(value);bad[key]=replacement
   with self.subTest(key=key),self.assertRaises(RuntimeError):gate.validate_report(bad,sources,shipped,dynamic,libraries)
  value['isolation']['namespaces']['mnt']['worker_inode']=value['isolation']['namespaces']['mnt']['parent_inode']
  with self.assertRaises(RuntimeError):gate.validate_report(value,sources,shipped,dynamic,libraries)

 def test_namespace_guard_precedes_mount_chmod_or_target_launch(self):
  args=types.SimpleNamespace(anchor_fds='{}')
  with mock.patch.object(gate.base,'namespace_guard',side_effect=RuntimeError('unsafe')),mock.patch.object(gate.producers,'private_filesystems')as mounts,mock.patch.object(gate.os,'chmod')as chmod,mock.patch.object(gate,'worker_cases')as cases:
   with self.assertRaisesRegex(RuntimeError,'unsafe'):gate.worker(args)
  mounts.assert_not_called();chmod.assert_not_called();cases.assert_not_called()

 def test_synthetic_snapshot_reads_hardlink_empty_regular_but_never_fifo_or_symlink(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);target=root/'target';target.write_bytes(gate.SEED);link=root/'alias';os.link(target,link)
   self.assertEqual(gate.decode(gate.file_snapshot(link)['bytes_base64']),gate.SEED);self.assertEqual(gate.file_snapshot(link)['nlink'],2)
   link.unlink();link.symlink_to(target.name);self.assertEqual(gate.file_snapshot(link)['type'],'symlink')
   link.unlink();os.mkfifo(link);self.assertEqual(gate.file_snapshot(link)['type'],'fifo')
   link.unlink();link.write_bytes(b'');self.assertEqual(gate.file_snapshot(link)['bytes_base64'],'')

 def test_source_collection_hashes_every_required_raw_file(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for index,name in enumerate(gate.SOURCE_PATHS.values()):
    path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('public source '+str(index)).encode())
   values=gate.source_inputs(root/'trunk');self.assertEqual(set(values),set(gate.SOURCE_PATHS))
   self.assertEqual(gate.source_hashes(values),{key:gate.sha((root/name).read_bytes())for key,name in gate.SOURCE_PATHS.items()})
   (root/gate.SOURCE_PATHS['default_file']).unlink()
   with self.assertRaises(OSError):gate.source_inputs(root/'trunk')

 def test_failed_case_retains_accumulated_raw_row_without_claiming_complete_pass(self):
  captured=[]
  def fail(args,index,row):row['before']={'public-partial-witness':True};raise RuntimeError('injected fixture failure')
  with mock.patch.object(gate,'exercise',side_effect=fail),self.assertRaisesRegex(RuntimeError,'injected fixture failure'):gate.worker_cases(None,captured)
  self.assertEqual(len(captured),1);self.assertEqual(captured[0]['status'],'FAIL');self.assertIn('fixture failure',captured[0]['failure']);self.assertEqual(captured[0]['before'],{'public-partial-witness':True})
  with self.assertRaises(RuntimeError):gate.validate_records(captured)

 def test_actual_command_builder_pins_rc_default_path_and_preserves_explicit_sinks(self):
  # Exercise the actual fixture command path with all file mutations/target
  # execution replaced. This catches an omitted-O even when report fixtures
  # and their expected schema were changed together.
  calls=[]
  class CapturedDaemon:
   def __init__(self,args,options):
    self.output=[bytearray(),bytearray()];self.options=list(options);calls.append(self.options)
   def ready(self):pass
   def pump(self):pass
   def wait(self,predicate,*args):pass
   def stop(self):return {'command_only_fixture':True}
  args=types.SimpleNamespace(sysroot=Path('/public/prefix'),rootfs=Path('/public/image'))
  def record_client(args,message,clients):clients.append({'message':message})
  with contextlib.ExitStack()as stack:
   patches=[mock.patch.object(gate,'clean_private_fixture'),mock.patch.object(gate,'objects',return_value={'private-command-capture':True}),mock.patch.object(gate,'fixture_file'),mock.patch.object(gate,'Daemon',CapturedDaemon),mock.patch.object(gate,'client',side_effect=record_client),mock.patch.object(gate.time,'sleep'),mock.patch.object(gate.os.path,'lexists',return_value=False),mock.patch.object(gate,'file_snapshot',return_value=None)]
   patches += [mock.patch.object(gate.Path,name)for name in('symlink_to','unlink')]
   patches += [mock.patch.object(gate.os,name)for name in('link','mkfifo','chown','close')]
   patches += [mock.patch.object(gate.os,'open',return_value=100),mock.patch.object(gate.os,'read',return_value=b''),mock.patch.object(gate.os,'fstat',return_value=types.SimpleNamespace(st_dev=7,st_ino=1,st_uid=0,st_mode=stat.S_IFIFO|0o600))]
   for patch in patches:stack.enter_context(patch)
   for index in range(9):
    row=dict(clients=[],daemons=[]);gate.exercise(args,index,row)
  expected=[['-s','1'if index==1 else'0','-O','/tmp/syslog.log']for index in range(8)]+[['-s','0','-O','/dev/null'],['-s','0','-O','-']]
  self.assertEqual(calls,expected)
  # Capture the actual Popen argv builder as well as its fixture options;
  # the command is never executed by this control.
  for options in calls:
   with mock.patch.object(gate.subprocess,'Popen')as launch,mock.patch.object(gate.os,'set_blocking'):
    gate.Daemon(args,options)
   self.assertEqual(launch.call_args[0][0],['qemu-mipsel','-L','/public/prefix','/public/image/bin/busybox','syslogd','-n','-S','-b','0']+options)
  records=rows();records[0]['daemons'][0]['options']=['-s','0']
  with self.assertRaisesRegex(RuntimeError,'options differ'):gate.validate_records(records)

 def test_native_harmless_driver_capture_and_term_cleanup_not_a_MIPS_claim(self):
  actual=subprocess.Popen
  def start(command,**kwargs):
   self.assertEqual(command[0],'qemu-mipsel');self.assertIn('syslogd',command)
   return actual([sys.executable,'-c','import sys,time;sys.stdout.write("PUBLIC_DRIVER_ONLY");sys.stdout.flush();time.sleep(20)'],**kwargs)
  args=types.SimpleNamespace(sysroot=Path('/public/prefix'),rootfs=Path('/public/image'))
  with mock.patch.object(gate.subprocess,'Popen',side_effect=start),mock.patch.object(gate,'identity',side_effect=lambda process:dict(pid=process.pid,starttime=42)):
   process=gate.Daemon(args,['-s','0']);process.before=gate.identity(process.process)
   try:process.wait(lambda:b'PUBLIC_DRIVER_ONLY'in process.output[0]);record=process.stop()
   finally:
    if not process.closed:process.stop()
  self.assertEqual(gate.decode(record['stdout_base64']),b'PUBLIC_DRIVER_ONLY');self.assertEqual(record['returncode'],-15)
  self.assertFalse(record['forced_stop']);self.assertIsNotNone(process.process.poll());self.assertTrue(process.process.stdout.closed)

 def test_native_harmless_driver_output_cap_still_reaps_and_closes_owned_child(self):
  actual=subprocess.Popen
  def start(command,**kwargs):return actual([sys.executable,'-c','import os,time;os.write(1,b"x"*70000);time.sleep(20)'],**kwargs)
  args=types.SimpleNamespace(sysroot=Path('/public/prefix'),rootfs=Path('/public/image'))
  with mock.patch.object(gate.subprocess,'Popen',side_effect=start),mock.patch.object(gate,'identity',side_effect=lambda process:dict(pid=process.pid,starttime=42)):
   process=gate.Daemon(args,['-s','0']);process.before=gate.identity(process.process)
   try:
    with self.assertRaisesRegex(RuntimeError,'output cap'):process.wait(lambda:False)
   finally:
    try:process.stop()
    except RuntimeError:pass
  self.assertIsNotNone(process.process.poll());self.assertTrue(process.process.stdout.closed);self.assertTrue(process.process.stderr.closed)

 def test_runtime_closure_uses_every_real_needed_alias_and_rejects_prefix_mismatch(self):
  root,prefix=Path('/image'),Path('/prefix');program=b'public-busybox';names={'lib/ld-uClibc.so.0':[],'lib/libc.so.0':['ld-uClibc.so.1'],'lib/ld-uClibc.so.1':[],'lib/libm.so.0':['libc.so.0']}
  def library(where,name):
   body=name.encode();return dict(bytes=len(body),sha256=gate.sha(body),resolved=name),body
  def details(body):return dict(interpreter='/lib/ld-uClibc.so.0'if body==program else None,needed=['libc.so.0','libm.so.0']if body==program else names[body.decode()])
  with mock.patch.object(gate,'read_file',return_value=program),mock.patch.object(gate.base,'elf',return_value={'e_machine':8}),mock.patch.object(gate.ntp,'elf_dynamic',side_effect=details),mock.patch.object(gate.ntp,'_runtime_library',side_effect=library):
   shipped,dynamic,libraries=gate.image_bindings(root,prefix)
  self.assertEqual(set(libraries),set(names));self.assertEqual(shipped['busybox']['sha256'],gate.sha(program))
  def corrupt(where,name):
   identity,body=library(where,name)
   return(identity,body+b'wrong')if where==prefix and name=='lib/libm.so.0'else(identity,body)
  with mock.patch.object(gate,'read_file',return_value=program),mock.patch.object(gate.base,'elf',return_value={'e_machine':8}),mock.patch.object(gate.ntp,'elf_dynamic',side_effect=details),mock.patch.object(gate.ntp,'_runtime_library',side_effect=corrupt),self.assertRaisesRegex(RuntimeError,'prefix differs'):
   gate.image_bindings(root,prefix)
  del names['lib/libm.so.0']
  def missing(where,name):
   if name not in names:raise FileNotFoundError(name)
   return library(where,name)
  with mock.patch.object(gate,'read_file',return_value=program),mock.patch.object(gate.base,'elf',return_value={'e_machine':8}),mock.patch.object(gate.ntp,'elf_dynamic',side_effect=details),mock.patch.object(gate.ntp,'_runtime_library',side_effect=missing),self.assertRaises(FileNotFoundError):
   gate.image_bindings(root,prefix)


if __name__=='__main__':unittest.main()
