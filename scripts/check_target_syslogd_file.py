#!/usr/bin/env python3
"""Actual shipped BusyBox syslogd/logger default-file tests in private Linux namespaces.

Public synthetic files only. No host /tmp/syslog.log, sysctl change or router test.
"""
import argparse,base64,json,os,re,signal,stat,subprocess,sys,time
from pathlib import Path
import check_target_syslog_producers as producers
import check_target_ntp as ntp
base=producers.base
require=base.require
sha=base.sha
SOURCE_PATHS={
 'syslogd':'trunk/user/busybox/busybox-1.24.x/sysklogd/syslogd.c',
 'default_file':'trunk/user/busybox/busybox-1.24.x/sysklogd/default_logfile.h',
 'logger':'trunk/user/busybox/busybox-1.24.x/sysklogd/logger.c',
 'safe_write':'trunk/user/busybox/busybox-1.24.x/libbb/safe_write.c',
 'full_write':'trunk/user/busybox/busybox-1.24.x/libbb/full_write.c',
 'bounded_log':'trunk/user/shared/bounded_syslog.h',
 'busybox_makefile':'trunk/user/busybox/Makefile',
 'busybox_config':'trunk/configs/boards/busybox.config',
 'rc_services':'trunk/user/rc/services.c','rc_init':'trunk/user/rc/init.c',
 'dev_init':'trunk/user/scripts/dev_init.sh'}
CASE_NAMES=('default-create-append','default-rotate-b0','owned-world-writable','owned-private',
 'symlink-reject-recover','hardlink-reject-recover','fifo-reader-reject-recover',
 'foreign-owner-reject-recover','explicit-null-stdout')
ROLE='Actual shipped MIPS BusyBox syslogd and logger under QEMU in anchored private PID/mount/network namespaces; synthetic root-owned and UID99 default-file fixtures only; no router or host-log claim'
FILESYSTEM_LIMITS=dict(producers.FILESYSTEM_LIMITS)
LIMITS=dict(worker_seconds=120,command_seconds=5,command_ms=5000,output_bytes=65536,
 report_bytes=1048576,file_bytes=65536,source_bytes=2097152,program_bytes=4194304,
 startup_seconds=5,observation_seconds=5,stop_seconds=3,settle_ms=200,runtime_aliases=16)
CONTRACT={
 'path':'Only literal /tmp/syslog.log is hardened; explicit -O /dev/null and -O - retain their separate behavior',
 'private':'Root PID1 namespace guard precedes tmpfs mounts; private /tmp is1777; no host protected_* sysctl changes',
 'ownership':'Default regular file must be euid0 single-link; new0644, verified0666 removes go-w to0644, existing0600 is not broadened',
 'unsafe':'Root-owned symlink and hardlink, FIFO with an active nonblocking reader, and real UID99 regular occupancy are neither written, chmodded nor removed by the daemon; no stdout/stderr fallback',
 'recovery':'Only the fixture removes its known alias; the same PID/starttime must then log the recovery marker without the rejected marker',
 'rotation':'Normal -b0 purge rotation is accelerated with -s1(1024bytes), not the production512KiB limit; old inode changes and no .0 backup appears',
 'witnesses':'Raw client results, daemon stdout/stderr, PID/starttime and lstat/fstat-bound synthetic file bytes/uid/mode/nlink/dev/ino/type are preserved',
 'limits':'Bounded clients/observations and daemon TERM cleanup; this is a CI execution attestation, not race exhaustiveness, hardware availability or physical RAM proof'}
DEFAULT=Path('/tmp/syslog.log')
TARGET=Path('/tmp/k2p-syslogd-target')
SEED=b'PUBLIC_SYSLOGD_FIXTURE_ONLY\n'
PROGRAMS={'busybox':'bin/busybox'}
STAT_KEYS={'type','uid','gid','mode','nlink','device','inode','size','bytes_base64','link_target','device_major','device_minor'}
OBJECT_KEYS={'alias','target','rotation'}
IDENTITY_KEYS={'pid','starttime'}
CLIENT_KEYS={'message','returncode','stdout_base64','stderr_base64','elapsed_ms'}
DAEMON_KEYS={'options','before','after','returncode','forced_stop','stopped','stdout_base64','stderr_base64'}
ROW_KEYS={'case','status','failure','before','checkpoint','after','clients','daemons',
 'fifo_reader','fifo_bytes_base64','fixture_removed_alias','rotation_scale_bytes','null_device'}


def integer(value,low=0,high=2**63-1):return type(value)is int and low<=value<=high

def encode(data):return base64.b64encode(data).decode('ascii')

def decode(value,maximum=LIMITS['file_bytes']):
 require(type(value)is str and len(value)<=((maximum+2)//3)*4,'Raw encoding exceeds limit')
 try:data=base64.b64decode(value,validate=True)
 except Exception as error:raise ValueError('Invalid raw byte encoding')from error
 require(encode(data)==value and len(data)<=maximum,'Noncanonical/excessive raw bytes')
 return data


def read_file(path,maximum):return producers.read_preflight_file(path,maximum)

def source_inputs(trunk):return {key:read_file(trunk.parent/name,LIMITS['source_bytes'])for key,name in SOURCE_PATHS.items()}

def source_hashes(inputs):return {key:sha(value)for key,value in inputs.items()}

def image_bindings(rootfs,sysroot):
 data=read_file(rootfs/PROGRAMS['busybox'],LIMITS['program_bytes']);dynamic=ntp.elf_dynamic(data)
 require(dynamic['interpreter']=='/lib/ld-uClibc.so.0','BusyBox interpreter differs')
 shipped={'busybox':dict(path=PROGRAMS['busybox'],bytes=len(data),sha256=sha(data),elf=base.elf(data))}
 # Follow the actual bounded dependency closure, including loader aliases used
 # by libc. No invented librt/libm dependency or missing-library skip.
 pending=['lib/ld-uClibc.so.0']+['lib/'+name for name in dynamic['needed']];libraries={}
 while pending:
  name=pending.pop(0)
  if name in libraries:continue
  require(len(libraries)<LIMITS['runtime_aliases'],'BusyBox runtime closure exceeds limit')
  identity,body=ntp._runtime_library(rootfs,name);other,other_body=ntp._runtime_library(sysroot,name)
  require(identity==other and body==other_body,'BusyBox runtime prefix differs from actual image: '+name)
  details=ntp.elf_dynamic(body);require(details['interpreter']in(None,'/lib/ld-uClibc.so.0','/lib/ld-uClibc.so.1'),'Runtime interpreter differs')
  libraries[name]=dict(identity=identity,dynamic=details)
  pending+=['lib/'+needed for needed in details['needed']]
 return shipped,dynamic,libraries


def fixture_bytes(path,expected=None):
 # Synthetic observations deliberately permit a hardlink/UID99 regular inode
 # and an empty file; input/program readers retain their stricter contract.
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  require(stat.S_ISREG(before.st_mode)and 0<=before.st_size<=LIMITS['file_bytes'],'Nonregular/excessive fixture read')
  if expected is not None:require((before.st_dev,before.st_ino)==(expected.st_dev,expected.st_ino),'Fixture descriptor/path differs')
  chunks=[];total=0
  while True:
   part=os.read(fd,min(4096,LIMITS['file_bytes']+1-total))
   if not part:break
   chunks.append(part);total+=len(part);require(total<=LIMITS['file_bytes'],'Fixture bytes exceeded limit')
  after=os.fstat(fd)
  require((before.st_dev,before.st_ino,before.st_size)==(after.st_dev,after.st_ino,after.st_size)and total==before.st_size,'Fixture changed during read')
  return b''.join(chunks)
 finally:os.close(fd)


def contains(path,value):
 try:return path.is_file()and value in fixture_bytes(path)
 except (OSError,RuntimeError):return False


def file_snapshot(path):
 try:st=path.lstat()
 except FileNotFoundError:return None
 kind='regular' if stat.S_ISREG(st.st_mode)else'symlink'if stat.S_ISLNK(st.st_mode)else'fifo'if stat.S_ISFIFO(st.st_mode)else'character'if stat.S_ISCHR(st.st_mode)else'other'
 row=dict(type=kind,uid=st.st_uid,gid=st.st_gid,mode=stat.S_IMODE(st.st_mode),nlink=st.st_nlink,
          device=st.st_dev,inode=st.st_ino,size=st.st_size,bytes_base64=None,link_target=None,
          device_major=os.major(st.st_rdev)if kind=='character'else None,device_minor=os.minor(st.st_rdev)if kind=='character'else None)
 if kind=='regular':
  body=fixture_bytes(path,st);again=path.lstat()
  require((st.st_dev,st.st_ino,st.st_size)==(again.st_dev,again.st_ino,again.st_size),'Synthetic regular file changed during capture')
  row['bytes_base64']=encode(body)
 elif kind=='symlink':row['link_target']=os.readlink(path)
 return row


def objects():return dict(alias=file_snapshot(DEFAULT),target=file_snapshot(TARGET),rotation=file_snapshot(Path(str(DEFAULT)+'.0')))


def identity(process):
 require(process.poll()is None,'syslogd exited before observation')
 text=Path('/proc/'+str(process.pid)+'/stat').read_text();end=text.rfind(')');fields=text[end+2:].split()
 require(end>0 and len(fields)>=20 and fields[0]!='Z','Invalid/live syslogd proc identity')
 require(not Path('/proc/'+str(process.pid)+'/task/'+str(process.pid)+'/children').read_text().strip(),'syslogd unexpectedly created children')
 return dict(pid=process.pid,starttime=int(fields[19]))


class Daemon:
 def __init__(self,args,options):
  self.options=list(options)
  self.process=subprocess.Popen(['qemu-mipsel','-L',str(args.sysroot),str(args.rootfs/'bin/busybox'),'syslogd','-n','-S','-b','0']+options,
   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,umask=0o022)
  self.output=[bytearray(),bytearray()];self.before=None;self.closed=False
  for stream in (self.process.stdout,self.process.stderr):os.set_blocking(stream.fileno(),False)
 def pump(self):
  for index,stream in enumerate((self.process.stdout,self.process.stderr)):
   for _ in range(16):
    try:chunk=os.read(stream.fileno(),4096)
    except BlockingIOError:break
    if not chunk:break
    self.output[index].extend(chunk)
    require(sum(map(len,self.output))<=LIMITS['output_bytes'],'syslogd output cap exceeded')
 def wait(self,predicate,seconds=LIMITS['observation_seconds']):
  deadline=time.monotonic()+seconds
  while True:
   self.pump();require(self.process.poll()is None,'syslogd exited while waiting')
   if predicate():return
   require(time.monotonic()<deadline,'syslogd observation deadline exceeded')
   time.sleep(.01)
 def ready(self):
  self.wait(lambda:Path('/dev/log').exists()and stat.S_ISSOCK(Path('/dev/log').lstat().st_mode),LIMITS['startup_seconds'])
  self.before=identity(self.process)
 def stop(self):
  require(not self.closed,'syslogd cleanup called twice');self.closed=True
  observed=identity(self.process)if self.process.poll()is None else None;forced=False
  deadline=time.monotonic()+LIMITS['stop_seconds']
  try:
   if self.process.poll()is None:self.process.send_signal(signal.SIGTERM)
   while self.process.poll()is None:
    self.pump()
    if time.monotonic()>=deadline:
     forced=True;self.process.kill();break
    time.sleep(.01)
   code=self.process.wait(timeout=2);self.pump()
   return dict(options=self.options,before=self.before,after=observed,returncode=code,forced_stop=forced,stopped=True,
               stdout_base64=encode(bytes(self.output[0])),stderr_base64=encode(bytes(self.output[1])))
  finally:
   if self.process.poll()is None:self.process.kill();self.process.wait(timeout=2)
   self.process.stdout.close();self.process.stderr.close()


def client(args,message,rows):
 started=time.monotonic()
 code,out,err=base.run_bounded(['qemu-mipsel','-L',str(args.sysroot),str(args.rootfs/'bin/busybox'),'logger','-t','k2p-default','-p','user.notice',message],limits=LIMITS)
 row=dict(message=message,returncode=code,stdout_base64=encode(out),stderr_base64=encode(err),elapsed_ms=int((time.monotonic()-started)*1000));rows.append(row)
 require(code==0 and out==err==b'','Actual logger client failed')


def marker(index,suffix):return 'K2P_SYSLOGD_FILE_'+str(index).zfill(2)+'_'+suffix


def clean_private_fixture():
 # Only called after namespace guard, and only removes this gate's fixed names.
 for path in (DEFAULT,TARGET,Path(str(DEFAULT)+'.0'),Path('/dev/log')):
  if os.path.lexists(path):path.unlink()


def fixture_file(path,body,mode):base.regular(path,body,mode)


def exercise(args,index,row):
 name=CASE_NAMES[index];unsafe=4<=index<=7;reader=None;daemon=None
 clean_private_fixture()
 seed=SEED
 if index in (2,3):fixture_file(DEFAULT,seed,0o666 if index==2 else 0o600)
 elif index==4:fixture_file(TARGET,seed,0o600);DEFAULT.symlink_to(TARGET)
 elif index==5:fixture_file(TARGET,seed,0o600);os.link(TARGET,DEFAULT)
 elif index==6:
  os.mkfifo(DEFAULT,0o600);reader=os.open(DEFAULT,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  st=os.fstat(reader);row['fifo_reader']=dict(device=st.st_dev,inode=st.st_ino,uid=st.st_uid,mode=stat.S_IMODE(st.st_mode),type='fifo')
 elif index==7:fixture_file(DEFAULT,seed,0o666);os.chown(DEFAULT,99,99)
 row['before']=objects()
 try:
  if index==8:
   row['null_device']=file_snapshot(Path('/dev/null'))
   for destination,suffix in (('/dev/null','NULL'),('-','STDOUT')):
    if os.path.lexists('/dev/log'):Path('/dev/log').unlink()
    daemon=Daemon(args,['-s','0','-O',destination]);daemon.ready()
    client(args,marker(index,suffix),row['clients'])
    if destination=='-':daemon.wait(lambda:marker(index,suffix).encode()in daemon.output[0])
    else:time.sleep(LIMITS['settle_ms']/1000);daemon.pump()
    row['daemons'].append(daemon.stop());daemon=None
    if destination=='/dev/null':row['checkpoint']=objects()
   row['after']=objects()
  else:
   daemon=Daemon(args,['-s','1'if index==1 else'0','-O',str(DEFAULT)]);daemon.ready()
   if index==1:
    for suffix in ('FILL1','FILL2','FILL3'):
     value=marker(index,suffix)+'x'*300;client(args,value,row['clients'])
     daemon.wait(lambda value=value:contains(DEFAULT,value.encode()))
    row['checkpoint']=objects()
    client(args,marker(index,'TAIL'),row['clients'])
    daemon.wait(lambda:contains(DEFAULT,marker(index,'TAIL').encode()))
   elif unsafe:
    client(args,marker(index,'REJECTED'),row['clients']);time.sleep(LIMITS['settle_ms']/1000);daemon.pump()
    row['checkpoint']=objects()
    if reader is not None:
     data=bytearray()
     while True:
      try:chunk=os.read(reader,4096)
      except BlockingIOError:break
      if not chunk:break
      data.extend(chunk);require(len(data)<=LIMITS['file_bytes'],'FIFO received excessive bytes')
     row['fifo_bytes_base64']=encode(bytes(data))
    DEFAULT.unlink();row['fixture_removed_alias']=True
    client(args,marker(index,'RECOVERY'),row['clients'])
    daemon.wait(lambda:contains(DEFAULT,marker(index,'RECOVERY').encode()))
   else:
    client(args,marker(index,'ONE'),row['clients'])
    daemon.wait(lambda:contains(DEFAULT,marker(index,'ONE').encode()))
    row['checkpoint']=objects();client(args,marker(index,'TWO'),row['clients'])
    daemon.wait(lambda:contains(DEFAULT,marker(index,'TWO').encode()))
   row['after']=objects();row['daemons'].append(daemon.stop());daemon=None
 finally:
  if daemon is not None:
   try:row['daemons'].append(daemon.stop())
   except Exception as error:row['failure']='Daemon cleanup failed: '+str(error)[:1024]
  if reader is not None:os.close(reader)


def valid_snapshot(row):
 if row is None:return
 require(type(row)is dict and set(row)==STAT_KEYS and row['type']in('regular','symlink','fifo','character','other'),'File snapshot schema differs')
 require(all(integer(row[key])for key in ('uid','gid','mode','nlink','device','inode','size'))and row['mode']<=0o7777 and row['inode']>0 and row['nlink']>0,'File snapshot metadata differs')
 if row['type']=='character':require(integer(row['device_major'])and integer(row['device_minor']),'Invalid captured device identity')
 else:require(row['device_major']is row['device_minor']is None,'Nondevice has device identity')
 if row['type']=='regular':require(row['link_target']is None and len(decode(row['bytes_base64']))==row['size'],'Regular snapshot bytes differ')
 elif row['type']=='symlink':require(row['bytes_base64']is None and type(row['link_target'])is str and len(row['link_target'])<=4096,'Symlink snapshot differs')
 else:require(row['bytes_base64']is row['link_target']is None,'Nonregular snapshot was read')


def regular(row,mode):
 require(row is not None and row['type']=='regular'and row['uid']==0 and row['nlink']==1 and row['mode']==mode,'Safe default inode mode/owner/type differs')
 return decode(row['bytes_base64'])


def validate_records(rows,partial=False):
 require(type(partial)is bool and type(rows)is list and ((1<=len(rows)<=9)if partial else len(rows)==9),'Missing/extra syslogd file cases')
 for index,(name,row)in enumerate(zip(CASE_NAMES,rows)):
  require(type(row)is dict and set(row)==ROW_KEYS and row['case']==name and row['status']=='PASS'and row['failure']is None,'Syslogd file case schema/status/order differs')
  for phase in ('before','checkpoint','after'):
   require(type(row[phase])is dict and set(row[phase])==OBJECT_KEYS,'Missing exact file observation')
   for value in row[phase].values():valid_snapshot(value)
   require(row[phase]['rotation']is None,'Unexpected rotated backup in -b0 fixture')
   if index not in(4,5):require(row[phase]['target']is None,'Unexpected private target fixture')
  expected_clients=4 if index==1 else 2
  require(type(row['clients'])is list and len(row['clients'])==expected_clients,'Actual logger call count differs')
  suffixes=('FILL1','FILL2','FILL3','TAIL')if index==1 else('REJECTED','RECOVERY')if 4<=index<=7 else('NULL','STDOUT')if index==8 else('ONE','TWO')
  for record,suffix in zip(row['clients'],suffixes):
   expected=marker(index,suffix)+('x'*300 if suffix.startswith('FILL')else'')
   require(type(record)is dict and set(record)==CLIENT_KEYS and record['message']==expected and type(record['returncode'])is int and record['returncode']==0 and decode(record['stdout_base64'])==decode(record['stderr_base64'])==b''and integer(record['elapsed_ms'],0,LIMITS['command_ms']),'Raw logger invocation differs/blocked')
  require(type(row['daemons'])is list and len(row['daemons'])==(2 if index==8 else 1),'Syslogd lifecycle count differs')
  for position,record in enumerate(row['daemons']):
   require(type(record)is dict and set(record)==DAEMON_KEYS,'Syslogd lifecycle schema differs')
   expected_options=['-s','0','-O','/dev/null'if position==0 else'-']if index==8 else['-s','1'if index==1 else'0','-O',str(DEFAULT)]
   require(record['options']==expected_options,'Actual syslogd invocation options differ')
   for key in ('before','after'):require(type(record[key])is dict and set(record[key])==IDENTITY_KEYS and integer(record[key]['pid'],2)and integer(record[key]['starttime'],1),'Missing live syslogd identity')
   require(record['before']==record['after']and type(record['returncode'])is int and record['returncode']in(-15,143)and record['forced_stop']is False and record['stopped']is True,'Syslogd identity changed/did not stop normally')
   stdout=decode(record['stdout_base64'],LIMITS['output_bytes']);stderr=decode(record['stderr_base64'],LIMITS['output_bytes'])
   require(stderr==b'','Unexpected syslogd fallback/diagnostic stderr')
   if index==8 and position==1:require(marker(index,'STDOUT').encode()in stdout,'Explicit stdout lost marker')
   else:require(stdout==b'','Default file/null logging fell back to stdout')
  require(row['rotation_scale_bytes']==(1024 if index==1 else None)and row['fixture_removed_alias']is (True if 4<=index<=7 else False),'Rotation/removal fixture differs')
  if index==6:
   reader=row['fifo_reader'];before=row['before']['alias']
   require(type(reader)is dict and set(reader)=={'device','inode','uid','mode','type'}and all(integer(reader[key])for key in('device','inode','uid','mode'))and reader=={key:before[key]for key in reader}and reader['type']=='fifo'and reader['uid']==0 and decode(row['fifo_bytes_base64'])==b'','FIFO was not actively read or received bytes')
  else:require(row['fifo_reader']is row['fifo_bytes_base64']is None,'Unexpected FIFO fixture')
  before=row['before']['alias'];checkpoint=row['checkpoint']['alias'];after=row['after']['alias']
  if index==8:
   valid_snapshot(row['null_device']);node=row['null_device']
   require(node is not None and node['type']=='character'and node['uid']==0 and node['mode']==0o666 and (node['device_major'],node['device_minor'])==(1,3),'Explicit null is not private Linux null1:3')
   require(before is checkpoint is after is None,'Explicit output modified default log path');continue
  require(row['null_device']is None,'Unexpected null-device witness')
  if 4<=index<=7:
   require(row['before']==row['checkpoint'],'Unsafe inode/content/mode was changed or alias removed')
   require(before is not None and before['type']==('symlink'if index==4 else'regular'if index in(5,7)else'fifo'),'Unsafe fixture type differs')
   if index in(4,5):
    target=row['before']['target']
    require(target is not None and target['type']=='regular'and target['uid']==0 and target['mode']==0o600 and decode(target['bytes_base64'])==SEED,'Private target seed/ownership differs')
   if index==4:require(before['uid']==0 and before['link_target']==str(TARGET),'Symlink is not a root-owned private target')
   if index==5:require(before['nlink']==2 and row['before']['target']['inode']==before['inode']and row['before']['target']['device']==before['device']and row['before']['target']['nlink']==2 and before['uid']==0 and decode(before['bytes_base64'])==SEED,'Hardlink witness differs')
   if index==6:require(before['uid']==0 and before['mode']==0o600 and before['nlink']==1,'FIFO seed ownership differs')
   if index==7:require(before['uid']==99 and before['mode']==0o666 and before['nlink']==1 and decode(before['bytes_base64'])==SEED,'Foreign UID99 placeholder differs')
   target_before=row['before']['target'];target_after=row['after']['target']
   if target_before is not None:
    expected=dict(target_before)
    if index==5:expected['nlink']=1
    require(target_after==expected,'Private target was modified during rejection/recovery')
   body=regular(after,0o644);require(marker(index,'RECOVERY').encode()in body and marker(index,'REJECTED').encode()not in body,'Same-daemon recovery/drop policy differs')
  else:
   expected_mode=0o600 if index==3 else 0o644;body=regular(after,expected_mode);middle=regular(checkpoint,expected_mode)
   if index in(2,3):require(before['uid']==0 and before['nlink']==1 and before['mode']==(0o666 if index==2 else 0o600)and decode(before['bytes_base64'])==SEED and before['inode']==checkpoint['inode']==after['inode'],'Owned migration replaced inode or broadened private mode')
   else:require(before is None,'New default fixture already existed')
   if index==1:require(len(middle)>1024 and checkpoint['inode']!=after['inode']and marker(index,'TAIL').encode()in body and all(marker(index,s).encode()not in body for s in ('FILL1','FILL2','FILL3')),'-b0 rotation/purge did not occur')
   else:require(checkpoint['inode']==after['inode']and checkpoint['device']==after['device']and marker(index,'ONE').encode()in middle and all(marker(index,s).encode()in body for s in ('ONE','TWO')),'Normal append markers missing')
 return True


def unique(pairs):
 result={}
 for key,value in pairs:require(key not in result,'Duplicate JSON key');result[key]=value
 return result


def validate_report(report,sources,shipped,dynamic,libraries):
 keys={'schema_version','status','profile','execution_role','source_sha256','shipped','busybox_dynamic','runtime_libraries','required_cases','checks','filesystem_limits','limits','contract','isolation','failure'}
 require(type(report)is dict and set(report)==keys and type(report['schema_version'])is int and report['schema_version']==1 and report['status']=='PASS'and report['profile']=='k2p-4.4'and report['failure']is None,'Syslogd file gate is not complete PASS')
 require(report['execution_role']==ROLE and report['source_sha256']==sources and report['shipped']==shipped and report['busybox_dynamic']==dynamic and report['runtime_libraries']==libraries and report['required_cases']==list(CASE_NAMES)and report['filesystem_limits']==FILESYSTEM_LIMITS and report['limits']==LIMITS and report['contract']==CONTRACT,'Syslogd source/image/runtime/contract differs')
 producers.validate_isolation(report['isolation']);return validate_records(report['checks'])


def worker_cases(args,rows):
 for index,name in enumerate(CASE_NAMES):
  row=dict(case=name,status='RUNNING',failure=None,before=None,checkpoint=None,after=None,clients=[],daemons=[],fifo_reader=None,fifo_bytes_base64=None,fixture_removed_alias=False,rotation_scale_bytes=1024 if index==1 else None,null_device=None);rows.append(row)
  print('Target syslogd file CASE '+name,flush=True)
  try:exercise(args,index,row);row['status']='PASS';validate_records(rows,partial=True)
  except Exception as error:row['status']='FAIL';row['failure']=str(error)[:4096];raise
  print('Target syslogd file PASS '+name,flush=True)


def worker(args):
 namespaces=base.namespace_guard(json.loads(args.anchor_fds));producers.private_filesystems(args.sysroot);os.chmod('/tmp',0o1777)
 Path('/var/run').mkdir(mode=0o755,exist_ok=True)
 shipped,dynamic,libraries=image_bindings(args.rootfs,args.sysroot)
 report=dict(schema_version=1,status='FAIL',profile='k2p-4.4',execution_role=ROLE,source_sha256=source_hashes(source_inputs(args.trunk)),shipped=shipped,busybox_dynamic=dynamic,runtime_libraries=libraries,required_cases=list(CASE_NAMES),checks=[],filesystem_limits=FILESYSTEM_LIMITS,limits=LIMITS,contract=CONTRACT,isolation=dict(namespaces=namespaces,worker_pid=os.getpid(),loopback_only=True,private_mount_propagation=True,anchors_cloexec=True,namespace_exit_confirmed=False,private_dev_log=True),failure=None)
 try:worker_cases(args,report['checks']);report['status']='PASS'
 except Exception as error:report['failure']=str(error)[:4096];raise
 finally:base.write_output(args.output,json.loads(args.expected_output),report)


def root_parent(args):
 require(sys.platform.startswith('linux')and os.geteuid()==0,'Linux root launcher required')
 expected=json.loads(args.expected_output);require(base.output_identity(args.output)==expected,'Parent output inode changed')
 anchors={name:os.open('/proc/self/ns/'+name,os.O_RDONLY|os.O_CLOEXEC)for name in ('mnt','net','pid')}
 command=['unshare','--mount','--net','--pid','--fork','--mount-proc','--kill-child=KILL','--propagation','private',sys.executable,str(Path(__file__).resolve()),'--worker']
 for key in ('trunk','rootfs','sysroot','output'):command+=['--'+key,str(getattr(args,key))]
 command+=['--expected-output',args.expected_output,'--anchor-fds',json.dumps(anchors)]
 try:subprocess.run(command,check=True,timeout=LIMITS['worker_seconds'],pass_fds=tuple(anchors.values()))
 finally:
  for fd in anchors.values():os.close(fd)
 report=json.loads(args.output.read_text(),object_pairs_hook=unique);require(report['status']=='PASS','Private syslogd worker failed')
 report['isolation']['namespace_exit_confirmed']=True;base.write_output(args.output,expected,report)


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for key in ('trunk','rootfs','sysroot','output'):parser.add_argument('--'+key,type=Path,required=True)
 modes=parser.add_mutually_exclusive_group();modes.add_argument('--worker',action='store_true');modes.add_argument('--root-parent',action='store_true')
 for key in ('expected-output','anchor-fds'):parser.add_argument('--'+key)
 args=parser.parse_args()
 for key in ('trunk','rootfs','sysroot'):setattr(args,key,getattr(args,key).resolve())
 args.output=args.output.parent.resolve()/args.output.name
 if args.worker:return worker(args)
 if args.root_parent:return root_parent(args)
 require(sys.platform.startswith('linux'),'Actual syslogd gate requires Linux; no fallback PASS')
 for path in (args.trunk,args.rootfs,args.sysroot,args.output,Path(__file__).resolve()):require(not any(path.is_relative_to('/'+name)for name in FILESYSTEM_LIMITS),'Syslogd gate input hidden by private mounts')
 sources=source_hashes(source_inputs(args.trunk));shipped,dynamic,libraries=image_bindings(args.rootfs,args.sysroot);expected=base.prepare_output(args.output)
 try:
  command=(['sudo','-n','env','PATH='+os.environ['PATH']]if os.geteuid()else[])+[sys.executable,str(Path(__file__).resolve()),'--root-parent','--trunk',str(args.trunk),'--rootfs',str(args.rootfs),'--sysroot',str(args.sysroot),'--output',str(args.output),'--expected-output',json.dumps(expected)]
  subprocess.run(command,check=True,timeout=LIMITS['worker_seconds']+30)
  require(base.output_identity(args.output)==expected,'Root worker changed report owner/inode');validate_report(json.loads(args.output.read_text(),object_pairs_hook=unique),sources,shipped,dynamic,libraries)
 except Exception as error:
  try:report=json.loads(args.output.read_text(),object_pairs_hook=unique)
  except Exception:report=dict(schema_version=1,status='FAIL',profile='k2p-4.4',execution_role=ROLE,checks=[])
  report['status']='FAIL';report['failure']=str(error)[:4096];base.write_output(args.output,expected,report);raise
 print('Actual shipped BusyBox syslogd/logger: all9 private default-file cases PASS; no host-log/router claim')


if __name__=='__main__':main()
