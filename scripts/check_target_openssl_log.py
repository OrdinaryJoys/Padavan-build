#!/usr/bin/env python3
"""Actual shipped libcrypto BIO logging under QEMU in private Linux namespaces.

No OpenSSL OCSP server/key, host socket, whole-daemon or physical-router claim.
"""
import argparse,base64,errno,json,os,re,socket,stat,struct,subprocess,sys,time
from pathlib import Path
import check_target_syslog_producers as producers
import check_target_ntp as ntp
base=producers.base
require=base.require
sha=base.sha
SOURCE_PATHS={
 'shared_header':'trunk/user/shared/bounded_syslog.h',
 'libssl_makefile':'trunk/libs/libssl/Makefile',
 'libssl_patch':'trunk/libs/libssl/openssl-bounded-log.patch',
 'probe':'tests/openssl_log_probe.c',
 'bio_fixture':'tests/fixtures/openssl-log-sources/bss_log.c',
 'app_header_fixture':'tests/fixtures/openssl-log-sources/log.h',
 'app_log_fixture':'tests/fixtures/openssl-log-sources/log.c',
 'http_server_fixture':'tests/fixtures/openssl-log-sources/http_server.c',
 'ocsp_fixture':'tests/fixtures/openssl-log-sources/ocsp.c'}
CASE_NAMES=('bio-normal','bio-per-context','bio-large-input','bio-queue-full','bio-recovery','bio-control-lifecycle','bio-fork-lifecycle','bio-empty-input')
OPERATIONS=('normal','per-bio','long','pressure','normal','control','fork','empty')
INPUT_LENGTHS=([24],[11,8,13],[1048576],[24]*128,[24],[13,15],[14],[0])
ROLE='Actual public BIO APIs dynamically linked to the actual shipped MIPS libcrypto under QEMU; private PID/mount/network namespaces and synthetic /dev/log; not an OCSP server or physical router'
FILESYSTEM_LIMITS=dict(producers.FILESYSTEM_LIMITS)
LIMITS=dict(worker_seconds=120,command_seconds=5,command_ms=5000,output_bytes=131072,report_bytes=2097152,datagram_bytes=1024,syslog_fill_datagrams=1024,pressure_calls=128,large_input_bytes=1048576,library_bytes=16777216,probe_bytes=4194304,source_bytes=1048576)
CONTRACT={
 'transport':'Actual shipped libcrypto BIO_s_log; one nonblocking Unix datagram attempt per write; queue EAGAIN observed before pressure calls',
 'accepted_bytes':'BIO_write accepts input byte counts even when log frames truncate or are dropped under backpressure',
 'heap':'The caller owns the large input; native actual-source allocator controls, not target RSS, establish bounded per-BIO context and no full-input logger allocation',
 'errno_threads':'Whole BIO/allocator errno is observed, not promised preserved; callers retain OpenSSL same-BIO serialization requirements',
 'scope':'No OCSP server, private key, whole daemon, host /dev/log, router, flash or hardware boot; LOG_CONS remains a separate best-effort nonblocking console path'}
PROGRAMS={'openssl':'usr/bin/openssl','libcrypto':'lib/libcrypto.so.3'}
RUNTIME_PATHS=('lib/ld-uClibc.so.0','lib/ld-uClibc.so.1','lib/libc.so.0','lib/libcrypto.so.3','lib/libatomic.so.1')
FORBIDDEN_IMPORTS=('closelog','openlog','setlogmask','syslog','vsyslog')
ROW_KEYS={'case','operation','elapsed_ms','queue_full_errno','queue_filler_datagrams','probe_result','stdout','stderr','datagrams_base64'}
RESULT_KEYS={'schema_version','mode','calls','fd_before','fd_after','errno_entry','errno_after_write','child_status'}
FILLER=b'K2P_OPENSSL_QUEUE_FILL'+b'x'*(1024-len(b'K2P_OPENSSL_QUEUE_FILL'))


def integer(x,low=0,high=2**31-1):return type(x)is int and low<=x<=high

def read_file(path,maximum):
 return producers.read_preflight_file(path,maximum)

def source_inputs(trunk):
 root=trunk.parent
 return {name:read_file(root/path,LIMITS['source_bytes']).decode('utf-8') for name,path in SOURCE_PATHS.items()}

def source_hashes(inputs):return {k:sha(v.encode())for k,v in inputs.items()}

def generate_source(inputs):
 require(type(inputs)is dict and set(inputs)==set(SOURCE_PATHS) and all(type(v)is str for v in inputs.values()),'Missing exact OpenSSL source inputs')
 require('BIO_s_log()'in inputs['probe'] and '#include <openssl/bio.h>'in inputs['probe'],'Public BIO source missing')
 return inputs['probe']

def shipped_proof(rootfs):
 result={}
 for key,name in PROGRAMS.items():
  data=read_file(rootfs/name,LIMITS['library_bytes']);symbols=producers.dynamic_symbols(data)
  forbidden=sorted(set(symbols['undefined'])&set(FORBIDDEN_IMPORTS));require(not forbidden,'OpenSSL retains blocking imports: '+name+':'+repr(forbidden))
  if key=='libcrypto':require('BIO_s_log'in symbols['provided'],'Actual libcrypto lacks logging BIO')
  result[key]=dict(path=name,bytes=len(data),sha256=sha(data),elf=base.elf(data),forbidden_imports=forbidden)
 return result

def runtime_libraries(rootfs,sysroot):
 result={}
 for name in RUNTIME_PATHS:
  identity,data=ntp._runtime_library(rootfs,name);runtime,runtime_data=ntp._runtime_library(sysroot,name)
  require(identity==runtime and data==runtime_data,'Probe library/prefix differs from actual image: '+name)
  result[name]=dict(identity=identity,dynamic=ntp.elf_dynamic(data))
 require(set(result['lib/libcrypto.so.3']['dynamic']['needed'])=={'libatomic.so.1','libc.so.0'},'Unexpected libcrypto runtime dependencies')
 available={Path(name).name for name in result}
 for row in result.values():
  require(all(dep in available for dep in row['dynamic']['needed']),'OpenSSL runtime library closure missing')
  require(row['dynamic']['interpreter']in(None,'/lib/ld-uClibc.so.0','/lib/ld-uClibc.so.1'),'OpenSSL runtime loader mismatch')
 return result

def create_export(path,data,mode):
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,mode)
 try:
  with os.fdopen(fd,'wb',closefd=False)as f:f.write(data);f.flush()
 finally:os.close(fd)


def validate_probe_entry(data):
 # Public API probe is executable, unlike shared libraries whose entry may be0.
 ntp.elf(data)
 entry,offset=struct.unpack_from('<II',data,24);stride,count=struct.unpack_from('<HH',data,42)
 require(any(kind==1 and flags&1 and address<=entry<address+filesz
             for kind,start,address,physical,filesz,memory,flags,alignment in
             (struct.unpack_from('<8I',data,offset+i*stride)for i in range(count))),
         'BIO probe entry is not file-backed executable code')
 return True


def compile_probe(args,inputs):
 source=args.output.with_name('target-openssl-log-probe.c');binary=source.with_suffix('')
 require(not os.path.lexists(binary),'Probe binary export already exists')
 code=generate_source(inputs).encode();create_export(source,code,0o644)
 staged=args.trunk/'stage/lib';include=args.trunk/'libs/libssl/openssl-3.5.9/include'
 command=[str(args.compiler),'-std=gnu99','-Wall','-Wextra','-Werror','-O2','-I'+str(include),str(source),'-L'+str(staged),'-Wl,-rpath-link,'+str(staged),'-Wl,-rpath-link,'+str(args.sysroot/'lib'),'-lcrypto','-o',str(binary)]
 r=subprocess.run(command,capture_output=True,timeout=90)
 require(r.returncode==0,'Actual libcrypto probe compile failed: '+r.stderr.decode(errors='replace')[:4096])
 binary.chmod(0o755);data=read_file(binary,LIMITS['probe_bytes']);validate_probe_entry(data);dynamic=ntp.elf_dynamic(data)
 require(dynamic['interpreter']=='/lib/ld-uClibc.so.0' and dynamic['needed']==['libcrypto.so.3','libc.so.0'],'Unexpected dynamic BIO probe linkage')
 version=subprocess.run([str(args.compiler),'--version'],capture_output=True,check=True,timeout=10).stdout.decode(errors='replace').splitlines()[0]
 return dict(source_sha256=sha(code),sha256=sha(data),bytes=len(data),elf=base.elf(data),dynamic=dynamic),binary,dict(path=str(args.compiler),version=version)


def decode_frames(value):
 require(type(value)is list and len(value)<=LIMITS['syslog_fill_datagrams'],'Raw datagram count exceeded')
 frames=[]
 for text in value:
  require(type(text)is str and len(text)<=1400,'Raw datagram encoding exceeded')
  try:data=base64.b64decode(text,validate=True)
  except Exception as e:raise ValueError('Invalid raw datagram base64')from e
  require(base64.b64encode(data).decode()==text and 0<len(data)<=LIMITS['datagram_bytes'],'Raw datagram encoding/length mismatch');frames.append(data)
 return frames


def frame(data,priority,tag,body=None,long=False):
 require(data.endswith(b'\0') and data.count(b'\0')==1 and len(data)<=1024,'BIO frame must be bounded, NUL terminated')
 pattern=(r'^<'+str(priority)+r'>[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} '+re.escape(tag)+r'\[([1-9][0-9]*)\]: ').encode()
 match=re.match(pattern,data);require(match is not None,'BIO priority/tag/PID/timestamp mismatch')
 payload=data[match.end():-1]
 if long:require(len(data)==1024 and payload.startswith(b'[truncated] ') and len(payload)>64 and set(payload[len(b'[truncated] '):])=={ord('x')},'Long BIO frame missing bounded truncation')
 else:require(payload==body,'BIO body/literal format changed')
 return int(match[1])


def validate_records(rows,partial=False):
 require(type(partial)is bool,'Explicit prefix-validation selector required')
 require(type(rows)is list and ((1<=len(rows)<=len(CASE_NAMES))if partial else len(rows)==len(CASE_NAMES)),'Missing/extra BIO cases')
 for index,(name,row)in enumerate(zip(CASE_NAMES,rows)):
  require(type(row)is dict and set(row)==ROW_KEYS and row['case']==name and row['operation']==OPERATIONS[index],'BIO case schema/order mismatch')
  require(integer(row['elapsed_ms'],0,LIMITS['command_ms']) and type(row['stdout'])is str and len(row['stdout'].encode())<=LIMITS['output_bytes'] and row['stderr']=='','BIO invocation blocked or produced unexpected output')
  result=row['probe_result']
  require(type(result)is dict and set(result)==RESULT_KEYS and type(result['schema_version'])is int and result['schema_version']==1 and result['mode']==OPERATIONS[index],'Public BIO result schema mismatch')
  require(json.loads(row['stdout'],object_pairs_hook=unique)==result,'Stored BIO result differs from original stdout')
  require(type(result['calls'])is list and len(result['calls'])==len(INPUT_LENGTHS[index]),'BIO call count mismatch')
  for call,n in zip(result['calls'],INPUT_LENGTHS[index]):require(type(call)is dict and set(call)=={'input','accepted'} and type(call['input'])is type(call['accepted'])is int and call['input']==call['accepted']==n,'BIO accepted byte result mismatch')
  require(integer(result['fd_before'],3,4096) and result['fd_after']==result['fd_before'] and type(result['fd_after'])is int and result['errno_entry']==33 and type(result['errno_entry'])is int and integer(result['errno_after_write'],0,4095) and type(result['child_status'])is int and result['child_status']==(0 if name=='bio-fork-lifecycle'else-1),'BIO FD/errno/fork result mismatch')
  frames=decode_frames(row['datagrams_base64'])
  if name=='bio-queue-full':
   require(type(row['queue_full_errno'])is int and row['queue_full_errno']==11 and integer(row['queue_filler_datagrams'],1,1024) and len(frames)==row['queue_filler_datagrams'] and all(x==FILLER for x in frames),'Missing exact actual full-queue EAGAIN witness');continue
  require(row['queue_full_errno']is None and type(row['queue_filler_datagrams'])is int and row['queue_filler_datagrams']==0,'Unexpected pressure witness on another BIO case')
  if name in ('bio-normal','bio-recovery'):
   require(len(frames)==1,'Missing normal/recovery BIO frame');frame(frames[0],156,'bio-a',b'literal %n %s %%')
  elif name=='bio-per-context':
   require(len(frames)==3,'Missing per-BIO frames');pids=[frame(data,pri,tag,body)for data,pri,tag,body in zip(frames,(156,166,156),('bio-a','bio-b','bio-a'),(b'ONE',b'TWO',b'THREE'))];require(len(set(pids))==1,'Per-BIO frames came from different processes')
  elif name=='bio-large-input':require(len(frames)==1,'Missing long BIO frame');frame(frames[0],158,'bio-a',long=True)
  elif name=='bio-control-lifecycle':
   require(len(frames)==2,'Missing owned/replaced context frames');require(frame(frames[0],172,'owned-name',b'OWNED')==frame(frames[1],156,'updated-name',b'UPDATED'),'Control lifecycle process changed')
  elif name=='bio-fork-lifecycle':
   require(len(frames)==2,'Missing child/parent BIO frames');require(frame(frames[0],172,'bio-child',b'CHILD')!=frame(frames[1],156,'bio-a',b'PARENT'),'BIO fork did not produce a distinct child PID')
  else:require(frames==[],'Zero-input public BIO API emitted a log frame')
 return True


def unique(pairs):
 result={}
 for k,v in pairs:require(k not in result,'Duplicate JSON result key');result[k]=v
 return result


def validate_report(report,sources,shipped,libraries,code=None):
 keys={'schema_version','status','profile','execution_role','source_sha256','shipped','runtime_libraries','required_cases','checks','filesystem_limits','limits','contract','probe','compiler','isolation','failure'}
 require(type(report)is dict and set(report)==keys and type(report['schema_version'])is int and report['schema_version']==1 and report['status']=='PASS' and report['profile']=='k2p-4.4' and report['failure']is None,'OpenSSL log gate not complete PASS')
 require(report['execution_role']==ROLE and report['source_sha256']==sources and report['shipped']==shipped and report['runtime_libraries']==libraries and report['required_cases']==list(CASE_NAMES) and report['filesystem_limits']==FILESYSTEM_LIMITS and report['limits']==LIMITS and report['contract']==CONTRACT,'OpenSSL source/image/role/budget changed')
 probe=report['probe'];require(type(probe)is dict and set(probe)=={'source_sha256','sha256','bytes','elf','dynamic'} and all(type(probe[k])is str and re.fullmatch('[0-9a-f]{64}',probe[k])for k in ('sha256','source_sha256')) and integer(probe['bytes'],52,LIMITS['probe_bytes']) and probe['elf']in(dict(elf_class=32,byte_order='little',e_machine=8,e_type=2),dict(elf_class=32,byte_order='little',e_machine=8,e_type=3)) and probe['dynamic']==dict(interpreter='/lib/ld-uClibc.so.0',needed=['libcrypto.so.3','libc.so.0']),'BIO actual dynamic probe metadata differs')
 if code is not None:require(probe['source_sha256']==sha(code.encode()),'BIO exported C is not locked source')
 require(type(report['compiler'])is dict and set(report['compiler'])=={'path','version'} and all(type(v)is str and 0<len(v)<=4096 for v in report['compiler'].values()),'Missing compiler identity')
 producers.validate_isolation(report['isolation']);return validate_records(report['checks'])

class Receiver:
 def __init__(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
  self.sock.bind('/dev/log');self.sock.setblocking(False)
 def drain(self):
  packets=[]
  while True:
   try:data=self.sock.recv(2048)
   except BlockingIOError:break
   require(0<len(data)<=1024 and len(packets)<1024,'Unexpected raw logger queue payload')
   packets.append(data)
  return packets
 def fill(self):
  self.drain();sender=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);sender.setblocking(False);count=0
  try:
   for _ in range(LIMITS['syslog_fill_datagrams']):
    try:
     require(sender.sendto(FILLER,'/dev/log')==len(FILLER),'Short queue filler datagram');count+=1
    except BlockingIOError as e:
     require(e.errno==errno.EAGAIN and count>0,'Queue pressure is not EAGAIN');return count,e.errno
   raise RuntimeError('No full datagram queue witness')
  finally:sender.close()
 def close(self):self.sock.close()


def worker_cases(args,rows):
 receiver=Receiver()
 try:
  for name,operation in zip(CASE_NAMES,OPERATIONS):
   print('Target OpenSSL BIO CASE '+name,flush=True)
   if name=='bio-queue-full':count,full_errno=receiver.fill()
   else:receiver.drain();count=0;full_errno=None
   started=time.monotonic()
   code,out,err=base.run_bounded(['qemu-mipsel','-L',str(args.sysroot),args.probe_path,operation],limits=LIMITS)
   ms=int((time.monotonic()-started)*1000)
   require(code==0,'BIO probe rc='+str(code)+' operation='+operation+': '+(out+err).decode(errors='replace')[:4096])
   result=json.loads(out,object_pairs_hook=unique)
   packets=receiver.drain()
   row=dict(case=name,operation=operation,elapsed_ms=ms,queue_full_errno=full_errno,queue_filler_datagrams=count,probe_result=result,stdout=out.decode(),stderr=err.decode(),datagrams_base64=[base64.b64encode(x).decode()for x in packets])
   rows.append(row)
   # Validate every completed prefix without declaring missing later rows PASS.
   validate_records(rows,partial=True)
   print('Target OpenSSL BIO PASS '+name,flush=True)
  validate_records(rows)
 finally:receiver.close()


def report_shell(args):
 return dict(schema_version=1,status='FAIL',profile='k2p-4.4',execution_role=ROLE,
  source_sha256=source_hashes(source_inputs(args.trunk)),shipped=shipped_proof(args.rootfs),runtime_libraries=runtime_libraries(args.rootfs,args.sysroot),required_cases=list(CASE_NAMES),checks=[],filesystem_limits=FILESYSTEM_LIMITS,limits=LIMITS,contract=CONTRACT,probe=json.loads(args.probe_metadata),compiler=json.loads(args.compiler_metadata),isolation=None,failure=None)


def worker(args):
 # Guard anchored original namespaces/PID1 before any system path mount.
 namespaces=base.namespace_guard(json.loads(args.anchor_fds));producers.private_filesystems(args.sysroot)
 report=report_shell(args)
 report['isolation']=dict(namespaces=namespaces,worker_pid=os.getpid(),loopback_only=True,private_mount_propagation=True,anchors_cloexec=True,namespace_exit_confirmed=False,private_dev_log=True)
 try:
  worker_cases(args,report['checks']);report['status']='PASS'
 except Exception as error:report['failure']=str(error)[:4096];raise
 finally:base.write_output(args.output,json.loads(args.expected_output),report)


def root_parent(args):
 require(sys.platform.startswith('linux') and os.geteuid()==0,'Linux root namespace launcher required')
 expected=json.loads(args.expected_output);require(base.output_identity(args.output)==expected,'Parent-owned BIO output changed')
 anchors={name:os.open('/proc/self/ns/'+name,os.O_RDONLY|os.O_CLOEXEC)for name in ('mnt','net','pid')}
 command=['unshare','--mount','--net','--pid','--fork','--mount-proc','--kill-child=KILL','--propagation','private',sys.executable,str(Path(__file__).resolve()),'--worker']
 for key in ('trunk','rootfs','sysroot','output'):command+=['--'+key,str(getattr(args,key))]
 for key in ('expected-output','probe-metadata','compiler-metadata','probe-path'):command+=['--'+key,getattr(args,key.replace('-','_'))]
 command+=['--anchor-fds',json.dumps(anchors)]
 try:subprocess.run(command,check=True,timeout=LIMITS['worker_seconds'],pass_fds=tuple(anchors.values()))
 finally:
  for fd in anchors.values():os.close(fd)
 report=json.loads(args.output.read_text(),object_pairs_hook=unique);require(report['status']=='PASS','BIO namespace worker failed')
 report['isolation']['namespace_exit_confirmed']=True;base.write_output(args.output,expected,report)


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for key in ('trunk','rootfs','sysroot','output'):parser.add_argument('--'+key,type=Path,required=True)
 parser.add_argument('--compiler',type=Path)
 modes=parser.add_mutually_exclusive_group();modes.add_argument('--worker',action='store_true');modes.add_argument('--root-parent',action='store_true')
 for key in ('expected-output','anchor-fds','probe-metadata','compiler-metadata','probe-path'):parser.add_argument('--'+key)
 args=parser.parse_args()
 for key in ('trunk','rootfs','sysroot'):setattr(args,key,getattr(args,key).resolve())
 args.output=args.output.parent.resolve()/args.output.name
 if args.worker:return worker(args)
 if args.root_parent:return root_parent(args)
 require(sys.platform.startswith('linux') and args.compiler is not None,'Linux MIPS runtime BIO gate required; no fallback PASS')
 for path in (args.trunk,args.rootfs,args.sysroot,args.output,Path(__file__).resolve()):
  require(not any(path.is_relative_to('/'+name)for name in FILESYSTEM_LIMITS),'BIO gate input hidden by private mounts')
 inputs=source_inputs(args.trunk);sources=source_hashes(inputs);shipped=shipped_proof(args.rootfs);libraries=runtime_libraries(args.rootfs,args.sysroot)
 expected=base.prepare_output(args.output)
 try:
  probe,binary,compiler=compile_probe(args,inputs)
  command=(['sudo','-n','env','PATH='+os.environ['PATH']]if os.geteuid()else[])+[sys.executable,str(Path(__file__).resolve()),'--root-parent','--trunk',str(args.trunk),'--rootfs',str(args.rootfs),'--sysroot',str(args.sysroot),'--output',str(args.output),'--expected-output',json.dumps(expected),'--probe-metadata',json.dumps(probe),'--compiler-metadata',json.dumps(compiler),'--probe-path',str(binary)]
  subprocess.run(command,check=True,timeout=LIMITS['worker_seconds']+30)
  require(base.output_identity(args.output)==expected,'Root BIO worker changed output owner/inode')
  report=json.loads(args.output.read_text(),object_pairs_hook=unique);validate_report(report,sources,shipped,libraries,generate_source(inputs))
  require(read_file(binary,LIMITS['probe_bytes']) and sha(read_file(binary,LIMITS['probe_bytes']))==probe['sha256'],'Exported BIO probe changed')
 except Exception as error:
  # Preserve partial worker rows when available. A failed/blank report is never accepted.
  try:report=json.loads(args.output.read_text(),object_pairs_hook=unique)
  except Exception:report=dict(schema_version=1,status='FAIL',profile='k2p-4.4',execution_role=ROLE,checks=[])
  report['status']='FAIL';report['failure']=str(error)[:4096];base.write_output(args.output,expected,report);raise
 print('Actual shipped libcrypto BIO: all8 private-namespace cases PASS; no OCSP/router claim')


if __name__=='__main__':main()
