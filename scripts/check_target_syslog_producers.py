#!/usr/bin/env python3
"""Actual BusyBox logger + locked central logger components in private namespaces.

Only BusyBox logger is a whole shipped application runtime proof. Other services
are actual central functions with inert surrounding code, not daemon health,
authentication, routing or tunnel proofs. No host /dev/log is used.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

import check_target_log_reload as previous
import check_target_ntp as ntp
import check_target_hook as hook
base=previous.base
require=base.require
sha=base.sha
CENTRAL_PATHS={
 'common':'trunk/user/shared/bounded_syslog.h',
 'busybox':'trunk/user/busybox/busybox-1.24.x/libbb/bounded_syslog.c',
 'busybox_info':'trunk/user/busybox/busybox-1.24.x/libbb/info_msg.c',
 'busybox_error':'trunk/user/busybox/busybox-1.24.x/libbb/verror_msg.c',
 'miniupnpd':'trunk/user/miniupnpd/miniupnpd-2.x/boundedlog.c',
 'igmp':'trunk/user/igmpproxy/igmpproxy-0.1/src/syslog.c',
 'lldt':'trunk/user/lldt/src/util.c','pppd':'trunk/user/pppd/pppd/utils.c',
 'pptpd':'trunk/user/poptop/pptpd-1.4.0/our_syslog.h'}
INADYN_PATHS={'archive':'trunk/user/inadyn/inadyn-2.8.1.tar.xz','vendor_patch':'trunk/user/inadyn/inadyn-2.8.1.patch','bounded_patch':'trunk/user/inadyn/inadyn-bounded-log.patch'}
THIN_PATHS={'udpxy_util':'trunk/user/udpxy/util.c','xl2tpd_misc':'trunk/user/xl2tpd/misc.c',
 'iapp':'trunk/user/ralinkiappd/rtmpiapp.c','lanauth':'trunk/user/lanauth/lanauth.c'}
PACKAGE_PATHS={
 'openssh':('openssh-10.6p1-log.c','log.c'),
 'openvpn':('openvpn-2.6.23-error.c','src/openvpn/error.c'),
 'smartdns':('smartdns-ba282c8-dns_conf.c','src/dns_conf.c')}
SOURCE_PATHS=dict(CENTRAL_PATHS,**THIN_PATHS,
 central_generator='tests/bounded_log_harness.py',downloaded_generator='tests/downloaded_log_harness.py')
SOURCE_PATHS.update({'inadyn_'+key:path for key,path in INADYN_PATHS.items()})
SOURCE_PATHS.update({path:'trunk/'+path for path in ('user/inadyn/Makefile','user/poptop/Makefile','user/poptop/pptpd-1.4.0/pptpd.c','user/poptop/pptpd-1.4.0/pptpctrl.c','user/poptop/pptpd-1.4.0/bcrelay.c')})
for package,(fixture,_) in PACKAGE_PATHS.items():
 SOURCE_PATHS[package+'_fixture']='tests/fixtures/downloaded-log-sources/'+fixture
 SOURCE_PATHS[package+'_patch']='trunk/user/'+package+'/'+package+'-bounded-log.patch'
 SOURCE_PATHS[package+'_Makefile']='trunk/user/'+package+'/Makefile'
for path in ('user/busybox/busybox-1.24.x/libbb/Kbuild.src','user/busybox/busybox-1.24.x/include/libbb.h',
 'user/busybox/busybox-1.24.x/sysklogd/logger.c','user/miniupnpd/miniupnpd-2.x/Makefile.linux',
 'user/pppd/pppd/bounded_ppp_log.h','user/pppd/pppd/main.c','user/pppd/pppd/options.c','user/pppd/pppd/Makefile.linux',
 'user/pppd/pppd/plugins/rp-pppoe/pppoe.h',
 'user/pppd/pppd/plugins/rp-pppoe/common.c','user/pppd/pppd/plugins/pptp/util.c',
 'user/udpxy/util.h','user/udpxy/udpxy.c','user/xl2tpd/misc.h','user/xl2tpd/xl2tpd.c',
 'user/ralinkiappd/rt_config.h'):
 SOURCE_PATHS[path]='trunk/'+path
PROGRAMS={'busybox':'bin/busybox','pppd':'usr/sbin/pppd','rp-pppoe':'usr/lib/pppd/rp-pppoe.so',
 'pptp':'usr/lib/pppd/pptp.so','miniupnpd':'usr/bin/miniupnpd','igmp':'bin/igmpproxy',
 'lldt':'bin/lld2d','openssh':'usr/sbin/sshd','openvpn':'usr/sbin/openvpn',
 'smartdns':'usr/bin/smartdns','udpxy':'usr/sbin/udpxy','xl2tpd':'usr/sbin/xl2tpd',
 'iapp':'sbin/ralinkiappd','lanauth':'usr/sbin/lanauth',
 'libssh':'lib/libssh.so','scp':'usr/bin/scp','sftp-server':'usr/libexec/sftp-server','inadyn':'bin/inadyn',
 'pptpd':'usr/sbin/pptpd','pptpctrl':'usr/sbin/pptpctrl','bcrelay':'usr/sbin/bcrelay'}
CENTRAL_COMPONENTS=('header','busybox','miniupnpd','igmp','lldt','pppd','pptpd','inadyn')
DOWNLOADED_MODES={'openssh':0,'openvpn':1,'udpxy':6,'xl2tpd':7,'iapp':8,'lanauth':9,'smartdns':10}
CASE_NAMES=('busybox-logger-argv','busybox-logger-stdin')+tuple(x+'-central' for x in CENTRAL_COMPONENTS)+tuple(x+'-central' for x in DOWNLOADED_MODES)+('header-percent-m','pppd-plugin-symbol-closure',)
ROLE={'whole_application':'Actual shipped MIPS BusyBox logger argv/stdin under QEMU',
 'components':'Locked actual central logger functions under MIPS QEMU, inert surrounding service callbacks; not whole daemons',
 'downloaded':'Pinned upstream excerpts plus exact firmware patches; SSH visual escaping and surrounding VPN/config callbacks inert',
 'isolation':'Private anchored PID/mount/network namespaces, scratch /dev/log, no router or host socket',
 'symbols':'Actual shipped pppd exported dynsym and two plugin undefined logger imports; not tunnel negotiation'}
FILESYSTEM_LIMITS=dict(previous.FILESYSTEM_LIMITS)
LIMITS=dict(worker_seconds=180,command_seconds=5,output_bytes=131072,report_bytes=1048576,
            pressure_calls=128,command_ms=5000,syslog_fill_datagrams=1024)
CONTRACT={'transport':'One nonblocking Unix datagram attempt; EAGAIN witnessed before pressure invocations',
 'preserved':'Normal marker, errno and descriptor balance for component adapters; recovery after draining queue',
 'exclusions':'No LOG_PERROR/LOG_CONS console latency guarantee; not async-signal-safe or whole-system syslog proof'}
ROW_KEYS={'case','role','queue_full','normal_marker','recovery_marker','calls','exit_codes','elapsed_ms','fd_balanced','errno_preserved'}
PPP_EXPORTS=('ppp_log_open','ppp_log_close','ppp_log_mask','ppp_syslog')
FORBIDDEN_LOG_IMPORTS=('closelog','openlog','setlogmask','syslog','vsyslog')


def pure_generator(text,kind):
 tree=ast.parse(text)
 if kind=='central':
  tree.body=[node for node in tree.body if not (isinstance(node,ast.FunctionDef) and node.name=='read_source_inputs') and not (isinstance(node,ast.ImportFrom) and node.module=='pathlib' and [(n.name,n.asname)for n in node.names]==[('Path',None)])]
 allowed={'function','generate_source'} if kind=='downloaded' else {'mask','function','declaration','without_includes','generate_source','patched_inadyn_source'}
 for node in tree.body:
  if isinstance(node,ast.Expr) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str):continue
  if isinstance(node,ast.Import) and all(n.name in (('json','re') if kind=='downloaded' else ('json','re','io','tarfile')) and n.asname is None for n in node.names):continue
  if isinstance(node,ast.FunctionDef) and node.name in allowed and not node.decorator_list:continue
  if kind=='central' and isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('SOURCE_PATHS','INADYN_SOURCE_PATHS'):
   require(ast.literal_eval(node.value)==(CENTRAL_PATHS if node.targets[0].id=='SOURCE_PATHS' else INADYN_PATHS),'Central generator source paths differ');continue
  raise RuntimeError('Unexpected executable generator statement')
 require({n.name for n in tree.body if isinstance(n,ast.FunctionDef)}==allowed,'Generator function set differs')
 env={};exec(compile(tree,'<locked-logging-generator>','exec'),env)
 return env['generate_source']


def apply_patches(inputs):
 """Pure inputs -> private host patch; never download, execute target or patch repo."""
 results={}
 with tempfile.TemporaryDirectory(prefix='k2p-log-patches-') as private:
  for package,(_,relative) in PACKAGE_PATHS.items():
   patch=inputs[package+'_patch'];targets=[]
   for line in patch.splitlines():
    if line.startswith('+++ '):targets.append(line[4:].split('\t')[0].split(' ')[0])
   require(targets==['b/'+relative],'Package patch has unexpected target paths')
   root=Path(private)/package;target=root/relative;target.parent.mkdir(parents=True)
   target.write_text(inputs[package+'_fixture'])
   result=subprocess.run(['patch','--batch','--fuzz=0','-p1'],input=patch.encode(),cwd=root,capture_output=True,timeout=5)
   require(result.returncode==0 and len(result.stdout)+len(result.stderr)<=32768,'Pinned package logging patch failed')
   require(not list(root.rglob('*.rej')),'Rejected package logging patch')
   results[package]=target.read_text()
 return results


def wrap_descriptors(source):
 require(source.count('int main(')==1,'Component main changed')
 source=source.replace('int main(','static int component_main(',1)
 return source+r'''
#include <dirent.h>
static int fixture_fds(void) {
 DIR *d=opendir("/proc/self/fd");struct dirent *p;int n=0;
 if(!d)return -1;
 while((p=readdir(d)))if(strcmp(p->d_name,".")&&strcmp(p->d_name,".."))n++;
 if(closedir(d))return -1;
 return n;
}
int main(int argc,char **argv) {
 int before=fixture_fds(),result,after;
 if(argc==4&&!strcmp(argv[1],"percent-m")) {
  struct padavan_log_context context=PADAVAN_LOG_CONTEXT_INIT;
  int i,count=atoi(argv[2]);if(count<1||count>128)return 91;
  padavan_log_open(&context,"percent-m",LOG_PID,LOG_USER);
  for(i=0;i<count;i++){errno=ENOENT;padavan_log_write(&context,LOG_WARNING,"literal %%m | %m");if(errno!=ENOENT)return 92;}
  printf("PRODUCER component=percent-m count=%d errno=%d\n",count,ENOENT);result=0;
 } else result=component_main(argc,argv);
 after=fixture_fds();
 printf("FD_BALANCE before=%d after=%d\n",before,after);
 return before>=4&&before==after?result:94;
}
'''


def generate_sources(inputs):
 require(set(inputs)==set(SOURCE_PATHS),'Logging exact locked source set differs')
 core={key:inputs[key] for key in CENTRAL_PATHS}
 generator=pure_generator(inputs['central_generator'],'central')
 core['inadyn']=generator.__globals__['patched_inadyn_source'](inputs['inadyn_archive'],inputs['inadyn_vendor_patch'],inputs['inadyn_bounded_patch'])
 central=generator(core)
 patched=apply_patches(inputs)
 thin=dict(header=inputs['common'],**patched,**{key:inputs[key] for key in THIN_PATHS})
 downloaded=pure_generator(inputs['downloaded_generator'],'downloaded')(thin,'/dev/log')
 return {'central':wrap_descriptors(central),'downloaded':wrap_descriptors(downloaded)}


def dynamic_symbols(data):
 """Bounded actual ELF32LE dynsym, with section/string bounds checked."""
 base.elf(data)
 require(len(data)>=52,'Truncated ELF')
 offset=struct.unpack_from('<I',data,32)[0];stride,count=struct.unpack_from('<HH',data,46)
 require(stride==40 and 0<count<=8192 and offset+count*stride<=len(data),'Invalid ELF sections')
 sections=[struct.unpack_from('<10I',data,offset+i*stride) for i in range(count)]
 provided,undefined=set(),set();found=0
 for section in sections:
  if section[1]!=11:continue
  found+=1;require(section[9]==16 and section[5]%16==0 and section[5]//16<=131072 and section[6]<count,'Invalid dynsym')
  strings=sections[section[6]];begin,length=strings[4:6]
  require(begin+length<=len(data) and section[4]+section[5]<=len(data),'ELF symbol/string bounds')
  blob=data[begin:begin+length]
  for i in range(section[4],section[4]+section[5],16):
   name,_,_,info,other,index=struct.unpack_from('<IIIBBH',data,i)
   if not name or info>>4 not in (1,2):continue
   require(name<len(blob),'ELF symbol string offset')
   end=blob.find(b'\0',name,min(len(blob),name+65537));require(end>=name,'ELF symbol name bound')
   symbol=blob[name:end].decode('ascii')
   if index and other&3==0:provided.add(symbol)
   elif not index:undefined.add(symbol)
 require(found==1,'Missing/duplicate dynsym')
 return {'provided':sorted(provided),'undefined':sorted(undefined)}


def plugin_closure(rootfs):
 symbols={name:dynamic_symbols((rootfs/PROGRAMS[name]).read_bytes()) for name in ('pppd','rp-pppoe','pptp')}
 require(set(PPP_EXPORTS)<=set(symbols['pppd']['provided']),'pppd logger API not exported')
 for name in ('rp-pppoe','pptp'):
  required=set(symbols[name]['undefined'])&set(PPP_EXPORTS)
  require('ppp_syslog' in required and required<=set(symbols['pppd']['provided']),'Unresolved plugin logger import')
  require(not set(symbols[name]['undefined'])&{'syslog','vsyslog','openlog','closelog','setlogmask'},'Plugin bypasses bounded main logger')
 return {name:{'logger_exports':sorted(set(value['provided'])&set(PPP_EXPORTS)),
               'logger_imports':sorted(set(value['undefined'])&set(PPP_EXPORTS))} for name,value in symbols.items()}


def import_proof(rootfs):
 result={}
 for name,path in PROGRAMS.items():
  item=dynamic_symbols((rootfs/path).read_bytes())
  result[name]=sorted(set(item['undefined'])&set(FORBIDDEN_LOG_IMPORTS))
  require(not result[name],'Shipped producer still imports blocking libc logging: '+name)
 return dict(forbidden_symbols=list(FORBIDDEN_LOG_IMPORTS),undefined=result)


def source_inputs(trunk):
 root=trunk.parent
 require('CONFIG_LINUXDIR=linux-4.4.x' in (trunk/'.config').read_text(),'Producer gate requires4.4')
 return {key:(root/path).read_bytes() if key=='inadyn_archive' else (root/path).read_bytes().decode('utf-8') for key,path in SOURCE_PATHS.items()}


def source_hashes(inputs):return {key:sha(value if type(value)is bytes else value.encode())for key,value in inputs.items()}


def shipped_proof(rootfs):
 result={}
 for name,relative in PROGRAMS.items():
  path=rootfs/relative;info=path.lstat();require(stat.S_ISREG(info.st_mode) and 52<=info.st_size<=16*1024*1024,'Missing/big regular shipped producer: '+relative)
  data=path.read_bytes();result[name]=dict(path=relative,sha256=sha(data),bytes=len(data),elf=base.elf(data))
 return result


def compile_probes(args,inputs):
 generated=generate_sources(inputs);metadata={};paths={}
 for key,source in generated.items():
  path=args.output.with_name('target-syslog-'+key+'-probe.c');binary=path.with_suffix('')
  require(not path.exists() and not binary.exists(),'Producer probe export exists')
  path.write_text(source);path.chmod(0o644)
  result=subprocess.run([str(args.compiler),'-std=gnu99','-Wall','-Wextra','-Werror','-O2','-static',str(path),'-o',str(binary)],capture_output=True,timeout=90)
  require(result.returncode==0,'MIPS producer probe compile: '+result.stderr.decode(errors='replace')[:4096])
  binary.chmod(0o755);data=binary.read_bytes();hook.validate_static_mips(data)
  metadata[key]=dict(source_sha256=sha(source.encode()),sha256=sha(data),bytes=len(data),elf=base.elf(data))
  paths[key]=str(binary)
 return metadata,paths


def validate_records(records):
 require(type(records)is list and len(records)==len(CASE_NAMES),'Missing producer cases')
 for name,row in zip(CASE_NAMES,records):
  require(type(row)is dict and set(row)==ROW_KEYS and row['case']==name,'Producer exact case schema/order')
  symbol=name==CASE_NAMES[-1];fatal=name=='lanauth-central'
  require(row['role']==('actual-image-dynsym' if symbol else 'actual-shipped-logger' if name.startswith('busybox-logger') else 'actual-central-functions'), 'Producer role differs')
  require(row['queue_full'] is (None if symbol else True) and row['normal_marker'] is (None if symbol else True) and row['recovery_marker'] is (None if symbol else True),'Producer pressure/recovery missing')
  require(type(row['calls'])is list and all(type(x)is int for x in row['calls']) and type(row['exit_codes'])is list and all(type(x)is int for x in row['exit_codes']) and row['calls']==([] if symbol else [1,1 if fatal or name.startswith('busybox-logger') else 128,1]) and
          row['exit_codes']==([] if symbol else [1 if fatal else 0]*3),'Producer actual invocations differ')
  require(row['fd_balanced'] is (None if symbol or fatal or name.startswith('busybox-logger') else True) and
          row['errno_preserved'] is (None if symbol or fatal or name.startswith('busybox-logger') else True),'Producer errno/FD proof missing')
  require(type(row['elapsed_ms'])is list and len(row['elapsed_ms'])==(0 if symbol else 3) and
          all(type(x)is int and 0<=x<=LIMITS['command_ms'] for x in row['elapsed_ms']),'Producer blocked or missing timing')
 return True


def validate_isolation(iso):
 require(type(iso)is dict and set(iso)=={'namespaces','worker_pid','loopback_only','private_mount_propagation','anchors_cloexec','namespace_exit_confirmed','private_dev_log'} and
         type(iso['worker_pid'])is int and iso['worker_pid']==1 and all(iso[k]is True for k in iso if k not in ('namespaces','worker_pid')),'Unsafe producer isolation')
 require(type(iso['namespaces'])is dict and set(iso['namespaces'])=={'mnt','net','pid'},'Missing namespace anchors')
 for value in iso['namespaces'].values():
  require(type(value)is dict and set(value)=={'parent_inode','worker_inode'} and all(type(x)is int and x>0 for x in value.values()) and value['parent_inode']!=value['worker_inode'],'Initial namespace used')
 return True


def validate_report(report,sources,shipped,generated=None):
 require(type(report)is dict and set(report)=={'schema_version','status','profile','execution_role','source_sha256','shipped','required_cases','checks','filesystem_limits','limits','contract','isolation','probes','plugin_closure','patched_sources','import_check','failure'},'Producer report schema differs')
 require(type(report['schema_version'])is int and report['schema_version']==1 and report['status']=='PASS' and report['profile']=='k2p-4.4' and report['failure']is None,'Producer proof not PASS')
 require(report['execution_role']==ROLE and report['source_sha256']==sources and report['shipped']==shipped and report['required_cases']==list(CASE_NAMES) and report['limits']==LIMITS and report['contract']==CONTRACT and report['filesystem_limits']==FILESYSTEM_LIMITS,'Producer source/image/contract mismatch')
 require(type(report['probes'])is dict and set(report['probes'])=={'central','downloaded'},'Missing producer exports')
 for key,value in report['probes'].items():
  require(type(value)is dict and set(value)=={'source_sha256','sha256','bytes','elf'} and type(value['bytes'])is int and 52<=value['bytes']<=4194304 and all(re.fullmatch('[0-9a-f]{64}',value[k])for k in ('sha256','source_sha256')) and value['elf']==dict(elf_class=32,byte_order='little',e_machine=8,e_type=2),'Producer probe metadata mismatch')
  if generated is not None:require(value['source_sha256']==sha(generated[key].encode()),'Producer generated C differs')
 require(type(report['patched_sources'])is dict and set(report['patched_sources'])==set(PACKAGE_PATHS) and all(re.fullmatch('[0-9a-f]{64}',v)for v in report['patched_sources'].values()),'Missing patched source binding')
 imports=report['import_check']
 require(type(imports)is dict and set(imports)=={'forbidden_symbols','undefined'} and imports['forbidden_symbols']==list(FORBIDDEN_LOG_IMPORTS) and type(imports['undefined'])is dict and set(imports['undefined'])==set(PROGRAMS) and all(value==[] for value in imports['undefined'].values()),'Shipped producer retains blocking libc imports')
 closure=report['plugin_closure'];require(type(closure)is dict and set(closure)=={'pppd','rp-pppoe','pptp'},'Plugin closure missing')
 for name,value in closure.items():
  require(type(value)is dict and set(value)=={'logger_exports','logger_imports'} and all(type(x)is list and x==sorted(set(x)) and set(x)<=set(PPP_EXPORTS) for x in value.values()),'Invalid logger symbol record')
  if name=='pppd':require(value=={'logger_exports':sorted(PPP_EXPORTS),'logger_imports':[]},'pppd API exports missing')
  else:require('ppp_syslog'in value['logger_imports'] and not value['logger_exports'],'Plugin logger not shared')
 validate_isolation(report['isolation']);return validate_records(report['checks'])


PRIORITY={'header':156,'busybox':30,'miniupnpd':28,'igmp':12,'lldt':28,'pppd':148,
          'openssh':38,'openvpn':29,'udpxy':131,'xl2tpd':28,'iapp':28,'lanauth':27,'smartdns':141,'percent-m':12,'pptpd':28,'inadyn':12}


def validate_frame(data,needle,priority):
 require(type(data)is bytes and 1<=len(data)<=1026 and data.endswith(b'\0') and data.count(b'\0')==1 and
         data.startswith(('<'+str(priority)+'>').encode()) and needle in data,'Producer datagram framing/priority/body differs')
 return True


class Receiver(previous.Receiver):
 def marker(self,needle,priority):
  deadline=time.monotonic()+2;count=0
  while time.monotonic()<deadline:
   try:data=self.sock.recv(4096)
   except BlockingIOError:time.sleep(.01);continue
   count+=1;require(count<=1024,'Excessive marker packets')
   if needle in data:return validate_frame(data,needle,priority)
  raise RuntimeError('Actual producer normal/recovery datagram missing')


def run_program(command,expected=0,input_data=None):
 begin=time.monotonic();result=subprocess.run(command,input=input_data if input_data is not None else b'',capture_output=True,timeout=LIMITS['command_seconds'])
 require(len(result.stdout)+len(result.stderr)<=LIMITS['output_bytes'] and result.returncode==expected,'Producer invocation failed: '+(result.stdout+result.stderr).decode(errors='replace')[:4096])
 return result.stdout,int((time.monotonic()-begin)*1000)


def worker_cases(args,rows):
 receiver=Receiver();paths=json.loads(args.probe_paths)
 try:
  for name in CASE_NAMES:
   print('Target producer CASE '+name,flush=True)
   if name==CASE_NAMES[-1]:
    row=dict(case=name,role='actual-image-dynsym',queue_full=None,normal_marker=None,recovery_marker=None,calls=[],exit_codes=[],elapsed_ms=[],fd_balanced=None,errno_preserved=None)
   else:
    whole=name.startswith('busybox-logger');fatal=name=='lanauth-central';component='percent-m' if name=='header-percent-m' else name.removesuffix('-central')
    expected_exit=1 if fatal else 0;calls=[1,1 if whole or fatal else 128,1];elapsed=[]
    needle=b'literal %n %s %%' if whole or component in DOWNLOADED_MODES else b'PUBLIC seq=0 '
    if component=='percent-m':needle=b'literal %m | No such file or directory'
    if component=='smartdns':needle=b"smartdns: process config file 'literal %n %s %%' failed at line 13."
    for index,count in enumerate(calls):
     if index==1:require(receiver.fill(),'No EAGAIN pressure witness')
     else:receiver.drain()
     if whole:
      command=['qemu-mipsel','-L',str(args.sysroot),str(args.rootfs/'bin/busybox'),'logger','-t','K2P_BB']
      data=b'literal %n %s %%\n' if name.endswith('stdin') else None
      if data is None:command+=['literal %n %s %%']
     else:
      key='downloaded' if component in DOWNLOADED_MODES else 'central'
      command=['qemu-mipsel',paths[key]]
      command+=([str(DOWNLOADED_MODES[component]),str(count),'literal %n %s %%'] if key=='downloaded' else [component,str(count),'normal'])
      data=None
     out,ms=run_program(command,expected_exit,data);elapsed.append(ms)
     if not whole and not fatal:
      matches=re.findall(rb'FD_BALANCE before=([0-9]+) after=([0-9]+)\n',out)
      require(len(matches)==1 and int(matches[0][0])>=4 and matches[0][0]==matches[0][1],'Central adapter FD balance missing')
      if component not in DOWNLOADED_MODES:require(('PRODUCER component='+component+' count='+str(count)+' errno=').encode() in out,'Central producer call count missing')
     if index!=1:receiver.marker(needle,13 if whole else PRIORITY[component])
    row=dict(case=name,role='actual-shipped-logger' if whole else 'actual-central-functions',queue_full=True,normal_marker=True,recovery_marker=True,calls=calls,exit_codes=[expected_exit]*3,elapsed_ms=elapsed,fd_balanced=None if whole or fatal else True,errno_preserved=None if whole or fatal else True)
   rows.append(row);print('Target producer PASS '+name,flush=True)
  validate_records(rows)
 finally:receiver.close()


def worker(args):
 namespaces=base.namespace_guard(json.loads(args.anchor_fds))
 for name,size in FILESYSTEM_LIMITS.items():
  subprocess.run(['mount','-n','-t','tmpfs','-o','size='+str(size)+',mode=0755','tmpfs','/'+name],check=True,capture_output=True)
  prefix=args.sysroot/name;require(not prefix.is_symlink(),'QEMU private mount alias');prefix.mkdir(exist_ok=True)
  subprocess.run(['mount','-n','--bind','/'+name,str(prefix)],check=True,capture_output=True)
 for name,minor,mode in (('null',3,0o666),('urandom',9,0o444)):
  os.mknod('/dev/'+name,stat.S_IFCHR|mode,os.makedev(1,minor));os.chmod('/dev/'+name,mode)
 base.regular(Path('/etc/passwd'),b'root:x:0:0:root:/:/bin/sh\n',0o644)
 inputs=source_inputs(args.trunk);sources=source_hashes(inputs)
 report=dict(schema_version=1,status='FAIL',profile='k2p-4.4',execution_role=ROLE,source_sha256=sources,shipped=shipped_proof(args.rootfs),required_cases=list(CASE_NAMES),checks=[],filesystem_limits=FILESYSTEM_LIMITS,limits=LIMITS,contract=CONTRACT,probes=json.loads(args.probe_metadata),plugin_closure=plugin_closure(args.rootfs),import_check=import_proof(args.rootfs),patched_sources={k:sha(v.encode())for k,v in apply_patches(inputs).items()},failure=None,
  isolation=dict(namespaces=namespaces,worker_pid=os.getpid(),loopback_only=True,private_mount_propagation=True,anchors_cloexec=True,namespace_exit_confirmed=False,private_dev_log=True))
 try:worker_cases(args,report['checks']);report['status']='PASS'
 except Exception as error:report['failure']=str(error)[:4096];raise
 finally:base.write_output(args.output,json.loads(args.expected_output),report)


def root_parent(args):
 require(sys.platform.startswith('linux') and os.geteuid()==0,'Linux root launcher required')
 expected=json.loads(args.expected_output);require(base.output_identity(args.output)==expected,'Parent-owned producer output changed')
 anchors={name:os.open('/proc/self/ns/'+name,os.O_RDONLY|os.O_CLOEXEC)for name in ('mnt','net','pid')}
 command=['unshare','--mount','--net','--pid','--fork','--mount-proc','--kill-child=KILL','--propagation','private',sys.executable,str(Path(__file__).resolve()),'--worker']
 for key in ('trunk','rootfs','sysroot','output'):command+=['--'+key,str(getattr(args,key))]
 command+=['--expected-output',args.expected_output,'--anchor-fds',json.dumps(anchors),'--probe-metadata',args.probe_metadata,'--probe-paths',args.probe_paths]
 try:subprocess.run(command,check=True,timeout=LIMITS['worker_seconds'],pass_fds=tuple(anchors.values()))
 finally:
  for fd in anchors.values():os.close(fd)
 report=json.loads(args.output.read_text());require(report['status']=='PASS','Producer worker failed')
 report['isolation']['namespace_exit_confirmed']=True;base.write_output(args.output,expected,report)


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for key in ('trunk','output'):parser.add_argument('--'+key,type=Path,required=True)
 for key in ('rootfs','sysroot'):parser.add_argument('--'+key,type=Path)
 parser.add_argument('--preflight',action='store_true')
 parser.add_argument('--compiler',type=Path)
 modes=parser.add_mutually_exclusive_group();modes.add_argument('--worker',action='store_true');modes.add_argument('--root-parent',action='store_true')
 for key in ('expected-output','anchor-fds','probe-metadata','probe-paths'):parser.add_argument('--'+key)
 args=parser.parse_args()
 for key in ('trunk','rootfs','sysroot'):
  if getattr(args,key)is not None:setattr(args,key,getattr(args,key).resolve())
 args.output=args.output.parent.resolve()/args.output.name
 if args.worker:return worker(args)
 if args.root_parent:return root_parent(args)
 if args.preflight:
  require(sys.platform.startswith('linux') and args.compiler is not None,'Linux MIPS compile preflight required')
  inputs=source_inputs(args.trunk);metadata,_=compile_probes(args,inputs)
  args.output.write_text(json.dumps(dict(status='COMPILED',execution_role='Cross-compile only: static actual-source logger probes; no target/daemon/hardware execution',source_sha256=source_hashes(inputs),probes=metadata),indent=2)+'\n')
  print('Syslog producers: both actual-source MIPS probes strict compiled; no runtime claim');return
 require(args.rootfs is not None and args.sysroot is not None,'Final producer gate requires actual image and sysroot')
 require(sys.platform.startswith('linux') and args.compiler is not None,'Linux MIPS producer gate required; no fallback PASS')
 for path in (args.trunk,args.rootfs,args.sysroot,args.output,Path(__file__).resolve()):
  require(not any(path.is_relative_to('/'+name)for name in FILESYSTEM_LIMITS),'Gate input hidden by private mounts')
 inputs=source_inputs(args.trunk);sources=source_hashes(inputs);shipped=shipped_proof(args.rootfs)
 expected=base.prepare_output(args.output);probes,paths=compile_probes(args,inputs)
 command=(['sudo','-n','env','PATH='+os.environ['PATH']]if os.geteuid()else[])+[sys.executable,str(Path(__file__).resolve()),'--root-parent','--trunk',str(args.trunk),'--rootfs',str(args.rootfs),'--sysroot',str(args.sysroot),'--output',str(args.output),'--expected-output',json.dumps(expected),'--probe-metadata',json.dumps(probes),'--probe-paths',json.dumps(paths)]
 subprocess.run(command,check=True,timeout=LIMITS['worker_seconds']+30)
 require(base.output_identity(args.output)==expected,'Root worker changed producer output owner/inode')
 report=json.loads(args.output.read_text());validate_report(report,sources,shipped,generate_sources(inputs))
 require(report['plugin_closure']==plugin_closure(args.rootfs),'Plugin closure changed')
 require(report['import_check']==import_proof(args.rootfs),'Actual shipped producer import closure changed')
 require(report['patched_sources']=={k:sha(v.encode())for k,v in apply_patches(inputs).items()},'Patched source binding changed')
 print('Target syslog producers: '+str(len(CASE_NAMES))+' private namespace cases PASS')

if __name__=='__main__':main()
