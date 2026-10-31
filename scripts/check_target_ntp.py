#!/usr/bin/env python3
"""Actual NTP source callbacks under MIPS/QEMU with inert DNS/time backends."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time

SOURCE_PATHS = {
    'ntpd.c':'user/busybox/busybox-1.24.x/networking/ntpd.c',
    'ntp_startup.h':'user/busybox/busybox-1.24.x/networking/ntp_startup.h',
    'watchdog.c':'user/rc/watchdog.c', 'fixture.c':'../tests/ntp_startup_fixture.c',
}
FUNCTIONS = {'ntpd.c':('add_peers','ntp_init','ntp_first_reply'),
             'watchdog.c':('ntpc_reap_launcher','refresh_ntp','is_ntpc_updated','ntpc_handler'),
             'ntp_startup.h':('ntp_startup_budget_begin','ntp_startup_budget_end')}
CASE_NAMES = (
    'init-q-first-reply','init-q-success','init-noq-success','init-foreground-q-success','init-config-q-success',
    'init-resolver-production-timeout','init-resolver-ignored','init-resolver-blocked','init-config-timeout',
    'init-sigaction-fail','init-mask-fail','refresh-inhibited','refresh-poststop-inhibited','refresh-fork-fail',
    'reap-exited','reap-echild','reap-eintr','reap-error','disabled-reaps','timer-async-feed',
    'refresh-busy-no-overlap','stop-resolving-no-pidfile','refresh-server-fallback','refresh-server-alternation',
)
BACKEND = 'actual-NTP-source-MIPS-controller-inert-resolver-no-time-setting'
FIELDS = {'case','status','elapsed_ms','initialized','timed_out','resolver_reached','launches','stops','feeds',
          'largest_feed_gap_ms','daemonized','resolved','alarms','alarm_count','launcher_owned'}
CONTRACT = dict(startup_seconds=10,launcher_seconds=15,first_reply_seconds=10,finish_sync_seconds=50,
                fast_fixture_alarm_seconds=1,watchdog_fixture_tick_ms=50,maximum_owned_launchers=1)
LIMITS = [
    'Actual extracted ntp_init/add_peers/first-reply and watchdog callbacks run with real MIPS libc signals, fork, waitpid(WNOHANG), timers and monotonic time.',
    'Resolver/config/daemonization/NVRAM/stop/log backends are inert substitutes; no hostname lookup, socket, ntpd daemon, clock setting, router, flash or device operation occurs.',
    'Exactly one real production 10-second resolver deadline runs per checker invocation; other timeout fixtures map alarm budgets to one second. The 10/50-second post-initialization alarm values are checked as emitted, not waited in full.',
    'The watchdog fixture invokes actual ntpc_handler from real timer callbacks with inert hardware feed accounting; this does not test a hardware watchdog.',
    'Owned launcher SIGTERM is tested before DNS returns/pidfile creation; firmware kill_services name matching is not executed against host processes.',
    'A disconnected WAN can retain at most one exited launcher until the next connected check or watchdog exit/PID1 reap. No global SIGCHLD disposition is changed.',
    'The process deadline does not guarantee termination during uninterruptible kernel I/O or a stalled kernel. Shipped executable hashes bind identity only; the shipped BusyBox/rc programs are not executed by this source probe.',
]


def require(condition,message):
    if not condition: raise ValueError(message)


def sha(data): return hashlib.sha256(data).hexdigest()


def function(text,name):
    match=re.search(r'(?:static\s+)?(?:void|int|ssize_t|char\s*\*|FILE\s*\*)\s*\n?\b'+re.escape(name)+r'\s*\(',text)
    require(match is not None,'Actual NTP function missing: '+name)
    start=match.start();opening=text.index('{',match.end());depth=0
    token=re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|[{}]')
    for item in token.finditer(text,opening):
        if item.group()=='{':depth+=1
        elif item.group()=='}':
            depth-=1
            if not depth:return text[start:item.end()]
    raise ValueError('Unterminated actual NTP function: '+name)


def generate_source(texts):
    require(set(texts)==set(SOURCE_PATHS),'NTP source file set differs')
    enum=re.search(r'enum\s*\{\s*OPT_n\s*=.*?\n\};',texts['ntpd.c'],re.S)
    require(enum is not None,'NTP actual option enumeration missing')
    require('#define NTP_STARTUP_TIMEOUT 10' in texts['ntp_startup.h'],'NTP production deadline changed')
    require(texts['ntpd.c'].count('#include "ntp_startup.h"')==1 and
            texts['ntpd.c'].count('ntp_first_reply();')==1,'NTP production integration missing')
    init=function(texts['ntpd.c'],'ntp_init')
    require(init.index('ntp_startup_budget_begin()')<init.index('add_peers(') and
            init.index('ntp_startup_budget_end()')<init.index('bb_daemonize_or_rexec('),
            'NTP resolver/config deadline placement changed')
    result=texts['fixture.c']
    fragments={
        '/* NTP_STARTUP_HEADER */':texts['ntp_startup.h'], '/* NTP_OPTION_ENUM */':enum[0],
        '/* NTP_INIT_FUNCTIONS */':'\n\n'.join(function(texts['ntpd.c'],n) for n in FUNCTIONS['ntpd.c']),
        '/* NTP_WATCHDOG_FUNCTIONS */':'\n\n'.join(function(texts['watchdog.c'],n) for n in FUNCTIONS['watchdog.c']),
    }
    for marker,value in fragments.items():
        require(result.count(marker)==1,'NTP fixture marker missing/ambiguous: '+marker)
        result=result.replace(marker,value)
    return result


def role(name):
    if name in ('init-resolver-production-timeout','init-resolver-ignored','init-resolver-blocked','init-config-timeout'):return 'startup-deadline'
    if name in ('init-sigaction-fail','init-mask-fail'):return 'setup-reject'
    if name.startswith('init-'):return 'startup-success'
    if name in ('refresh-inhibited','refresh-poststop-inhibited'):return 'upgrade-suppressed'
    if name=='refresh-fork-fail':return 'launch-failure'
    if name.startswith('reap-') or name=='disabled-reaps':return 'nonblocking-reap'
    if name=='timer-async-feed':return 'asynchronous-feed'
    if name=='refresh-busy-no-overlap':return 'single-owned-launcher'
    if name=='stop-resolving-no-pidfile':return 'stoppable-startup'
    return 'server-compatibility'


def expected_result(name):
    require(name in CASE_NAMES,'Unknown NTP case')
    result={key:0 for key in FIELDS-{'case','alarms'}}
    result.update(case=name,alarms=[0,0,0,0])
    if role(name)=='startup-success':
        result.update(initialized=1,resolver_reached=1,resolved=1,
                      daemonized=int(name!='init-foreground-q-success'),alarms=[10,0,10,0],alarm_count=3)
        if name=='init-noq-success':result.update(alarms=[10,0,0,0],alarm_count=2)
        if name=='init-q-first-reply':result.update(alarms=[10,0,10,50],alarm_count=4)
    if role(name)=='startup-deadline':result.update(status=14,timed_out=1,resolver_reached=1)
    if role(name)=='setup-reject':result['status']=111<<8
    if name=='refresh-poststop-inhibited':result['stops']=1
    if name=='refresh-fork-fail':result.update(stops=1,launches=1)
    if name in ('reap-eintr','reap-error'):result['launcher_owned']=1
    if role(name) in ('asynchronous-feed','single-owned-launcher','stoppable-startup','server-compatibility'):
        result.update(status=15,resolver_reached=1,launches=1,stops=1)
    if name=='timer-async-feed':result['feeds']=6
    if name=='refresh-server-alternation':result.update(stops=2,launches=2)
    return result


def validate_records(records):
    require(type(records) is list and [x.get('case') if type(x) is dict else None for x in records]==list(CASE_NAMES),
            'NTP case order/set missing, duplicate or unexpected')
    for row in records:
        name=row['case'];result=row.get('result')
        require(set(row)=={'case','role','backend','result'} and row['role']==role(name) and row['backend']==BACKEND,
                'NTP row schema/role/backend differs: '+name)
        require(type(result) is dict and set(result)==FIELDS,'NTP result fields differ: '+name)
        require(all(type(result[key]) is int for key in FIELDS-{'case','alarms'}) and
                type(result['alarms']) is list and len(result['alarms'])==4 and all(type(x) is int for x in result['alarms']),
                'NTP result types differ: '+name)
        expected=expected_result(name)
        require(all(result[key]==expected[key] for key in FIELDS-{'elapsed_ms','largest_feed_gap_ms'}),
                'NTP exact behavioral result differs: '+name)
        elapsed=result['elapsed_ms'];gap=result['largest_feed_gap_ms']
        require(0<=elapsed<=13000 and gap>=0,'NTP invalid/unbounded elapsed result: '+name)
        if name=='init-resolver-production-timeout':require(9500<=elapsed<=13000,'NTP real production deadline was shortened')
        elif role(name)=='startup-deadline':require(800<=elapsed<=3000,'NTP short signal deadline did not actually run')
        elif name=='timer-async-feed':require(250<=elapsed<=5000 and 0<gap<750,'NTP resolver stalled timer feeds')
        else:require(elapsed<=5000 and gap==0,'NTP nonblocking/control case stalled')


def elf(data,static=False):
    require(len(data)>=52 and data[:7]==b'\x7fELF\x01\x01\x01','NTP ELF32 little-endian header missing')
    kind,machine=struct.unpack_from('<HH',data,16)
    require(machine==8 and kind in (2,3),'NTP target must be executable MIPS')
    entry,offset=struct.unpack_from('<II',data,24);size,count=struct.unpack_from('<HH',data,42)
    require(size==32 and 0<count<=128 and offset+size*count<=len(data),'NTP program header budget invalid')
    executable=False;interpreter=False
    for index in range(count):
        ptype,start,address,_,length,memory,flags,_=struct.unpack_from('<8I',data,offset+index*size)
        require(start+length<=len(data) and memory>=length,'NTP segment bounds invalid')
        if ptype==3:interpreter=True
        if static:require(ptype not in (2,3),'NTP static probe depends on a loader')
        executable|=ptype==1 and flags&1 and address<=entry<address+memory
    require(executable and (not static or kind==2),'NTP entry is not executable')
    return dict(sha256=sha(data),bytes=len(data),elf_class=32,byte_order='little',e_machine=machine,e_type=kind,interpreter=interpreter)


def write_report(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        metadata=os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid==os.geteuid() and metadata.st_nlink==1,'Unsafe NTP report file')
        os.fchmod(fd,0o600);os.ftruncate(fd,0)
        with os.fdopen(fd,'w',closefd=False) as stream:json.dump(value,stream,indent=2);stream.write('\n')
    finally:os.close(fd)


def runtime_library(root,name):
    current=name
    for _ in range(16):
        require(not current.startswith('/') and current not in ('','..') and not current.startswith('../'),
                'NTP runtime library escapes sysroot')
        path=root/current;metadata=path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            target=os.readlink(path)
            current=posixpath.normpath(target.lstrip('/') if target.startswith('/') else posixpath.join(posixpath.dirname(current),target))
            continue
        require(stat.S_ISREG(metadata.st_mode) and 52<=metadata.st_size<=16*1024*1024,
                'Unsafe NTP runtime library: '+name)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            after=os.fstat(fd)
            require(stat.S_ISREG(after.st_mode) and (after.st_dev,after.st_ino,after.st_size)==
                    (metadata.st_dev,metadata.st_ino,metadata.st_size),'NTP runtime library changed while opening')
            with os.fdopen(fd,'rb',closefd=False) as stream:data=stream.read(16*1024*1024+1)
        finally:os.close(fd)
        require(len(data)==metadata.st_size and data[:7]==b'\x7fELF\x01\x01\x01' and
                struct.unpack_from('<HH',data,16)==(3,8),'NTP runtime library is not MIPS ELF32LE ET_DYN')
        return dict(resolved=current,sha256=sha(data),bytes=len(data),elf_class=32,byte_order='little',e_machine=8,e_type=3)
    raise ValueError('NTP runtime library symlink budget exceeded')


def run_target(command,seconds=18,stdout_limit=8192,stderr_limit=16384):
    """Own a fresh PG and retain its leader until cleanup has signalled it.

    The probe fixture does not call setsid/setpgid. Escaped descendants and
    uninterruptible kernel I/O are outside this collector's guarantee.
    """
    require(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL,
            'NTP collector requires a waitable child and default SIGCHLD')
    process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,start_new_session=True)
    selector=selectors.DefaultSelector();output=[bytearray(),bytearray()]
    deadline=time.monotonic()+seconds
    try:
        for index,stream in enumerate((process.stdout,process.stderr)):
            os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_READ,index)
        while True:
            require(time.monotonic()<deadline,'NTP target command timed out')
            if not selector.get_map():
                # WNOWAIT keeps a zombie leader as our PID/PGID anchor. Never
                # poll()/wait() before the finally block has cleaned its PG.
                require(hasattr(os,'waitid') and hasattr(os,'WNOWAIT'),
                        'NTP successful target completion requires Linux waitid(WNOWAIT)')
                try:
                    exited=os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                except InterruptedError:
                    continue
                if exited is not None:
                    break
                time.sleep(min(0.01,max(0,deadline-time.monotonic())))
                continue
            for key,_ in selector.select(min(0.05,max(0,deadline-time.monotonic()))):
                try:chunk=os.read(key.fileobj.fileno(),4096)
                except BlockingIOError:continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(chunk)
                limit=(stdout_limit,stderr_limit)[key.data]
                require(len(output[key.data])<=limit,
                        'NTP target '+('stdout' if key.data==0 else 'stderr')+' output cap exceeded')
    finally:
        # Even a failed leader can have pipe-holding descendants. Its PID has
        # not been reaped, so this PG cannot yet belong to an unrelated task.
        try:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        finally:
            selector.close()
            process.stdout.close();process.stderr.close()
            process.wait(timeout=2)
    return process.returncode,bytes(output[0]),bytes(output[1])


def check(trunk,compiler,sysroot,output,static=False,rootfs=None):
    require(sys.platform.startswith('linux'),'Target NTP proof requires Linux/QEMU')
    qemu=shutil.which('qemu-mipsel');require(qemu,'qemu-mipsel required')
    require(static or (rootfs is not None and rootfs.is_dir()),'Late NTP proof requires --rootfs for shipped executable identity')
    texts={name:(trunk/path).read_text() for name,path in SOURCE_PATHS.items()}
    generated=generate_source(texts)
    write_report(output,dict(status='RUNNING',scope=BACKEND))
    source=output.with_name('target-ntp-probe.c');probe=output.with_name('target-ntp-probe')
    source.write_text(generated)
    flags=['-std=gnu99','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable']
    flags+=['-static'] if static else ['-Wl,-z,now']
    compiled=subprocess.run([str(compiler),*flags,str(source),'-o',str(probe),'-lrt'],capture_output=True,text=True,timeout=90)
    require(compiled.returncode==0,'NTP MIPS compile failed: '+compiled.stdout+compiled.stderr)
    binary=probe.read_bytes();probe_identity=elf(binary,static);probe.chmod(0o755)
    rows=[]
    for name in CASE_NAMES:
        status,out,err=run_target([qemu,'-L',str(sysroot),str(probe),name])
        require(status==0,'NTP target case failed '+name+': rc='+str(status)+' stderr='+repr(err)+' stdout='+repr(out))
        row=json.loads(out)
        rows.append(dict(case=name,role=role(name),backend=BACKEND,result=row))
    validate_records(rows)
    shipped={};libraries={}
    if not static:
        libraries={name:runtime_library(sysroot,name) for name in ('lib/ld-uClibc.so.0','lib/libc.so.0','lib/librt.so.0')}
        for name in ('bin/busybox','sbin/rc'):
            path=rootfs/name;metadata=path.lstat()
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_mode&0o100,'NTP shipped executable unsafe: '+name)
            shipped[name]=elf(path.read_bytes())
    report=dict(schema_version=1,status='PASS',profile='k2p-4.4',mode='static-preflight' if static else 'dynamic-shipped-libc',
                backend=BACKEND,required_cases=list(CASE_NAMES),contract=CONTRACT,checks=rows,
                source_paths=SOURCE_PATHS,source_sha256={name:sha(text.encode()) for name,text in texts.items()},
                function_sha256={key+':'+name:sha(function(texts[key],name).encode()) for key,names in FUNCTIONS.items() for name in names},
                generated_source_sha256=sha(generated.encode()),mips_probe=probe_identity,
                shipped_programs=shipped,runtime_libraries=libraries,compiler=str(compiler),sysroot=str(sysroot),
                rootfs=str(rootfs) if rootfs is not None else None,limits=LIMITS)
    write_report(output,report)
    print('Target NTP:'+str(len(rows))+' exact '+report['mode']+' cases PASS (inert DNS/time backends)')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('trunk','compiler','sysroot','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--static',action='store_true');parser.add_argument('--rootfs',type=Path);args=parser.parse_args()
    try:check(args.trunk.resolve(),args.compiler.resolve(),args.sysroot.resolve(),args.output.resolve(),args.static,
              args.rootfs.resolve() if args.rootfs is not None else None)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        write_report(args.output,dict(status='FAIL',error=str(error),scope=BACKEND))
        parser.exit(1,'Target NTP validation failed: '+str(error)+'\n')
