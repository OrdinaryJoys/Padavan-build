#!/usr/bin/env python3
"""Run current Storage cache functions in shipped MIPS ash and private files.

Only explicit target applet/helper wrappers and inert ordinary-file MTD seams
run. No full boot/Storage dispatcher, service, device, proc or router is used.
"""
import argparse
import base64
import bz2
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

import check_target_boot_storage as boot
import check_target_ntp as ntp

SOURCE_PATHS = {'storage': 'user/scripts/mtd_storage.sh',
                'validator': 'user/scripts/storage_validate.c',
                'validator_header': 'user/scripts/startup_config_publish.h',
                'validator_makefile': 'user/scripts/Makefile',
                'busybox_template': 'configs/boards/busybox.config',
                'shell_common': 'user/busybox/busybox-1.24.x/shell/shell_common.c'}
EXPECTED_SOURCE_SHA256 = {'storage': 'b2e40a853fb308d7b7d773f903c034cf5ab32f67d92ceed542c130ac64f6d017',
 'validator': 'f59b020c3ec02dcc06435a308516b75d2a6ff4f32bfabcb78df9da559e7039de',
 'validator_header': '2ae303e59ff2b39f15075f7fa9fe585c91cb893f779925d351b0a51e369daeef',
 'validator_makefile': '11d3a7e40debdc342c31306f2b6aed0e701dffb458f5fad4b87c49f8a3be87d9',
 'busybox_template': '49789620f949cd362a6cfee16e2025672a30d71b08b9ca615b1d87e6044a7e70',
 'shell_common': '8f2f353859e3cee9c4b5aee07c855eb28e56e5c9f75a138eb7bec7fc9983f34f'}
FUNCTION_NAMES = ('func_save', 'func_record_hash', 'func_invalidate_hash', 'func_erase')
EXPECTED_FUNCTION_SHA256 = {'func_save': '1e9d9fd2cdb1bd2dd1cf5c61d3d72cf5de267e06f4ab173c23c39ee42cb42611',
 'func_record_hash': '10701d7177009b128fdec3ea71c8edb670a781bce617c061961f7a27394c7c60',
 'func_invalidate_hash': '95336811cadeba5453b445c38c2bf485da40bb43fd565a3b249a0d51db829ad1',
 'func_erase': 'b3048c3ef9c674ea64314b03b5d8148a4a9d8fe541144a25326288702c6e5435'}
REQUIRED_CONFIG = ('CONFIG_ASH=y', 'CONFIG_FEATURE_SH_IS_ASH=y', 'CONFIG_MD5SUM=y',
                   'CONFIG_CUT=y', 'CONFIG_STAT=y', 'CONFIG_BZIP2=y', 'CONFIG_RM=y', 'CONFIG_CP=y')
# input, fault, raw exit, ordinary-flash state, cache state, backend calls.
CASES = (
 ('same-A-skip', (('A','normal',0,'A','A',0),)),
 ('changed-B-success-then-skip', (('B','normal',0,'B','B',1),('B','normal',0,'B','B',0))),
 ('prewrite-invalidate-error', (('B','invalidate-error',1,'A','A',0),)),
 ('partial-B-error-then-A', (('B','write-partial-error',1,'partial',None,1),('A','normal',0,'A','A',1),('A','normal',0,'A','A',0))),
 ('zero-write-error-then-A', (('B','write-error',1,'A',None,1),('A','normal',0,'A','A',1))),
 ('kill-before-write-then-A', (('B','kill-before-write',-9,'A',None,1),('A','normal',0,'A','A',1))),
 ('kill-partial-B-then-A', (('B','kill-partial',-9,'partial',None,1),('A','normal',0,'A','A',1))),
 ('kill-complete-B-then-B', (('B','kill-after-write',-9,'B',None,1),('B','normal',0,'B','B',1))),
 ('hash-stage-error-then-B', (('B','hash-stage-error',1,'B',None,1),('B','normal',0,'B','B',1))),
 ('hash-publish-error-then-A', (('B','publish-error',1,'B',None,1),('A','normal',0,'A','A',1))),
 ('kill-before-publish-then-A', (('B','kill-before-publish',-9,'B',None,1),('A','normal',0,'A','A',1))),
 ('kill-after-publish-then-B-skip', (('B','kill-after-publish',-9,'B','B',1),('B','normal',0,'B','B',0))),
 ('erase-partial-error-then-A', (('A','erase-partial-error',1,'partial',None,1),('A','normal',0,'A','A',1),('A','normal',0,'A','A',0))),
)
FIXTURE_TEXT_A = 'ordinary Storage cache fixture A\n'
FIXTURE_TEXT_B = 'ordinary Storage cache fixture B\n'
FIXTURE_REPEAT = 64
PARTIAL_TEXT = 'ordinary partial B write; no physical MTD\n'
SKIP_TEXT = 'Storage hash is not changed, skip write to MTD partition. Exit.\n'
RAW_FIELDS = ('case','phase','raw_exit','stdout','stderr','events','cache','flash_base64')
ROW_FIELDS = ('phase','operation','input','fault','raw_exit','function_result','dispatcher_result',
              'backend_calls','flash_kind','cache_state','stdout_sha256','stderr_sha256','events')
SCRIPT_FILE = 'target-storage-cache.sh'
STDOUT_FILE = 'target-storage-cache.stdout.json'
CONFIG_FILE = 'target-storage-cache-busybox.config'
ROLE = 'Four current Storage cache/save/erase functions in shipped MIPS ash; inert ordinary-file MTD effects'
LIMITS = (
 'No complete boot/script dispatch, service, real MTD/proc, private backup, Flash operation or router reset executes.',
 'Fixed synthetic save-input bytes exercise cache sequencing, not tar validation or ready authorization.',
 'Only the absolute storage_validate command token is rebound to the same shipped MIPS helper.',
 'Ordinary-file disturbance and self-SIGKILL do not prove Flash atomicity, power loss, hardware timing or efd2 first-hop safety.',
 'Source/script/runtime/image references require separate independent extraction from the final TRX.',
)
MAX_RAW = 4194304
MAX_STDOUT = 16384
MAX_STDERR = 4096
MAX_EVENTS = 16384
MAX_CACHE = 1024
MAX_FLASH = 524288
TIMEOUT = 20
DRIVER_PREFIX = r'''set -u
ulimit -c 0
umask 077
fixture=$1
fault=$2
qemu=$3
runtime=$4
validator=$5
work_dir="$fixture/work"
tmp="$fixture/input"
hsh="$fixture/cache"
dir_storage="$fixture/storage"
slk="$fixture/storage-lock"
mtd_part_name=Storage
mtd_part_size=524288
backend_calls=0
bb() { "$qemu" -L "$runtime" "$runtime/bin/busybox" "$@"; }
event() { printf '%s\n' "$1" >> "$fixture/events"; }
logger() { event logger; }
cut() { bb cut "$@"; }
stat() { bb stat "$@"; }
bzip2() { bb bzip2 "$@"; }
mkdir() { bb mkdir "$@"; }
touch() { bb touch "$@"; }
md5sum() {
 if [ "$fault" = hash-stage-error ] && [ "$backend_calls" = 1 ]; then
  event hash:stage:error
  return 1
 fi
 bb md5sum "$@"
}
rm() {
 if [ "$#" = 2 ] && [ "$1" = -f ] && [ "$2" = "$hsh" ]; then
  event invalidate:begin
  if [ "$fault" = invalidate-error ]; then event invalidate:error; return 1; fi
  bb rm "$@" || return 81
  event invalidate:ok
  return 0
 fi
 if [ "$#" = 2 ] && [ "$1" = -rf ] && [ "$2" = "$dir_storage" ]; then bb rm "$@"; return $?; fi
 return 82
}
mtd_write() {
 backend_calls=$((backend_calls + 1))
 if [ "$#" = 2 ] && [ "$1" = erase ] && [ "$2" = Storage ] && [ "$fault" = erase-partial-error ]; then
  event erase:enter
  printf 'ordinary partial B write; no physical MTD\n' > "$fixture/flash" || return 84
  event erase:partial
  event erase:error
  return 1
 fi
 [ "$#" = 3 ] && [ "$1" = write ] && [ "$2" = "$work_dir/storage.tar.bz2" ] && [ "$3" = Storage ] || return 83
 event writer:enter
 case "$fault" in
 kill-before-write) event kill:before-write; kill -KILL "$$";;
 write-error) event writer:error; return 1;;
 write-partial-error|kill-partial)
  printf 'ordinary partial B write; no physical MTD\n' > "$fixture/flash" || return 84
  event writer:partial
  if [ "$fault" = kill-partial ]; then event kill:partial; kill -KILL "$$"; fi
  event writer:error
  return 1;;
 esac
 bb cp "$2" "$fixture/flash" || return 85
 event writer:complete
 if [ "$fault" = kill-after-write ]; then event kill:after-write; kill -KILL "$$"; fi
 return 0
}
cache_validator() {
 [ "$#" = 3 ] && [ "$1" = --replace-file ] && [ "$2" = "$work_dir/hash.commit" ] && [ "$3" = "$hsh" ] || return 86
 event publish:begin
 case "$fault" in
 publish-error) event publish:error; return 1;;
 kill-before-publish) event kill:before-publish; kill -KILL "$$";;
 esac
 "$qemu" -L "$runtime" "$validator" "$@" || return 87
 event publish:done
 if [ "$fault" = kill-after-publish ]; then event kill:after-publish; kill -KILL "$$"; fi
 return 0
}
'''
DRIVER_SUFFIX = r'''
printf 'BEGIN\n'
if [ "$fault" = erase-partial-error ]; then
 result=0
 func_erase
 function_result=$?
 dispatcher_result=$result
else
 func_save
 function_result=$?
 dispatcher_result=$function_result
fi
printf 'RESULT:%s\nDISPATCH:%s\n' "$function_result" "$dispatcher_result"
exit "$dispatcher_result"
'''
MODEL_NAMES = ('SOURCE_PATHS','FUNCTION_NAMES','REQUIRED_CONFIG','CASES','FIXTURE_TEXT_A',
               'FIXTURE_TEXT_B','FIXTURE_REPEAT','PARTIAL_TEXT','SKIP_TEXT','RAW_FIELDS','ROW_FIELDS',
               'DRIVER_PREFIX','DRIVER_SUFFIX','MAX_RAW','MAX_STDOUT','MAX_STDERR','MAX_EVENTS','MAX_CACHE','MAX_FLASH','TIMEOUT')
MODEL_DATA_SHA256 = '878cb393937e6b36a95618878cd91cf13183db6ca9db5e5dc4556ac7255ff04e'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def exact(actual, expected, message):
    require(canonical(actual)==canonical(expected),message)


def strict_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'Duplicate Storage cache JSON key')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda v:(_ for _ in ()).throw(ValueError(v)))


def model_contract():
    require(sha(canonical({name:globals()[name] for name in MODEL_NAMES}))==MODEL_DATA_SHA256,
            'Storage cache fixed literal model changed')


def fixture_inputs():
    return {'A':(FIXTURE_TEXT_A*FIXTURE_REPEAT).encode(),'B':(FIXTURE_TEXT_B*FIXTURE_REPEAT).encode()}


def cache_content(key):
    return hashlib.md5(fixture_inputs()[key]).hexdigest()+'  /tmp/storage.tar\n'


def config_contract(raw):
    lines=raw.decode('ascii').splitlines()
    for line in REQUIRED_CONFIG:
        require(lines.count(line)==1,'Storage cache BusyBox option differs: '+line)


def source_contract(inputs):
    model_contract()
    require(type(inputs)is dict and set(inputs)==set(SOURCE_PATHS),'Storage cache source set differs')
    hashes={key:sha(raw) for key,raw in inputs.items()}
    exact(hashes,EXPECTED_SOURCE_SHA256,'Storage cache source pin differs or is not finalized')
    source=inputs['storage'].decode()
    bodies={name:boot.shell_function(source,name) for name in FUNCTION_NAMES}
    exact({name:sha(body.encode())for name,body in bodies.items()},EXPECTED_FUNCTION_SHA256,
          'Storage cache whole-function pin differs or is not finalized')
    require(bodies['func_record_hash'].count('/sbin/storage_validate')==1,'Validator rebinding is ambiguous')
    save=bodies['func_save']
    require(save.count('func_invalidate_hash || return 1')==1 and
            save.index('func_invalidate_hash || return 1')<save.index('mtd_write write'),
            'Storage cache invalidation is not before writer')
    invalidate=bodies['func_invalidate_hash']
    require('rm -f "$hsh"'in invalidate and '[ -e "$hsh" ]'in invalidate and '[ -L "$hsh" ]'in invalidate,
            'Storage cache invalidation must reject residual objects')
    erase=bodies['func_erase']
    require(erase.index('func_invalidate_hash')<erase.index('mtd_write erase') and
            'result=1\n\t\treturn 1'in erase,'Storage erase must reject invalidation failure before backend')
    config_contract(inputs['busybox_template'])
    manifest={}
    for name,body in bodies.items():
        executed=body.replace('/sbin/storage_validate','cache_validator')
        manifest[name]={'source':'storage','execution':'whole-source-function-with-explicit-helper-rebinding',
                        'full_body_sha256':sha(body.encode()),'executed_body_sha256':sha(executed.encode()),
                        'helper_command_rebindings':1 if name=='func_record_hash'else 0}
    return {'source_sha256':hashes,'function_manifest':manifest}


def render_script(inputs):
    source_contract(inputs)
    source=inputs['storage'].decode()
    bodies=[boot.shell_function(source,name).replace('/sbin/storage_validate','cache_validator')for name in FUNCTION_NAMES]
    return (DRIVER_PREFIX+'\n'+'\n\n'.join(bodies)+'\n'+DRIVER_SUFFIX).encode()


def expected_events(fault,calls):
    if not calls:
        return ['invalidate:begin','invalidate:error','logger']if fault=='invalidate-error'else []
    prefix=['invalidate:begin','invalidate:ok']
    if fault=='erase-partial-error':
        return prefix+['erase:enter','erase:partial','erase:error']
    result=prefix+['writer:enter']
    if fault=='kill-before-write':return result+['kill:before-write']
    if fault=='write-error':return result+['writer:error','logger']
    if fault in ('write-partial-error','kill-partial'):
        return result+['writer:partial']+(['kill:partial']if fault=='kill-partial'else ['writer:error','logger'])
    result+=['writer:complete']
    if fault=='kill-after-write':return result+['kill:after-write']
    if fault=='hash-stage-error':return result+['hash:stage:error']
    result+=['publish:begin']
    if fault=='publish-error':return result+['publish:error']
    if fault=='kill-before-publish':return result+['kill:before-publish']
    result+=['publish:done']
    return result+(['kill:after-publish']if fault=='kill-after-publish'else [])


def expected_records():
    rows=[]
    for name,phases in CASES:
        records=[]
        for index,(key,fault,status,flash,cache,calls)in enumerate(phases,1):
            stdout='BEGIN\n'
            if status!=-9:
                if not calls and status==0:stdout+=SKIP_TEXT
                stdout+='RESULT:'+str(status)+'\nDISPATCH:'+str(status)+'\n'
            records.append({'phase':index,'operation':'erase'if fault=='erase-partial-error'else 'save',
                            'input':key,'fault':fault,'raw_exit':status,
                            'function_result':None if status==-9 else status,
                            'dispatcher_result':None if status==-9 else status,
                            'backend_calls':calls,'flash_kind':flash,'cache_state':cache,
                            'stdout_sha256':sha(stdout.encode()),'stderr_sha256':sha(b''),
                            'events':expected_events(fault,calls)})
        rows.append({'case':name,'phases':records})
    return rows


def validate_records(rows):
    exact(rows,expected_records(),'Storage cache fixed typed records differ')


def observe_raw(records):
    require(type(records)is list and len(records)==sum(len(p)for _,p in CASES),
            'Storage cache raw phase count differs')
    cursor,rows=0,[]
    for case in expected_records():
        phases=[]
        for expected in case['phases']:
            raw=records[cursor];cursor+=1
            require(type(raw)is dict and set(raw)==set(RAW_FIELDS),'Storage cache raw phase schema differs')
            require(type(raw['case'])is str and type(raw['phase'])is int and type(raw['raw_exit'])is int and
                    all(type(raw[k])is str for k in ('stdout','stderr','events','flash_base64'))and
                    (raw['cache']is None or type(raw['cache'])is str),'Storage cache raw phase types differ')
            require(raw['case']==case['case']and raw['phase']==expected['phase']and
                    raw['raw_exit']==expected['raw_exit'],'Storage cache raw order/exit differs')
            stdout,stderr,events=(raw[k].encode('ascii')for k in ('stdout','stderr','events'))
            require(len(stdout)<=MAX_STDOUT and len(stderr)<=MAX_STDERR and len(events)<=MAX_EVENTS,
                    'Storage cache exported output exceeds bound')
            require(events==''.join(item+'\n'for item in expected['events']).encode(),'Storage cache complete event stream differs')
            require(raw['cache']==(None if expected['cache_state']is None else cache_content(expected['cache_state'])),
                    'Storage cache persisted hash state differs')
            flash=base64.b64decode(raw['flash_base64'],validate=True)
            require(len(flash)<=MAX_FLASH and base64.b64encode(flash).decode()==raw['flash_base64'],
                    'Storage cache ordinary flash encoding/budget differs')
            if expected['flash_kind']=='partial':
                require(flash==PARTIAL_TEXT.encode(),'Storage cache partial-write fixture differs')
            else:
                decompressor=bz2.BZ2Decompressor()
                data=decompressor.decompress(flash,max_length=16384)
                require(decompressor.eof and not decompressor.unused_data and
                        data==fixture_inputs()[expected['flash_kind']],'Storage cache ordinary flash content differs')
            phases.append(dict(expected,stdout_sha256=sha(stdout),stderr_sha256=sha(stderr)))
        rows.append({'case':case['case'],'phases':phases})
    validate_records(rows)
    return rows


def bounded_run(command,cwd,env,timeout=TIMEOUT):
    process=subprocess.Popen(command,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    selector=selectors.DefaultSelector();streams={'stdout':bytearray(),'stderr':bytearray()}
    for name in streams:
        pipe=getattr(process,name);os.set_blocking(pipe.fileno(),False)
        selector.register(pipe,selectors.EVENT_READ,name)
    deadline=time.monotonic()+timeout
    try:
        while selector.get_map():
            require(time.monotonic()<deadline,'Storage cache phase deadline exceeded')
            for key,_ in selector.select(min(0.1,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fileobj.fileno(),4096)
                if not chunk:selector.unregister(key.fileobj);continue
                streams[key.data].extend(chunk)
                require(len(streams[key.data])<=(MAX_STDOUT if key.data=='stdout'else MAX_STDERR),
                        'Storage cache process output exceeded bound')
        remaining=deadline-time.monotonic();require(remaining>0,'Storage cache phase deadline exceeded')
        status=process.wait(timeout=remaining)
        return status,bytes(streams['stdout']),bytes(streams['stderr'])
    finally:
        selector.close()
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait(timeout=5)
        process.stdout.close();process.stderr.close()


def tool_path(name):
    path=shutil.which(name);require(path is not None,'Required Storage cache tool missing: '+name)
    return Path(path).resolve(strict=True)


def safe_runtime_inputs(rootfs,sysroot):
    require(not rootfs.is_symlink()and not sysroot.is_symlink(),'Storage cache runtime root alias forbidden')
    for root in (rootfs,sysroot):
        for name in ('bin','sbin','usr','lib','usr/lib'):
            path=root/name
            require(path.is_dir()and not path.is_symlink(),'Storage cache runtime directory alias/missing entry')
    return boot.inventory_runtime(sysroot)


def parent_reference(raw,storage,runtime,image,dev_init,compiled_config):
    parent=strict_json(raw)
    require(type(parent)is dict and parent.get('status')=='PASS'and parent.get('profile')=='k2p-4.4'and
            parent.get('phase')=='final-shipped-busybox-private-quota','Storage cache parent boot phase/status differs')
    exact(parent['required_cases'],[c[0]for c in boot.CASES],'Storage cache parent boot cases differ')
    boot.validate_records(parent['checks'])
    expected_diagnostics=[]
    for name,_,_,status,_ in boot.CASES:
        expected_diagnostics.append({'case':name,'stdout_sha256':sha(b'ARMED\nCOMPLETE\n'if status==0 else b'ARMED\n'),
                                     'stderr_bytes':0,'stderr_sha256':sha(b'')})
    exact(parent['diagnostics'],expected_diagnostics,'Storage cache parent diagnostics differ')
    exact(parent['rootfs_scripts']['storage'],storage,'Storage cache parent script differs')
    require(parent['source_sha256']['storage']==storage['sha256'],'Storage cache parent source differs')
    exact(parent['rootfs_scripts']['dev_init'],dev_init,'Storage cache parent dev_init differs')
    require(parent['source_sha256']['dev_init']==dev_init['sha256'],'Storage cache parent dev_init source differs')
    exact(parent['compiled_busybox_config'],{'file':'target-boot-storage-busybox.config',
          'sha256':sha(compiled_config)},'Storage cache parent compiled config differs')
    for name in ('busybox','busybox_dynamic','libraries'):
        exact(parent['runtime'][name],runtime[name],'Storage cache parent runtime differs: '+name)
    return {'report_file':'target-boot-storage.json','report_sha256':sha(raw),'parent_cases':4,
            'shared_source_sha256':{'storage':storage['sha256'],'dev_init':dev_init['sha256']},
            'storage_script':storage,'dev_init_script':dev_init,
            'busybox_sha256':runtime['busybox']['ELF']['sha256'],'image_sha256':sha(image),
            'image_bytes':len(image),'independent_image_extraction_required':True}


def check(trunk,rootfs,sysroot,image,boot_storage_report,output):
    model_contract()
    trunk,rootfs,sysroot=map(Path,(trunk,rootfs,sysroot))
    budget=safe_runtime_inputs(rootfs,sysroot)
    config=boot.read_regular(trunk/'.config',1048576).decode()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$',config,re.M)and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$',config,re.M),'Storage cache requires configured K2P4.4')
    inputs={key:boot.read_regular(trunk/path)for key,path in SOURCE_PATHS.items()}
    source=source_contract(inputs);script=render_script(inputs)
    actual_config=boot.read_regular(trunk/'user/busybox/busybox-1.24.x/.config',1048576)
    config_contract(actual_config)
    script_bytes=boot.read_regular(rootfs/'sbin/mtd_storage.sh')
    require(script_bytes==inputs['storage']and(rootfs/'sbin/mtd_storage.sh').stat().st_mode&0o7777==0o755,
            'Storage cache shipped script differs')
    storage={'rootfs_path':'sbin/mtd_storage.sh','bytes':len(script_bytes),'sha256':sha(script_bytes),'mode':'0o755'}
    dev_init_bytes=boot.read_regular(rootfs/'sbin/dev_init.sh')
    require((rootfs/'sbin/dev_init.sh').stat().st_mode&0o7777==0o755,'Storage cache dev_init mode differs')
    dev_init={'rootfs_path':'sbin/dev_init.sh','bytes':len(dev_init_bytes),'sha256':sha(dev_init_bytes),'mode':'0o755'}
    busybox=boot.read_regular(rootfs/'bin/busybox');validator=boot.read_regular(rootfs/'sbin/storage_validate')
    require((rootfs/'sbin/storage_validate').stat().st_mode&0o7777==0o755,'Storage cache validator mode differs')
    busybox_identity=ntp.elf(busybox);validator_identity=ntp.elf(validator)
    qemu=tool_path('qemu-mipsel')
    image_bytes=boot.read_regular(Path(image),33554432)
    require(len(image_bytes)>=64,'Storage cache image is too short')
    parent_bytes=boot.read_regular(Path(boot_storage_report),MAX_RAW)
    raw=[]
    with tempfile.TemporaryDirectory(prefix='k2p-storage-cache-',dir='/tmp')as temporary:
        directory=Path(temporary).resolve()
        require(re.fullmatch(r'/tmp/k2p-storage-cache-[a-z0-9_]+',str(directory)),
                'Storage cache fixture root must be private /tmp')
        runtime,hashes=boot.prepare_uid_runtime(rootfs,sysroot,directory)
        runtime_info={'busybox':{'rootfs_path':'bin/busybox','ELF':busybox_identity},
                      **boot.runtime_closure(rootfs,sysroot,runtime,busybox)}
        helper_closure=boot.runtime_closure(rootfs,sysroot,runtime,validator)
        helper=directory/'storage_validate';boot.write_export(helper,validator);helper.chmod(0o755)
        run_script=directory/SCRIPT_FILE;boot.write_export(run_script,script)
        parent=parent_reference(parent_bytes,storage,runtime_info,image_bytes,dev_init,actual_config)
        boot.verify_runtime_copy(runtime,rootfs,sysroot,hashes)
        for name,phases in CASES:
            fixture=directory/name;fixture.mkdir(mode=0o700)
            (fixture/'storage').mkdir(mode=0o700)
            (fixture/'cache').write_text(cache_content('A'))
            (fixture/'flash').write_bytes(bz2.compress(fixture_inputs()['A'],compresslevel=9))
            for index,(key,fault,_,_,_,_)in enumerate(phases,1):
                work=fixture/'work'
                if work.exists():shutil.rmtree(work)
                work.mkdir(mode=0o700)
                (fixture/'input').write_bytes(fixture_inputs()[key]);(fixture/'events').write_bytes(b'')
                status,stdout,stderr=bounded_run(
                    [str(qemu),'-L',str(runtime),str(runtime/'bin/busybox'),'sh',str(run_script),
                     str(fixture),fault,str(qemu),str(runtime),str(helper)],fixture,
                    {'PATH':'','HOME':str(fixture),'LANG':'C','LC_ALL':'C','TZ':'UTC'})
                cache=fixture/'cache'
                raw.append({'case':name,'phase':index,'raw_exit':status,'stdout':stdout.decode('ascii'),
                            'stderr':stderr.decode('ascii'),
                            'events':boot.read_regular(fixture/'events',MAX_EVENTS).decode('ascii'),
                            'cache':boot.read_regular(cache,MAX_CACHE).decode('ascii')if cache.exists()or cache.is_symlink()else None,
                            'flash_base64':base64.b64encode(boot.read_regular(fixture/'flash',MAX_FLASH)).decode()})
        rows=observe_raw(raw)
        boot.verify_runtime_copy(runtime,rootfs,sysroot,hashes)
        exact(boot.runtime_closure(rootfs,sysroot,runtime,busybox),
              {key:runtime_info[key]for key in ('busybox_dynamic','libraries')},'Storage cache runtime changed')
        exact(boot.runtime_closure(rootfs,sysroot,runtime,validator),helper_closure,'Storage cache validator runtime changed')
        require(boot.read_regular(helper)==validator,'Storage cache copied validator changed')
    require(boot.read_regular(rootfs/'bin/busybox')==busybox and
            boot.read_regular(rootfs/'sbin/storage_validate')==validator and
            boot.read_regular(rootfs/'sbin/mtd_storage.sh')==script_bytes and
            boot.read_regular(rootfs/'sbin/dev_init.sh')==dev_init_bytes,'Storage cache shipped bytes changed during proof')
    exact(source_contract({key:boot.read_regular(trunk/path)for key,path in SOURCE_PATHS.items()}),source,
          'Storage cache source changed during proof')
    require(boot.read_regular(trunk/'user/busybox/busybox-1.24.x/.config')==actual_config,
            'Storage cache compiled config changed during proof')
    stdout_bytes=(json.dumps(raw,indent=2)+'\n').encode()
    require(len(stdout_bytes)<=MAX_RAW,'Storage cache raw export exceeded budget')
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    for name,data in ((SCRIPT_FILE,script),(STDOUT_FILE,stdout_bytes),(CONFIG_FILE,actual_config)):
        boot.write_export(output.parent/name,data)
    report={'schema_version':1,'status':'PASS','profile':'k2p-4.4',
            'phase':'final-shipped-busybox-storage-cache','execution_role':ROLE,
            'required_cases':[name for name,_ in CASES],'checks':rows,
            'source_files':SOURCE_PATHS,**source,'model_data_sha256':MODEL_DATA_SHA256,
            'rootfs_bindings':{'storage':storage,'dev_init':dev_init,'validator':{'rootfs_path':'sbin/storage_validate',
                               'bytes':len(validator),'sha256':sha(validator),'mode':'0o755','ELF':validator_identity}},
            'compiled_busybox_config':{'file':CONFIG_FILE,'sha256':sha(actual_config)},
            'script':{'file':SCRIPT_FILE,'sha256':sha(script)},
            'stdout':{'file':STDOUT_FILE,'sha256':sha(stdout_bytes),'bytes':len(stdout_bytes),'cases':13,'phases':26},
            'runtime':{**runtime_info,'validator_closure':helper_closure,'copy_budget':budget,
                       'all_copied_regular_files_unchanged':True},
            'qemu':{'path':str(qemu),'sha256':sha(boot.read_regular(qemu,67108864))},
            'parent_reference':parent,'image_reference':{'file':Path(image).name,'bytes':len(image_bytes),
             'sha256':sha(image_bytes),'independent_image_extraction_required':True},'limits':list(LIMITS)}
    ntp.write_report(output,report)
    print('Storage cache: 13 fixed cases / 26 private MIPS ash phases PASS')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('trunk','rootfs','sysroot','image','boot-storage-report','output'):
        parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    try:
        check(args.trunk,args.rootfs,args.sysroot,args.image,args.boot_storage_report,args.output)
    except (OSError,ValueError,RuntimeError,KeyError,TypeError,subprocess.SubprocessError)as error:
        ntp.write_report(args.output,{'schema_version':1,'status':'FAIL','execution_role':ROLE,'error':str(error)})
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
