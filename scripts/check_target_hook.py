#!/usr/bin/env python3
"""Static MIPS shutdown-hook controller proof with local host-shell fixtures.
No router, daemon, network, flash, mount or production hook is invoked.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time

SOURCE_PATHS = {'hook_runner.h': 'user/rc/hook_runner.h', 'fixture.c': '../tests/hook_runner_fixture.c',
                'rc.c': 'user/rc/rc.c', 'Makefile': 'user/rc/Makefile'}
CONTRACT = dict(timeout_ms=30000, term_ms=2000, kill_ms=1000, stream_limit_bytes=131072, proc_entry_limit=8192)
BACKEND = 'static-MIPS-controller-with-host-POSIX-shell-fixtures'
LIMITS = ['The actual production header runs as a static MIPS controller under QEMU; /bin/sh and fixture commands are host programs, not a target MIPS shell.',
          'Only synthetic local scripts/files and their owned process groups are used; no router, daemon, network, flash, mount or production hook is invoked.',
          'The real Linux /proc group scan, fork/waitid(WNOWAIT)/waitpid, pipes, descriptors, signals and monotonic deadlines are exercised.',
          'This is not a sandbox: setsid/group escape, noncooperating privileged writers, uninterruptible I/O and stalled kernels remain outside the guarantee.']


def spec(name, role, body, **overrides):
    options = dict(level=0, timeout_ms=2000, term_ms=2000, kill_ms=1000, fault='none',
                   descriptors='normal', script_mode=0o755, shebang=True, cancel_signal=None)
    options.update(overrides)
    return dict(case=name, role=role, body=body, inputs=options)


BG = 'sleep 8 &\nbg=$!\nprintf "%s" "$bg" > "$HOOK_CHILD_PID"\n'
CASES = (
    spec('normal-action-exit0', 'success', 'printf "%s" "$1" > "$HOOK_ARG_OUT"\nexit 0\n', level=2),
    spec('raw-exit7', 'raw-exit', 'exit 7\n'),
    spec('raw-sigterm', 'raw-signal', 'kill -TERM $$\n'),
    spec('child-signal-mask-unblocked', 'raw-signal', 'kill -USR2 $$\n'),
    spec('literal-path-no-shebang', 'success', 'printf literal > "$HOOK_EFFECT"\n', shebang=False),
    spec('nonexecutable-script-refused', 'raw-exit', 'printf forbidden > "$HOOK_EFFECT"\n', script_mode=0o600),
    spec('closed-stdio-cloexec-cleared', 'success', 'if IFS= read -r value; then exit 33; fi\nprintf OUT\nprintf ERR >&2\n', descriptors='closed-stdio'),
    spec('fd512-above-soft64-closed', 'success', 'if [ -e "$HOOK_FD_DIRECTORY/512" ]; then exit 44; fi\nexit 0\n', descriptors='high-fd'),
    spec('descriptor-close-error-noexec', 'raw-exit', 'printf forbidden > "$HOOK_EFFECT"\n', fault='fd-close'),
    spec('sigchld-ignore-nochild', 'policy-reject', 'exit 0\n', fault='chld-ignore'),
    spec('sigchld-nocldwait-nochild', 'policy-reject', 'exit 0\n', fault='chld-nocldwait'),
    spec('waitid-eintr-retried', 'success', 'exit 0\n', fault='wait-eintr'),
    spec('production30s-closed-pipes-timeout', 'timeout', 'exec 1>&- 2>&-\nsleep 40 &\nprintf "%s" "$!" > "$HOOK_CHILD_PID"\nwait\n', timeout_ms=30000),
    spec('exit0-live-background-refused', 'background-reject', BG + 'exit 0\n'),
    spec('exit0-closed-pipe-background-refused', 'background-reject', BG.replace('sleep 8 &', 'sleep 8 > /dev/null 2>&1 &') + 'exit 0\n'),
    spec('stdout128k-cap', 'output-reject', 'cat "$HOOK_TEST_PAYLOAD"\n'),
    spec('stderr128k-cap', 'output-reject', 'cat "$HOOK_TEST_PAYLOAD" >&2\n'),
    spec('dual-stream-fair-cap', 'output-reject', 'i=0\nwhile [ "$i" -lt 64 ]; do printf "%04096d" 0; printf "%04096d" 1 >&2; i=$((i+1)); done\n'),
    spec('parent-term-cleanup-reraise', 'parent-cancel', BG + 'wait\n', timeout_ms=5000, cancel_signal='SIGTERM'),
    spec('term-ignoring-group-killed', 'timeout', 'trap "" TERM\nprintf ready > "$HOOK_EFFECT"\ni=0\nwhile [ "$i" -lt 4 ]; do sleep 2; i=$((i+1)); done\n', timeout_ms=1000),
)
CASE_NAMES = tuple(row['case'] for row in CASES)
RESULT_FIELDS = {'status','error','timeout','output_limit','background','cancelled','elapsed_ms','forks','waits',
                 'exits_seen','group_signals','signal_after_reap','reaped_direct_by_old_handler','mask_restored',
                 'handlers_restored','signals_seen','read_bytes','group_scan_backend'}
POST_FIELDS = {'exec_audit_count','action_argument','hook_effect','injection_marker_exists','owned_child_alive'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def generate_source(texts):
    require(set(texts) == set(SOURCE_PATHS), 'Hook source file set changed')
    header, fixture, rc = texts['hook_runner.h'], texts['fixture.c'], texts['rc.c']
    require(fixture.count('#include "hook_runner.h"') == 1, 'Hook fixture include missing/ambiguous')
    for literal in ('#define HOOK_RUNNER_TIMEOUT_MS 30000U', '#define HOOK_RUNNER_TERM_MS 2000U',
                    '#define HOOK_RUNNER_KILL_MS 1000U', '#define HOOK_RUNNER_STREAM_LIMIT (128U * 1024U)',
                    '#define HOOK_RUNNER_PROC_LIMIT 8192U'):
        require(literal in header, 'Hook production budget changed: ' + literal)
    require('#include "hook_runner.h"' in rc and rc.count('shutdown_hook_run(script_name,') == 2,
            'Both upgrade and ordinary shutdown must use the bounded hook runner')
    require('-lrt' in texts['Makefile'] and 'rc.o: hook_runner.h' in texts['Makefile'], 'Hook clock/header build dependency missing')
    return fixture.replace('#include "hook_runner.h"', header)


def script_bytes(case):
    return (('#!/bin/sh\n' if case['inputs']['shebang'] else '') + case['body']).encode()


def validate_static_mips(data):
    require(len(data) >= 52 and data[:7] == b'\x7fELF\x01\x01\x01' and
            struct.unpack_from('<HH', data, 16) == (2, 8), 'Hook probe must be static ELF32LE MIPS ET_EXEC')
    entry, offset = struct.unpack_from('<II', data, 24)
    size, count = struct.unpack_from('<HH', data, 42)
    require(size == 32 and 0 < count <= 128 and offset + size*count <= len(data), 'Hook ELF program table invalid')
    executable = False
    for index in range(count):
        kind, start, address, _, length, memory, flags, _ = struct.unpack_from('<8I', data, offset+index*size)
        require(start+length <= len(data) and memory >= length, 'Hook ELF segment bounds invalid')
        require(kind not in (2, 3), 'Hook probe must not depend on a dynamic loader/library')
        executable |= kind == 1 and flags & 1 and address <= entry < address+memory
    require(executable, 'Hook ELF entry is outside an executable load segment')


def validate_records(records):
    require(type(records) is list and [row.get('case') if type(row) is dict else None for row in records] == list(CASE_NAMES),
            'Hook case order/set missing, duplicate or unexpected')
    for row, case in zip(records, CASES):
        name, role, options = case['case'], case['role'], case['inputs']
        require(set(row) == {'case','role','backend','inputs','result','script_sha256','postconditions'}, 'Hook row schema changed: '+name)
        require(row['role'] == role and row['backend'] == BACKEND and
                json.dumps(row['inputs'],sort_keys=True) == json.dumps(options,sort_keys=True), 'Hook case role/inputs changed: '+name)
        require(row['script_sha256'] == hashlib.sha256(script_bytes(case)).hexdigest(), 'Hook synthetic script differs: '+name)
        result, post = row['result'], row['postconditions']
        require(type(result) is dict and set(result) == RESULT_FIELDS and
                all(type(result[key]) is int for key in RESULT_FIELDS-{'signals_seen','read_bytes','group_scan_backend'}), 'Hook result schema/types invalid: '+name)
        require(type(result['signals_seen']) is list and len(result['signals_seen']) == 4 and
                all(type(value) is int and value >= 0 for value in result['signals_seen']) and
                type(result['read_bytes']) is list and len(result['read_bytes']) == 2 and
                all(type(value) is int and value >= 0 for value in result['read_bytes']), 'Hook vector types invalid: '+name)
        require(result['group_scan_backend'] == 'linux-real-proc', 'Hook target must use actual Linux /proc: '+name)
        require(result['signal_after_reap'] == result['reaped_direct_by_old_handler'] == 0 and
                result['mask_restored'] == result['handlers_restored'] == 1, 'Hook PID anchor/signal restoration failed: '+name)
        require(0 <= result['elapsed_ms'] <= options['timeout_ms']+options['term_ms']+options['kill_ms']+1000,
                'Hook wall-clock bound violated: '+name)
        require(type(post) is dict and set(post) == POST_FIELDS and type(post['exec_audit_count']) is int and
                post['injection_marker_exists'] is False and post['owned_child_alive'] in (None,False) and
                type(post['owned_child_alive']) in (type(None),bool), 'Hook fixture postcondition invalid: '+name)
        expected_status = 0
        if name == 'raw-exit7': expected_status = 7 << 8
        if name in ('nonexecutable-script-refused','descriptor-close-error-noexec'): expected_status = 126 << 8
        if name == 'raw-sigterm': expected_status = 15
        if name == 'child-signal-mask-unblocked': expected_status = 17  # Linux MIPS SIGUSR2
        if role in ('timeout','background-reject','output-reject','parent-cancel','policy-reject'): expected_status = -1
        require(result['status'] == expected_status, 'Hook raw/failure status differs: '+name)
        expected_error = {'timeout':145,'background-reject':16,'output-reject':27,'parent-cancel':4,'policy-reject':22}.get(role,0)
        require(result['error'] == expected_error and
                [result['timeout'],result['output_limit'],result['background'],result['cancelled']] ==
                [int(role=='timeout'),int(role=='output-reject'),int(role=='background-reject'),int(role=='parent-cancel')], 'Hook failure reason differs: '+name)
        no_child = role == 'policy-reject'
        require(result['forks'] == int(not no_child), 'Hook spawn count differs: '+name)
        require(post['exec_audit_count'] == (0 if no_child or name=='descriptor-close-error-noexec' else 1), 'Hook exec side effect differs: '+name)
        expected_post = dict(exec_audit_count=0 if no_child or name=='descriptor-close-error-noexec' else 1,
                             action_argument='2' if name=='normal-action-exit0' else None,
                             hook_effect='literal' if name=='literal-path-no-shebang' else 'ready' if name=='term-ignoring-group-killed' else None,
                             injection_marker_exists=False,
                             owned_child_alive=False if name in ('production30s-closed-pipes-timeout','exit0-live-background-refused',
                                                                 'exit0-closed-pipe-background-refused','parent-term-cleanup-reraise') else None)
        require(json.dumps(post,sort_keys=True)==json.dumps(expected_post,sort_keys=True), 'Hook exact fixture postconditions differ: '+name)
        require(result['signals_seen'] == ([1,0,0,0] if role=='parent-cancel' else [0]*4), 'Hook did not honor old cancellation handler exactly once: '+name)
        if no_child:
            require(result['group_signals'] == result['waits'] == result['exits_seen'] == 0 and result['read_bytes']==[0,0],
                    'Nonwaitable caller spawned/signalled a child: '+name)
        else:
            require(result['waits'] > 0 and result['exits_seen'] > 0, 'Hook did not observe owned child with WNOWAIT: '+name)
        if role in ('timeout','background-reject','output-reject','parent-cancel'):
            require(result['group_signals'] > 0, 'Hook failure did not clean its process group: '+name)
        if role == 'timeout':
            require(result['elapsed_ms'] >= options['timeout_ms'], 'Hook deadline was shortened: '+name)
        if name == 'production30s-closed-pipes-timeout':
            require(result['elapsed_ms'] >= 30000, 'Production hook deadline was shortened in the target test')
        if name == 'term-ignoring-group-killed':
            require(result['group_signals'] >= 2 and post['hook_effect'] == 'ready', 'TERM-ignoring ready group did not require KILL')
        if name == 'normal-action-exit0': require(post['action_argument']=='2', 'Hook action argument changed')
        if name == 'literal-path-no-shebang': require(post['hook_effect']=='literal', 'Hook fallback/literal path not executed')
        if name in ('nonexecutable-script-refused','descriptor-close-error-noexec'): require(post['hook_effect'] is None, 'Refused hook executed')
        if name == 'closed-stdio-cloexec-cleared': require(result['read_bytes']==[3,3], 'Closed standard descriptors did not survive exec')
        if name == 'dual-stream-fair-cap': require(all(value>0 for value in result['read_bytes']), 'Output drain starved a stream')
        if name == 'stdout128k-cap': require(result['read_bytes'][0]>CONTRACT['stream_limit_bytes'], 'stdout cap was not actually reached')
        if name == 'stderr128k-cap': require(result['read_bytes'][1]>CONTRACT['stream_limit_bytes'], 'stderr cap was not actually reached')
        if name == 'dual-stream-fair-cap': require(min(result['read_bytes'])>=CONTRACT['stream_limit_bytes']-4096, 'Noisy stream starved its peer before the cap')
        if name == 'waitid-eintr-retried': require(result['waits']>1, 'waitid EINTR was not retried')


def child_alive(path):
    if not path.exists(): return None
    pid = int(path.read_text())
    require(pid > 1, 'Invalid fixture descendant PID')
    try:
        data = Path(f'/proc/{pid}/stat').read_text()
    except FileNotFoundError:
        return False
    return data.rsplit(')',1)[1].split()[0] != 'Z'


def execute_cases(command, base):
    rows = []
    for index, case in enumerate(CASES):
        directory = base/str(index); directory.mkdir()
        options = case['inputs']; script = directory/('literal name $(touch K2P_HOOK_INJECTION)' if case['case']=='literal-path-no-shebang' else 'shutdown.sh')
        script.write_bytes(script_bytes(case)); script.chmod(options['script_mode'])
        report, audit, effect, child, argument = (directory/name for name in ('result.json','audit','effect','child','argument'))
        payload = directory/'payload'; payload.write_bytes(b'X'*(CONTRACT['stream_limit_bytes']+4096))
        env = dict(os.environ, HOOK_EXEC_AUDIT=str(audit),HOOK_EFFECT=str(effect),HOOK_CHILD_PID=str(child),HOOK_ARG_OUT=str(argument),
                   HOOK_TEST_PAYLOAD=str(payload),HOOK_FD_DIRECTORY='/proc/self/fd',HOOK_TEST_PROC='')
        args = [*command,str(script),str(options['level']),str(options['timeout_ms']),str(options['term_ms']),str(options['kill_ms']),
                '/proc',options['fault'],str(report),options['descriptors']]
        process = subprocess.Popen(args,cwd=directory,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            if options['cancel_signal']:
                deadline = time.monotonic()+3
                while not child.exists() and process.poll() is None and time.monotonic()<deadline: time.sleep(.01)
                require(child.exists() and process.poll() is None, 'Hook cancellation fixture never became ready')
                process.send_signal(getattr(signal,options['cancel_signal']))
            stdout,stderr = process.communicate(timeout=(options['timeout_ms']+options['term_ms']+options['kill_ms'])/1000+5)
        except BaseException:
            if process.poll() is None: process.kill()
            process.communicate(timeout=3)
            raise
        require(process.returncode==0 and not stdout, f'Hook target fixture failed {case["case"]}: exit={process.returncode}, stderr={stderr!r}')
        result=json.loads(report.read_text())
        rows.append(dict(case=case['case'],role=case['role'],backend=BACKEND,inputs=options.copy(),result=result,
                         script_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
                         postconditions=dict(exec_audit_count=len(audit.read_bytes()) if audit.exists() else 0,
                                             action_argument=argument.read_text() if argument.exists() else None,
                                             hook_effect=effect.read_text() if effect.exists() else None,
                                             injection_marker_exists=(directory/'K2P_HOOK_INJECTION').exists(),owned_child_alive=child_alive(child))))
    validate_records(rows)
    return rows


def write_report(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1,'Unsafe hook diagnostic output')
        os.fchmod(fd,0o600);os.ftruncate(fd,0)
        with os.fdopen(fd,'w',closefd=False) as stream: json.dump(value,stream,indent=2);stream.write('\n')
    finally:
        os.close(fd)


def check(trunk, compiler, output):
    require(sys.platform.startswith('linux'),'Actual hook target proof requires Linux /proc')
    texts={name:(trunk/path).read_text() for name,path in SOURCE_PATHS.items()}
    generated=generate_source(texts)
    qemu=shutil.which('qemu-mipsel');require(qemu,'qemu-mipsel is required')
    write_report(output,dict(status='RUNNING',scope=BACKEND))
    source=output.with_name('target-hook-probe.c');probe=output.with_name('target-hook-probe')
    source.write_text(generated)
    compiled=subprocess.run([str(compiler),'-static','-std=gnu99','-Wall','-Wextra','-Werror','-Wno-unused-function',str(source),'-o',str(probe),'-lrt'],capture_output=True,text=True,timeout=60)
    require(compiled.returncode==0,'Static MIPS hook compilation failed: '+compiled.stdout+compiled.stderr)
    binary=probe.read_bytes();validate_static_mips(binary);probe.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix='k2p-hook-target-',dir='/tmp') as temp:
        base=Path(temp);prefix=base/'empty-interpreter-prefix';prefix.mkdir()
        rows=execute_cases([qemu,'-L',str(prefix),str(probe)],base)
    report=dict(schema_version=1,status='PASS',profile='k2p-4.4',backend=BACKEND,required_cases=list(CASE_NAMES),contract=CONTRACT,
                checks=rows,source_paths=SOURCE_PATHS,source_sha256={name:hashlib.sha256(text.encode()).hexdigest() for name,text in texts.items()},
                generated_source_sha256=hashlib.sha256(generated.encode()).hexdigest(),mips_probe_sha256=hashlib.sha256(binary).hexdigest(),
                compiler=str(compiler),limits=LIMITS)
    write_report(output,report)
    print(f'Target shutdown hook:{len(rows)} exact static-MIPS cases PASS (host POSIX shell fixtures, real Linux /proc)')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('trunk','compiler','output'): parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    try:
        check(args.trunk.resolve(),args.compiler.resolve(),args.output.resolve())
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        write_report(args.output,dict(status='FAIL',error=str(error),scope=BACKEND))
        parser.exit(1,'Target hook validation failed: '+str(error)+'\n')
