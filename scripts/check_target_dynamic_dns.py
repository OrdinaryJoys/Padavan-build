#!/usr/bin/env python3
"""Check the shipped MIPS startup parser with private, harmless generators.

QEMU executes dnsmasq --test, never a listener. Its /bin/sh exec fallback is
the native host shell, proved separately by each fixture's /proc parent ELF.
No user configuration, MTD, router or external filesystem mutation is used.
"""
import argparse
import ast
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time


SOURCE_PATHS = {
    'Makefile': 'user/dnsmasq/dnsmasq-2.93/Makefile',
    'option.c': 'user/dnsmasq/dnsmasq-2.93/src/option.c',
    'dynamic_conf.c': 'user/dnsmasq/dnsmasq-2.93/src/dynamic_conf.c',
    'dynamic_conf.h': 'user/dnsmasq/dnsmasq-2.93/src/dynamic_conf.h',
}
MACROS = {
    'script_ms': 'CONF_SCRIPT_TIMEOUT_MS', 'total_ms': 'CONF_SCRIPT_TOTAL_MS',
    'output_bytes': 'CONF_SCRIPT_MAX_BYTES', 'total_output_bytes': 'CONF_SCRIPT_TOTAL_BYTES',
    'stderr_bytes': 'CONF_SCRIPT_STDERR_BYTES', 'line_bytes': 'CONF_SCRIPT_LINE_BYTES',
    'script_calls': 'CONF_SCRIPT_MAX_CALLS', 'script_depth': 'CONF_SCRIPT_MAX_DEPTH',
    'file_bytes': 'CONF_CONFIG_MAX_BYTES', 'parsed_bytes': 'CONF_CONFIG_TOTAL_BYTES',
    'files': 'CONF_CONFIG_MAX_FILES', 'parse_depth': 'CONF_CONFIG_MAX_DEPTH',
    'directory_entries': 'CONF_CONFIG_MAX_DIR_ENTRIES',
}
PRODUCTION_LIMITS = dict(zip(MACROS, (10000, 30000, 2097152, 4194304, 65536,
                                    16384, 16, 8, 2097152, 16777216, 128, 32, 4096)))
PRODUCTION_LIMITS['directory_files'] = 128
EXECUTION_ROLE = 'Actual shipped MIPS dnsmasq --test under qemu-user; no daemon listener'
GENERATOR_ROLE = 'Private harmless native host /bin/sh fixtures via QEMU exec fallback; not MIPS shell execution'
# name, exact process exit, required diagnostic, minimum/maximum wall seconds,
# expected successful fixture registrations, total shared progress controls.
RULES = (
    ('valid-exact-output-and-stderr-caps', 0, 'syntax check OK', 0, 14, 1),
    ('empty-output', 0, 'syntax check OK', 0, 14, 1),
    ('nonzero-output-not-parsed', 1, 'nonzero status', 0, 14, 1),
    ('stdout-over2MiB', 1, 'output budget exceeded', 0, 14, 1),
    ('stderr-over64KiB', 1, 'diagnostic output limit exceeded', 0, 14, 1),
    ('eof-child-hung-10s', 1, 'time budget exceeded', 9.5, 14, 1),
    ('orphan-held-pipe-10s', 1, 'time budget exceeded', 9.5, 14, 1),
    ('ignore-term-10s', 1, 'time budget exceeded', 9.5, 14, 1),
    ('recursive-command-string', 1, 'invocation or nesting limit exceeded', 0, 14, 8),
    ('fifo-include', 1, 'not a regular file', 0, 14, 1),
    ('device-alias-include', 1, 'not a regular file', 0, 14, 1),
    ('stdin-include', 1, 'stdin configuration', 0, 14, 1),
    ('longline-output', 1, 'NUL or overlong output line', 0, 14, 1),
    ('longline-include', 1, 'NUL or overlong input line', 0, 14, 1),
    ('nul-output', 1, 'NUL or overlong output line', 0, 14, 1),
    ('shared-total-30s', 1, 'time budget exceeded', 29.5, 35, 4),
)
CASE_NAMES = tuple(rule[0] for rule in RULES)
SHA = re.compile(r'[0-9a-f]{64}\Z')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def elf(data, mips=False):
    if len(data) < 52 or data[:4] != b'\x7fELF' or data[5] not in (1, 2):
        raise ValueError('ELF header missing')
    endian = '<' if data[5] == 1 else '>'
    result = {'class': 32 if data[4] == 1 else 64 if data[4] == 2 else 0,
              'byte_order': 'little' if data[5] == 1 else 'big',
              'machine': struct.unpack_from(endian+'H', data, 18)[0],
              'type': struct.unpack_from(endian+'H', data, 16)[0]}
    if mips and (result['class'] != 32 or result['byte_order'] != 'little' or
                 result['machine'] != 8 or result['type'] not in (2, 3)):
        raise ValueError('Shipped dnsmasq must be ELF32 little-endian MIPS')
    return result


def integer_expression(text):
    tree = ast.parse(re.sub(r'(?<=\d)[uUlL]+\b', '', text), mode='eval')
    def visit(node):
        if isinstance(node, ast.Expression): return visit(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int: return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return visit(node.left)*visit(node.right)
        raise ValueError('Unexpected limit expression')
    return visit(tree)


def source_proof(trunk):
    config = (trunk/'.config').read_text()
    if 'CONFIG_LINUXDIR=linux-4.4.x' not in config:
        raise ValueError('Dynamic DNS proof is only for the 4.4 profile')
    source = {key: (trunk/path).read_bytes() for key, path in SOURCE_PATHS.items()}
    header = source['dynamic_conf.h'].decode()
    limits = {}
    for key, macro in MACROS.items():
        matches = re.findall(r'^#define\s+'+macro+r'\s+(.+)$', header, re.M)
        if len(matches) != 1:
            raise ValueError('Missing or ambiguous production limit: '+macro)
        limits[key] = integer_expression(matches[0])
    limits['directory_files'] = limits['files']
    if limits != PRODUCTION_LIMITS:
        raise ValueError('Production DNS limits differ from the audited contract')
    return {key: sha(data) for key, data in source.items()}


def session_tasks(session):
    """Read proc metadata only; never select tasks outside our new session."""
    records = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit(): continue
        try:
            text = (entry/'stat').read_text()
            fields = text[text.rfind(')')+2:].split()
            if int(fields[3]) == session and fields[0] not in ('Z', 'X'):
                records.append({'pid': int(entry.name), 'group': int(fields[2]),
                                'session': session, 'state': fields[0]})
        except (OSError, ValueError, IndexError):
            pass
    return sorted(records, key=lambda item: item['pid'])


def stop_session(session):
    if session <= 1 or session == os.getsid(0):
        raise RuntimeError('Refusing to signal an unrelated session')
    for sig in (signal.SIGTERM, signal.SIGKILL):
        groups = {row['group'] for row in session_tasks(session)}
        for group in groups:
            if group <= 1 or group == os.getpgrp():
                raise RuntimeError('Unsafe fixture process group')
            try: os.killpg(group, sig)
            except ProcessLookupError: pass
        if groups: time.sleep(0.25 if sig == signal.SIGTERM else 0.05)


REGISTER = r'''import hashlib,json,os,pathlib,struct,sys
p=pathlib.Path('/proc')/str(os.getppid())/'exe'
exe=p.resolve(strict=True);data=exe.read_bytes()
if data[:4]!=b'\x7fELF':raise RuntimeError('fixture shell is not ELF')
machine=struct.unpack_from('<H' if data[5]==1 else '>H',data,18)[0]
record={'pid':os.getpid(),'group':os.getpgrp(),'session':os.getsid(0),
        'parent_executable':str(exe),'parent_sha256':hashlib.sha256(data).hexdigest(),
        'parent_elf_machine':machine}
with open(sys.argv[1],'a') as out:out.write(json.dumps(record)+'\n')
'''


def make_fixture(directory, case):
    directory.mkdir(mode=0o700)
    marker, progress = directory/'markers.jsonl', directory/'progress'
    marker.touch(mode=0o600); progress.touch(mode=0o600)
    register = directory/'register.py'; register.write_text(REGISTER)
    script, config = directory/'generator.sh', directory/'dnsmasq.conf'
    payload = directory/'output'; error_output = directory/'error-output'
    body = ':'
    if case == 'valid-exact-output-and-stderr-caps':
        data = b'cache-size=128\n'
        block = b'#'+b'x'*16383+b'\n'
        data += (block*((2097152-len(data))//len(block)+1))[:2097152-len(data)]
        payload.write_bytes(data); error_output.write_bytes(b'e'*65536)
        body = 'cat '+shlex.quote(str(error_output))+' >&2; cat '+shlex.quote(str(payload))
    elif case == 'nonzero-output-not-parsed': body = "printf 'BadDirective\\n'; exit 7"
    elif case in ('stdout-over2MiB', 'stderr-over64KiB'):
        data = (b'# harmless\n'*(2097153//11+1))[:2097153] if case.startswith('stdout') else b'e'*65537
        payload.write_bytes(data)
        body = 'cat '+shlex.quote(str(payload))+(' >&2' if case.startswith('stderr') else '')
    elif case == 'eof-child-hung-10s': body = 'exec 1>&- 2>&-; sleep 60'
    elif case == 'orphan-held-pipe-10s': body = 'sleep 60 & exit 0'
    elif case == 'ignore-term-10s': body = "trap '' TERM; exec 1>&- 2>&-; while :; do sleep 60; done"
    elif case == 'recursive-command-string': body = "printf 'conf-script=%s recursive\\n' \"$0\""
    elif case == 'fifo-include':
        payload = directory/'input-fifo'; os.mkfifo(payload,0o600)
        body = "printf 'conf-file=%s\\n' "+shlex.quote(str(payload))
    elif case == 'device-alias-include':
        payload = directory/'null-device-alias';payload.symlink_to('/dev/null')
        # Read-only open/fstat of this private alias, never a device write.
        body = "printf 'conf-file=%s\\n' "+shlex.quote(str(payload))
    elif case == 'stdin-include': body = "printf 'conf-file=-\\n'"
    elif case in ('longline-output','longline-include'):
        payload.write_bytes(b'#'+b'x'*16384)
        body = ('cat '+shlex.quote(str(payload)) if case.endswith('output') else
                "printf 'conf-file=%s\\n' "+shlex.quote(str(payload)))
    elif case == 'nul-output': body = "printf 'cache-size=128\\000\\n'"
    elif case == 'shared-total-30s':
        quoted = shlex.quote(str(progress))
        body = ('printf "start\\n" >> '+quoted+'; sleep 8; '+
                'printf "complete\\n" >> '+quoted+"; printf '# harmless\\n'")
    elif case != 'empty-output': raise ValueError('Unknown dynamic DNS case')
    registration = shlex.join([str(Path(sys.executable).resolve()),str(register),str(marker)])
    script.write_text('#!/bin/sh\n'+registration+' || exit 125\n'+body+'\n');script.chmod(0o700)
    command = shlex.quote(str(script))+(' recursive' if case == 'recursive-command-string' else '')
    lines = ['port=0','no-hosts','no-resolv']
    lines += ['conf-script='+command+' attempt'+str(i) for i in range(4)] if case == 'shared-total-30s' else ['conf-script='+command]
    config.write_text('\n'.join(lines)+'\n')
    return config, marker, progress


def execute_case(command, directory, rule):
    name, _, _, _, maximum, _ = rule
    config, marker, progress = make_fixture(directory, name)
    stdout_path, stderr_path = directory/'stdout', directory/'stderr'
    def limits(): resource.setrlimit(resource.RLIMIT_FSIZE,(65536,65536))
    start = time.monotonic(); process = None; timed_out = False; active = []
    with stdout_path.open('w+b') as stdout, stderr_path.open('w+b') as stderr:
        try:
            process = subprocess.Popen([*command,'--test','-C',str(config)],stdin=subprocess.DEVNULL,
                                       stdout=stdout,stderr=stderr,start_new_session=True,preexec_fn=limits)
            if os.getsid(process.pid) != process.pid: raise RuntimeError('Fixture session setup failed')
            # Keep the leader waitable until all session cleanup is complete,
            # preventing its PID/session id from being reused in between.
            while True:
                info = os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                if info and info.si_pid: break
                if time.monotonic()-start > maximum+1:
                    timed_out = True; break
                time.sleep(0.02)
            elapsed = time.monotonic()-start
            active = [row for row in session_tasks(process.pid) if row['pid'] != process.pid]
        finally:
            if process is not None:
                stop_session(process.pid)
                process.wait(timeout=3)
        stdout.seek(0); stderr.seek(0); out, err = stdout.read(), stderr.read()
    events = progress.read_text().splitlines()
    markers = [json.loads(line) for line in marker.read_text().splitlines()]
    return {'case':name,'exit_code':process.returncode,'elapsed_seconds':round(elapsed,3),
            'stdout':out.decode(errors='replace'),'stderr':err.decode(errors='replace'),
            'stdout_sha256':sha(out),'stderr_sha256':sha(err),
            'marker_records':markers,'parser_session':process.pid,
            'active_fixture_tasks':active,'watchdog_timeout':timed_out,
            'progress':{'started':events.count('start'),'completed':events.count('complete'),'events':events}}


def validate_records(records, host_shell):
    if type(records) is not list or any(type(row) is not dict for row in records) or [row.get('case') for row in records] != list(CASE_NAMES):
        raise ValueError('Dynamic DNS case set/order mismatch')
    keys = {'case','exit_code','elapsed_seconds','stdout','stderr','stdout_sha256','stderr_sha256',
            'marker_records','parser_session','active_fixture_tasks','watchdog_timeout','progress'}
    for row, rule in zip(records,RULES):
        name, status, reason, minimum, maximum, registrations = rule
        if set(row) != keys or type(row['exit_code']) is not int or row['exit_code'] != status:
            raise ValueError(name+': unexpected exit code/schema (signal is not a rejection)')
        elapsed = row['elapsed_seconds']
        if type(elapsed) not in (int,float) or not math.isfinite(elapsed) or not minimum <= elapsed <= maximum:
            raise ValueError(name+': production wall-clock budget not demonstrated')
        if row['watchdog_timeout'] is not False or row['active_fixture_tasks'] != []:
            raise ValueError(name+': controller timeout or surviving generator is not PASS')
        for stream in ('stdout','stderr'):
            if type(row[stream]) is not str or len(row[stream].encode()) > 65536 or sha(row[stream].encode()) != row[stream+'_sha256']:
                raise ValueError(name+': invalid bounded diagnostic stream')
        if reason not in row['stderr'] or row['stdout'] or ('bad option' in row['stderr'] and name == 'nonzero-output-not-parsed'):
            raise ValueError(name+': parser did not report the expected rejection/acceptance')
        session = row['parser_session']
        if type(session) is not int or session <= 1: raise ValueError(name+': invalid private session')
        markers = row['marker_records']
        if type(markers) is not list or len(markers) != registrations:
            raise ValueError(name+': generator execution registrations missing')
        for marker in markers:
            if (type(marker) is not dict or set(marker) != {'pid','group','session','parent_executable','parent_sha256','parent_elf_machine'} or
                any(type(marker[k]) is not int or marker[k] <= 1 for k in ('pid','group','session')) or
                marker['session'] != session or marker['group'] == session or
                marker['parent_executable'] != host_shell['path'] or
                marker['parent_sha256'] != host_shell['sha256'] or
                type(marker['parent_elf_machine']) is not int or
                marker['parent_elf_machine'] != host_shell['elf']['machine'] or marker['parent_elf_machine'] == 8):
                raise ValueError(name+': native shell fallback was not independently registered')
        events = ['start','complete']*3+['start'] if name == 'shared-total-30s' else []
        expected = {'started':4,'completed':3,'events':events} if events else {'started':0,'completed':0,'events':[]}
        if row['progress'] != expected or any(type(row['progress'][k]) is not int for k in ('started','completed')):
            raise ValueError(name+': shared deadline progress mismatch')


def validate_report(report, binary_sha=None, source_sha=None):
    if set(report) != {'schema_version','status','profile','target','source_sha256','production_limits',
                       'execution_role','generator_role','host_shell','checks','failure'}:
        raise ValueError('Dynamic DNS top-level schema mismatch')
    if type(report['schema_version']) is not int or report['schema_version'] != 1 or report['status'] != 'PASS' or report['profile'] != 'k2p-4.4' or report['failure'] is not None:
        raise ValueError('Dynamic DNS proof is not a successful 4.4 schema1 report')
    if report['production_limits'] != PRODUCTION_LIMITS or any(type(v) is not int for v in report['production_limits'].values()):
        raise ValueError('Dynamic DNS production limits mismatch')
    if report['execution_role'] != EXECUTION_ROLE or report['generator_role'] != GENERATOR_ROLE:
        raise ValueError('Dynamic DNS execution role mismatch')
    target = report['target']; host = report['host_shell']
    for item in (target,host):
        if type(item) is not dict or set(item) != {'path','bytes','sha256','elf'} or type(item['path']) is not str or type(item['sha256']) is not str or type(item['bytes']) is not int or item['bytes'] <= 0 or not SHA.fullmatch(item['sha256']):
            raise ValueError('Dynamic DNS binary metadata mismatch')
        if type(item['elf']) is not dict or set(item['elf']) != {'class','byte_order','machine','type'} or any(type(item['elf'][k]) is not int for k in ('class','machine','type')):
            raise ValueError('Dynamic DNS ELF metadata mismatch')
    if target['path'] != 'usr/sbin/dnsmasq' or target['elf']['class'] != 32 or target['elf']['byte_order'] != 'little' or target['elf']['machine'] != 8 or target['elf']['type'] not in (2,3):
        raise ValueError('Dynamic DNS target is not shipped MIPS ELF')
    if not Path(host['path']).is_absolute() or host['elf']['machine'] <= 0 or host['elf']['machine'] == 8 or host['elf']['class'] not in (32,64) or host['elf']['byte_order'] not in ('little','big') or host['elf']['type'] not in (2,3):
        raise ValueError('Dynamic DNS native host shell metadata mismatch')
    sources = report['source_sha256']
    if set(sources) != set(SOURCE_PATHS) or any(type(v) is not str or not SHA.fullmatch(v) for v in sources.values()):
        raise ValueError('Dynamic DNS source SHA set mismatch')
    if binary_sha is not None and target['sha256'] != binary_sha: raise ValueError('Dynamic DNS image binary SHA mismatch')
    if source_sha is not None and sources != source_sha: raise ValueError('Dynamic DNS locked source SHA mismatch')
    validate_records(report['checks'],host)


def check(rootfs, sysroot, trunk, output):
    if sys.platform != 'linux' or not hasattr(os,'WNOWAIT'):
        raise RuntimeError('Target dynamic DNS execution requires Linux proc/waitid')
    source = source_proof(trunk)
    binary = rootfs/'usr/sbin/dnsmasq'
    if binary.is_symlink() or not binary.is_file(): raise ValueError('Shipped dnsmasq is not regular')
    data = binary.read_bytes(); machine = elf(data,True)
    shell = Path('/bin/sh').resolve(strict=True); shell_bytes = shell.read_bytes(); shell_elf = elf(shell_bytes)
    if shell_elf['machine'] == 8: raise ValueError('Host fallback must be independently native, not target MIPS')
    qemu = shutil.which('qemu-mipsel')
    if not qemu: raise RuntimeError('qemu-mipsel missing')
    report = {'schema_version':1,'status':'FAIL','profile':'k2p-4.4',
              'target':{'path':'usr/sbin/dnsmasq','bytes':len(data),'sha256':sha(data),'elf':machine},
              'source_sha256':source,'production_limits':dict(PRODUCTION_LIMITS),
              'execution_role':EXECUTION_ROLE,'generator_role':GENERATOR_ROLE,
              'host_shell':{'path':str(shell),'bytes':len(shell_bytes),'sha256':sha(shell_bytes),'elf':shell_elf},
              'checks':[],'failure':None}
    try:
        with tempfile.TemporaryDirectory(prefix='k2p-dynamic-dns-') as temporary:
            directory = Path(temporary).resolve()
            for rule in RULES:
                print('Target dynamic DNS: '+rule[0],flush=True)
                record = execute_case([qemu,'-L',str(sysroot),str(binary)],directory/rule[0],rule)
                report['checks'].append(record)
        report['status'] = 'PASS'; validate_report(report,sha(data),source)
    except BaseException as error:
        report['status'] = 'FAIL'; report['failure'] = str(error); raise
    finally:
        output.write_text(json.dumps(report,indent=2)+'\n')
    print('Target dynamic DNS: 16 cases PASS (production10s/30s; native shell fixtures, no listener)',flush=True)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--rootfs',type=Path,required=True)
    parser.add_argument('--sysroot',type=Path,required=True)
    parser.add_argument('--trunk',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    check(args.rootfs.resolve(),args.sysroot.resolve(),args.trunk.resolve(),args.output)
