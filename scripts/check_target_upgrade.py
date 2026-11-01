#!/usr/bin/env python3
"""MIPS/QEMU proof of locked rc recovery helpers with synthetic/inert backends."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

RC_HELPERS = ('write_storage_to_mtd', 'firmware_upgrade_signal_inhibited', 'firmware_upgrade_signal_fault',
              'firmware_upgrade_inhibited', 'firmware_upgrade_inhibit',
              'firmware_upgrade_stage_writer', 'firmware_upgrade_number', 'firmware_upgrade_result',
              'firmware_upgrade_run', 'firmware_upgrade_start_networkmap', 'firmware_upgrade_start_detect',
              'firmware_upgrade_stop_watchdog', 'firmware_upgrade_disable_watchdog',
              'firmware_upgrade_services', 'flash_firmware')
WD_HELPERS = ('start_watchdog', 'notify_watchdog_time', 'watchdog_main')
REQUIRED_HELPERS = RC_HELPERS + WD_HELPERS
SOURCE_PATHS = {'rc.c': 'trunk/user/rc/rc.c', 'rc.h': 'trunk/user/rc/rc.h',
                'watchdog.c': 'trunk/user/rc/watchdog.c', 'upgrade_gate_harness.py': 'tests/upgrade_gate_harness.py',
                'hook_runner.h': 'trunk/user/rc/hook_runner.h',
                'upgrade_guard.h': 'trunk/user/shared/upgrade_guard.h'}
HOOK_CONTRACT = dict(timeout_ms=30000, term_ms=2000, kill_ms=1000, stream_limit_bytes=131072, proc_entry_limit=8192)
PROFILE = 'USE_STORAGE=1, USE_USB_SUPPORT=1 superset; synthetic file owner mapping; private action flock real; service/device/Storage-lock/reboot and hook-outcome backends inert'
LIMITS = ('Synthetic files use test-user-to-root metadata mapping; no claim of real UID transitions.',
          'All daemon, hook, Storage, hardware ioctl, mlock, sync, sleep and reboot effects are inert; fork/wait, private action flock and synthetic file I/O are real target syscalls.',
          'Lock failure is a modeled save wait256; real target Storage locking is a separate proof.',
          'This proves target control flow/ABI, not physical flash/disarm/boot, memory residency under pressure, management survival, or rollback.',
          'Shutdown-hook outcomes are injected here; the actual bounded supervisor requires the separate mandatory target-hook proof.')
NAMES = ('watchdog', 'rstats', 'detect_internet', 'networkmap', 'lld2d', 'infosvr', 'crond')


def case(name, **values):
    options = dict(mode='flash', first=0, second=0, hook=0, hook_status=0, kind=1, mask=127,
                   stop_fail=-1, start_fail=-1, hardware=0, stage_fault=0, pin_failure=0,
                   marker=False, trusted_mode=0o755)
    options.update(values)
    return name, options


CASES = (
    *(case('status-' + name, mode='status', first=value) for name, value in
      (('success', 0), ('system-minus1', -1), ('exit1-wait256', 256), ('signal15', 15))),
    *(case('first-save-' + name, first=value, hook=1) for name, value in
      (('exit1', 256), ('system-minus1', -1), ('signal15', 15), ('lock-failure', 256))),
    *(case('hook-' + name, hook=1, hook_status=value) for name, value in
      (('exit1', 256), ('system-minus1', -1), ('signal15', 15))),
    *(case('second-save-' + name, hook=1, second=value) for name, value in
      (('exit1', 256), ('system-minus1', -1), ('signal15', 15))),
    case('no-hook-safe-prewrite'), case('hook-safe-prewrite', hook=1),
    case('safe-prewrite-disabled-stay-disabled', mask=43),
    case('safe-prewrite-start-pid-failure', start_fail=0),
    case('initial-watchdog-absent', mask=126), case('quiesce-pid-still-running', stop_fail=1),
    *(case('private-copy-' + name, stage_fault=value) for name, value in
      (('partial-failure', 1), ('source-close-failure', 2), ('target-close-failure', 3),
       ('stat-failure', 4), ('short-writes-complete', 5))),
    case('private-copy-unsafe-source-mode', trusted_mode=0o777),
    *(case('watchdog-' + name, hardware=value) for name, value in
      (('exclusive-open-failure', 1), ('wrong-owner', 2), ('not-character-device', 3),
       ('disable-failure', 4), ('close-failure', 5))),
    case('resident-request-failure', pin_failure=1),
    *(case('unknown-' + name, kind=value) for name, value in
      (('maybe-written', 2), ('signal-with-prewrite', 3), ('prewrite-exit21', 4),
       ('verified-exit21', 5), ('missing-record', 6), ('stale-pid', 7), ('extra-bytes', 8),
       ('symlink', 9), ('exec-failure', 10), ('unsafe-mode', 11), ('hardlink', 12),
       ('zero-verified-size', 13), ('wrong-target-case', 14), ('oversize', 15),
       ('zero-pid', 16), ('truncated', 17), ('embedded-nul', 18), ('signed-pid', 19),
       ('prewrite-exit0', 20), ('readback-size-mismatch', 21), ('prewrite-nonzero-size', 22))),
    case('verified-direct-reboot-return', kind=0), case('existing-inhibit-holds-before-save', marker=True),
    case('watchdog-start-wan-notify-inhibited', mode='guard', marker=True, mask=0),
    case('watchdog-start-wan-notify-normal', mode='guard', mask=0),
    case('watchdog-main-inhibited', mode='mainguard', marker=True),
    case('watchdog-main-inhibit-during-daemonize', mode='mainguard-late'),
)
CASE_NAMES = tuple(name for name, _ in CASES)
ARGUMENT_KEYS = ('mode', 'first', 'second', 'hook', 'hook_status', 'kind', 'mask',
                 'stop_fail', 'start_fail', 'hardware', 'stage_fault', 'pin_failure')


def mask_c(text):
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*',
                  lambda match: ' ' * len(match.group()), text)


def extract_function(text, name):
    pattern = r'(?:static\s+)?(?:void|int)\s+\b' + re.escape(name) + r'\s*\([^;{}]*\)\s*\{'
    matches = list(re.finditer(pattern, mask_c(text)))
    if len(matches) != 1:
        raise ValueError('Missing/old/ambiguous recovery helper: ' + name)
    match = matches[0]
    opening, depth = text.index('{', match.start()), 0
    for token in re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|[{}]', text[opening:]):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if depth == 0:
                return text[match.start():opening + token.end()]
    raise ValueError('Unterminated recovery helper: ' + name)


def read_source_inputs(trunk):
    return {key: (trunk.parent / path).read_text() for key, path in SOURCE_PATHS.items()}


def generate_source(inputs, fixture_root):
    for literal in ('#define HOOK_RUNNER_TIMEOUT_MS 30000U', '#define HOOK_RUNNER_TERM_MS 2000U',
                    '#define HOOK_RUNNER_KILL_MS 1000U', '#define HOOK_RUNNER_STREAM_LIMIT (128U * 1024U)',
                    '#define HOOK_RUNNER_PROC_LIMIT 8192U'):
        if literal not in inputs.get('hook_runner.h', ''):
            raise ValueError('Missing/changed bounded hook contract: ' + literal)
    if '#include "hook_runner.h"' not in inputs['rc.c']:
        raise ValueError('rc does not include the bounded hook supervisor')
    header = inputs['rc.h']
    for name in ('write_storage_to_mtd', 'firmware_upgrade_inhibited'):
        if not re.search(r'\bint\s+' + name + r'\s*\(\s*void\s*\)\s*;', header):
            raise ValueError('Missing/old int header prototype: ' + name)
    functions = {name: extract_function(inputs['rc.c'], name) for name in RC_HELPERS}
    functions.update({name: extract_function(inputs['watchdog.c'], name) for name in WD_HELPERS})
    if not re.search(r'\bshutdown_hook_run\s*\(\s*script_name\s*,\s*0\s*,\s*HOOK_RUNNER_TIMEOUT_MS\s*,\s*HOOK_RUNNER_TERM_MS\s*,\s*HOOK_RUNNER_KILL_MS\s*\)', functions['flash_firmware']):
        raise ValueError('Upgrade hook must use the bounded supervisor production budget')
    for name, body in functions.items():
        expected = 'void' if name in ('firmware_upgrade_stop_watchdog', 'notify_watchdog_time', 'firmware_upgrade_signal_fault') else 'int'
        if not re.match(r'(?:static\s+)?' + expected + r'\s+', body):
            raise ValueError('Missing/old recovery return type: ' + name)
    allowed = set(REQUIRED_HELPERS) | set(NAMES) | {
        'if', 'for', 'while', 'sizeof', 'defined', 'doSystem', 'logmessage', 'open', 'openat',
        'fstat', 'fstatat', 'close', 'read', 'write', 'fsync', 'fchmod', 'lseek', 'unlink', 'unlinkat',
        'rmdir', 'mkdtemp', 'strncmp', 'strcmp', 'strlen', 'memcmp', 'memchr', 'memset', 'strerror', 'snprintf',
        'sigemptyset', 'sigaddset', 'sigprocmask', 'waitpid', '_eval', 'S_ISREG', 'S_ISCHR',
        'WIFEXITED', 'WEXITSTATUS', 'pids', 'start_networkmap', 'start_detect_internet', 'kill_services',
        'ioctl', '_IOR', 'usleep', 'start_rstats', 'stop_rstats', 'stop_detect_internet',
        'stop_networkmap', 'start_lltd', 'stop_lltd', 'start_infosvr', 'stop_infosvr', 'start_crond',
        'stop_crond', 'stop', 'start', 'storage_save_time', 'check_if_file_exist', 'sync', 'reboot',
        'mlockall', 'munlockall', 'kill_pidfile_s', 'eval', 'sigaction', 'daemon', 'perror', 'exit',
        'getpid', 'oom_score_adjust', 'fopen', 'fprintf', 'fclose', 'nvram_set_int_temp',
        'hw_watchdog_init', 'wd_alarmtimer', 'remove', 'pause', 'shutdown_hook_run',
        'upgrade_actions_blocked', 'upgrade_transaction_enter', 'upgrade_action_leave'}
    for name, body in functions.items():
        calls = set(re.findall(r'\b([a-zA-Z_]\w*)\s*\(', mask_c(body)))
        if len(body) > 65536 or calls - allowed:
            raise ValueError(f'Unstubbed/oversized recovery helper {name}: {sorted(calls - allowed)}')
    tree = ast.parse(inputs['upgrade_gate_harness.py'])
    declared = [node for node in tree.body if isinstance(node, ast.Assign) and
                any(isinstance(target, ast.Name) and target.id == 'FUNCTIONS' for target in node.targets)]
    generators = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'generate']
    if len(declared) != 1 or ast.literal_eval(declared[0].value) != RC_HELPERS or len(generators) != 1:
        raise ValueError('Locked synthetic adapter missing exact recovery helper group')
    sources = {'trunk/user/rc/rc.c': inputs['rc.c'], 'trunk/user/rc/watchdog.c': inputs['watchdog.c'],
               'trunk/user/shared/upgrade_guard.h': inputs['upgrade_guard.h']}
    namespace = {'json': json, 'source': sources.__getitem__, 'function': extract_function, 'FUNCTIONS': RC_HELPERS}
    exec(compile(ast.Module(body=generators, type_ignores=[]), '<locked-upgrade-adapter>', 'exec'), namespace)
    generated = '#define USE_STORAGE 1\n#define USE_USB_SUPPORT 1\n' + namespace['generate'](fixture_root)
    for name, body in functions.items():
        if generated.count(body) != 1:
            raise ValueError('Adapter omitted/duplicated actual helper: ' + name)
    for marker in ('#define open fixture_open', '#define ioctl fixture_ioctl', '#define reboot fake_reboot',
                   '#define sync fake_sync', '#define mlockall fixture_mlockall',
                   '#define munlockall fixture_munlockall', '#define daemon fixture_daemon',
                   'static int _eval(', 'static int doSystem('):
        if marker not in generated:
            raise ValueError('Missing inert adapter boundary: ' + marker)
    return generated, functions


def expected_trace(o):
    if o['mode'] == 'status':
        return {'status': o['first']}
    if o['mode'] == 'guard':
        return {'result': 1 if o['marker'] else 0, 'execs': 0 if o['marker'] else 2}
    if o['mode'].startswith('mainguard'):
        return {'result': 1, 'daemon': int(o['mode'] == 'mainguard-late'), 'hardware_inits': 0}
    original = [int(bool(o['mask'] & (1 << i))) for i in range(7)]
    r = dict(phase=0, saves=0, hooks=0, time_calls=0, writes=0, logs=0, criticals=0,
             reboots=0, syncs=0, mlocks=0, munlocks=0, inhibited=int(o['marker']),
             hardware_opens=0, hardware_disables=0, hardware_closes=0, hardware_keepalives=0,
             snapshot_revisions=[0, 0], stops=[0] * 7, starts=[0] * 7,
             running=original.copy(), trace=[])
    def log(critical=False):
        r['logs'] += 1; r['criticals'] += int(critical); r['trace'].append('log')
    if o['marker']:
        r['phase'] = 1; log(); return r
    r.update(saves=1, time_calls=1, trace=['time', 'save'])
    if o['first']:
        log(); return r
    if o['hook']:
        r['hooks'] = 1; r['trace'].append('hook')
        if o['hook_status']:
            log(); return r
        r['saves'] = 2; r['snapshot_revisions'] = [0, 1]; r['trace'].append('save')
        if o['second']:
            log(); return r
    if o['trusted_mode'] != 0o755 or o['stage_fault'] in (1, 2, 3, 4) or not original[0]:
        log(); return r
    r['mlocks'] = 1; r['trace'].append('pin')
    if o['pin_failure']:
        log(); return r
    for i, active in enumerate(original):
        if active:
            r['stops'][i] = 1; r['trace'].append('stop:' + NAMES[i])
            if i == o['stop_fail']:
                log()
            else:
                r['running'][i] = 0
    safe = o['stop_fail'] >= 0 and original[o['stop_fail']]
    if not safe:
        r['hardware_opens'] = 1; r['trace'].append('hardware-open')
        if o['hardware'] != 1:
            r['hardware_closes'] = 1
        if o['hardware'] in (0, 4, 5):
            r['hardware_disables'] = 1; r['trace'].append('hardware-disable')
        if o['hardware'] in (2, 3, 4):
            r['hardware_keepalives'] = 1
        safe = bool(o['hardware'])
    if not safe:
        r['syncs'] = 1; r['writes'] = 1; r['trace'] += ['sync', 'writer']
        safe = o['kind'] == 1
    if safe:
        log()
        failed = False
        for i in reversed(range(7)):
            if original[i] and not r['running'][i]:
                r['starts'][i] = 1; r['trace'].append('start:' + NAMES[i])
                if i == o['start_fail']:
                    failed = True; log()
                else:
                    r['running'][i] = 1
        if failed:
            log(True)
        r['munlocks'] = 1; r['trace'].append('unpin')
        return r
    r.update(phase=1, inhibited=1)
    if o['kind'] == 0:
        log(); r['syncs'] += 1; r['reboots'] = 1; r['trace'] += ['sync', 'reboot']
    log(True)
    return r


def validate_records(records):
    if type(records) is not list or any(type(row) is not dict or set(row) != {'case', 'inputs', 'observed'} for row in records):
        raise ValueError('Invalid upgrade proof record schema')
    if [row['case'] for row in records] != list(CASE_NAMES):
        raise ValueError('Upgrade proof case set/order missing, duplicate or unexpected')
    for row, (name, options) in zip(records, CASES):
        if (json.dumps(row['inputs'], sort_keys=True) != json.dumps(options, sort_keys=True) or
                json.dumps(row['observed'], sort_keys=True) != json.dumps(expected_trace(options), sort_keys=True)):
            raise ValueError('Upgrade trace/status/phase mismatch: ' + name)


def prepare_fixture(root, options):
    private = root / 'private'
    if private.exists():
        shutil.rmtree(private)
    private.mkdir(mode=0o700)
    writer = root / 'rom-writer'
    writer.write_bytes(b'SYNTHETIC-INERT-WRITER\n' * 319)
    writer.chmod(options['trusted_mode'])
    (root / 'hardware-fixture').write_bytes(b'')
    if options['marker']:
        (private / 'firmware-upgrade-inhibit').touch(mode=0o600)


def execute_cases(command, fixture_root):
    records = []
    for name, options in CASES:
        prepare_fixture(fixture_root, options)
        arguments = [str(options[key]) for key in ARGUMENT_KEYS]
        result = subprocess.run([*command, *arguments], capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise RuntimeError(f'{name}: probe exit={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}')
        observed = json.loads(result.stdout)
        if 'trace' in observed:
            observed['trace'] = observed['trace'].strip(',').split(',') if observed['trace'] else []
        records.append({'case': name, 'inputs': options.copy(), 'observed': observed})
    validate_records(records)
    return records


def validate_mips_elf(data):
    if len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01' or struct.unpack_from('<H', data, 18)[0] != 8:
        raise ValueError('Compiler did not produce a little-endian ELF32 MIPS proof')


def export_probe(output, generated_data, binary_data):
    (output.parent / 'target-upgrade-probe.c').write_bytes(generated_data)
    binary = output.parent / 'target-upgrade-probe'
    binary.write_bytes(binary_data); binary.chmod(0o755)


def check(trunk, compiler, sysroot, output):
    config = (trunk / '.config').read_text()
    if not re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) or not re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M):
        raise ValueError('Upgrade proof requires configured K2P4.4; no legacy/SUSU fallback')
    inputs = read_source_inputs(trunk)
    qemu = shutil.which('qemu-mipsel')
    if not qemu:
        raise RuntimeError('qemu-mipsel is required for the target upgrade proof')
    with tempfile.TemporaryDirectory(prefix='k2p-target-upgrade-', dir='/tmp') as temp:
        root = Path(temp); fixture = root / 'fixture'; fixture.mkdir()
        generated, functions = generate_source(inputs, fixture)
        generated_data = generated.encode()
        source, binary = root / 'upgrade-proof.c', root / 'upgrade-proof'
        source.write_bytes(generated_data)
        compiled = subprocess.run([str(compiler), '-std=gnu99', '-Wall', '-Wextra', '-Werror',
                                   '-Wno-unused-parameter', '-Wno-unused-function', str(source), '-o', str(binary)],
                                  capture_output=True, text=True, timeout=60)
        if compiled.returncode:
            raise RuntimeError(f'Upgrade MIPS compilation failed: {compiled.stdout}{compiled.stderr}')
        binary_data = binary.read_bytes(); validate_mips_elf(binary_data)
        records = execute_cases([qemu, '-L', str(sysroot), str(binary)], fixture)
    output.parent.mkdir(parents=True, exist_ok=True)
    export_probe(output, generated_data, binary_data)
    report = dict(schema_version=3, status='PASS', profile='k2p-4.4',
                  target='real MIPS cross compiler and qemu-mipsel with target sysroot',
                  preprocessor_profile=PROFILE, probe_fixture_root=str(fixture),
                  hook_runner_contract=HOOK_CONTRACT,
                  required_helpers=list(REQUIRED_HELPERS), required_cases=list(CASE_NAMES), checks=records,
                  source_files=SOURCE_PATHS, source_sha256={**{key: hashlib.sha256(value.encode()).hexdigest() for key, value in inputs.items()},
                  **{key: hashlib.sha256(value.encode()).hexdigest() for key, value in functions.items()}},
                  generated_source_sha256=hashlib.sha256(generated_data).hexdigest(),
                  mips_probe_sha256=hashlib.sha256(binary_data).hexdigest(), compiler=str(compiler),
                  limits=list(LIMITS))
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Target upgrade recovery: {len(records)} exact cases and {len(functions)} actual helpers PASS')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for option in ('trunk', 'compiler', 'sysroot', 'output'):
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    try:
        check(args.trunk.resolve(), args.compiler.resolve(), args.sysroot.resolve(), args.output)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Target upgrade validation failed: ' + str(error) + '\n')
