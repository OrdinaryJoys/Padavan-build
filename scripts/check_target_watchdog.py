#!/usr/bin/env python3
"""Compile actual scheduler bodies for MIPS with inert update/reboot backends."""
import argparse
import ast
import hashlib
import json
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

from check_target_upgrade import extract_function
from check_target_writer import require, validate_elf_binding

SOURCE_PATHS = {'watchdog.c': 'user/rc/watchdog.c', 'rc.c': 'user/rc/rc.c',
                'notify_rc.h': 'user/shared/notify_rc.h',
                'fixture': '../tests/test_watchdog_scheduled_update.py'}
FUNCTIONS = ('watchdog_schedule_valid', 'timecheck_reboot', 'watchdog_schedule_dlink',
             'svc_timecheck', 'watchdog_on_timer', 'start_scheduled_dlink')
CASES = tuple((name, True) for name in ('valid', 'time', 'launcher', 'timer', 'disabled',
                                      'not-ready', 'inhibited', 'bad', 'debounce', 'clock-backward')) + (('timer', False),)
CASE_NAMES = tuple(('ss-on:' if flag else 'ss-off:') + name for name, flag in CASES)
ROLE = 'Locked scheduler source fragments, real MIPS libc/timer signals, inert service/watchdog/update/reboot callbacks'


def generate_source(texts, enabled):
    require(set(texts) == set(SOURCE_PATHS) and type(enabled) is bool, 'Unexpected source/profile set')
    constants = {}
    for node in ast.parse(texts['fixture']).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ('PRELUDE', 'SUFFIX'):
                require(name not in constants, 'Duplicate fixture constant')
                constants[name] = ast.literal_eval(node.value)
    require(set(constants) == {'PRELUDE', 'SUFFIX'} and all(type(x) is str for x in constants.values()),
            'Missing pure C fixture constants')
    macro = r'^#define\s+RCN_SCHEDULE_DLINK\s+("[^"\n]+")\s*$'
    actual = re.findall(macro, texts['notify_rc.h'], re.MULTILINE)
    fixture = re.findall(macro, constants['PRELUDE'], re.MULTILINE)
    require(actual == fixture == ['"schedule_dlink_update"'], 'Scheduled update event binding drift')
    bodies = {name: extract_function(texts['rc.c' if name == 'start_scheduled_dlink' else 'watchdog.c'], name)
              for name in FUNCTIONS}
    names = ('watchdog_schedule_valid', 'timecheck_reboot')
    if enabled:
        names += ('watchdog_schedule_dlink', 'start_scheduled_dlink')
    names += ('svc_timecheck', 'watchdog_on_timer')
    return ('#define APP_SHADOWSOCKS 1\n' if enabled else '') + constants['PRELUDE'] + '\n'.join(bodies[name] for name in names) + constants['SUFFIX']


def validate_records(records):
    require(type(records) is list and len(records) == len(CASE_NAMES), 'Watchdog case count mismatch')
    for row, name in zip(records, CASE_NAMES):
        require(type(row) is dict and set(row) == {'case', 'exit_code', 'stdout', 'stderr'} and row['case'] == name,
                'Watchdog case order/fields mismatch')
        require(type(row['exit_code']) is int and row['exit_code'] == 0 and row['stdout'] == row['stderr'] == '',
                'Watchdog control failed/crashed/produced unexpected output')


def check(trunk, compiler, sysroot, output):
    qemu = shutil.which('qemu-mipsel')
    require(qemu is not None, 'qemu-mipsel required')
    texts = {name: (trunk / path).read_text() for name, path in SOURCE_PATHS.items()}
    probes = {}
    for enabled in (True, False):
        label = 'ss-on' if enabled else 'ss-off'
        source = output.with_name(output.stem + '-' + label + '.c')
        binary = source.with_suffix('')
        body = generate_source(texts, enabled).encode(); source.write_bytes(body)
        command = [str(compiler), '-std=gnu99', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                   '-UNDEBUG', '-Wl,-z,now']
        if sysroot is None:
            command.append('-static')
        command += [str(source), '-o', str(binary), '-lrt']
        built = subprocess.run(command, capture_output=True, text=True, timeout=60)
        require(built.returncode == 0, 'Watchdog MIPS probe compile failed: ' + built.stderr)
        payload = binary.read_bytes(); binding = validate_elf_binding(payload)
        require(int.from_bytes(payload[16:18], 'little') in (2, 3), 'Probe is not an executable ELF')
        binary.chmod(0o755)
        probes[label] = {'source_sha256': hashlib.sha256(body).hexdigest(),
                         'elf_sha256': hashlib.sha256(payload).hexdigest(), 'binding': binding,
                         'command': [qemu, *(['-L', str(sysroot)] if sysroot is not None else []), str(binary)]}
    records = []
    for (case, enabled), name in zip(CASES, CASE_NAMES):
        run = subprocess.run(probes['ss-on' if enabled else 'ss-off']['command'] + [case],
                             capture_output=True, text=True, timeout=10)
        records.append({'case': name, 'exit_code': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr})
    validate_records(records)
    for value in probes.values():
        del value['command']
    report = {'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4', 'execution_role': ROLE,
              'runtime': 'static toolchain libc' if sysroot is None else 'shipped target sysroot',
              'required_cases': list(CASE_NAMES), 'checks': records,
              'source_sha256': {name: hashlib.sha256(text.encode()).hexdigest() for name, text in texts.items()},
              'probes': probes,
              'limits': ['No real hardware watchdog, daemon, subscription update, router network or reboot executed.',
                         'The optional application is tested enabled and disabled independently of the firmware feature selection.']}
    output.write_text(json.dumps(report, indent=2) + '\n')
    print('Target watchdog scheduler:11 source cases PASS (' + report['runtime'] + ')')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--sysroot', type=Path)
    args = parser.parse_args()
    check(args.trunk.resolve(), args.compiler.resolve(), args.sysroot.resolve() if args.sysroot else None, args.output.resolve())
