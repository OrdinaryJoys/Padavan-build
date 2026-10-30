#!/usr/bin/env python3
"""Compile locked rc functions for MIPS and verify inert upgrade call traces.

All service, hook, time, sync, sleep, MTD and watchdog backends are stubs.
This exercises target C/control-flow/ABI, never router or flash hardware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile


# mode, first-save system status, second-save status, hook present, hook status,
# firmware eval status. Lockfailure256 models the save script's busy exit1;
# real target flock/archive tests live in check_target_storage.py.
CASES = (
    ('status-success', ('status', 0, 0, 0, 0, 0)),
    ('status-system-minus1', ('status', -1, 0, 0, 0, 0)),
    ('status-exit1-wait256', ('status', 256, 0, 0, 0, 0)),
    ('status-signal15', ('status', 15, 0, 0, 0, 0)),
    ('first-save-exit1', ('upgrade', 256, 0, 1, 0, 0)),
    ('first-save-system-minus1', ('upgrade', -1, 0, 1, 0, 0)),
    ('first-save-signal15', ('upgrade', 15, 0, 1, 0, 0)),
    ('first-save-lock-failure', ('upgrade', 256, 0, 1, 0, 0)),
    ('hook-exit1', ('upgrade', 0, 0, 1, 256, 0)),
    ('hook-system-minus1', ('upgrade', 0, 0, 1, -1, 0)),
    ('hook-signal15', ('upgrade', 0, 0, 1, 15, 0)),
    ('second-save-exit1', ('upgrade', 0, 256, 1, 0, 0)),
    ('second-save-system-minus1', ('upgrade', 0, -1, 1, 0, 0)),
    ('second-save-signal15', ('upgrade', 0, 15, 1, 0, 0)),
    ('no-hook-one-save-success', ('upgrade', 0, 0, 0, 0, 0)),
    ('hook-two-saves-success', ('upgrade', 0, 0, 1, 0, 0)),
    ('firmware-eval-failure-restarts-watchdog', ('upgrade', 0, 0, 1, 0, 51)),
)
CASE_NAMES = tuple(name for name, _ in CASES)
PROFILE = 'USE_STORAGE=1, USE_USB_SUPPORT=1 superset; callbacks inert, not a USB/device probe'


def extract_int_function(text, name):
    pattern = r'(?:static\s+)?(?P<type>void|int)\s+\b' + re.escape(name) + r'\s*\(\s*void\s*\)\s*\{'
    found = list(re.finditer(pattern, text))
    if len(found) != 1 or found[0].group('type') != 'int':
        raise ValueError('Missing/old/ambiguous int rc helper: ' + name)
    match = found[0]
    opening, depth = text.index('{', match.start()), 0
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|[{}]')
    for token in tokens.finditer(text, opening):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if depth == 0:
                return text[match.start():token.end()]
    raise ValueError('Unterminated rc helper: ' + name)


PRELUDE = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#define SCRIPT_SHUTDOWN "/etc/storage/shutdown_script.sh"
#define FW_IMG_NAME "/tmp/linux.trx"
#define FW_MTD_NAME "firmware"
#define USE_STORAGE 1
#define USE_USB_SUPPORT 1
static int first_status,second_status,hook_status,hook_exists,firmware_status;
static int saves,hooks,stops_misc,stops_services,detach_calls,spool_calls,kills,writes;
static int syncs,sleeps,watchdog=1,restarts,logs,time_calls,revision,versions[2];
static char trace[4096];
static void event(const char*s){assert(strlen(trace)+strlen(s)+2<sizeof(trace));strcat(trace,s);strcat(trace,",");}
static int doSystem(const char*fmt,...){
 char command[512];va_list ap;va_start(ap,fmt);vsnprintf(command,sizeof(command),fmt,ap);va_end(ap);
 if(!strcmp(command,"/sbin/mtd_storage.sh save")){assert(saves<2);versions[saves]=revision;event("save");saves++;return saves==1?first_status:second_status;}
 assert(!strcmp(command,SCRIPT_SHUTDOWN " 0"));event("hook");hooks++;revision++;return hook_status;
}
static void logmessage(const char*tag,const char*fmt,...){assert(!strcmp(tag,"firmware"));logs++;event("log");}
static void stop_misc(void){stops_misc++;watchdog=0;event("stop_misc");}
static void stop_services(int all){assert(all==0);stops_services++;event("stop_services");}
static int check_if_file_exist(const char*path){assert(!strcmp(path,SCRIPT_SHUTDOWN));return hook_exists;}
static void safe_remove_all_stor_devices(int all){assert(all==0);detach_calls++;event("detach");}
static void stop_usb_printer_spoolers(void){spool_calls++;event("spool");}
static void stop_igmpproxy(const char*unused){event("igmp");}
static void kill_services(char**names,int timeout,int force){assert(timeout==6&&force==1);kills++;event("kill");}
static void storage_save_time(int seconds){assert(seconds==60);time_calls++;event("time");}
static void inert_sync(void){syncs++;event("sync");}
static void inert_sleep(int seconds){assert(seconds==1);sleeps++;event("sleep");}
#define sync inert_sync
#define sleep inert_sleep
static int eval(const char*program,const char*a,const char*b,const char*image,const char*target){
 assert(!strcmp(program,"/tmp/mtd_write")&&!strcmp(a,"-r")&&!strcmp(b,"write"));
 assert(!strcmp(image,FW_IMG_NAME)&&!strcmp(target,FW_MTD_NAME));writes++;event("writer");return firmware_status;
}
static void start_watchdog(void){watchdog=1;restarts++;event("restart_watchdog");}
'''
MAIN = r'''
int main(int argc,char**argv){
 char result[32];int phase=-1;assert(argc==7);
 first_status=atoi(argv[2]);second_status=atoi(argv[3]);hook_exists=atoi(argv[4]);hook_status=atoi(argv[5]);firmware_status=atoi(argv[6]);
 if(!strcmp(argv[1],"status"))snprintf(result,sizeof(result),"%d",write_storage_to_mtd());
 else {assert(!strcmp(argv[1],"upgrade"));strcpy(result,"null");phase=flash_firmware();}
 printf("{\"phase\":%d,\"save_result\":%s,\"save_calls\":%d,\"hook_calls\":%d,\"stop_misc\":%d,\"stop_services\":%d,\"detach_calls\":%d,\"spool_calls\":%d,\"selected_kills\":%d,\"firmware_calls\":%d,\"sync_calls\":%d,\"sleep_calls\":%d,\"watchdog_state\":%d,\"watchdog_restarts\":%d,\"logs\":%d,\"time_calls\":%d,\"snapshot_revisions\":[%d,%d],\"trace\":\"%s\"}\n",
 phase,result,saves,hooks,stops_misc,stops_services,detach_calls,spool_calls,kills,writes,syncs,sleeps,watchdog,restarts,logs,time_calls,versions[0],versions[1],trace);
 return 0;
}
'''


def generate_source(rc, header):
    if not re.search(r'\bint\s+write_storage_to_mtd\s*\(\s*void\s*\)\s*;', header):
        raise ValueError('Missing/old int write_storage_to_mtd header prototype')
    functions = {name: extract_int_function(rc, name) for name in ('write_storage_to_mtd', 'flash_firmware')}
    allowed = {'write_storage_to_mtd', 'flash_firmware', 'doSystem', 'logmessage', 'stop_misc',
               'stop_services', 'check_if_file_exist', 'safe_remove_all_stor_devices',
               'stop_usb_printer_spoolers', 'stop_igmpproxy', 'kill_services',
               'storage_save_time', 'sync', 'sleep', 'eval', 'start_watchdog',
               'if', 'sizeof', 'defined'}
    for name, body in functions.items():
        code = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*', '', body)
        calls = set(re.findall(r'\b([a-zA-Z_]\w*)\s*\(', code))
        if calls - allowed:
            raise ValueError(f'Unstubbed callback in {name}: {sorted(calls - allowed)}')
    return PRELUDE + '\n'.join(functions.values()) + MAIN, functions


def expected_trace(arguments):
    mode, first, second, hook, hook_status, firmware = arguments
    result = dict(phase=-1, save_result=first if mode == 'status' else None,
                  save_calls=1, hook_calls=0, stop_misc=0, stop_services=0,
                  detach_calls=0, spool_calls=0, selected_kills=0, firmware_calls=0,
                  sync_calls=0, sleep_calls=0, watchdog_state=1, watchdog_restarts=0,
                  logs=0, time_calls=0, snapshot_revisions=[0, 0], trace=['save'])
    if mode == 'status':
        return result
    result.update(phase=0, time_calls=1, trace=['time', 'save'])
    failed = first != 0
    if not failed and hook:
        result['hook_calls'] = 1; result['trace'].append('hook')
        failed = hook_status != 0
        if not failed:
            result['save_calls'] = 2; result['snapshot_revisions'] = [0, 1]
            result['trace'].append('save'); failed = second != 0
    if failed:
        result['logs'] = 1; result['trace'].append('log')
        return result
    for key in ('stop_misc', 'stop_services', 'detach_calls', 'spool_calls', 'selected_kills',
                'firmware_calls', 'sync_calls', 'sleep_calls'):
        result[key] = 1
    result.update(phase=1, watchdog_state=0)
    result['trace'] += ['stop_misc', 'stop_services', 'detach', 'spool', 'igmp', 'kill', 'sync', 'sleep', 'writer']
    if firmware:
        result.update(watchdog_state=1, watchdog_restarts=1)
        result['trace'].append('restart_watchdog')
    return result


def validate_records(records):
    if type(records) is not list or any(type(row) is not dict or set(row) != {'case', 'inputs', 'observed'} for row in records):
        raise ValueError('Invalid upgrade proof record schema')
    if [row.get('case') for row in records] != list(CASE_NAMES):
        raise ValueError('Upgrade proof case set/order missing, duplicate or unexpected')
    for row, (name, arguments) in zip(records, CASES):
        if (json.dumps(row['inputs'], sort_keys=True) != json.dumps(list(arguments), sort_keys=True) or
                json.dumps(row['observed'], sort_keys=True) != json.dumps(expected_trace(arguments), sort_keys=True)):
            raise ValueError('Upgrade trace/status/phase mismatch: ' + name)


def execute_cases(command):
    records = []
    for name, arguments in CASES:
        result = subprocess.run([*command, *map(str, arguments)], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise RuntimeError(f'{name}: probe exit={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}')
        try:
            observed = json.loads(result.stdout)
            observed['trace'] = observed['trace'].strip(',').split(',')
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            raise ValueError('Invalid upgrade probe output for ' + name) from error
        records.append({'case': name, 'inputs': list(arguments), 'observed': observed})
    validate_records(records)
    return records


def validate_mips_elf(data):
    if (len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01' or
            struct.unpack_from('<H', data, 18)[0] != 8):
        raise ValueError('Compiler did not produce a little-endian ELF32 MIPS proof')


def export_probe(output, generated_data, binary_data):
    """Keep the exact compiled input/output as independently hashable diagnostics."""
    source = output.parent / 'target-upgrade-probe.c'
    binary = output.parent / 'target-upgrade-probe'
    source.write_bytes(generated_data)
    binary.write_bytes(binary_data)
    binary.chmod(0o755)


def check(trunk, compiler, sysroot, output):
    config = (trunk / '.config').read_text()
    if not re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) or not re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M):
        raise ValueError('Upgrade proof requires configured K2P4.4; no legacy/SUSU fallback')
    rc, header = (trunk / 'user/rc/rc.c').read_text(), (trunk / 'user/rc/rc.h').read_text()
    generated, functions = generate_source(rc, header)
    generated_data = generated.encode()
    qemu = shutil.which('qemu-mipsel')
    if not qemu:
        raise RuntimeError('qemu-mipsel is required for the target upgrade proof')
    with tempfile.TemporaryDirectory(prefix='k2p-target-upgrade-', dir='/tmp') as temp:
        source, binary = Path(temp) / 'upgrade-proof.c', Path(temp) / 'upgrade-proof'
        source.write_bytes(generated_data)
        compiled = subprocess.run([str(compiler), '-std=gnu99', '-Wall', '-Wextra', '-Werror',
                                   '-Wno-unused-parameter', '-Wno-unused-function', str(source), '-o', str(binary)],
                                  capture_output=True, text=True, timeout=60)
        if compiled.returncode:
            raise RuntimeError(f'Upgrade MIPS compilation failed: {compiled.stdout}{compiled.stderr}')
        binary_data = binary.read_bytes(); validate_mips_elf(binary_data)
        records = execute_cases([qemu, '-L', str(sysroot), str(binary)])
    export_probe(output, generated_data, binary_data)
    report = {'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4',
              'target': 'real MIPS cross compiler and qemu-mipsel with target sysroot',
              'preprocessor_profile': PROFILE, 'required_cases': list(CASE_NAMES), 'checks': records,
              'source_sha256': {'rc.c': hashlib.sha256(rc.encode()).hexdigest(),
                                'rc.h': hashlib.sha256(header.encode()).hexdigest(),
                                **{name: hashlib.sha256(body.encode()).hexdigest() for name, body in functions.items()}},
              'generated_source_sha256': hashlib.sha256(generated_data).hexdigest(),
              'mips_probe_sha256': hashlib.sha256(binary_data).hexdigest(), 'compiler': str(compiler),
              'limits': ['All effect backends inert: no real service stop, hook, time write, sync/sleep, MTD, watchdog or reboot.',
                         'Lockfailure is modeled as Storage busy exit1/system wait256; this is control flow, not the target flock syscall test.',
                         'This does not establish hardware flash/boot success, atomicity with other Storage writers, or rollback of user hook side effects.']}
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Target upgrade save gate: {len(records)} exact trace/status cases PASS')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--trunk', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        check(args.trunk.resolve(), args.compiler.resolve(), args.sysroot.resolve(), args.output)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Target upgrade validation failed: ' + str(error) + '\n')
