#!/usr/bin/env python3
"""Validate legacy protocol refusal and an inert MIPS writer-core probe.

The probe uses the locked production core header and ordinary files. No
MTD, real erase/write IOCTL, real mlockall, daemon or reboot is executed.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zlib

SOURCE_PATHS = {
    'mtd.c': 'user/mtd_write/mtd.c',
    'legacy_guard.h': 'user/mtd_write/legacy_guard.h',
    'upgrade_write.h': 'user/mtd_write/upgrade_write.h',
    'crc32.h': 'user/mtd_write/crc32.h',
    'crc32.c': 'user/mtd_write/crc32.c',
    'mtd-abi.h': 'user/shared/include/mtd-abi.h',
    'fixture': '../tests/test_firmware_writer_protocol.py',
    'Makefile': 'user/mtd_write/Makefile',
}
# fault, expected exit, state, payload equal to the immutable image afterwards.
CASES = (
    ('success-supported-sync', None, 0, 'VERIFIED', True),
    ('success-mtdchar-unsupported-sync', 'sync-unsupported', 0, 'VERIFIED', True),
    ('success-short-writes', 'short', 0, 'VERIFIED', True),
    ('success-write-eintr', 'write-eintr', 0, 'VERIFIED', True),
    ('memory-lock-prewrite', 'memory-lock', 20, 'PREWRITE', False),
    ('image-read-prewrite', 'image-read', 20, 'PREWRITE', False),
    ('invalid-crc-prewrite', 'invalid-crc', 20, 'PREWRITE', False),
    ('readback-interface-prewrite', 'pre-read', 20, 'PREWRITE', False),
    ('state-maybe-write-unknown', 'maybe-write', 21, 'PREWRITE', False),
    ('state-maybe-sync-unknown', 'maybe-dir-sync', 21, 'MAYBE_WRITTEN', False),
    ('unlock-unknown', 'unlock', 21, 'MAYBE_WRITTEN', False),
    ('erase-unknown', 'erase', 21, 'MAYBE_WRITTEN', False),
    ('write-partial-unknown', 'partial', 21, 'MAYBE_WRITTEN', False),
    ('sync-unknown', 'sync', 21, 'MAYBE_WRITTEN', True),
    ('writer-close-unknown', 'close', 21, 'MAYBE_WRITTEN', True),
    ('readback-mismatch-unknown', 'mismatch', 21, 'MAYBE_WRITTEN', True),
    ('reader-close-unknown', 'reader-close', 21, 'MAYBE_WRITTEN', True),
    ('state-verified-write-unknown', 'verified-write', 21, 'MAYBE_WRITTEN', True),
    ('state-verified-sync-unknown', 'verified-dir-sync', 21, 'VERIFIED', True),
    ('global-lock-busy-unknown', 'global-lock', 21, 'PREWRITE', False),
)
CASE_NAMES = ('shipped-legacy-protocol-refused',) + tuple(row[0] for row in CASES)
IMAGE_BYTES = 9064
PADDED_BYTES = 12288
FIELDS = {'case', 'backend', 'fault', 'exit_code', 'child_pid', 'record', 'events',
          'payload_matches_snapshot', 'record_metadata'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def generate_source(texts):
    """Pure generation from locked source strings; no import/exec of fixtures."""
    require(set(texts) == set(SOURCE_PATHS), 'Writer generator source set changed')
    tree = ast.parse(texts['fixture'])
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'FirmwareWriterProtocolTests']
    require(len(classes) == 1, 'Missing/ambiguous writer fixture')
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == 'setUpClass']
    require(len(methods) == 1, 'Missing writer fixture constructor')
    strings = [node.args[0].value for node in ast.walk(methods[0])
               if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
               and isinstance(node.func.value, ast.Name) and node.func.value.id == 'harness'
               and node.func.attr == 'write_text' and len(node.args) == 1
               and isinstance(node.args[0], ast.Constant) and type(node.args[0].value) is str]
    require(len(strings) == 1, 'Missing/ambiguous inert C fixture')
    harness = strings[0]
    branch = re.findall(r'\tif \(argc > 1 && !strcmp\(argv\[1\], "--upgrade-write"\)\) \{\n.*?\n\t\}',
                        texts['mtd.c'], re.S)
    require(len(branch) == 1 and texts['mtd.c'].index(branch[0]) < texts['mtd.c'].index('while ((ch = getopt') and
            'return 21;' in branch[0] and 'firmware_upgrade_write(' not in branch[0],
            'Legacy writer must reject the former protocol before legacy options')
    require('-Wl,-z,now' in texts['Makefile'], 'Writer must bind dynamic symbols before main')
    old_main = 'int main(int argc,char**argv){if(argc!=4)return 99;_exit(firmware_upgrade_write(argv[1],argv[2],argv[3]));}'
    require(harness.count(old_main) == 1, 'Inert fixture main changed')
    header = texts['upgrade_write.h'].replace('#include "crc32.h"', texts['crc32.h'])
    require(header != texts['upgrade_write.h'], 'CRC header inclusion missing')
    require(harness.count('#include "mtd-abi.h"') == 1 and harness.count('#include "upgrade_write.h"') == 1,
            'Inert fixture production includes changed')
    harness = harness.replace('#include "mtd-abi.h"', texts['mtd-abi.h'])
    harness = harness.replace('#include "upgrade_write.h"',
                              'static char *probe_operation;\n#define FWUP_OPERATION_DIR probe_operation\n' + header)
    new_main = ('int main(int argc,char**argv){\nprobe_operation=getenv("WRITER_OPERATION");\n'
                'if(!probe_operation)return 98;\n'
                'if(argc!=5||strcmp(argv[1],"--upgrade-write"))return 99;\n'
                '_exit(firmware_upgrade_write(argv[2],argv[3],argv[4]));\n}')
    harness = harness.replace(old_main, new_main)
    return ('/* Locked writer source probe; all device and memory-lock effects are inert. */\n'
            + harness + '\n' + texts['crc32.c'])


def expected_events(fault):
    if fault == 'global-lock':
        return []
    events = ['open-device']
    if fault in ('image-read', 'invalid-crc', 'pre-read'):
        return events
    events += ['device-sync', 'memory-lock']
    if fault == 'memory-lock':
        return events + ['memory-unlock']
    if fault in ('maybe-write', 'maybe-dir-sync'):
        return events
    for _ in range(3):
        events.append('unlock')
        if fault == 'unlock': return events
        events.append('erase')
        if fault == 'erase': return events
    events += ['write'] * ((PADDED_BYTES + 16) // 17 if fault == 'short' else 2 if fault in ('partial', 'write-eintr') else 1)
    if fault == 'partial': return events
    events.append('device-sync')
    if fault == 'sync': return events
    events.append('writer-close')
    if fault == 'close': return events
    events.append('readback')
    if fault == 'mismatch': return events
    return events + ['reader-close']


def validate_records(records, expected_owner=0, include_shipped=True):
    require(type(include_shipped) is bool, 'Writer shipped-case selection must be boolean')
    specs = [('shipped-legacy-protocol-refused', None, 21, None, None), *CASES] if include_shipped else list(CASES)
    require(type(records) is list and [row.get('case') if type(row) is dict else None for row in records] == [spec[0] for spec in specs],
            'Writer case order/set missing, duplicate or unexpected')
    for row, spec in zip(records, specs):
        name, fault, code, state, matches = spec
        shipped = name == 'shipped-legacy-protocol-refused'
        require(set(row) == FIELDS, 'Writer record keys changed: ' + name)
        require(row['backend'] == ('actual-shipped-writer' if shipped else 'inert-production-source-MIPS-probe'),
                'Writer backend role changed: ' + name)
        require(row['fault'] == fault and type(row['exit_code']) is int and row['exit_code'] == code,
                'Writer exit/fault mismatch: ' + name)
        require(type(row['child_pid']) is int and row['child_pid'] > 1, 'Invalid writer child PID')
        if shipped:
            require(row['record'] is None and row['record_metadata'] is None and row['events']==[] and
                    row['payload_matches_snapshot'] is None, 'Legacy refusal created a writer status or used a device')
            continue
        r = row['record']
        require(type(r) is dict and set(r) == {'state', 'pid', 'target', 'image_bytes', 'verified_bytes'},
                'Writer status schema mismatch: ' + name)
        require(all(type(r[k]) is int for k in ('pid', 'image_bytes', 'verified_bytes')),
                'Writer status numeric types changed: ' + name)
        image_bytes = 0 if state == 'PREWRITE' else IMAGE_BYTES
        require(r == {'state': state, 'pid': row['child_pid'], 'target': 'firmware', 'image_bytes': image_bytes,
                      'verified_bytes': IMAGE_BYTES if state == 'VERIFIED' else 0}, 'Writer status mismatch: ' + name)
        require(row['events'] == ([] if shipped else expected_events(fault)), 'Writer phase/event order mismatch: ' + name)
        require(row['payload_matches_snapshot'] is matches, 'Writer payload preservation mismatch: ' + name)
        require(type(row['record_metadata']) is dict and set(row['record_metadata']) == {'uid', 'mode', 'nlink'} and
                all(type(value) is int for value in row['record_metadata'].values()) and
                row['record_metadata'] == {'uid': expected_owner, 'mode': 0o600, 'nlink': 1},
                'Writer status is not private/owned/single-link: ' + name)


def validate_elf_binding(data):
    require(len(data) >= 52 and data[:7] == b'\x7fELF\x01\x01\x01' and
            struct.unpack_from('<H', data, 18)[0] == 8, 'Writer is not ELF32 little-endian MIPS')
    offset = struct.unpack_from('<I', data, 28)[0]
    entry_size, count = struct.unpack_from('<HH', data, 42)
    require(entry_size == 32 and 0 < count <= 128 and offset + count * entry_size <= len(data), 'Invalid ELF program headers')
    dynamic = False
    for index in range(count):
        kind, start, _, _, size, _, _, _ = struct.unpack_from('<8I', data, offset + index * entry_size)
        if kind != 2: continue
        dynamic = True
        require(size % 8 == 0 and size <= 65536 and start + size <= len(data), 'Invalid ELF dynamic table')
        for position in range(start, start + size, 8):
            tag, value = struct.unpack_from('<II', data, position)
            if tag == 24 or tag == 30 and value & 8 or tag == 0x6ffffffb and value & 1:
                return 'eager-dynamic-binding'
            if tag == 0: break
    require(not dynamic, 'Dynamic writer/probe is missing BIND_NOW')
    return 'static-no-dynamic-segment'


def synthetic_image():
    data = bytearray(IMAGE_BYTES)
    data[28:32] = bytes([5, 5, 2, 3]); data[32:36] = bytes([4, 4, 1, 1]); data[36:40] = b'K2P\0'
    struct.pack_into('>I', data, 60, 4096)
    data[64:] = bytes(n % 251 for n in range(IMAGE_BYTES - 64)); data[4096:4100] = b'hsqs'
    struct.pack_into('>7I', data, 0, 0x27051956, 0, 0, IMAGE_BYTES - 64,
                     0x81001000, 0x81001000, zlib.crc32(data[64:]) & 0xffffffff)
    struct.pack_into('>I', data, 4, zlib.crc32(data[:64]) & 0xffffffff)
    return bytes(data)


def parse_record(path, child_pid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= 256, 'Invalid status file/size')
        data = b''
        while len(data) < 257:
            block = os.read(fd, 257 - len(data))
            if not block: break
            data += block
        require(len(data) == st.st_size, 'Status length changed')
    finally:
        os.close(fd)
    match = re.fullmatch(rb'K2P_FWUP_V1\nstate=(PREWRITE|MAYBE_WRITTEN|VERIFIED)\npid=([1-9][0-9]*)\n'
                         rb'target=firmware\nimage_bytes=(0|[1-9][0-9]*)\nverified_bytes=(0|[1-9][0-9]*)\n', data)
    require(match is not None and int(match[2]) == child_pid, 'Malformed/stale writer status')
    return ({'state': match[1].decode(), 'pid': int(match[2]), 'target': 'firmware',
             'image_bytes': int(match[3]), 'verified_bytes': int(match[4])},
            {'uid': st.st_uid, 'mode': st.st_mode & 0o7777, 'nlink': st.st_nlink})


def execute(command, environment, preexec=None):
    process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL, close_fds=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=preexec)
    try:
        stdout, stderr = process.communicate(timeout=30)
    except BaseException:
        process.kill(); process.communicate(timeout=5); raise
    return process.pid, process.returncode, stdout, stderr


def prepare_output(path):
    """Reserve the report as the unprivileged controller before sudo writes.

    Refuse every pre-existing path, including links. A root worker truncating
    this file keeps its inode and controller ownership for the final rewrite.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1 and
                st.st_size == 0 and st.st_mode & 0o7777 == 0o600, 'Unsafe controller-owned report reservation')
    finally:
        os.close(fd)
    return st


def run_probe_case(command, base, spec):
    name, fault, _, _, _ = spec
    directory = base / name; directory.mkdir(mode=0o700)
    source, device, status, events = (directory / n for n in ('image', 'ordinary-file-device', 'status', 'events'))
    expected = synthetic_image(); source.write_bytes(expected); source.chmod(0o600)
    if fault == 'invalid-crc':
        data = bytearray(expected); data[80] ^= 1; source.write_bytes(data)
    with device.open('wb') as stream: stream.truncate(15925248)
    operation = directory / 'operation'
    env = dict(os.environ, WRITER_IMAGE=str(source), WRITER_DEVICE=str(device), WRITER_STATUS=str(status),
               WRITER_LOG=str(events), WRITER_OPERATION=str(operation))
    env.pop('WRITER_FAULT', None)
    if fault: env['WRITER_FAULT'] = fault
    lock = None
    if fault == 'global-lock':
        import fcntl
        operation.mkdir(mode=0o700); lock = (operation / 'lock').open('w'); os.chmod(operation / 'lock', 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        pid, code, stdout, stderr = execute([*command, '--upgrade-write', str(source), 'firmware', str(status)], env)
    finally:
        if lock is not None: lock.close()
    require(not stdout and 'AddressSanitizer' not in stderr and 'runtime error:' not in stderr, 'Unexpected probe diagnostic')
    record, metadata = parse_record(status, pid)
    return {'case': name, 'backend': 'inert-production-source-MIPS-probe', 'fault': fault,
            'exit_code': code, 'child_pid': pid, 'record': record,
            'events': events.read_text().splitlines() if events.exists() else [],
            'payload_matches_snapshot': device.read_bytes()[:len(expected)] == expected, 'record_metadata': metadata}


def worker(rootfs, sysroot, probe, output):
    require(sys.platform.startswith('linux') and os.geteuid() == 0, 'Isolated Linux root child required')
    require(os.stat('/proc/self/ns/mnt').st_ino != os.stat('/proc/1/ns/mnt').st_ino, 'Private mount namespace required')
    roots = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4] == '/']
    require(len(roots) == 1 and not any(x.startswith('shared:') for x in roots[0][6:roots[0].index('-')]),
            'Private mount propagation required')
    subprocess.run(['mount', '-n', '-t', 'tmpfs', '-o', 'size=24M,mode=1777', 'tmpfs', '/tmp'], check=True, capture_output=True)
    (sysroot / 'tmp').mkdir(exist_ok=True)
    subprocess.run(['mount', '-n', '--bind', '/tmp', str(sysroot / 'tmp')], check=True, capture_output=True)
    shipped = rootfs / 'bin/mtd_write'
    binding = validate_elf_binding(shipped.read_bytes())
    # The single actual invocation must be a legacy-protocol refusal. The
    # build host has no MTD and host reboot/IOCTL remain denied as defense.
    import types
    resident = types.ModuleType('_writer_refusal_sandbox')
    resident_path = Path(__file__).with_name('check_target_resident_upgrade.py')
    exec(compile(resident_path.read_text(), str(resident_path), 'exec'), resident.__dict__)
    isolation = resident.refusal_environment()
    rows = []
    with tempfile.TemporaryDirectory(prefix='k2p-writer-target-', dir='/tmp') as temporary:
        base = Path(temporary)
        attempt = base / 'shipped'; attempt.mkdir(mode=0o700)
        bad, status = attempt / 'bad-image', attempt / 'status'
        bad.write_bytes(b'not a valid image\n'); bad.chmod(0o600)
        pid, code, stdout, stderr = execute(['qemu-mipsel', '-L', str(sysroot), str(shipped), '--upgrade-write',
                                           str(bad), 'firmware', str(status)], {}, resident.refusal_preexec())
        require(code == 21 and not stdout and stderr ==
                'mtd_write: firmware protocol moved to the controlled resident upgrade helper\n' and
                not status.exists() and not status.is_symlink(),
                'Shipped legacy writer did not refuse the removed protocol: ' + stderr)
        record, metadata = None, None
        rows.append({'case': CASE_NAMES[0], 'backend': 'actual-shipped-writer', 'fault': None, 'exit_code': code,
                     'child_pid': pid, 'record': record, 'events': [], 'payload_matches_snapshot': None,
                     'record_metadata': metadata})
        for spec in CASES:
            rows.append(run_probe_case(['qemu-mipsel', '-L', str(sysroot), str(probe)], base, spec))
    validate_records(rows)
    output.write_text(json.dumps({'checks': rows, 'shipped_binding': binding,
                                 'shipped_refusal_isolation': isolation}, indent=2) + '\n')
    os.chmod(output, 0o644)


def check(trunk, rootfs, compiler, sysroot, output):
    require(sys.platform.startswith('linux'), 'Writer target proof requires Linux')
    for path in (trunk, rootfs, compiler, sysroot, output, Path(__file__).resolve()):
        require(not path.is_relative_to('/tmp') and not path.is_relative_to('/etc'), 'Namespace input/output cannot live under /tmp or /etc')
    texts = {name: (trunk / relative).read_text() for name, relative in SOURCE_PATHS.items()}
    generated = generate_source(texts)
    source, probe = output.with_name('target-writer-probe.c'), output.with_name('target-writer-probe')
    source.write_text(generated)
    result = subprocess.run([str(compiler), '-std=gnu99', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wl,-z,now',
                             '-DFWUP_TEST_UID=geteuid()', str(source), '-o', str(probe)],
                            capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, 'Writer probe compilation failed: ' + result.stdout + result.stderr)
    probe_binding = validate_elf_binding(probe.read_bytes()); probe.chmod(0o755)
    reserved = prepare_output(output)
    command = (['sudo', '-n'] if os.geteuid() else []) + [
        'env', 'PATH=' + os.environ['PATH'], 'unshare', '--mount', '--fork', '--kill-child=KILL',
        '--propagation', 'private', sys.executable, str(Path(__file__).resolve()), '--worker',
        '--trunk', str(trunk), '--rootfs', str(rootfs), '--compiler', str(compiler),
        '--sysroot', str(sysroot), '--output', str(output)]
    subprocess.run(command, check=True, timeout=180)
    actual = output.lstat()
    require(stat.S_ISREG(actual.st_mode) and actual.st_nlink == 1 and actual.st_uid == reserved.st_uid and
            actual.st_dev == reserved.st_dev and actual.st_ino == reserved.st_ino,
            'Privileged worker replaced the controller-owned report inode')
    partial = json.loads(output.read_text()); validate_records(partial['checks'])
    report = {'schema_version': 2, 'status': 'PASS', 'profile': 'k2p-4.4', 'required_cases': list(CASE_NAMES),
              'checks': partial['checks'], 'source_sha256': {name: hashlib.sha256(text.encode()).hexdigest() for name, text in texts.items()},
              'shipped_writer_sha256': hashlib.sha256((rootfs / 'bin/mtd_write').read_bytes()).hexdigest(),
              'generated_source_sha256': hashlib.sha256(generated.encode()).hexdigest(),
              'mips_probe_sha256': hashlib.sha256(probe.read_bytes()).hexdigest(),
              'binding': {'shipped': partial['shipped_binding'], 'probe': probe_binding},
              'shipped_refusal_isolation': partial['shipped_refusal_isolation'],
              'filesystem_limits': {'tmp': 24 * 1024 * 1024},
              'limits': ['One actual shipped legacy mtd_write case refuses its removed protocol with21 and no status; no real MTD is opened.',
                         'The20 core protocol cases cross-compile the production header through an inert ABI shim, not the resident finalizer main; ordinary-file device, IOCTL, memory-lock and reboot effects are inert.',
                         'Neither this test nor checked mlockall proves every page is resident on Linux4.4; internal mlockall errors may be ignored by that kernel.',
                         'No hardware write, erase, memory locking, reboot, power-loss safety or router boot is established.']}
    output.write_text(json.dumps(report, indent=2) + '\n')
    print('Target firmware writer:21 exact cases PASS (one legacy refusal,20 inert core MIPS cases; resident finalizer requires its separate gate)')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'rootfs', 'compiler', 'sysroot', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    values = [getattr(args, name).resolve() for name in ('trunk', 'rootfs', 'compiler', 'sysroot', 'output')]
    if args.worker:
        worker(values[1], values[3], values[4].with_name('target-writer-probe'), values[4])
    else:
        check(*values)
