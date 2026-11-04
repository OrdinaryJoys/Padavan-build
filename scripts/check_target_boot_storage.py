#!/usr/bin/env python3
"""Final-only shipped BusyBox ash quota checks in private ordinary files.

The real boot scripts are byte-bound and statically checked, never executed.
Only a finite builtin-only quota script runs under qemu-mipsel. No router,
MTD, proc setting, service, custom hook, tar or compressor is executed here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import subprocess
import tempfile

import check_target_ntp as ntp
from check_target_storage import prepare_uid_runtime

SOURCE_PATHS = {
    'storage': 'user/scripts/mtd_storage.sh',
    'dev_init': 'user/scripts/dev_init.sh',
    'rc': 'user/rc/rc.c',
    'init': 'user/rc/init.c',
    'rc_header': 'user/rc/rc.h',
    'runner': 'user/rc/hook_runner.h',
    'shell_common': 'user/busybox/busybox-1.24.x/shell/shell_common.c',
    'busybox_template': 'configs/boards/busybox.config',
}
# Declared from the reviewed source before reading candidate artifact bytes.
EXPECTED_SOURCE_SHA256 = {
    'storage': '0c56bb501692a0c73d51266d2bd7037de4d1a63b8c546973eef353d1d1f4c1dd',
    'dev_init': 'cb2ff8015f4a649bd1e3978ca5b3185706503b9e36c39a6ff0e41efd4199cd2b',
    'rc': '261cb624ee1446dcb28436f2397696886ce51ff22b2797230a9901f0aeaed80e',
    'init': '1d01ebbbd9a130d5d5cda3ed7ac20befb8624abec556aff6fbe439f14eadae52',
    'rc_header': '04002579c5c64f235a2b43682e4bb64e267406af725f0006d96956bcd04f711a',
    'runner': 'c847b8939ceeaddade736e57b0f9dd032d501a4c19f0c1c53db2140c060c0020',
    'shell_common': '8f2f353859e3cee9c4b5aee07c855eb28e56e5c9f75a138eb7bec7fc9983f34f',
    'busybox_template': '49789620f949cd362a6cfee16e2025672a30d71b08b9ca615b1d87e6044a7e70',
}
ROOTFS_SCRIPTS = {'storage': 'sbin/mtd_storage.sh', 'dev_init': 'sbin/dev_init.sh'}
SHELL_FUNCTIONS = (
    'func_ready_parent', 'func_ready', 'func_ready_clear', 'func_ready_publish',
    'func_load', 'func_unpack', 'func_tarb', 'func_save', 'func_restore', 'func_reset',
)
C_FUNCTIONS = {'rc': ('run_startup_script',), 'init': ('init_main_loop',),
               'runner': ('shutdown_hook_run',)}
REQUIRED_CONFIG = (
    'CONFIG_ASH=y', 'CONFIG_ASH_BUILTIN_PRINTF=y', 'CONFIG_ASH_BUILTIN_TEST=y',
    'CONFIG_FEATURE_SH_IS_ASH=y', 'CONFIG_RMDIR=y', 'CONFIG_STAT=y',
)
CASES = (
    ('two-block-normal', 2, 1024, 0, 1024),
    ('two-block-overflow', 2, 1025, 73, 1024),
    ('storage-save-overflow', 1024, 524289, 73, 524288),
    ('tar-producer-overflow', 16384, 8388609, 73, 8388608),
)
CASE_NAMES = tuple(row[0] for row in CASES)
FIELDS = {'case', 'limit_blocks', 'requested_bytes', 'raw_exit',
          'actual_bytes', 'sha256', 'eof'}
MAX_FILE = 32 * 1024 * 1024
MAX_RUNTIME_FILES = 4096
MAX_RUNTIME_BYTES = 256 * 1024 * 1024
SCRIPT_FILE = 'target-boot-storage-quota.sh'
CONFIG_FILE = 'target-boot-storage-busybox.config'
ROLE = 'Actual shipped BusyBox ash builtins, explicit copied MIPS runtime, private ordinary quota files'
LIMITS = [
    'This executes neither dev_init.sh nor mtd_storage.sh, a custom startup hook, tar, bzip2, a service, MTD IO or a router boot.',
    'The quota cases measure actual ash ulimit units and bounded ordinary-file output; source byte/hash checks bind their intended production placement, not a full boot execution.',
    'It does not prove total system memory peaks, uninterruptible-IO termination, background-session cleanup, physical warm reset or old efd2 first-hop safety.',
]

# Ignore only SIGXFSZ so the real EFBIG write failure has a deterministic
# fixture exit73. The actual file limit remains active. Every command is an
# ash builtin; an empty PATH prevents an accidental native applet fallback.
QUOTA_SCRIPT = r'''set -e
ulimit -c 0
trap '' XFSZ
ulimit -f "$1"
printf 'ARMED\n'
{
 i=0
 while [ "$i" -lt "$2" ]; do
  printf '%01024d' 0 || exit 73
  i=$((i + 1))
 done
 if [ "$3" = 1 ]; then printf '0' || exit 73; fi
} > "$4"
printf 'COMPLETE\n'
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, maximum=MAX_FILE):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and
            0 <= metadata.st_size <= maximum, 'Unsafe ordinary input: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        now = os.fstat(fd)
        require((now.st_dev, now.st_ino, now.st_size) ==
                (metadata.st_dev, metadata.st_ino, metadata.st_size), 'Input changed while opening')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(maximum + 1)
        require(len(data) == metadata.st_size, 'Input changed while reading')
        return data
    finally:
        os.close(fd)


def c_function(text, name):
    matches = list(re.finditer(r'(?:static\s+)?(?:void|int)\s+\n?' + re.escape(name) +
                              r'\s*\([^;{}]*\)\s*\{', text))
    require(len(matches) == 1, 'Missing/ambiguous boot function: ' + name)
    found = matches[0]
    opening = text.index('{', found.start())
    depth = 0
    tokens = re.compile(r'"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|[{}]')
    for token in tokens.finditer(text, opening):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if depth == 0:
                return text[found.start():token.end()]
    raise ValueError('Unterminated boot function: ' + name)


def shell_function(text, name):
    found = re.findall(r'^' + re.escape(name) + r'\(\)\n\{\n.*?^\}', text, re.M | re.S)
    require(len(found) == 1, 'Missing/ambiguous Storage function: ' + name)
    return found[0]


def config_contract(raw):
    text = raw.decode('ascii')
    for line in REQUIRED_CONFIG:
        require(len(re.findall('^' + re.escape(line) + '$', text, re.M)) == 1,
                'BusyBox required compiled/template option missing: ' + line)


def source_contract(inputs):
    require(set(inputs) == set(SOURCE_PATHS), 'Boot Storage source set differs')
    require({key: sha(value) for key, value in inputs.items()} == EXPECTED_SOURCE_SHA256,
            'Boot Storage reviewed source bytes differ')
    texts = {key: value.decode() for key, value in inputs.items()}
    config_contract(inputs['busybox_template'])
    require(re.search(r'\{ RLIMIT_FSIZE,\s+9,\s+\'f\'', texts['shell_common']),
            'BusyBox file quota unit is not 512 bytes')
    storage = texts['storage']
    shell = {name: shell_function(storage, name) for name in SHELL_FUNCTIONS}
    bodies = {name: c_function(texts[key], name) for key, names in C_FUNCTIONS.items() for name in names}
    revoke = 'case "$1" in load|erase|reset) func_ready_clear || exit 1;; esac'
    require(revoke in storage and storage.index(revoke) < storage.index('func_begin || exit 1'),
            'Coldboot revoke no longer precedes early failure paths')
    require('save)\n\tfunc_ready || exit 1\n\tif [ -e "$slk" ] || [ -L "$slk" ]; then exit 1; fi' in storage,
            'Storage save authorization or unsafe lock rejection missing')
    require('func_record_hash &&\n\t   rm -f "$slk" && func_ready_publish' in shell['func_load'],
            'Load authorizes before complete publication/hash')
    require(shell['func_restore'].index('func_ready_clear || return 1') <
            shell['func_restore'].index('func_stop_apps'), 'Restore changes RAM before revoke')
    require(shell['func_reset'] == 'func_reset()\n{\n\trm -f "$slk" &&\n\t\trm -rf "$dir_storage" &&\n\t\tmkdir -p -m 755 "$dir_storage"\n}',
            'Explicit reset must check lock removal, old-tree removal and new-directory creation')
    require('if func_reset && func_fill && func_tarb && func_ready_publish; then' in storage and
            'fill)\n\tfunc_mdir || exit 1\n\tfunc_fill\n\t;;' in storage,
            'Fill implicitly authorizes defaults or explicit reset gate missing')
    require('(ulimit -f 16384 && cd "$dir_storage" &&' in shell['func_tarb'] and
            'blocks=$((mtd_part_size / 512))' in shell['func_save'] and
            '(ulimit -f "$blocks" && bzip2 -c -9 "$tmp" > "$archive")' in shell['func_save'] and
            '"$fsz" -gt "$mtd_part_size"' in shell['func_save'], 'Production output quota placement changed')
    require('storage_load_status=0\nmtd_storage.sh load || storage_load_status=$?' in texts['dev_init'] and
            'exit "$storage_load_status"' in texts['dev_init'] and
            '\n\t/etc/storage/start_script.sh' not in texts['dev_init'], 'Boot load result/direct startup bypass changed')
    init = bodies['init_main_loop']
    require(init.count('run_startup_script();') == 1 and
            init.index('system("dev_init.sh -l")') < init.index('run_startup_script();') < init.index('init_nodes();') and
            'if (early_status != 0)' in init, 'Actual bounded startup integration missing')
    startup = bodies['run_startup_script']
    require('access(SCRIPT_STARTUP, X_OK)' in startup and
            'shutdown_hook_run(SCRIPT_STARTUP, HOOK_RUNNER_NO_ARGUMENT,' in startup and
            '#define SCRIPT_STARTUP\t\t\t"/etc/storage/start_script.sh"' in texts['rc_header'],
            'Original executable startup path/argument contract changed')
    require('#define HOOK_RUNNER_NO_ARGUMENT (-1)' in texts['runner'] and
            'level < HOOK_RUNNER_NO_ARGUMENT || level > 2' in bodies['shutdown_hook_run'] and
            r'"exec \"$0\"" : "exec \"$0\" \"$1\""' in bodies['shutdown_hook_run'],
            'Bounded runner no-argument/shutdown boundary changed')
    return {'source_sha256': {key: sha(value) for key, value in inputs.items()},
            'actual_functions_sha256': {name: sha(body.encode()) for name, body in {**shell, **bodies}.items()},
            'semantics': {'coldboot_default_deny': True, 'early_revoke': True,
                          'validated_load_restore_or_explicit_reset_only': True,
                          'reset_requires_checked_recreate': True,
                          'tar_bytes': 8388608, 'storage_bytes': 524288,
                          'startup_zero_arguments_at_original_boundary': True,
                          'whole_boot_executed': False, 'custom_script_executed': False}}


def expected_rows():
    return [{'case': name, 'limit_blocks': blocks, 'requested_bytes': requested,
             'raw_exit': status, 'actual_bytes': size, 'sha256': sha(b'0' * size), 'eof': True}
            for name, blocks, requested, status, size in CASES]


def validate_records(rows):
    require(type(rows) is list and len(rows) == len(CASES), 'Quota case count differs')
    for row, expected in zip(rows, expected_rows()):
        require(type(row) is dict and set(row) == FIELDS, 'Quota row schema differs')
        require(type(row['case']) is str and type(row['sha256']) is str and
                type(row['eof']) is bool and
                all(type(row[key]) is int for key in
                    ('limit_blocks', 'requested_bytes', 'raw_exit', 'actual_bytes')), 'Quota row types differ')
        require(row == expected, 'Quota fixed case observation differs: ' + expected['case'])


def inventory_runtime(sysroot):
    count = total = 0
    for name in ('lib', 'usr/lib'):
        parent = sysroot / name
        require(parent.is_dir() and not parent.is_symlink(), 'Unsafe runtime library directory')
        for directory, folders, files in os.walk(parent, followlinks=False):
            for leaf in folders + files:
                path = Path(directory) / leaf
                item = path.lstat()
                count += 1
                require(count <= MAX_RUNTIME_FILES, 'Runtime entry budget exceeded')
                if stat.S_ISREG(item.st_mode):
                    require(item.st_mode & 0o004 and item.st_size <= MAX_FILE,
                            'Runtime ordinary file is not public or exceeds budget')
                    total += item.st_size
                    require(total <= MAX_RUNTIME_BYTES, 'Runtime byte budget exceeded')
                else:
                    require(stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode), 'Special runtime entry forbidden')
    return {'entries': count, 'regular_bytes': total}


def runtime_library(root, name):
    """Rebase image-internal leaf links; never follow a directory alias."""
    current = name
    for _ in range(16):
        require(not current.startswith('/') and current not in ('', '..') and
                not current.startswith('../'), 'Runtime dependency leaves isolated image')
        parts = current.split('/')
        require(all(part not in ('', '.', '..') for part in parts), 'Unsafe runtime dependency path')
        for index in range(1, len(parts)):
            parent = root.joinpath(*parts[:index])
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and not parent.is_symlink(), 'Runtime directory alias forbidden')
        path = root / current
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            current = posixpath.normpath(target.lstrip('/') if target.startswith('/') else
                                        posixpath.join(posixpath.dirname(current), target))
            continue
        return ntp._runtime_library(root, current)
    raise ValueError('Runtime dependency link budget exceeded')


def runtime_closure(rootfs, sysroot, runtime, busybox):
    dynamic = ntp.elf_dynamic(busybox)
    require(dynamic['interpreter'] == '/lib/ld-uClibc.so.0', 'Unexpected shipped BusyBox interpreter')
    libraries = {}
    pending = [dynamic['interpreter'].lstrip('/')]

    def add_needed(dependencies):
        for dependency in dependencies:
            chosen = None
            for prefix in ('lib/', 'usr/lib/'):
                name = prefix + dependency
                try:
                    (rootfs / name).lstat()
                except FileNotFoundError:
                    continue
                chosen = name
                break
            require(chosen is not None, 'Shipped BusyBox dependency missing: ' + dependency)
            pending.append(chosen)

    add_needed(dynamic['needed'])
    while pending:
        name = pending.pop(0)
        if name in libraries:
            continue
        require(len(libraries) < 32, 'BusyBox dependency closure exceeds budget')
        records = []
        data = None
        for base in (rootfs, sysroot, runtime):
            identity, content = runtime_library(base, name)
            metadata = ntp.elf_dynamic(content)
            if data is None:
                data = content
            require(content == data, 'Shipped/sysroot/copied BusyBox library bytes differ: ' + name)
            records.append({'identity': identity, 'dynamic': metadata})
        require(all(record['dynamic'] == records[0]['dynamic'] for record in records),
                'BusyBox runtime dynamic closure differs')
        metadata = records[0]['dynamic']
        libraries[name] = {'rootfs': records[0], 'sysroot': records[1], 'copied': records[2]}
        if metadata['interpreter']:
            require(metadata['interpreter'] in ('/lib/ld-uClibc.so.0', '/lib/ld-uClibc.so.1'),
                    'Unexpected runtime-library interpreter')
            pending.append(metadata['interpreter'].lstrip('/'))
        add_needed(metadata['needed'])
    return {'busybox_dynamic': dynamic, 'libraries': libraries}


def verify_runtime_copy(runtime, rootfs, sysroot, hashes):
    for name, record in hashes.items():
        copied = runtime / name
        source = rootfs / name if name == 'bin/busybox' else sysroot / name
        require(not copied.is_symlink() and not source.is_symlink(), 'Runtime regular entry became an alias')
        require(sha(read_regular(copied)) == record['sha256'] == sha(read_regular(source)),
                'Original/copied runtime bytes changed: ' + name)
        require(oct(copied.stat().st_mode & 0o7777) == record['mode'] ==
                oct(source.stat().st_mode & 0o7777), 'Original/copied runtime mode changed')


def observe_case(qemu, runtime, directory, rule):
    name, blocks, requested, status, expected_size = rule
    case = directory / name
    case.mkdir(mode=0o700)
    output = case / 'ordinary-output'
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    before = os.fstat(fd)
    os.close(fd)
    chunks, tail = divmod(requested, 1024)
    require(tail in (0, 1), 'Fixed quota fixture tail changed')
    command = [str(qemu), '-L', str(runtime), str(runtime / 'bin/busybox'),
               'sh', '-c', QUOTA_SCRIPT, 'quota-fixture', str(blocks), str(chunks), str(tail), str(output)]
    result = subprocess.run(command, cwd=case, stdin=subprocess.DEVNULL, capture_output=True,
                            env={'PATH': '', 'HOME': str(case), 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}, timeout=30)
    require(result.returncode == status, 'Actual BusyBox quota exit differs: ' + name)
    expected_stdout = b'ARMED\nCOMPLETE\n' if status == 0 else b'ARMED\n'
    require(result.stdout == expected_stdout and len(result.stderr) <= 4096,
            'Actual BusyBox quota stage/diagnostic bound differs: ' + name)
    after = output.lstat()
    require(stat.S_ISREG(after.st_mode) and after.st_nlink == 1 and after.st_uid == os.geteuid() and
            after.st_mode & 0o7777 == 0o600 and
            (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino), 'Quota output is not the original private file')
    fd = os.open(output, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(os.fstat(fd).st_size == expected_size, 'Quota output size differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(expected_size)
            eof = stream.read(1) == b''
        require(len(data) == expected_size and eof, 'Quota bounded read/EOF differs')
    finally:
        os.close(fd)
    row = {'case': name, 'limit_blocks': blocks, 'requested_bytes': requested,
           'raw_exit': result.returncode, 'actual_bytes': after.st_size,
           'sha256': sha(data), 'eof': eof}
    diagnostic = {'case': name, 'stdout_sha256': sha(result.stdout),
                  'stderr_bytes': len(result.stderr), 'stderr_sha256': sha(result.stderr)}
    return row, diagnostic


def write_export(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and
                metadata.st_uid == os.geteuid(), 'Unsafe quota export path')
        os.fchmod(fd, 0o600)
        os.ftruncate(fd, 0)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            require(stream.write(data) == len(data), 'Incomplete quota export write')
    finally:
        os.close(fd)


def check(trunk, rootfs, sysroot, output):
    trunk, rootfs, sysroot = (Path(path).resolve(strict=True) for path in (trunk, rootfs, sysroot))
    for name in ('bin', 'sbin', 'usr', 'lib', 'usr/lib'):
        info = (rootfs / name).lstat()
        require(stat.S_ISDIR(info.st_mode) and not (rootfs / name).is_symlink(), 'Shipped image directory alias forbidden')
    config = read_regular(trunk / '.config', 1024 * 1024).decode()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M), 'Boot Storage proof requires configured K2P4.4')
    inputs = {key: read_regular(trunk / path) for key, path in SOURCE_PATHS.items()}
    source = source_contract(inputs)
    bindings = {}
    for key, relative in ROOTFS_SCRIPTS.items():
        content = read_regular(rootfs / relative)
        require(content == inputs[key], 'Shipped boot/Storage script differs from reviewed source: ' + key)
        mode = (rootfs / relative).stat().st_mode & 0o7777
        require(mode == 0o755, 'Shipped boot/Storage script executable mode differs: ' + key)
        bindings[key] = {'rootfs_path': relative, 'bytes': len(content), 'sha256': sha(content), 'mode': oct(mode)}
    actual_config = read_regular(trunk / 'user/busybox/busybox-1.24.x/.config', 1024 * 1024)
    config_contract(actual_config)
    qemu = shutil.which('qemu-mipsel')
    require(qemu is not None, 'Actual BusyBox quota proof requires qemu-mipsel')
    qemu = Path(qemu).resolve(strict=True)
    original_busybox = read_regular(rootfs / 'bin/busybox')
    require((rootfs / 'bin/busybox').stat().st_mode & 0o7022 == 0,
            'Shipped BusyBox has unsafe write or special mode bits')
    busybox_elf = ntp.elf(original_busybox)
    budget = inventory_runtime(sysroot)
    rows, diagnostics = [], []
    with tempfile.TemporaryDirectory(prefix='k2p-shipped-ash-quota-') as temporary:
        directory = Path(temporary).resolve()
        runtime, hashes = prepare_uid_runtime(rootfs, sysroot, directory)
        require(read_regular(runtime / 'bin/busybox') == original_busybox, 'Copied BusyBox bytes differ')
        closure = runtime_closure(rootfs, sysroot, runtime, original_busybox)
        verify_runtime_copy(runtime, rootfs, sysroot, hashes)
        for rule in CASES:
            row, diagnostic = observe_case(qemu, runtime, directory, rule)
            rows.append(row)
            diagnostics.append(diagnostic)
        validate_records(rows)
        verify_runtime_copy(runtime, rootfs, sysroot, hashes)
        require(runtime_closure(rootfs, sysroot, runtime, original_busybox) == closure,
                'BusyBox dependency closure changed during quota proof')
    require(read_regular(rootfs / 'bin/busybox') == original_busybox, 'Shipped BusyBox changed')
    require(source_contract({key: read_regular(trunk / path) for key, path in SOURCE_PATHS.items()}) == source and
            read_regular(trunk / 'user/busybox/busybox-1.24.x/.config', 1024 * 1024) == actual_config,
            'Reviewed source or compiled BusyBox config changed during proof')
    require(all(read_regular(rootfs / path) == inputs[key] and
                oct((rootfs / path).stat().st_mode & 0o7777) == bindings[key]['mode']
                for key, path in ROOTFS_SCRIPTS.items()),
            'Shipped boot scripts changed during proof')
    output.parent.mkdir(parents=True, exist_ok=True)
    write_export(output.parent / SCRIPT_FILE, QUOTA_SCRIPT.encode())
    write_export(output.parent / CONFIG_FILE, actual_config)
    report = {'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4',
              'phase': 'final-shipped-busybox-private-quota', 'execution_role': ROLE,
              'required_cases': list(CASE_NAMES), 'checks': rows, 'diagnostics': diagnostics,
              'source_files': SOURCE_PATHS, **source, 'rootfs_scripts': bindings,
              'quota_script': {'file': SCRIPT_FILE, 'sha256': sha(QUOTA_SCRIPT.encode())},
              'compiled_busybox_config': {'file': CONFIG_FILE, 'sha256': sha(actual_config)},
              'runtime': {'busybox': {'rootfs_path': 'bin/busybox', 'ELF': busybox_elf},
                          **closure, 'copy_budget': budget, 'all_copied_regular_files_unchanged': True},
              'qemu': {'path': str(qemu), 'sha256': sha(read_regular(qemu, 64 * 1024 * 1024))},
              'limits': list(LIMITS)}
    ntp.write_report(output, report)
    print('Shipped BusyBox ash quotas: 4 finite private-file cases PASS')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'rootfs', 'sysroot', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        check(args.trunk, args.rootfs, args.sysroot, args.output)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        ntp.write_report(args.output, {'schema_version': 1, 'status': 'FAIL', 'error': str(error), 'execution_role': ROLE})
        parser.exit(1, 'Target boot Storage proof failed: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
