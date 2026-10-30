#!/usr/bin/env python3
"""Actual shipped DNS snapshot and listener proof in private Linux namespaces.

The worker is PID 1 in a fresh PID/mount/network namespace. Namespace anchors
are real inherited descriptors, not caller-supplied inode numbers. No router,
MTD, host-network listener or original configuration is used.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import socket
import stat
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
    'conf_snapshot.c': 'user/dnsmasq/dnsmasq-2.93/src/conf_snapshot.c',
    'conf_snapshot.h': 'user/dnsmasq/dnsmasq-2.93/src/conf_snapshot.h',
    'snapshot_sha256.h': 'user/dnsmasq/dnsmasq-2.93/src/snapshot_sha256.h',
    'dnsmasq.sh': 'user/dnsmasq/dnsmasq.sh',
    'services_ex.c': 'user/rc/services_ex.c',
}
CASE_NAMES = ('busybox-exec-adapter-preflight', 'capture-seal-replay-once',
              'changed-input-before-seal', 'changed-input-after-seal',
              'changed-directory-after-seal', 'tampered-flat', 'cache-alias',
              'ticket-mismatch', 'oversized-input', 'managed-foreground',
              'changed-deduplicated-file-alias', 'changed-deduplicated-directory-alias',
              'wrapper-migration-daemon-loopback', 'wrapper-graph-race')
REJECT_CASES = set(CASE_NAMES[2:12]) | {'wrapper-graph-race'}
FILESYSTEM_LIMITS = {'etc': 6 * 1024 * 1024, 'tmp': 24 * 1024 * 1024,
                     'var': 4 * 1024 * 1024, 'run': 1024 * 1024}
LIMITS = {'command_seconds': 45, 'worker_seconds': 180, 'output_bytes': 131072,
          'query_seconds': 4, 'report_bytes': 1048576,
          'wrapper_config_bytes': 1792 * 1024, 'occupied_tmp_bytes': 10 * 1024 * 1024}
ROLES = {'dns': 'Actual shipped MIPS dnsmasq under qemu-mipsel',
         'wrapper': 'Unmodified shipped wrapper executed by actual shipped MIPS BusyBox ash under QEMU',
         'tools': 'Fixed private native QEMU exec adapters and harmless native shell/coreutils/nvram fixtures',
         'network': 'Only loopback UDP DNS in a fresh private Linux network namespace',
         'cleanup': 'Explicit checked daemon termination plus kernel teardown of private PID namespace'}
SHA = re.compile(r'[0-9a-f]{64}\Z')
NATIVE_TOOLS = ('awk', 'cat', 'df', 'head', 'md5sum', 'mkdir', 'rm', 'sed', 'stat')
CHECK_KEYS = {'case', 'exit_code', 'outcome', 'generator_executions', 'flat_sha256',
              'flat_bytes', 'first_answer', 'after_cleanup_answer', 'workspaces_remaining',
              'daemon_stopped'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def function(text, name):
    matches = list(re.finditer(r'(?:static\s+)?(?:void|int)\s*\n?\b' + re.escape(name) + r'\s*\(', text))
    require(len(matches) == 1, 'Missing or ambiguous source function: ' + name)
    match = matches[0]
    opening, depth = text.index('{', match.end()), 0
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|[{}]')
    for token in tokens.finditer(text, opening):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth:
                return text[match.start():token.end()]
    raise RuntimeError('Unclosed source function: ' + name)


def source_proof(trunk):
    require('CONFIG_LINUXDIR=linux-4.4.x' in (trunk / '.config').read_text(),
            'Snapshot proof requires the 4.4 profile')
    result = {key: sha((trunk / path).read_bytes()) for key, path in SOURCE_PATHS.items()}
    result['start_dns_dhcpd'] = sha(function((trunk / SOURCE_PATHS['services_ex.c']).read_text(),
                                                  'start_dns_dhcpd').encode())
    return result


def production_objects(makefile):
    matches = re.findall(r'^objs\s*=\s*((?:[^\n]*\\\n)*[^\n]*)', makefile, re.M)
    require(len(matches) == 1, 'Missing/ambiguous DNS production object list')
    names = matches[0].replace('\\\n', ' ').split()
    require(names and len(names) <= 128 and len(names) == len(set(names)) and
            all(re.fullmatch(r'[a-z][a-z0-9_-]*\.o', name) for name in names),
            'Unsafe or duplicated production object list')
    require({'dnsmasq.o', 'option.o', 'dynamic_conf.o', 'conf_snapshot.o'} <= set(names),
            'Snapshot sources absent from production link')
    return [name[:-2] + '.c' for name in names]


def production_copts(config):
    values = {}
    for line in config.splitlines():
        if re.match(r'^CONFIG_\w+=', line):
            key, value = line.split('=', 1)
            require(key not in values, 'Duplicate firmware configuration assignment')
            values[key] = value
    require(values.get('CONFIG_LINUXDIR') == 'linux-4.4.x', 'Static DNS preflight requires4.4 config')
    result = ['-DHAVE_BROKEN_RTC', '-DNO_INOTIFY', '-DNO_AUTH', '-DNO_LOOP']
    if values.get('CONFIG_FIRMWARE_ENABLE_IPV6') != 'y':
        result.append('-DNO_IPV6')
    if values.get('CONFIG_FIRMWARE_ENABLE_USB') != 'y':
        result.append('-DNO_TFTP')
    if values.get('CONFIG_FIRMWARE_INCLUDE_IPSET') != 'y':
        result.append('-DNO_IPSET')
    return result


def preflight(args):
    require(sys.platform.startswith('linux') and args.compiler is not None,
            'Static DNS preflight requires Linux and the target compiler')
    qemu = shutil.which('qemu-mipsel')
    require(qemu is not None, 'qemu-mipsel required for parser-only preflight')
    source = args.trunk / 'user/dnsmasq/dnsmasq-2.93'
    objects = production_objects((source / 'Makefile').read_text())
    copts = production_copts((args.trunk / '.config').read_text())
    output_identity_before = prepare_output(args.output)
    binary = args.output.with_name(args.output.stem + '-dnsmasq')
    compile_log = args.output.with_name(args.output.stem + '-compile.txt')
    require(not binary.exists() and not binary.is_symlink() and
            not compile_log.exists() and not compile_log.is_symlink(), 'Preflight export already exists')
    report = {'schema_version': 1, 'status': 'FAIL', 'profile': 'k2p-4.4',
              'role': 'Static full production DNS source and target-libc parser-only preflight; not the shipped binary or a daemon startup proof',
              'source_sha256': source_proof(args.trunk), 'copts': copts,
              'strict_new_modules': ['dynamic_conf.c', 'conf_snapshot.c'],
              'upstream_flags': ['-std=gnu99', '-Os', '-Wall', '-Wextra'],
              'objects': [], 'checks': [], 'binary_sha256': None, 'failure': None}
    log = bytearray()
    try:
        with tempfile.TemporaryDirectory(prefix='dns-snapshot-preflight-', dir=args.output.parent) as temporary:
            work = Path(temporary)
            object_paths = []
            for name in objects:
                path = source / 'src' / name
                require(path.is_file() and not path.is_symlink(), 'Invalid production source: ' + name)
                obj = work / (name[:-2] + '.o')
                strict = name in report['strict_new_modules']
                command = [str(args.compiler), '-std=gnu99', '-Os', '-Wall', '-Wextra',
                           *(['-Werror'] if strict else []), *copts, '-DVERSION="2.93"',
                           '-c', str(path), '-o', str(obj)]
                rc, out, err = run_bounded(command)
                log.extend(('\n=== ' + name + (' strict-Werror' if strict else ' production-warning-policy') + ' ===\n').encode())
                log.extend(out + err)
                require(len(log) <= 1048576, 'Compiler diagnostics exceed1MiB budget')
                report['objects'].append({'name': name, 'source_sha256': sha(path.read_bytes()),
                                          'strict_werror': strict, 'exit_code': rc,
                                          'diagnostic_bytes': len(out) + len(err)})
                require(rc == 0, 'Static DNS compile failed: ' + name + ': ' + err.decode(errors='replace')[:2048])
                object_paths.append(obj)
            rc, out, err = run_bounded([str(args.compiler), '-static', '-Wl,-z,now',
                                       *map(str, object_paths), '-o', str(binary), '-lrt'])
            log.extend(b'\n=== static link ===\n' + out + err)
            require(rc == 0, 'Static DNS link failed: ' + err.decode(errors='replace')[:2048])
            payload = binary.read_bytes()
            elf(payload)
            binary.chmod(0o755)
            report['binary_sha256'] = sha(payload)
            fixture_root = work / 'fixture'
            fixture_root.mkdir(mode=0o700)
            custom, candidate, main = (fixture_root / name for name in ('custom', 'candidate', 'main'))
            counter, generator, cache = (fixture_root / name for name in ('counter', 'generator.sh', 'cache'))
            shared, alias = fixture_root / 'shared.conf', fixture_root / 'duplicate-alias'
            regular(shared, b'cache-size=123\n')
            alias.symlink_to(shared)
            script = '#!/bin/sh\nn=0\n[ ! -f ' + str(counter) + ' ] || n=$(cat ' + str(counter) + ')\n'
            script += 'n=$((n+1))\nprintf "%s\\n" "$n" > ' + str(counter) + '\nprintf "address=/snapshot.fixture/192.0.2.51\\n"\n'
            regular(generator, script.encode(), 0o700)
            regular(custom, ('conf-script=' + str(generator) + '\n').encode())
            regular(candidate, custom.read_bytes() + b'# candidate\n')
            regular(main, ('no-resolv\nno-hosts\nconf-file=' + str(shared) + '\nconf-file=' + str(alias) +
                           '\nconf-file=' + str(custom) + '\n').encode())
            dns = [qemu, str(binary)]
            rc, _, err = run_bounded(dns + ['--test', '-C', str(main), '--snapshot-capture', str(cache),
                                           '--snapshot-overlay', str(custom), '--snapshot-candidate', str(candidate),
                                           '--snapshot-managed'])
            require(rc == 0 and b'syntax check OK' in err, 'Static capture parser control failed: ' + err.decode(errors='replace')[:1024])
            ticket_data = (cache / 'ticket').read_bytes()
            require(re.fullmatch(b'[0-9a-f]{32}\n', ticket_data) is not None, 'Invalid static preflight ticket')
            ticket = ticket_data.decode().strip()
            regular(work / 'install', candidate.read_bytes())
            os.replace(work / 'install', custom)
            rc, _, err = run_bounded(dns + ['--snapshot-seal', str(cache), '--snapshot-ticket', ticket, '--snapshot-managed'])
            require(rc == 0, 'Static snapshot seal failed: ' + err.decode(errors='replace')[:1024])
            replay = dns + ['--test', '--snapshot-use', str(cache), '--snapshot-ticket', ticket, '--snapshot-managed']
            rc, _, err = run_bounded(replay)
            require(rc == 0 and b'syntax check OK' in err and counter.read_text().strip() == '1',
                    'Static replay repeated generator or failed syntax')
            report['checks'].append({'case': 'static-capture-seal-replay-once', 'exit_code': 0, 'generator_executions': 1})
            # The real target parser must have recorded the skipped alias,
            # which crosses the fixed-width device/inode module interface.
            manifest = (cache / 'manifest').read_bytes()
            require(len(manifest) > 48 and struct.unpack_from('>Q', manifest, 40)[0] == 5,
                    'Static parser omitted its deduplicated source reference')
            report['checks'].append({'case': 'static-deduplicated-alias-interface', 'exit_code': 0,
                                     'generator_executions': 1, 'source_records': 5})
            tamper_flat(cache / 'flat.conf')
            rc, _, err = run_bounded(replay)
            require(rc == 1 and b'snapshot' in err.lower() and counter.read_text().strip() == '1',
                    'Static tampered snapshot did not fail as audited')
            report['checks'].append({'case': 'static-tampered-flat-rejected', 'exit_code': 1, 'generator_executions': 1})
            report['status'] = 'PASS'
    except Exception as error:
        report['failure'] = str(error)[:4096]
        raise
    finally:
        regular(compile_log, bytes(log), 0o600)
        write_output(args.output, output_identity_before, report)
    print('Target DNS snapshot preflight: full static compile and3 parser-only controls PASS')


def elf(data):
    require(len(data) >= 52 and data[:7] == b'\x7fELF\x01\x01\x01', 'ELF32LE required')
    result = {'elf_class': 32, 'byte_order': 'little',
              'e_machine': struct.unpack_from('<H', data, 18)[0],
              'e_type': struct.unpack_from('<H', data, 16)[0]}
    require(result['e_machine'] == 8 and result['e_type'] in (2, 3), 'MIPS executable required')
    return result


def shipped_proof(rootfs):
    result = {}
    for key, name in (('dnsmasq', 'usr/sbin/dnsmasq'), ('busybox', 'bin/busybox'),
                      ('publisher', 'sbin/storage_validate'), ('wrapper', 'usr/bin/dnsmasq.sh')):
        path = rootfs / name
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= 8 * 1024 * 1024,
                'Invalid shipped input: ' + name)
        data = path.read_bytes()
        result[key] = {'path': name, 'bytes': len(data), 'sha256': sha(data)}
        if key != 'wrapper':
            result[key]['elf'] = elf(data)
    return result


def output_identity(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
            stat.S_IMODE(st.st_mode) == 0o600, 'Unsafe report output inode')
    return {'device': st.st_dev, 'inode': st.st_ino, 'owner': st.st_uid,
            'group': st.st_gid, 'mode': stat.S_IMODE(st.st_mode), 'links': st.st_nlink}


def prepare_output(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    identity = output_identity(path)
    require(identity['owner'] == os.geteuid(), 'Report output owner differs from parent')
    return identity


def write_output(path, expected, value):
    require(output_identity(path) == expected, 'Report inode changed before worker write')
    data = (json.dumps(value, indent=2) + '\n').encode()
    require(len(data) <= LIMITS['report_bytes'], 'Snapshot report too large')
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        require(st.st_dev == expected['device'] and st.st_ino == expected['inode'] and
                st.st_uid == expected['owner'] and st.st_nlink == 1 and
                stat.S_IMODE(st.st_mode) == 0o600, 'Unsafe opened report inode')
        os.ftruncate(fd, 0)
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            require(count > 0, 'Report write failed')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    require(output_identity(path) == expected, 'Worker changed parent report ownership')


def namespace_guard(anchors):
    require(sys.platform.startswith('linux') and os.geteuid() == 0 and os.getpid() == 1,
            'Private Linux root PID1 worker required before any mount')
    require(set(anchors) == {'mnt', 'net', 'pid'}, 'Three anchored namespace FDs required')
    observed = {}
    for name, fd in anchors.items():
        require(type(fd) is int and fd >= 3, 'Invalid namespace descriptor')
        link = os.readlink('/proc/self/fd/' + str(fd))
        require(re.fullmatch(re.escape(name) + r':\[[0-9]+\]', link) is not None,
                'Anchor descriptor is not the expected namespace type')
        anchor = os.fstat(fd)
        current = os.stat('/proc/self/ns/' + name)
        require((anchor.st_dev, anchor.st_ino) != (current.st_dev, current.st_ino),
                'Refusing initial/parent ' + name + ' namespace')
        fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.fcntl(fd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
        observed[name] = {'parent_inode': anchor.st_ino, 'worker_inode': current.st_ino}
    roots = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
             if line.split()[4] == '/']
    require(len(roots) == 1 and not any(x.startswith(('shared:', 'master:'))
            for x in roots[0][6:roots[0].index('-')]), 'Private root mount propagation required')
    require({name for _, name in socket.if_nameindex()} == {'lo'},
            'Private network must contain only loopback before setup')
    return observed


def run_bounded(command, env=None):
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, start_new_session=True)
    output = [bytearray(), bytearray()]
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + LIMITS['command_seconds']
    for index, stream in enumerate((process.stdout, process.stderr)):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, index)
    try:
        while selector.get_map():
            require(time.monotonic() < deadline, 'Snapshot command timed out')
            for key, _ in selector.select(0.05):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    output[key.data].extend(chunk)
                    require(sum(map(len, output)) <= LIMITS['output_bytes'],
                            'Snapshot command output cap exceeded')
        status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return status, bytes(output[0]), bytes(output[1])
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            stream.close()
        if process.poll() is None:
            process.kill()  # Only this unreaped child; worker exit kills its whole private PID tree.
            process.wait(timeout=2)


def regular(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def resolve_native_tools(names=NATIVE_TOOLS):
    result = {}
    for name in names:
        found = shutil.which(name)
        require(found is not None, 'Required native fixture tool missing: ' + name)
        actual = Path(found).resolve(strict=True)
        require(actual.is_file() and os.access(actual, os.X_OK), 'Invalid native fixture executable: ' + name)
        result[name] = actual
    return result


def install_native_tools(directory, bindings):
    for name, executable in bindings.items():
        regular(directory / name, ('#!/bin/sh\nexec ' + shlex.quote(str(executable)) + ' "$@"\n').encode(), 0o700)


def tamper_flat(path):
    data = path.read_bytes()
    # The early preflight is unprivileged; make only its private owned fixture
    # writable before truncation, then restore0400 for the corruption check.
    path.chmod(0o600)
    regular(path, data + b'# deliberate fixture corruption\n', 0o400)


def read_ticket(cache):
    data = (cache / 'ticket').read_bytes()
    require(re.fullmatch(b'[0-9a-f]{32}\n', data) is not None, 'Malformed snapshot ticket')
    for name in ('flat.conf', 'manifest', 'ticket'):
        st = (cache / name).lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                stat.S_IMODE(st.st_mode) == 0o400, 'Unsafe sealed snapshot leaf')
    require(stat.S_IMODE(cache.lstat().st_mode) == 0o700, 'Unsafe snapshot container')
    return data.decode().strip()


def skip_name(data, offset):
    for _ in range(128):
        require(offset < len(data), 'Truncated DNS name')
        count = data[offset]
        offset += 1
        if count == 0:
            return offset
        if count & 0xc0 == 0xc0:
            require(offset < len(data), 'Truncated DNS compression pointer')
            return offset + 1
        require(count <= 63 and offset + count <= len(data), 'Invalid DNS label')
        offset += count
    raise RuntimeError('Unbounded DNS name')


def parse_answer(data, query_id):
    require(12 <= len(data) <= 4096, 'Invalid DNS response size')
    ident, flags, questions, answers, _, _ = struct.unpack_from('!6H', data)
    require(ident == query_id and flags & 0x8000 and flags & 15 == 0 and
            questions == 1 and 1 <= answers <= 16, 'Unexpected DNS response header')
    offset = skip_name(data, 12) + 4
    addresses = []
    for _ in range(answers):
        offset = skip_name(data, offset)
        require(offset + 10 <= len(data), 'Truncated DNS answer')
        kind, klass, _, length = struct.unpack_from('!HHIH', data, offset)
        offset += 10
        require(offset + length <= len(data), 'Truncated DNS answer payload')
        if kind == 1 and klass == 1 and length == 4:
            addresses.append(socket.inet_ntoa(data[offset:offset + 4]))
        offset += length
    require(addresses == ['192.0.2.51'], 'Snapshot DNS answer differs from first generator policy')
    return addresses[0]


def query_dns():
    query_id = 0x4b32
    query = struct.pack('!6H', query_id, 0x100, 1, 0, 0, 0) + b'\x08snapshot\x07fixture\0\0\x01\0\x01'
    deadline, last = time.monotonic() + LIMITS['query_seconds'], None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.25)
        while time.monotonic() < deadline:
            try:
                sock.sendto(query, ('127.0.0.1', 10530))
                data, peer = sock.recvfrom(4097)
                require(peer == ('127.0.0.1', 10530), 'Non-fixture DNS peer')
                return parse_answer(data, query_id)
            except (socket.timeout, ConnectionRefusedError) as exc:
                last = exc
    raise RuntimeError('Private DNS listener did not answer: ' + str(last))


def stop_daemon(rootfs):
    path = Path('/var/run/snapshot-daemon.pid')
    data = path.read_text()
    require(re.fullmatch(r'[0-9]+\n', data) is not None, 'Malformed fixture daemon PID')
    pid = int(data)
    require(pid > 1 and str(rootfs / 'usr/sbin/dnsmasq').encode() in
            Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0'),
            'Refusing to signal a process without fixture binary identity')
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                return True
        except ChildProcessError:
            if not Path('/proc', str(pid)).exists():
                return True
        time.sleep(0.02)
    raise RuntimeError('Fixture daemon did not terminate; PID namespace will be destroyed')


def fixture(case):
    root = Path('/tmp/snapshot-fixture')
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(mode=0o700)
    Path('/tmp/linux.trx').unlink(missing_ok=True)
    Path('/etc/storage/other-large-config').unlink(missing_ok=True)
    parent = Path('/etc/storage/dnsmasq')
    if parent.exists():
        shutil.rmtree(parent)
    parent.mkdir(parents=True)
    parent.chmod(0o755)
    custom, extra = parent / 'dnsmasq.conf', parent / 'extra.conf'
    generator, count = root / 'generator.sh', root / 'count'
    script = '#!/bin/sh\nn=0\n[ ! -f ' + str(count) + ' ] || n=$(cat ' + str(count) + ')\nn=$((n+1))\nprintf "%s\\n" "$n" > ' + str(count) + '\n'
    if case == 'wrapper-graph-race':
        script += 'printf "# changed by controlled generator\\n" >> ' + str(extra) + '\n'
    script += 'printf "address=/snapshot.fixture/192.0.2.%s\\n" "$((50+n))"\n'
    regular(generator, script.encode(), 0o700)
    regular(extra, ('conf-script=' + str(generator) + '\n').encode())
    custom_data = ('gfwlist=/legacy-unused\nconf-file=' + str(extra) + '\n').encode()
    if case == 'wrapper-migration-daemon-loopback':
        available = LIMITS['wrapper_config_bytes'] - len(custom_data)
        padding = (b'# public capacity fixture\n' * (available // 26 + 1))[:available]
        # Keep every padding line valid even when the final fragment is short.
        padding = padding[:-1] + b'\n'
        custom_data = padding + custom_data
        regular(Path('/tmp/linux.trx'), b'F' * LIMITS['occupied_tmp_bytes'])
        regular(Path('/etc/storage/other-large-config'), b'P' * LIMITS['wrapper_config_bytes'])
        require(len(custom_data) == LIMITS['wrapper_config_bytes'], 'Capacity fixture length changed')
    regular(custom, custom_data)
    candidate = root / 'candidate'
    regular(candidate, custom.read_bytes().replace(b'gfwlist=', b'#gfwlist='))
    directory = root / 'includes'
    directory.mkdir(mode=0o700)
    regular(directory / '10-base.conf', b'# static directory input\n')
    main = Path('/etc/dnsmasq.conf')
    regular(main, ('port=10530\ninterface=lo\nlisten-address=127.0.0.1\nbind-interfaces\n'
                   'no-resolv\nno-hosts\nuser=root\ngroup=root\n'
                   'pid-file=/var/run/snapshot-daemon.pid\nconf-dir=' + str(directory) +
                   '\nconf-file=' + str(custom) + '\n').encode())
    return root, main, custom, candidate, extra, directory, count


def install_fixture_config(candidate, destination):
    # /tmp and /etc are deliberately distinct tmpfs mounts. Model the
    # publisher's same-filesystem staging and atomic rename, not EXDEV.
    stage = destination.parent / '.snapshot-test-install'
    require(not stage.exists() and not stage.is_symlink(), 'Fixture install stage already exists')
    try:
        regular(stage, candidate.read_bytes())
        os.replace(stage, destination)
    finally:
        stage.unlink(missing_ok=True)


def worker_cases(rootfs, sysroot, env):
    dns = ['qemu-mipsel', '-L', str(sysroot), str(rootfs / 'usr/sbin/dnsmasq')]
    checks = []
    for case in CASE_NAMES:
        root, main, custom, candidate, extra, directory, count = fixture(case)
        cache, ticket, flat_hash, flat_size = root / 'cache', None, None, 0
        first_answer = after_answer = None
        remaining, stopped = 0, True
        if case == 'busybox-exec-adapter-preflight':
            smoke = ('set -eu; d=/tmp/snapshot-tool-smoke; mkdir "$d"; '
                     'printf "x\\n" | awk "{print}" | head -c2 | sed s/x/y/ > "$d/value"; '
                     '[ "$(cat "$d/value")" = y ]; [ "$(stat -c %s "$d/value")" = 2 ]; '
                     'md5sum "$d/value" >/dev/null; df -Pk /tmp >/dev/null; rm -rf "$d"; '
                     'printf "COREUTILS_PREFLIGHT_OK\\n"; /usr/sbin/dnsmasq --version')
            rc, out, err = run_bounded(['qemu-mipsel', '-L', str(sysroot), str(rootfs / 'bin/busybox'),
                                       'sh', '-c', smoke], env)
            require(rc == 0 and b'Dnsmasq version 2.93' in out + err and
                    b'COREUTILS_PREFLIGHT_OK' in out, 'Actual BusyBox/native-tool exec adapter failed: ' +
                    (out + err).decode(errors='replace')[:2048])
        elif case.startswith('wrapper-'):
            old = custom.read_bytes()
            rc, out, err = run_bounded(['qemu-mipsel', '-L', str(sysroot), str(rootfs / 'bin/busybox'),
                                       'sh', str(rootfs / 'usr/bin/dnsmasq.sh'), '--launch'], env)
            remaining = len(list(Path('/tmp').glob('.dnsmasq-startup.*')))
            require(remaining == 0, 'Wrapper did not clean its startup workspace')
            if case == 'wrapper-graph-race':
                require(rc == 1 and not Path('/var/run/snapshot-daemon.pid').exists() and
                        custom.read_bytes() == old, 'Changed graph launched daemon or replaced original')
            else:
                require(rc == 0, 'Actual wrapper launch failed: ' + (out + err).decode(errors='replace')[:2048])
                first_answer = query_dns()
                after_answer = query_dns()
                backups = list((custom.parent / '.config-backups').glob('dnsmasq.conf.before-migration*'))
                require(len(backups) == 1 and backups[0].read_bytes() == old,
                        'Actual wrapper did not retain original migration backup')
                stopped = stop_daemon(rootfs)
        else:
            deduplicated_alias = deduplicated_original = None
            if case == 'changed-deduplicated-file-alias':
                deduplicated_original = extra
                deduplicated_alias = root / 'duplicate-alias'
                deduplicated_alias.symlink_to(extra)
                regular(main, main.read_bytes() + ('conf-file=' + str(deduplicated_alias) + '\n').encode())
            elif case == 'changed-deduplicated-directory-alias':
                deduplicated_original = directory / '10-base.conf'
                deduplicated_alias = directory / '20-alias.conf'
                deduplicated_alias.symlink_to(deduplicated_original)
            if case == 'oversized-input':
                regular(candidate, b'#x\n' * (2097152 // 3 + 1))
            if case == 'managed-foreground':
                regular(candidate, candidate.read_bytes() + b'no-daemon\n')
            capture = dns + ['--test', '-C', str(main), '--snapshot-capture', str(cache),
                             '--snapshot-overlay', str(custom), '--snapshot-candidate', str(candidate),
                             '--snapshot-managed']
            rc, out, err = run_bounded(capture, env)
            if case not in ('oversized-input', 'managed-foreground'):
                require(rc == 0, case + ': capture failed: ' + (out + err).decode(errors='replace')[:2048])
                ticket = read_ticket(cache)
                flat = (cache / 'flat.conf').read_bytes()
                flat_hash, flat_size = sha(flat), len(flat)
                # Keep the private candidate, as the real publisher does. Only
                # the declared live overlay is promoted to a new inode.
                install_fixture_config(candidate, custom)
                if case == 'changed-input-before-seal':
                    regular(extra, extra.read_bytes() + b'# changed\n')
                rc, out, err = run_bounded(dns + ['--snapshot-seal', str(cache),
                                                '--snapshot-ticket', ticket, '--snapshot-managed'], env)
                if case != 'changed-input-before-seal':
                    require(rc == 0, case + ': seal failed: ' + (out + err).decode(errors='replace')[:2048])
                    if case == 'changed-input-after-seal':
                        regular(extra, extra.read_bytes() + b'# changed\n')
                    elif case == 'changed-directory-after-seal':
                        regular(directory / '20-new.conf', b'# graph changed\n')
                    elif case == 'tampered-flat':
                        tamper_flat(cache / 'flat.conf')
                    elif case == 'cache-alias':
                        alias = root / 'alias'
                        alias.symlink_to(cache, target_is_directory=True)
                        cache = alias
                    elif case == 'ticket-mismatch':
                        ticket = ('0' if ticket[0] != '0' else '1') + ticket[1:]
                    elif case in ('changed-deduplicated-file-alias', 'changed-deduplicated-directory-alias'):
                        # Keep selected names and bytes unchanged. Only the
                        # previously skipped alias now targets a new inode.
                        replacement = root / 'same-bytes-other-inode'
                        regular(replacement, deduplicated_original.read_bytes())
                        deduplicated_alias.unlink()
                        deduplicated_alias.symlink_to(replacement)
                    rc, out, err = run_bounded(dns + ['--test', '--snapshot-use', str(cache),
                                                    '--snapshot-ticket', ticket, '--snapshot-managed'], env)
                    if case == 'capture-seal-replay-once':
                        require(rc == 0 and b'syntax check OK' in err, 'Sealed replay failed')
            if case in REJECT_CASES:
                require(rc == 1 and (b'snapshot' in err.lower() or
                        (case == 'oversized-input' and b'limit' in err.lower())),
                        case + ': rejection was not the audited parser failure')
            else:
                require(rc == 0, case + ': expected success')
        executions = int(count.read_text().strip()) if count.exists() else 0
        expected_count = 0 if case in ('busybox-exec-adapter-preflight', 'oversized-input') else 1
        require(executions == expected_count, case + ': generator was repeated or not executed')
        checks.append({'case': case, 'exit_code': rc,
                       'outcome': 'rejected-without-launch' if case in REJECT_CASES else 'snapshot-policy-verified',
                       'generator_executions': executions, 'flat_sha256': flat_hash,
                       'flat_bytes': flat_size, 'first_answer': first_answer,
                       'after_cleanup_answer': after_answer, 'workspaces_remaining': remaining,
                       'daemon_stopped': stopped})
    return checks


def validate_records(records):
    require(type(records) is list and len(records) == len(CASE_NAMES), 'Incomplete snapshot cases')
    for expected, record in zip(CASE_NAMES, records):
        require(type(record) is dict and set(record) == CHECK_KEYS and record['case'] == expected,
                'Snapshot case schema/order mismatch')
        reject = expected in REJECT_CASES
        require(type(record['exit_code']) is int and record['exit_code'] == (1 if reject else 0), 'Wrong snapshot exit code')
        require(record['outcome'] == ('rejected-without-launch' if reject else 'snapshot-policy-verified'), 'Wrong snapshot outcome')
        executions = 0 if expected in ('busybox-exec-adapter-preflight', 'oversized-input') else 1
        require(type(record['generator_executions']) is int and record['generator_executions'] == executions,
                'Generator was not executed exactly as required')
        require(type(record['flat_bytes']) is int and 0 <= record['flat_bytes'] <= 16777216,
                'Invalid flat snapshot size')
        require((record['flat_sha256'] is None and record['flat_bytes'] == 0) or
                (isinstance(record['flat_sha256'], str) and SHA.fullmatch(record['flat_sha256']) and record['flat_bytes'] > 0),
                'Invalid flat snapshot digest')
        have_flat = expected not in ('busybox-exec-adapter-preflight', 'oversized-input',
                                     'managed-foreground', 'wrapper-migration-daemon-loopback',
                                     'wrapper-graph-race')
        require((record['flat_sha256'] is not None) == have_flat, 'Missing or unexpected captured flat proof')
        require(record['workspaces_remaining'] == 0 and type(record['workspaces_remaining']) is int and
                record['daemon_stopped'] is True, 'Snapshot cleanup was not confirmed')
        answer = '192.0.2.51' if expected == 'wrapper-migration-daemon-loopback' else None
        require(record['first_answer'] == answer and record['after_cleanup_answer'] == answer,
                'Actual daemon did not preserve first generator policy after cleanup')
    return True


def validate_report(report, source_sha, shipped):
    keys = {'schema_version', 'status', 'profile', 'execution_roles', 'source_sha256', 'shipped',
            'isolation', 'filesystem_limits', 'limits', 'required_cases', 'checks', 'failure'}
    require(type(report) is dict and set(report) == keys and type(report['schema_version']) is int and report['schema_version'] == 1 and
            report['status'] == 'PASS' and report['profile'] == 'k2p-4.4' and report['failure'] is None,
            'Snapshot report schema/status mismatch')
    require(report['source_sha256'] == source_sha and report['shipped'] == shipped,
            'Snapshot source or shipped bytes binding mismatch')
    require(report['execution_roles'] == ROLES and report['filesystem_limits'] == FILESYSTEM_LIMITS and
            report['limits'] == LIMITS and report['required_cases'] == list(CASE_NAMES), 'Snapshot contract mismatch')
    isolation = report['isolation']
    require(type(isolation) is dict and set(isolation) == {'namespaces', 'worker_pid', 'loopback_only',
            'private_mount_propagation', 'anchors_cloexec', 'namespace_exit_confirmed'} and
            type(isolation['worker_pid']) is int and isolation['worker_pid'] == 1 and isolation['loopback_only'] is True and
            isolation['private_mount_propagation'] is True and isolation['anchors_cloexec'] is True and
            isolation['namespace_exit_confirmed'] is True, 'Snapshot isolation incomplete')
    require(set(isolation['namespaces']) == {'mnt', 'net', 'pid'}, 'Namespace proof incomplete')
    for value in isolation['namespaces'].values():
        require(type(value) is dict and set(value) == {'parent_inode', 'worker_inode'} and
                all(type(x) is int and x > 0 for x in value.values()) and
                value['parent_inode'] != value['worker_inode'], 'Initial namespace was used')
    return validate_records(report['checks'])


def worker(args):
    expected = json.loads(args.expected_output)
    namespaces = namespace_guard(json.loads(args.anchor_fds))
    # Resolve alternatives before /etc is covered. In Ubuntu, /usr/bin/awk
    # reaches gawk through /etc/alternatives and becomes dangling afterward.
    native_tools = resolve_native_tools()
    for executable in native_tools.values():
        require(not any(executable.is_relative_to('/' + name) for name in FILESYSTEM_LIMITS) and
                not executable.is_relative_to('/usr/sbin'), 'Native fixture tool would be covered by a mount')
    # The guard is complete before the first mount. All covered paths are private.
    for name, size in FILESYSTEM_LIMITS.items():
        subprocess.run(['mount', '-n', '-t', 'tmpfs', '-o',
                        'size=' + str(size) + ',mode=' + ('1777' if name == 'tmp' else '0755'),
                        'tmpfs', '/' + name], check=True, capture_output=True)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, capture_output=True)
    require({name for _, name in socket.if_nameindex()} == {'lo'}, 'Unexpected private interface')
    for name in ('etc', 'tmp', 'var', 'run'):
        (args.sysroot / name).mkdir(exist_ok=True)
        subprocess.run(['mount', '-n', '--bind', '/' + name, str(args.sysroot / name)], check=True, capture_output=True)
    subprocess.run(['mount', '-n', '-t', 'tmpfs', '-o', 'size=1048576,mode=0755',
                    'tmpfs', '/usr/sbin'], check=True, capture_output=True)
    (args.sysroot / 'usr/sbin').mkdir(parents=True, exist_ok=True)
    subprocess.run(['mount', '-n', '--bind', '/usr/sbin', str(args.sysroot / 'usr/sbin')], check=True, capture_output=True)
    qemu = shutil.which('qemu-mipsel')
    require(qemu is not None, 'qemu-mipsel missing')
    for name, image in (('dnsmasq', 'usr/sbin/dnsmasq'), ('storage_validate', 'sbin/storage_validate')):
        regular(Path('/usr/sbin') / name, ('#!/bin/sh\nexec ' + shlex.join([qemu, '-L', str(args.sysroot),
                str(args.rootfs / image)]) + ' "$@"\n').encode(), 0o755)
    if not Path('/sbin').is_symlink():
        subprocess.run(['mount', '-n', '--bind', '/usr/sbin', '/sbin'], check=True, capture_output=True)
    tools = Path('/tmp/snapshot-tools')
    tools.mkdir(mode=0o700)
    install_native_tools(tools, native_tools)
    regular(tools / 'nvram', b'#!/bin/sh\n[ "$1" = get ] && [ "$2" = dhcp_filter_aaa ] || exit 1\nprintf "0\\n"\n', 0o700)
    regular(tools / 'logger', b'#!/bin/sh\nexit 0\n', 0o700)
    regular(Path('/etc/passwd'), b'root:x:0:0:root:/:/bin/sh\nnobody:x:99:99:nobody:/:/bin/false\n', 0o644)
    regular(Path('/etc/group'), b'root:x:0:\nnobody:x:99:\n', 0o644)
    Path('/var/run').mkdir(mode=0o755)
    env = dict(os.environ, PATH=str(tools) + ':/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL='C')
    report = {'schema_version': 1, 'status': 'FAIL', 'profile': 'k2p-4.4',
              'execution_roles': ROLES, 'source_sha256': source_proof(args.trunk),
              'shipped': shipped_proof(args.rootfs), 'filesystem_limits': FILESYSTEM_LIMITS,
              'limits': LIMITS, 'required_cases': list(CASE_NAMES), 'checks': [], 'failure': None,
              'isolation': {'namespaces': namespaces, 'worker_pid': os.getpid(), 'loopback_only': True,
                            'private_mount_propagation': True, 'anchors_cloexec': True,
                            'namespace_exit_confirmed': False}}
    try:
        require(report['shipped']['wrapper']['sha256'] == report['source_sha256']['dnsmasq.sh'],
                'Shipped wrapper does not match source')
        report['checks'] = worker_cases(args.rootfs, args.sysroot, env)
        validate_records(report['checks'])
        report['status'] = 'PASS'
    except Exception as exc:
        report['failure'] = str(exc)[:4096]
        raise
    finally:
        write_output(args.output, expected, report)


def root_parent(args):
    require(sys.platform.startswith('linux') and os.geteuid() == 0, 'Linux root launcher required')
    expected = json.loads(args.expected_output)
    require(output_identity(args.output) == expected, 'Parent-owned report inode changed')
    anchors = {name: os.open('/proc/self/ns/' + name, os.O_RDONLY | os.O_CLOEXEC)
               for name in ('mnt', 'net', 'pid')}
    command = ['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
               '--kill-child=KILL', '--propagation', 'private', sys.executable,
               str(Path(__file__).resolve()), '--worker', '--trunk', str(args.trunk),
               '--rootfs', str(args.rootfs), '--sysroot', str(args.sysroot), '--output', str(args.output),
               '--expected-output', args.expected_output, '--anchor-fds', json.dumps(anchors)]
    try:
        subprocess.run(command, check=True, timeout=LIMITS['worker_seconds'], pass_fds=tuple(anchors.values()))
    finally:
        for fd in anchors.values():
            os.close(fd)
    report = json.loads(args.output.read_text())
    require(report['status'] == 'PASS', 'Isolated snapshot worker failed')
    report['isolation']['namespace_exit_confirmed'] = True
    write_output(args.output, expected, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('rootfs', 'sysroot', 'compiler'):
        parser.add_argument('--' + name, type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--worker', action='store_true')
    modes.add_argument('--root-parent', action='store_true')
    modes.add_argument('--preflight', action='store_true')
    parser.add_argument('--expected-output')
    parser.add_argument('--anchor-fds')
    args = parser.parse_args()
    for name in ('trunk', 'rootfs', 'sysroot', 'compiler'):
        if getattr(args, name) is not None:
            setattr(args, name, getattr(args, name).resolve())
    args.output = args.output.parent.resolve() / args.output.name
    if args.preflight:
        preflight(args)
        return
    require(args.rootfs is not None and args.sysroot is not None, 'Final proof requires rootfs and target sysroot')
    if args.worker:
        worker(args)
        return
    if args.root_parent:
        root_parent(args)
        return
    require(sys.platform.startswith('linux'), 'Snapshot target proof requires Linux; no fallback PASS')
    for path in (args.trunk, args.rootfs, args.sysroot, args.output, Path(__file__).resolve()):
        require(not path.is_relative_to('/tmp') and not path.is_relative_to('/var') and
                not path.is_relative_to('/etc') and not path.is_relative_to('/run'),
                'Namespace input/output must stay outside covered paths')
    source, shipped = source_proof(args.trunk), shipped_proof(args.rootfs)
    expected = prepare_output(args.output)
    command = (['sudo', '-n', 'env', 'PATH=' + os.environ['PATH']] if os.geteuid() else []) + [
        sys.executable, str(Path(__file__).resolve()), '--root-parent', '--trunk', str(args.trunk),
        '--rootfs', str(args.rootfs), '--sysroot', str(args.sysroot), '--output', str(args.output),
        '--expected-output', json.dumps(expected)]
    subprocess.run(command, check=True, timeout=LIMITS['worker_seconds'] + 30)
    require(output_identity(args.output) == expected, 'Root child changed report owner/inode/mode')
    validate_report(json.loads(args.output.read_text()), source, shipped)
    print('Target DNS snapshot: ' + str(len(CASE_NAMES)) + ' private-namespace MIPS cases PASS')


if __name__ == '__main__':
    main()
