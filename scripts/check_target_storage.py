#!/usr/bin/env python3
"""Exercise the actual MIPS validator and BusyBox in private host temp trees.

Only accepted, ordinary fixtures are extracted. Rejected inputs are given to
the read-only validator, never to tar. No MTD, service or router is accessed.
"""
import argparse
import fcntl
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile


PUBLIC_DNS = b'192.0.2.55 fixture.example.invalid\n'


def install_functions(script):
    """Use the shipped restore implementation, including its extraction umask."""
    functions = []
    for name in ('func_dns_directory_access', 'func_install_tar'):
        found = re.search(r'^' + name + r'\(\)\n\{\n.*?^\}', script, re.M | re.S)
        if not found:
            raise RuntimeError('Shipped Storage function missing: ' + name)
        functions.append(found.group(0))
    return '\n'.join(functions)


def public_dns_fixture(mode=None, unknown=False, alias=False, hardlink=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        entries = [('start_script.sh', b'#!/bin/sh\n', 0o755, tarfile.REGTYPE, ''),
                   ('private', b'', 0o700, tarfile.DIRTYPE, ''),
                   ('private/secret', b'private fixture only\n', 0o600, tarfile.REGTYPE, '')]
        dns = 'private' if alias else 'dnsmasq'
        if mode is not None and not alias:
            entries.append((dns, b'', mode, tarfile.DIRTYPE, ''))
        entries.extend([
            (dns + '/dnsmasq.conf', b'local-service\n', 0o644, tarfile.REGTYPE, ''),
            (dns + '/hosts', PUBLIC_DNS, 0o644, tarfile.REGTYPE, ''),
            (dns + '/dhcp.conf', b'', 0o644,
             tarfile.LNKTYPE if hardlink else tarfile.REGTYPE, dns + '/hosts' if hardlink else '')])
        if alias:
            entries.append(('dnsmasq', b'', 0o777, tarfile.SYMTYPE, 'private'))
        if unknown:
            entries.append((dns + '/unknown-policy', b'preserve boundary\n', 0o644, tarfile.REGTYPE, ''))
        for name, payload, entry_mode, kind, target in entries:
            info = tarfile.TarInfo(name)
            info.mode, info.type, info.linkname = entry_mode, kind, target
            info.size = len(payload) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(payload) if info.size else None)
    return output.getvalue()


def check_storage_access(rootfs, sysroot, directory):
    """Root restore, real uid99 reads, conservative migration/alias controls."""
    prefix = [] if os.geteuid() == 0 else ['sudo', '-n']
    qemu = shutil.which('qemu-mipsel')
    if not qemu:
        raise RuntimeError('qemu-mipsel missing')
    busybox = [qemu, '-L', str(sysroot), str(rootfs / 'bin/busybox')]
    helper = [qemu, '-L', str(sysroot), str(rootfs / 'sbin/storage_validate')]
    functions = install_functions((rootfs / 'sbin/mtd_storage.sh').read_text())
    functions = functions.replace('/sbin/storage_validate', shlex.join(helper))
    probe = directory / 'storage-uid-probe'
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
                    str(Path(__file__).with_name('storage_uid_probe.c')), '-o', str(probe)],
                   check=True, capture_output=True, timeout=30)

    def uid99_read(path):
        return subprocess.run([*prefix, str(probe), *busybox, 'cat', str(path)],
                              capture_output=True, timeout=20)

    def metadata(path):
        result = subprocess.run([*prefix, *busybox, 'stat', '-c', '%a:%u:%h', str(path)],
                                check=True, capture_output=True, timeout=20)
        return result.stdout.decode().strip().split(':')

    def denied(result):
        return result.returncode == 1 and not result.stdout and b'Permission denied' in result.stderr

    records = []
    try:
        cases = [('implicit-public', {}, '755', True),
                 ('known-explicit700', {'mode': 0o700}, '755', True),
                 ('unknown-explicit700', {'mode': 0o700, 'unknown': True}, '700', False),
                 ('alias-to-private700', {'alias': True}, '700', False),
                 ('hardlink-explicit700', {'mode': 0o700, 'hardlink': True}, '700', False)]
        for name, options, expected_mode, accessible in cases:
            archive, tree = directory / (name + '.tar'), directory / name
            archive.write_bytes(public_dns_fixture(**options))
            # Production Storage is owned by root. The directory-exchange
            # helper checks both old/new source owners against its real euid;
            # a runner-owned placeholder would fail before extraction checks.
            subprocess.run([*prefix, *busybox, 'mkdir', '-m', '755', str(tree)],
                           check=True, capture_output=True, timeout=20)
            if metadata(tree)[:2] != ['755', '0']:
                raise RuntimeError(name + ': initial fixture directory is not root0755')
            # No startup hook is run: only these two archive install functions.
            # Actual target stat/chmod/tar cover their shipped applet options.
            script = ('set -eu\numask 077\n' +
                      ''.join(command + '() { ' + shlex.join(busybox) + ' ' + command + ' "$@"; }\n'
                              for command in ('tar', 'stat', 'chmod')) +
                      'logger() { printf "%s\\n" "$*" >&2; }\n' +
                      'tmp=' + shlex.quote(str(archive)) + '\n' +
                      'dir_storage=' + shlex.quote(str(tree)) + '\n' + functions + '\nfunc_install_tar\n')
            result = subprocess.run([*prefix, '/bin/sh', '-c', script], capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError(name + ': target install failed: ' + result.stderr.decode(errors='replace'))
            dns = tree / ('private' if options.get('alias') else 'dnsmasq')
            mode, owner, links = metadata(dns)
            if mode != expected_mode or owner != '0':
                raise RuntimeError(f'{name}: directory mode/owner {mode}:{owner}, expected {expected_mode}:0')
            mode, owner, links = metadata(dns / 'hosts')
            if mode != '644' or owner != '0' or links != ('2' if options.get('hardlink') else '1'):
                raise RuntimeError(name + ': public fixture mode/owner/link metadata changed')
            if metadata(tree / 'private/secret')[:2] != ['600', '0']:
                raise RuntimeError(name + ': private file mode/owner changed')
            if metadata(tree / 'private')[0] != '700':
                raise RuntimeError(name + ': explicit private directory boundary was widened')
            public_result = uid99_read(tree / 'dnsmasq/hosts')
            if accessible:
                if public_result.returncode or public_result.stdout != PUBLIC_DNS:
                    raise RuntimeError(name + ': uid99 public read failed: ' + public_result.stderr.decode(errors='replace'))
            elif not denied(public_result):
                raise RuntimeError(name + ': uid99 private/alias directory read was not denied')
            if not denied(uid99_read(tree / 'private/secret')):
                raise RuntimeError(name + ': uid99 private key read was not denied')
            if accessible:
                # Root-running or DAC-bypassing tests must fail this control.
                subprocess.run([*prefix, *busybox, 'chmod', '700', str(dns)], check=True, capture_output=True, timeout=20)
                if not denied(uid99_read(tree / 'dnsmasq/hosts')):
                    raise RuntimeError(name + ':0700 parent negative control did not reject uid99')
            records.append({'fixture': name, 'validator': 'accepted', 'target_tar': 'shipped-install-functions',
                            'dns_directory_mode': expected_mode, 'directory_owner': 0, 'public_file_mode': '0644',
                            'private_file_mode': '0600', 'real_linux_uid': 99, 'groups': 'cleared',
                            'capabilities': 'none', 'public_read': 'pass' if accessible else 'denied-as-intended',
                            'private_read': 'denied', '0700_parent_control': 'denied'})
    finally:
        # Root created these synthetic trees. Return ownership solely so the
        # normal runner's TemporaryDirectory cleanup can remove them on error.
        subprocess.run([*prefix, 'chown', '-R', f'{os.getuid()}:{os.getgid()}', str(directory)],
                       check=True, capture_output=True, timeout=20)
    return records


def permission_profile(profile, rootfs, sysroot, directory):
    if profile == 'k2p-4.4':
        return {'checks': check_storage_access(rootfs, sysroot, directory),
                'new_permission_gate': 'passed', 'known_limitations': []}
    if profile == 'k2p-susu':
        return {'checks': [], 'new_permission_gate': 'not-run-unfixed-legacy-source',
                'known_limitations': [
                    'SUSU legacy source has not received this Storage permission repair. '
                    'Only the original archive/applet checks ran; public DNS directory '
                    'restoration and real UID99 access are not verified for this profile.']}
    raise ValueError('Unknown Storage validation profile: ' + profile)


def fixture(extra=(), format=tarfile.USTAR_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=format) as archive:
        for name, payload, kind, target in [('start_script.sh', b'#!/bin/sh\n', tarfile.REGTYPE, ''), *extra]:
            info = tarfile.TarInfo(name)
            info.mode = 0o755 if name == 'start_script.sh' else 0o644
            info.type, info.linkname = kind, target
            info.size = len(payload) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(payload) if info.size else None)
    return output.getvalue()


def check(rootfs, output, sysroot=None, profile='k2p-4.4'):
    if profile not in ('k2p-4.4', 'k2p-susu'):
        raise ValueError('Unknown Storage validation profile: ' + profile)
    rootfs = rootfs.resolve()
    sysroot = (sysroot or rootfs).resolve()
    checked = []

    def target(program, *arguments, **options):
        return subprocess.run(['qemu-mipsel', '-L', str(sysroot), str(rootfs / program), *map(str, arguments)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, **options)

    with tempfile.TemporaryDirectory(prefix='k2p-target-storage-', dir='/tmp') as directory:
        directory = Path(directory)
        # The isolated uid99 child must traverse this fixture parent. No
        # production/private data is placed in this publicly traversable tree.
        directory.chmod(0o755)
        valid = {
            'ustar-dotfile': fixture([('.hidden', b'keep hidden', tarfile.REGTYPE, '')]),
            'gnu-long-path': fixture([('segment/' * 20 + 'payload', b'keep GNU', tarfile.REGTYPE, '')], tarfile.GNU_FORMAT),
            'internal-links': fixture([('payload', b'keep links', tarfile.REGTYPE, ''),
                                       ('hard', b'', tarfile.LNKTYPE, 'payload'),
                                       ('soft', b'', tarfile.SYMTYPE, 'payload')]),
        }
        for name, data in valid.items():
            archive = directory / (name + '.tar')
            archive.write_bytes(data)
            result = target('sbin/storage_validate', archive, str(16 * 1024 * 1024))
            if result.returncode:
                raise RuntimeError(f'{name}: validator rejected fixture: {result.stderr.decode(errors="replace")}')
            extracted = directory / name
            extracted.mkdir()
            result = target('bin/busybox', 'tar', 'xof', archive, '-C', extracted)
            if result.returncode or not (extracted / 'start_script.sh').is_file():
                raise RuntimeError(f'{name}: target BusyBox extraction failed: {result.stderr.decode(errors="replace")}')
            if name == 'ustar-dotfile':
                assert (extracted / '.hidden').read_bytes() == b'keep hidden'
            elif name == 'gnu-long-path':
                assert (extracted / ('segment/' * 20 + 'payload')).read_bytes() == b'keep GNU'
            else:
                assert (extracted / 'hard').read_bytes() == b'keep links'
                assert (extracted / 'soft').is_symlink()
                assert (extracted / 'soft').read_bytes() == b'keep links'
            checked.append({'fixture': name, 'validator': 'accepted', 'target_tar': 'extracted-and-content-checked'})

        invalid = {
            'truncated': valid['ustar-dotfile'][:700],
            'unsupported-pax': fixture([('pax/' + 'x' * 120, b'payload', tarfile.REGTYPE, '')], tarfile.PAX_FORMAT),
            'long-component': fixture([('x' * 256, b'payload', tarfile.REGTYPE, '')], tarfile.GNU_FORMAT),
            'non-directory-parent': fixture([('ordinary', b'file', tarfile.REGTYPE, ''),
                                             ('ordinary/child', b'', tarfile.DIRTYPE, '')]),
        }
        for name, data in invalid.items():
            archive = directory / (name + '.tar')
            archive.write_bytes(data)
            result = target('sbin/storage_validate', archive, str(16 * 1024 * 1024))
            if result.returncode != 1:
                raise RuntimeError(f'{name}: expected controlled validator rejection (1), got {result.returncode}: {result.stderr.decode(errors="replace")}')
            checked.append({'fixture': name, 'validator': 'rejected', 'target_tar': 'not-executed'})

        # The production script relies on these BusyBox applet options; native
        # host-shell fixtures cannot establish that they ship in the target.
        payload = directory / 'internal-links/payload'
        link = directory / 'internal-links/soft'
        original_mtime = payload.stat().st_mtime_ns
        result = target('bin/busybox', 'touch', '-c', '-h', '-t', '201001010000.00', link)
        if result.returncode or payload.stat().st_mtime_ns != original_mtime:
            raise RuntimeError('Target touch -c -h -t failed or followed the link')
        result = target('bin/busybox', 'stat', '-c', '%a:%s:%u', payload)
        if result.returncode or not result.stdout.decode().strip().startswith('644:10:'):
            raise RuntimeError('Target stat -c metadata options failed')
        checked.append({'fixture': 'busybox-touch-stat', 'target_tar': 'not-required', 'validator': 'metadata-options-pass'})

        result = target('bin/busybox', 'find', directory / 'ustar-dotfile', '-print0')
        if result.returncode or b'/.hidden\0' not in result.stdout:
            raise RuntimeError('Target find -print0 failed')
        result = target('bin/busybox', 'xargs', '-0', '/usr/bin/printf', '%s|', input=b'first item\0second\0')
        if result.returncode or result.stdout != b'first item|second|':
            raise RuntimeError('Target xargs -0 failed')
        checked.append({'fixture': 'busybox-nul-arguments', 'target_tar': 'not-required', 'validator': 'find-xargs-options-pass'})

        with (directory / 'operation.lock').open('w') as held:
            result = target('bin/busybox', 'flock', '-n', held.fileno(), pass_fds=(held.fileno(),))
            if result.returncode:
                raise RuntimeError('Target flock -n fd failed')
            with (directory / 'operation.lock').open('w') as competing:
                try:
                    fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise RuntimeError('Target flock did not retain a lock on the inherited description')
            fcntl.flock(held, fcntl.LOCK_UN)
        checked.append({'fixture': 'busybox-inherited-flock', 'target_tar': 'not-required', 'validator': 'lock-verified-by-host'})

        permissions = permission_profile(profile, rootfs, sysroot, directory)
        checked.extend(permissions.pop('checks'))
    output.write_text(json.dumps({'checks': checked, 'target': 'qemu-mipsel with shipped libc/BusyBox',
                                  'profile': profile, **permissions,
                                  'limit': 'No flash write, live service, boot or power-failure test'}, indent=2) + '\n')
    print(f'Target storage validator/BusyBox: {len(checked)} fixtures PASS; '
          f'new permission gate: {permissions["new_permission_gate"]}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path)
    parser.add_argument('--profile', choices=['k2p-4.4', 'k2p-susu'], default='k2p-4.4')
    arguments = parser.parse_args()
    check(arguments.rootfs, arguments.output, arguments.sysroot, arguments.profile)
