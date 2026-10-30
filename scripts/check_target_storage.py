#!/usr/bin/env python3
"""Exercise the actual MIPS validator and BusyBox in private host temp trees.

Only accepted, ordinary fixtures are extracted. Rejected inputs are given to
the read-only validator, never to tar. No MTD, service or router is accessed.
"""
import argparse
import fcntl
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


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


def check(rootfs, output, sysroot=None):
    rootfs = rootfs.resolve()
    sysroot = (sysroot or rootfs).resolve()
    checked = []

    def target(program, *arguments, **options):
        return subprocess.run(['qemu-mipsel', '-L', str(sysroot), str(rootfs / program), *map(str, arguments)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, **options)

    with tempfile.TemporaryDirectory(prefix='k2p-target-storage-') as directory:
        directory = Path(directory)
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
            if result.returncode == 0:
                raise RuntimeError(f'{name}: invalid fixture was accepted')
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
    output.write_text(json.dumps({'checks': checked, 'target': 'qemu-mipsel with shipped libc/BusyBox',
                                  'limit': 'No flash write, live service, boot or power-failure test'}, indent=2) + '\n')
    print(f'Target storage validator/BusyBox: {len(checked)} fixtures PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path)
    arguments = parser.parse_args()
    check(arguments.rootfs, arguments.output, arguments.sysroot)
