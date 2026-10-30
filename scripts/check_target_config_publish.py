#!/usr/bin/env python3
"""Run the shipped MIPS publisher inside private Linux /etc and /tmp mounts."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

CASES = ('first-boot', 'large-migration', 'changed-original', 'busy-storage-lock',
         'candidate-too-large', 'insufficient-etc', 'first-boot-existing',
         'destination-symlink', 'unaccounted-hardlink', 'backup-slots-full',
         'backup-directory-symlink')
MAX_BYTES = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def regular(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def identity(path):
    st = path.lstat()
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def worker(rootfs, sysroot, output):
    require(sys.platform.startswith('linux') and os.geteuid() == 0, 'Isolated Linux root child required')
    require(os.stat('/proc/self/ns/mnt').st_ino != os.stat('/proc/1/ns/mnt').st_ino,
            'Refusing to cover paths in the initial mount namespace')
    root_mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
                   if line.split()[4] == '/']
    require(len(root_mounts) == 1 and not any(field.startswith('shared:')
            for field in root_mounts[0][6:root_mounts[0].index('-')]),
            'Private mount propagation required')
    # The caller created a private mount namespace. These cover only this
    # child's view; no write reaches the host /etc or existing /tmp files.
    for path, size, mode in (('/etc', '6M', '0755'), ('/tmp', '24M', '1777')):
        subprocess.run(['mount', '-n', '-t', 'tmpfs', '-o', f'size={size},mode={mode}',
                        'tmpfs', path], check=True, capture_output=True)
    # QEMU may prefix open("/") with -L before the helper walks openat()
    # components. Bind the same scratch mounts at both views; use literal
    # directories so the production NOFOLLOW walk is still exercised.
    for name in ('etc', 'tmp'):
        (sysroot / name).mkdir(exist_ok=True)
        subprocess.run(['mount', '-n', '--bind', '/' + name, str(sysroot / name)],
                       check=True, capture_output=True)
    helper = rootfs / 'sbin/storage_validate'
    header = helper.read_bytes()[:52]
    require(len(header) == 52 and header[:7] == b'\x7fELF\x01\x01\x01' and
            struct.unpack_from('<H', header, 18)[0] == 8, 'Shipped publisher is not ELF32LE MIPS')
    records = []
    size = 1792 * 1024
    original = (b'# public old policy\n' * (size // 20 + 2))[:size]
    candidate = (b'# public new policy\n' * (size // 20 + 2))[:size]
    for name in CASES:
        for path in (Path('/etc/storage'), Path('/tmp/publish-fixture')):
            if path.exists():
                shutil.rmtree(path)
        Path('/etc/fill').unlink(missing_ok=True)
        parent = Path('/etc/storage/dnsmasq')
        parent.mkdir(parents=True)
        parent.chmod(0o755)
        inputs = Path('/tmp/publish-fixture')
        inputs.mkdir(mode=0o700)
        target, source, snapshot = parent / 'dnsmasq.conf', inputs / 'candidate', inputs / 'original'
        regular(target, original, 0o644)
        regular(source, candidate)
        regular(snapshot, original)
        old_argument = str(snapshot)
        lock = None
        expected = 1
        if name == 'first-boot':
            target.unlink()
            old_argument, expected = '-', 0
        elif name == 'large-migration':
            regular(Path('/etc/storage/other-large-config'), original, 0o600)
            expected = 0
        elif name == 'changed-original':
            regular(target, b'operator changed policy\n', 0o644)
        elif name == 'busy-storage-lock':
            operation = Path('/tmp/.storage_operation')
            operation.mkdir(mode=0o700, exist_ok=True)
            operation.chmod(0o700)
            lock = (operation / 'lock').open('a+')
            os.chmod(operation / 'lock', 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif name == 'candidate-too-large':
            regular(source, b'x' * (MAX_BYTES + 1))
        elif name == 'insufficient-etc':
            regular(Path('/etc/fill'), b'x' * (3 * 1024 * 1024))
        elif name == 'first-boot-existing':
            old_argument = '-'
        elif name == 'destination-symlink':
            regular(parent / 'alias-target', original, 0o644)
            target.unlink()
            target.symlink_to('alias-target')
        elif name == 'unaccounted-hardlink':
            os.link(target, parent / 'outside-alias')
        elif name == 'backup-slots-full':
            for slot in range(10):
                regular(parent / ('dnsmasq.conf.before-migration' + ('.' + str(slot) if slot else '')),
                        b'preserve historical backup\n')
        elif name == 'backup-directory-symlink':
            (parent / 'private-target').mkdir(mode=0o700)
            (parent / '.config-backups').symlink_to('private-target', target_is_directory=True)
        before = target.read_bytes() if target.exists() else None
        before_identity = identity(target) if target.exists() or target.is_symlink() else None
        try:
            result = subprocess.run(['qemu-mipsel', '-L', str(sysroot), str(helper),
                                     '--publish-config', str(source), old_argument, str(target)],
                                    capture_output=True, text=True, timeout=30)
        finally:
            if lock is not None:
                lock.close()
        require(result.returncode == expected,
                f'{name}: expected {expected}, got {result.returncode}: {result.stdout}{result.stderr}')
        if expected == 0:
            require(target.read_bytes() == candidate and target.stat().st_mode & 0o777 == 0o600,
                    name + ': complete private candidate was not installed')
            if name == 'large-migration':
                backup = Path(result.stdout.strip())
                require(backup.parent == parent / '.config-backups' and
                        backup.parent.stat().st_mode & 0o777 == 0o700 and
                        backup.read_bytes() == original, name + ': private original backup missing')
        else:
            require(target.read_bytes() == before, name + ': rejected transaction altered original')
            require(identity(target) == before_identity,
                    name + ': rejected transaction altered original inode/owner/mode/link metadata')
            if name == 'destination-symlink':
                require(target.is_symlink(), name + ': rejection replaced alias')
        require(not list(Path('/etc').glob('.config-publish.*')), name + ': local staging was retained')
        records.append({'case': name, 'exit_code': result.returncode,
                        'outcome': 'validated-candidate-installed' if expected == 0 else 'original-preserved',
                        'target': 'actual-shipped-MIPS-helper'})
    output.write_text(json.dumps({'schema_version': 1, 'profile': 'k2p-4.4',
                                 'target': 'shipped storage_validate under qemu-mipsel',
                                 'helper_sha256': hashlib.sha256(helper.read_bytes()).hexdigest(),
                                 'filesystem_limits': {'etc': 6 * 1024 * 1024, 'tmp': 24 * 1024 * 1024},
                                 'checks': records, 'required_cases': list(CASES),
                                 'limitations': ['No daemon, MTD, router boot or firmware writer executed.',
                                                 'Crash/short-write/return2 controls are exercised by separate source tests.']}, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    rootfs, sysroot, output = args.rootfs.resolve(), args.sysroot.resolve(), args.output.resolve()
    if args.worker:
        worker(rootfs, sysroot, output)
    else:
        require(sys.platform.startswith('linux'), 'Target namespace proof requires Linux')
        # All executable paths and the output stay outside the covered /tmp.
        for path in (rootfs, sysroot, output, Path(__file__).resolve()):
            require(not path.is_relative_to('/tmp'), 'Namespace input/output may not live under /tmp')
        command = (['sudo', '-n'] if os.geteuid() else []) + [
            'env', 'PATH=' + os.environ['PATH'], 'unshare', '--mount', '--fork',
            '--kill-child=KILL', '--propagation', 'private', sys.executable,
            str(Path(__file__).resolve()), '--worker', '--rootfs', str(rootfs),
            '--sysroot', str(sysroot), '--output', str(output)]
        subprocess.run(command, check=True, timeout=180)
        value = json.loads(output.read_text())
        require([r['case'] for r in value['checks']] == list(CASES), 'Target publisher case set incomplete')
        print(f'Target configuration publisher: {len(CASES)} isolated MIPS cases PASS')


if __name__ == '__main__':
    main()
