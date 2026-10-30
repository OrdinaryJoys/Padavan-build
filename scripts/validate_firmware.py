#!/usr/bin/env python3
"""Validate the actual Padavan mkimage header before accepting an artifact."""
import argparse
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import tempfile
import zlib

FIRMWARE_LIMIT = 15_925_248
CA_SHA256 = 'a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505'
REQUIRED_EXECUTABLES = (
    'bin/busybox', 'sbin/rc', 'usr/sbin/httpd', 'usr/sbin/dnsmasq', 'usr/bin/miniupnpd',
    'usr/bin/curl', 'usr/bin/openssl', 'usr/bin/ssh', 'usr/sbin/sshd',
    'usr/libexec/sshd-session', 'usr/libexec/sshd-auth', 'usr/sbin/openvpn',
    'usr/bin/openvpn-cert.sh', 'usr/bin/wg', 'sbin/storage_validate',
)


def parse_rootfs_listing(listing):
    """Parse numeric unsquashfs listings without extracting device nodes/links."""
    entries = {}
    pattern = re.compile(
        r'^([bcdlps-][rwxstST-]{9})\s+\d+/\d+\s+(\d+(?:,\s*\d+)?)\s+'
        r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+squashfs-root(?:/(.*))?$')
    for line in listing.splitlines():
        if not line.strip():
            continue
        match = pattern.fullmatch(line)
        if not match:
            raise ValueError(f'unrecognised SquashFS listing: {line!r}')
        mode, size, name = match.groups()
        if name is None:
            continue  # root directory
        target = None
        if mode[0] == 'l':
            if ' -> ' not in name:
                raise ValueError(f'symlink target missing: {name!r}')
            name, target = name.split(' -> ', 1)
        if any(part in ('', '.', '..') for part in name.split('/')):
            raise ValueError(f'unsafe SquashFS path: {name!r}')
        if name in entries:
            raise ValueError(f'duplicate SquashFS path: {name!r}')
        entries[name] = {'mode': mode, 'size': size, 'target': target}
    if not entries:
        raise ValueError('empty SquashFS listing')
    return entries


def resolve_rootfs_path(entries, name):
    """Resolve links against the image root, never the build host's root."""
    pending, resolved, links = name.split('/'), [], 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            if not resolved:
                raise ValueError(f'SquashFS link escapes root: {name}')
            resolved.pop()
            continue
        resolved.append(part)
        current = '/'.join(resolved)
        if current not in entries:
            raise ValueError(f'missing SquashFS path: {current}')
        node = entries[current]
        if node['mode'][0] == 'l':
            links += 1
            if links > 40:
                raise ValueError(f'SquashFS symlink loop: {name}')
            resolved.pop()
            target = node['target']
            if target.startswith('/'):
                resolved = []
            pending = target.split('/') + pending
        elif pending and node['mode'][0] != 'd':
            raise ValueError(f'SquashFS path traverses a non-directory: {current}')
    if not resolved:
        raise ValueError(f'SquashFS path resolves to root: {name}')
    return '/'.join(resolved)


def validate_rootfs(data, ca_sha256=CA_SHA256):
    """Read every regular file, then check shipped boot/auth/TLS helpers.

    Legal hard links share inodes. Do not reject them as "duplicate inodes";
    duplicate paths, unreadable data and invalid required links are failures.
    No files, symlinks or device nodes from the image are created on the host.
    """
    with tempfile.TemporaryDirectory(prefix='k2p-rootfs-') as directory:
        image = pathlib.Path(directory) / 'rootfs.squashfs'
        image.write_bytes(data)

        def run(*arguments, discard=False):
            try:
                result = subprocess.run(
                    ['unsquashfs', '-no-progress', *arguments],
                    stdout=subprocess.DEVNULL if discard else subprocess.PIPE,
                    stderr=subprocess.PIPE, check=True, timeout=120)
            except (OSError, subprocess.SubprocessError) as error:
                raise ValueError(f'SquashFS read failed: {error}') from error
            return result.stdout

        entries = parse_rootfs_listing(run('-lln', str(image)).decode('utf-8'))
        files = [name for name, node in entries.items() if node['mode'][0] == '-']
        if not files:
            raise ValueError('SquashFS has no regular files')
        # One unsquashfs process reads all file data, including helpers not in
        # the required set. Listing metadata alone does not detect bad blocks.
        run('-no-wildcards', '-cat', str(image), *files, discard=True)
        for name in (*REQUIRED_EXECUTABLES, 'init'):
            resolved = resolve_rootfs_path(entries, name)
            node = entries[resolved]
            if node['mode'][0] != '-' or node['mode'][3] not in ('x', 's') or int(node['size']) == 0:
                raise ValueError(f'non-executable or empty required file: {name}')

        def content(name):
            resolved = resolve_rootfs_path(entries, name)
            if entries[resolved]['mode'][0] != '-':
                raise ValueError(f'required path is not a regular file: {name}')
            return run('-no-wildcards', '-cat', str(image), resolved)

        if content('init') != content('sbin/rc'):
            raise ValueError('/init contents differ from /sbin/rc')
        actual_ca = hashlib.sha256(content('etc_ro/ca-certificates.crt')).hexdigest()
        if actual_ca != ca_sha256:
            raise ValueError('shipped CA certificate SHA256 mismatch')
        return {'entries': len(entries), 'regular_files_read': len(files),
                'required_executables': len(REQUIRED_EXECUTABLES) + 1,
                'ca_sha256': actual_ca, 'init_matches_rc': True}


def validate(data, product='K2P', limit=FIRMWARE_LIMIT, kernel=None):
    if len(data) < 64:
        raise ValueError('image is shorter than its 64-byte header')
    if len(data) > limit:
        raise ValueError(f'image is {len(data)} bytes, exceeds partition {limit}')
    magic, header_crc, timestamp, payload_size, load, entry, data_crc = struct.unpack('>7I', data[:28])
    if magic != 0x27051956:
        raise ValueError('invalid U-Boot image magic')
    if payload_size != len(data) - 64:
        raise ValueError('payload length does not match the image header')
    header = bytearray(data[:64])
    header[4:8] = b'\0' * 4
    if zlib.crc32(header) & 0xffffffff != header_crc:
        raise ValueError('header CRC mismatch')
    if zlib.crc32(data[64:]) & 0xffffffff != data_crc:
        raise ValueError('payload CRC mismatch')
    # mkimage/include/image.h: TAIL begins at 32; product follows 4 version bytes.
    image_product = data[36:59].split(b'\0', 1)[0].decode('ascii', errors='strict')
    if image_product != product:
        raise ValueError(f'product is {image_product!r}, expected {product!r}')
    if data[28:31] != bytes([5, 5, 2]):
        raise ValueError('expected Linux/MIPS/kernel image')
    if data[31] not in (0, 3):
        raise ValueError('expected uncompressed or LZMA kernel')
    kernel_size = struct.unpack('>I', data[60:64])[0]
    if not 64 < kernel_size < len(data):
        raise ValueError('invalid kernel/rootfs boundary')
    if data[kernel_size:kernel_size+4] != b'hsqs':
        raise ValueError('SquashFS rootfs missing at the declared boundary')
    kernel_version = f'{data[32]}.{data[33]}'
    if kernel and kernel_version != kernel:
        raise ValueError(f'kernel is {kernel_version}, expected {kernel}')
    return dict(product=image_product, kernel=kernel_version, bytes=len(data),
                partition_bytes=limit, spare_bytes=limit-len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                header_crc=f'{header_crc:08x}', payload_crc=f'{data_crc:08x}',
                kernel_bytes=kernel_size, timestamp=timestamp,
                load_address=f'0x{load:08x}', entry_address=f'0x{entry:08x}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('image', type=pathlib.Path)
    parser.add_argument('--kernel', required=True, choices=['3.4', '4.4'])
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--rootfs-check', action='store_true',
                        help='read all SquashFS files and verify shipped helpers (requires unsquashfs)')
    args = parser.parse_args()
    try:
        data = args.image.read_bytes()
        result = validate(data, kernel=args.kernel)
        if args.rootfs_check:
            result['rootfs'] = validate_rootfs(data[result['kernel_bytes']:])
    except (OSError, ValueError, UnicodeError) as error:
        parser.exit(1, f'Firmware validation failed: {error}\n')
    result['file'] = args.image.name
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
