#!/usr/bin/env python3
"""Validate the actual Padavan mkimage header before accepting an artifact."""
import argparse
import hashlib
import json
import lzma
import pathlib
import re
import struct
import subprocess
import tempfile
import zlib

FIRMWARE_LIMIT = 15_925_248
MAX_KERNEL_BYTES = 32 * 1024 * 1024
LZMA_MEMORY_LIMIT = 64 * 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_DTB_DEPTH = 64
MAX_DTB_NODES = 4096
MAX_DTB_PROPERTIES = 16384
MAX_DTB_NAME_BYTES = 255
MAX_DTB_PATH_BYTES = 2048
CA_SHA256 = 'a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505'
REQUIRED_EXECUTABLES = (
    'bin/busybox', 'sbin/rc', 'usr/sbin/httpd', 'usr/sbin/dnsmasq', 'usr/bin/miniupnpd',
    'usr/bin/curl', 'usr/bin/openssl', 'usr/bin/ssh', 'usr/sbin/sshd',
    'usr/libexec/sshd-session', 'usr/libexec/sshd-auth', 'usr/sbin/openvpn',
    'usr/bin/openvpn-cert.sh', 'usr/bin/wg', 'sbin/storage_validate',
)


def parse_dtb(data):
    """Read bounded FDT structure/properties without executing external tools."""
    if len(data) < 40:
        raise ValueError('truncated DTB header')
    magic, total, structure, strings, reserve, version, last, cpu, nstrings, nstructure = struct.unpack_from('>10I', data)
    if magic != 0xd00dfeed or not 40 <= total <= min(len(data), 1024 * 1024):
        raise ValueError('invalid DTB total size')
    if version != 17 or last > 17 or reserve < 40 or reserve % 8:
        raise ValueError('invalid DTB version/reservation layout')
    if structure % 4 or min(structure, strings) < 40 or not nstructure or not nstrings:
        raise ValueError('invalid DTB block layout')
    if max(structure + nstructure, strings + nstrings) > total or not (
            structure + nstructure <= strings or strings + nstrings <= structure):
        raise ValueError('DTB blocks overlap or exceed total size')
    end_reserve = reserve
    while end_reserve + 16 <= min(structure, strings):
        address, size = struct.unpack_from('>QQ', data, end_reserve)
        end_reserve += 16
        if address == size == 0:
            break
    else:
        raise ValueError('unterminated DTB reservation map')
    table = data[strings:strings + nstrings]
    offset, end, stack, nodes = structure, structure + nstructure, [], {}
    properties = 0
    while offset + 4 <= end:
        token = struct.unpack_from('>I', data, offset)[0]
        offset += 4
        if token == 1:
            if len(stack) >= MAX_DTB_DEPTH or len(nodes) >= MAX_DTB_NODES:
                raise ValueError('DTB depth/node budget exceeded')
            terminator = data.find(b'\0', offset, min(end, offset + MAX_DTB_NAME_BYTES + 1))
            if terminator < 0:
                raise ValueError('DTB node name too long/unterminated')
            name = data[offset:terminator].decode('ascii')
            if '/' in name or (stack and not name) or (not stack and (name or nodes)):
                raise ValueError('invalid DTB root/node name')
            stack.append(name)
            path = '/'.join(stack)
            if len(path) > MAX_DTB_PATH_BYTES:
                raise ValueError('DTB path budget exceeded')
            if path in nodes:
                raise ValueError('duplicate DTB node')
            nodes[path] = {}
            offset = (terminator + 4) & ~3
        elif token == 2:
            if not stack:
                raise ValueError('unbalanced DTB node')
            stack.pop()
        elif token == 3:
            if not stack or offset + 8 > end:
                raise ValueError('invalid DTB property header')
            properties += 1
            if properties > MAX_DTB_PROPERTIES:
                raise ValueError('DTB property budget exceeded')
            size, nameoff = struct.unpack_from('>II', data, offset)
            offset += 8
            terminator = table.find(b'\0', nameoff, nameoff + MAX_DTB_NAME_BYTES + 1)
            if nameoff >= len(table) or terminator < 0 or offset + size > end:
                raise ValueError('invalid DTB property bounds/name budget')
            name = table[nameoff:terminator].decode('ascii')
            props = nodes['/'.join(stack)]
            if not name or name in props:
                raise ValueError('duplicate/empty DTB property')
            props[name] = data[offset:offset + size]
            offset = (offset + size + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            if stack or not nodes or any(data[offset:end]):
                raise ValueError('incomplete DTB structure')
            return nodes, total
        else:
            raise ValueError('invalid DTB structure token')
    raise ValueError('DTB end token missing')


def validate_kernel(compressed, compression, load, entry, kernel):
    if compression == 3:
        if len(compressed) < 13:
            raise ValueError('truncated LZMA kernel header')
        declared = int.from_bytes(compressed[5:13], 'little')
        if declared != 0xffffffffffffffff and not 0 < declared <= MAX_KERNEL_BYTES:
            raise ValueError('LZMA kernel declared output exceeds limit')
        try:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=LZMA_MEMORY_LIMIT)
            raw = decoder.decompress(compressed, max_length=MAX_KERNEL_BYTES + 1)
        except lzma.LZMAError as error:
            raise ValueError(f'LZMA kernel decompression failed: {error}') from error
        if len(raw) > MAX_KERNEL_BYTES:
            raise ValueError('LZMA kernel output exceeds limit')
        if not decoder.eof:
            raise ValueError('LZMA kernel stream is incomplete')
        padding = decoder.unused_data
        # Padavan mkimage aligns to16 with0xff; no second stream is permitted.
        if len(padding) > 15 or any(value != 0xff for value in padding):
            raise ValueError('unexpected data after LZMA kernel stream')
        if declared != 0xffffffffffffffff and declared != len(raw):
            raise ValueError('LZMA kernel output length mismatch')
    else:
        raw, padding = compressed, b''
        if len(raw) > MAX_KERNEL_BYTES:
            raise ValueError('uncompressed kernel exceeds limit')
    expected_load = {'4.4': 0x81001000, '3.4': 0x80001000}.get(kernel)
    if expected_load is None or load != expected_load:
        raise ValueError('unexpected K2P kernel load address/version')
    if len(raw) < 1024 or entry % 4 or not load <= entry <= load + len(raw) - 4:
        raise ValueError('kernel entry is outside its loaded image or unaligned')
    if raw[entry - load:entry - load + 4] == b'\0' * 4:
        raise ValueError('kernel entry points to empty instructions')
    if not re.search(rb'Linux version ' + re.escape(kernel.encode()) + rb'\.\d+\s', raw):
        raise ValueError('decompressed kernel version banner missing/mismatched')
    result = {'decompressed_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
              'padding_bytes': len(padding), 'entry_offset': entry - load,
              'dtb': None, 'embedded_config_sha256': None}
    if kernel == '3.4':
        # This legacy board uses compiled platform data; IKCONFIG is disabled.
        return result
    start, finish = raw.find(b'IKCFG_ST'), raw.find(b'IKCFG_ED')
    if start < 0 or finish <= start + 8 or raw.count(b'IKCFG_ST') != 1:
        raise ValueError('embedded kernel configuration missing/ambiguous')
    decoder = zlib.decompressobj(31)
    try:
        config = decoder.decompress(raw[start + 8:finish], MAX_CONFIG_BYTES + 1)
    except zlib.error as error:
        raise ValueError(f'embedded kernel configuration gzip invalid: {error}') from error
    if len(config) > MAX_CONFIG_BYTES or not decoder.eof or decoder.unused_data:
        raise ValueError('embedded kernel configuration incomplete/oversized')
    required = (b'CONFIG_MIPS=y', b'CONFIG_CPU_LITTLE_ENDIAN=y', b'CONFIG_SOC_MT7621=y',
                b'CONFIG_BUILTIN_DTB=y', b'CONFIG_RALINK_BUILTIN_DTB_NAME="k2p"', b'CONFIG_BOOT_RAW=y')
    if any(item not in config.splitlines() for item in required):
        raise ValueError('embedded kernel configuration does not match K2P4.4 layout')
    result['embedded_config_sha256'] = hashlib.sha256(config).hexdigest()
    magic = b'\xd0\x0d\xfe\xed'
    position = raw.find(magic)
    if position < 0 or raw.find(magic, position + 1) >= 0:
        raise ValueError('expected one builtin K2P DTB')
    nodes, size = parse_dtb(raw[position:])
    if nodes[''].get('model') != b'Phicomm K2P\0' or b'mediatek,mt7621-soc\0' not in nodes[''].get('compatible', b''):
        raise ValueError('builtin DTB is not the K2P/MT7621 board')
    partitions = {}
    for props in nodes.values():
        if 'label' in props and 'reg' in props and len(props['reg']) == 8:
            label = props['label'].rstrip(b'\0').decode('ascii')
            if label in partitions:
                raise ValueError('duplicate DTB partition label')
            partitions[label] = list(struct.unpack('>II', props['reg']))
    expected = {'Bootloader': [0, 0x30000], 'Config': [0x30000, 0x10000],
                'Factory': [0x40000, 0x10000], 'firmware': [0x50000, FIRMWARE_LIMIT],
                'Storage': [0xf80000, 0x80000], 'ALL': [0, 0x1000000]}
    if any(partitions.get(name) != region for name, region in expected.items()):
        raise ValueError('builtin DTB flash partition layout mismatch')
    result['dtb'] = {'offset': position, 'bytes': size, 'nodes': len(nodes), 'partitions': partitions}
    return result


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
    kernel_info = validate_kernel(data[64:kernel_size], data[31], load, entry, kernel_version)
    return dict(product=image_product, kernel=kernel_version, bytes=len(data),
                partition_bytes=limit, spare_bytes=limit-len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                header_crc=f'{header_crc:08x}', payload_crc=f'{data_crc:08x}',
                kernel_bytes=kernel_size, timestamp=timestamp,
                load_address=f'0x{load:08x}', entry_address=f'0x{entry:08x}',
                kernel_validation=kernel_info)


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
