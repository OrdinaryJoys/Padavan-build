#!/usr/bin/env python3
"""Validate the actual Padavan mkimage header before accepting an artifact."""
import argparse
import hashlib
import json
import pathlib
import struct
import zlib

FIRMWARE_LIMIT = 15_925_248


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
    args = parser.parse_args()
    try:
        result = validate(args.image.read_bytes(), kernel=args.kernel)
    except (ValueError, UnicodeError) as error:
        parser.exit(1, f'Firmware validation failed: {error}\n')
    result['file'] = args.image.name
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
