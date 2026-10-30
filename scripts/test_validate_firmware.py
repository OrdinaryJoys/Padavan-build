import importlib.util
import hashlib
import gzip
import lzma
import os
import pathlib
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import zlib

spec = importlib.util.spec_from_file_location('validator', pathlib.Path(__file__).with_name('validate_firmware.py'))
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def checksums(data):
    struct.pack_into('>I', data, 24, zlib.crc32(data[64:]) & 0xffffffff)
    data[4:8] = b'\0' * 4
    struct.pack_into('>I', data, 4, zlib.crc32(data[:64]) & 0xffffffff)
    return data


def dtb(firmware_offset=0x50000):
    strings, tree = bytearray(), bytearray()
    def node(name):
        tree.extend(struct.pack('>I', 1) + name.encode() + b'\0')
        tree.extend(b'\0' * (-len(tree) % 4))
    def prop(name, payload):
        offset = len(strings); strings.extend(name.encode() + b'\0')
        tree.extend(struct.pack('>III', 3, len(payload), offset) + payload)
        tree.extend(b'\0' * (-len(tree) % 4))
    def end():
        tree.extend(struct.pack('>I', 2))
    node(''); prop('model', b'Phicomm K2P\0'); prop('compatible', b'mediatek,mt7621-soc\0')
    node('spi'); node('flash')
    for index, (name, start, size) in enumerate([
        ('Bootloader', 0, 0x30000), ('Config', 0x30000, 0x10000),
        ('Factory', 0x40000, 0x10000), ('firmware', firmware_offset, validator.FIRMWARE_LIMIT),
        ('Storage', 0xf80000, 0x80000), ('ALL', 0, 0x1000000)]):
        node('partition@' + str(index)); prop('label', name.encode() + b'\0')
        prop('reg', struct.pack('>II', start, size)); end()
    end(); end(); end(); tree.extend(struct.pack('>I', 9))
    return struct.pack('>10I', 0xd00dfeed, 56 + len(tree) + len(strings), 56,
                       56 + len(tree), 40, 17, 16, 0, len(strings), len(tree)) + b'\0' * 16 + tree + strings


def raw_kernel(kernel='4.4', board_dtb=None, config=None):
    raw = bytearray(8192)
    raw[256:260] = b'\x27\xbd\xff\xe0'
    banner = ('Linux version ' + kernel + '.198 fixture\0').encode()
    raw[512:512 + len(banner)] = banner
    if kernel == '4.4':
        config = config if config is not None else b'\n'.join([
            b'CONFIG_MIPS=y', b'CONFIG_CPU_LITTLE_ENDIAN=y', b'CONFIG_SOC_MT7621=y',
            b'CONFIG_BUILTIN_DTB=y', b'CONFIG_RALINK_BUILTIN_DTB_NAME="k2p"', b'CONFIG_BOOT_RAW=y']) + b'\n'
        blob = b'IKCFG_ST' + gzip.compress(config, mtime=0) + b'IKCFG_ED'
        raw[2048:2048 + len(blob)] = blob
        blob = board_dtb if board_dtb is not None else dtb()
        raw[4096:4096 + len(blob)] = blob
    return raw


def image(kernel='4.4', raw=None, compression=3):
    raw = raw if raw is not None else raw_kernel(kernel)
    compressed = lzma.compress(bytes(raw), format=lzma.FORMAT_ALONE) if compression == 3 else raw
    compressed += b'\xff' * (-len(compressed) % 16) if compression == 3 else b''
    boundary = 64 + len(compressed)
    data = bytearray(boundary + 64)
    load = 0x81001000 if kernel == '4.4' else 0x80001000
    struct.pack_into('>7I', data, 0, 0x27051956, 0, 0, len(data) - 64, load, load + 256, 0)
    major, minor = map(int, kernel.split('.'))
    data[28:36] = bytes([5, 5, 2, compression, major, minor, 198, 9])
    data[36:39] = b'K2P'
    struct.pack_into('>I', data, 60, boundary)
    data[64:boundary] = compressed
    data[boundary:boundary + 4] = b'hsqs'
    return checksums(data)


class ValidationTests(unittest.TestCase):
    def test_valid_padavan_header(self):
        self.assertEqual(validator.validate(image(), kernel='4.4')['product'], 'K2P')

    def test_corrupt_header(self):
        data = image(); data[16] ^= 1
        with self.assertRaisesRegex(ValueError, 'header CRC'):
            validator.validate(data)

    def test_corrupt_payload(self):
        data = image(); data[120] ^= 1
        with self.assertRaisesRegex(ValueError, 'payload CRC'):
            validator.validate(data)

    def test_wrong_product_with_valid_crc(self):
        data = image(); data[36:39] = b'K3P'
        with self.assertRaisesRegex(ValueError, 'product is'):
            validator.validate(checksums(data))

    def test_oversized_partition(self):
        with self.assertRaisesRegex(ValueError, 'exceeds partition'):
            validator.validate(image(), limit=len(image()) - 1)

    def test_truncated_payload(self):
        with self.assertRaisesRegex(ValueError, 'payload length'):
            validator.validate(image()[:-1])

    def test_wrong_kernel_with_valid_crc(self):
        with self.assertRaisesRegex(ValueError, 'kernel is'):
            validator.validate(image(), kernel='3.4')

    def test_wrong_rootfs_boundary_with_valid_crc(self):
        data = image(); struct.pack_into('>I', data, 60, 100)
        with self.assertRaisesRegex(ValueError, 'SquashFS rootfs'):
            validator.validate(checksums(data))

    def test_susu_without_dtb_or_ikconfig_remains_supported(self):
        result = validator.validate(image('3.4'), kernel='3.4')
        self.assertIsNone(result['kernel_validation']['dtb'])
        self.assertEqual(result['kernel_validation']['decompressed_bytes'], 8192)

    def test_uncompressed_kernel_is_checked(self):
        self.assertEqual(validator.validate(image(compression=0))['kernel_validation']['decompressed_bytes'], 8192)

    def test_valid_crc_cannot_hide_broken_lzma(self):
        data = image(); data[77:85] = b'\xff' * 8
        with self.assertRaisesRegex(ValueError, 'LZMA kernel'):
            validator.validate(checksums(data))

    def test_truncated_lzma_with_repaired_crcs_is_rejected(self):
        data = image(); end = struct.unpack_from('>I', data, 60)[0]
        data[64:end] = data[64:64 + (end - 64) // 2] + b'\xff' * ((end - 64 + 1) // 2)
        with self.assertRaisesRegex(ValueError, 'LZMA kernel'):
            validator.validate(checksums(data))

    def test_dictionary_memory_limit_is_enforced(self):
        data = image(); data[65:69] = struct.pack('<I', 0x40000000)
        with self.assertRaisesRegex(ValueError, 'LZMA kernel decompression'):
            validator.validate(checksums(data))

    def test_output_limit_is_enforced(self):
        with mock.patch.object(validator, 'MAX_KERNEL_BYTES', 4096):
            with self.assertRaisesRegex(ValueError, 'output exceeds limit'):
                validator.validate(image())

    def test_lzma_declared_size_is_bounded(self):
        data = image(); data[69:77] = struct.pack('<Q', validator.MAX_KERNEL_BYTES + 1)
        with self.assertRaisesRegex(ValueError, 'declared output exceeds'):
            validator.validate(checksums(data))

    def test_trailing_lzma_garbage_is_rejected(self):
        data = image(); end = struct.unpack_from('>I', data, 60)[0]
        data[end - 1] = 0x55
        with self.assertRaisesRegex(ValueError, 'after LZMA'):
            validator.validate(checksums(data))

    def test_entry_outside_loaded_image_is_rejected(self):
        data = image(); struct.pack_into('>I', data, 20, 0x88000000)
        with self.assertRaisesRegex(ValueError, 'kernel entry'):
            validator.validate(checksums(data))

    def test_zero_instruction_entry_is_rejected(self):
        data = image(); struct.pack_into('>I', data, 20, 0x81001000)
        with self.assertRaisesRegex(ValueError, 'empty instructions'):
            validator.validate(checksums(data))

    def test_wrong_load_address_is_rejected(self):
        data = image(); struct.pack_into('>I', data, 16, 0x80001000)
        with self.assertRaisesRegex(ValueError, 'load address'):
            validator.validate(checksums(data))

    def test_wrong_board_partition_layout_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'partition layout'):
            validator.validate(image(raw=raw_kernel(board_dtb=dtb(0xa0000))))

    def test_missing_builtin_dtb_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'builtin K2P DTB'):
            validator.validate(image(raw=raw_kernel(board_dtb=b'')))

    def test_corrupt_dtb_structure_is_rejected(self):
        blob = bytearray(dtb()); struct.pack_into('>I', blob, 56, 0x12345678)
        with self.assertRaisesRegex(ValueError, 'DTB structure token'):
            validator.validate(image(raw=raw_kernel(board_dtb=blob)))

    def test_invalid_embedded_config_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'configuration does not match'):
            validator.validate(image(raw=raw_kernel(config=b'CONFIG_MIPS=y\n')))

    def test_second_fdt_magic_is_rejected(self):
        raw = raw_kernel(); raw[8000:8004] = b'\xd0\x0d\xfe\xed'
        with self.assertRaisesRegex(ValueError, 'one builtin K2P DTB'):
            validator.validate(image(raw=raw))


class DTBResourceTests(unittest.TestCase):
    @staticmethod
    def node(name):
        payload = struct.pack('>I', 1) + name.encode() + b'\0'
        return payload + b'\0' * (-len(payload) % 4)

    @staticmethod
    def blob(tree, strings=b'property\0'):
        tree += struct.pack('>I', 9)
        return struct.pack('>10I', 0xd00dfeed, 56 + len(tree) + len(strings), 56,
                           56 + len(tree), 40, 17, 16, 0, len(strings), len(tree)) + b'\0' * 16 + tree + strings

    def chain(self, depth, name='n'):
        return self.node('') + self.node(name) * (depth - 1) + struct.pack('>I', 2) * depth

    def test_depth64_is_accepted(self):
        nodes, _ = validator.parse_dtb(self.blob(self.chain(64)))
        self.assertEqual(len(nodes), 64)

    def test_depth65_is_rejected_without_large_input(self):
        with self.assertRaisesRegex(ValueError, 'depth/node budget'):
            validator.parse_dtb(self.blob(self.chain(65)))

    def test_node_budget_is_enforced_with_small_control(self):
        tree = self.node('')
        for name in ('a', 'b', 'c'):
            tree += self.node(name) + struct.pack('>I', 2)
        tree += struct.pack('>I', 2)
        with mock.patch.object(validator, 'MAX_DTB_NODES', 3):
            with self.assertRaisesRegex(ValueError, 'depth/node budget'):
                validator.parse_dtb(self.blob(tree))

    def test_property_budget_is_global_across_nodes(self):
        prop_a = struct.pack('>III', 3, 0, 0)
        prop_b = struct.pack('>III', 3, 0, 2)
        tree = self.node('') + prop_a + self.node('child') + prop_a + struct.pack('>I', 2) + prop_b + struct.pack('>I', 2)
        with mock.patch.object(validator, 'MAX_DTB_PROPERTIES', 2):
            with self.assertRaisesRegex(ValueError, 'property budget'):
                validator.parse_dtb(self.blob(tree, b'a\0b\0'))

    def test_node_name255_is_accepted(self):
        nodes, _ = validator.parse_dtb(self.blob(self.chain(2, 'x' * 255)))
        self.assertEqual(len(nodes), 2)

    def test_node_name256_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'node name too long'):
            validator.parse_dtb(self.blob(self.chain(2, 'x' * 256)))

    def test_property_name255_is_accepted(self):
        tree = self.node('') + struct.pack('>III', 3, 0, 0) + struct.pack('>I', 2)
        nodes, _ = validator.parse_dtb(self.blob(tree, b'x' * 255 + b'\0'))
        self.assertIn('x' * 255, nodes[''])

    def test_property_name256_is_rejected(self):
        tree = self.node('') + struct.pack('>III', 3, 0, 0) + struct.pack('>I', 2)
        with self.assertRaisesRegex(ValueError, 'property bounds/name budget'):
            validator.parse_dtb(self.blob(tree, b'x' * 256 + b'\0'))

    def test_path2048_is_accepted(self):
        nodes, _ = validator.parse_dtb(self.blob(self.chain(9, 'x' * 255)))
        self.assertEqual(max(map(len, nodes)), 2048)

    def test_path_over2048_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'path budget'):
            validator.parse_dtb(self.blob(self.chain(10, 'x' * 255)))


class RootfsListingTests(unittest.TestCase):
    def test_duplicate_paths_are_rejected(self):
        line = '-rwxr-xr-x 0/0 10 2026-10-21 15:25 squashfs-root/init\n'
        with self.assertRaisesRegex(ValueError, 'duplicate SquashFS path'):
            validator.parse_rootfs_listing(line + line)

    def test_parent_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unsafe SquashFS path'):
            validator.parse_rootfs_listing(
                '-rwxr-xr-x 0/0 10 2026-10-21 15:25 squashfs-root/../init\n')

    def test_symlink_cannot_escape_image_root(self):
        entries = {'init': {'mode': 'lrwxrwxrwx', 'target': '../sbin/rc'}}
        with self.assertRaisesRegex(ValueError, 'escapes root'):
            validator.resolve_rootfs_path(entries, 'init')

    def test_symlink_loop_is_rejected(self):
        entries = {'init': {'mode': 'lrwxrwxrwx', 'target': 'init'}}
        with self.assertRaisesRegex(ValueError, 'symlink loop'):
            validator.resolve_rootfs_path(entries, 'init')


@unittest.skipUnless(shutil.which('mksquashfs') and shutil.which('unsquashfs'),
                     'SquashFS tools are required for compressed image regressions')
class RootfsImageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='test-k2p-rootfs-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)
        self.root = self.directory / 'root'
        for name in validator.REQUIRED_EXECUTABLES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('executable ' + name).encode())
            path.chmod(0o755)
        (self.root / 'init').symlink_to('sbin/rc')
        ca = self.root / 'etc_ro/ca-certificates.crt'
        ca.parent.mkdir(parents=True, exist_ok=True)
        ca.write_bytes(b'fixture CA bytes')
        self.ca_sha256 = hashlib.sha256(ca.read_bytes()).hexdigest()

    def squashfs(self):
        image_path = self.directory / 'image.squashfs'
        subprocess.run(['mksquashfs', str(self.root), str(image_path),
                        '-noappend', '-no-progress', '-processors', '1',
                        '-no-xattrs', '-all-root'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return image_path.read_bytes()

    def validate(self):
        return validator.validate_rootfs(self.squashfs(), self.ca_sha256)

    def test_shipped_contents_are_read(self):
        result = self.validate()
        self.assertEqual(result['ca_sha256'], self.ca_sha256)
        self.assertTrue(result['init_matches_rc'])
        self.assertEqual(result['regular_files_read'], len(validator.REQUIRED_EXECUTABLES) + 1)

    def test_non_executable_auth_helper_is_rejected(self):
        (self.root / 'usr/libexec/sshd-auth').chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'non-executable'):
            self.validate()

    def test_empty_auth_helper_is_rejected(self):
        (self.root / 'usr/libexec/sshd-session').write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'empty required file'):
            self.validate()

    def test_missing_storage_validator_is_rejected(self):
        (self.root / 'sbin/storage_validate').unlink()
        with self.assertRaisesRegex(ValueError, 'missing SquashFS path: sbin/storage_validate'):
            self.validate()

    def test_missing_management_server_is_rejected(self):
        (self.root / 'usr/sbin/httpd').unlink()
        with self.assertRaisesRegex(ValueError, 'missing SquashFS path: usr/sbin/httpd'):
            self.validate()

    def test_changed_shipped_ca_is_rejected(self):
        (self.root / 'etc_ro/ca-certificates.crt').write_bytes(b'wrong CA')
        with self.assertRaisesRegex(ValueError, 'CA certificate SHA256 mismatch'):
            self.validate()

    def test_wrong_init_copy_is_rejected(self):
        (self.root / 'init').unlink()
        (self.root / 'init').write_bytes(b'wrong executable')
        (self.root / 'init').chmod(0o755)
        with self.assertRaisesRegex(ValueError, '/init contents differ'):
            self.validate()

    def test_missing_symlink_target_is_rejected(self):
        (self.root / 'init').unlink()
        (self.root / 'init').symlink_to('sbin/missing')
        with self.assertRaisesRegex(ValueError, 'missing SquashFS path'):
            self.validate()

    def test_absolute_image_link_is_accepted(self):
        (self.root / 'init').unlink()
        (self.root / 'init').symlink_to('/sbin/rc')
        self.assertTrue(self.validate()['init_matches_rc'])

    def test_legal_hardlink_is_accepted(self):
        (self.root / 'init').unlink()
        os.link(self.root / 'sbin/rc', self.root / 'init')
        self.assertTrue(self.validate()['init_matches_rc'])

    def test_truncated_squashfs_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SquashFS read failed'):
            validator.validate_rootfs(self.squashfs()[:96], self.ca_sha256)


if __name__ == '__main__':
    unittest.main()
