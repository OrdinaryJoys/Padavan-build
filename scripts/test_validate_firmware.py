import importlib.util
import hashlib
import os
import pathlib
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib

spec = importlib.util.spec_from_file_location('validator', pathlib.Path(__file__).with_name('validate_firmware.py'))
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def checksums(data):
    struct.pack_into('>I', data, 24, zlib.crc32(data[64:]) & 0xffffffff)
    data[4:8] = b'\0' * 4
    struct.pack_into('>I', data, 4, zlib.crc32(data[:64]) & 0xffffffff)
    return data


def image():
    data = bytearray(160)
    struct.pack_into('>7I', data, 0, 0x27051956, 0, 0, 96, 0x81001000, 0x81001000, 0)
    data[28:36] = bytes([5, 5, 2, 3, 4, 4, 198, 9])
    data[36:39] = b'K2P'
    struct.pack_into('>I', data, 60, 96)
    data[96:100] = b'hsqs'
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
            validator.validate(image(), limit=159)

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
