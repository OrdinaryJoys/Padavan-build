import importlib.util
import pathlib
import struct
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


if __name__ == '__main__':
    unittest.main()
