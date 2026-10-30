"""Isolation preserves target file bytes/modes without relying on checkout rx."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('storage', Path(__file__).with_name('check_target_storage.py'))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class UIDRuntimeCopyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'private-checkout'; self.source.mkdir(mode=0o700)
        for name in ('bin', 'lib', 'usr/lib'):
            (self.source / name).mkdir(parents=True, mode=0o755)
        self.binary = self.source / 'bin/busybox'
        self.binary.write_bytes(b'synthetic target executable'); self.binary.chmod(0o755)
        self.loader = self.source / 'lib/ld-uClibc-test.so'
        self.loader.write_bytes(b'synthetic loader'); self.loader.chmod(0o755)
        (self.source / 'lib/ld-uClibc.so.0').symlink_to('/lib/ld-uClibc-test.so')
        (self.source / 'usr/lib/libfixture.so').symlink_to('../../lib/ld-uClibc-test.so')
        self.destination = self.base / 'public-fixture'; self.destination.mkdir(mode=0o755)

    def test_copy_preserves_bytes_modes_and_rebases_internal_links(self):
        runtime, records = storage.prepare_uid_runtime(self.source, self.source, self.destination)
        self.assertEqual((runtime / 'bin/busybox').read_bytes(), self.binary.read_bytes())
        self.assertEqual((runtime / 'bin/busybox').stat().st_mode & 0o777, 0o755)
        self.assertEqual((runtime / 'lib/ld-uClibc.so.0').read_bytes(), self.loader.read_bytes())
        self.assertEqual((runtime / 'usr/lib/libfixture.so').read_bytes(), self.loader.read_bytes())
        self.assertFalse(os.readlink(runtime / 'lib/ld-uClibc.so.0').startswith('/'))
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o700)
        self.assertIn('bin/busybox', records)

    def test_nonpublic_busybox_mode_is_rejected_not_repaired(self):
        self.binary.chmod(0o750)
        with self.assertRaisesRegex(RuntimeError, 'publicly readable/executable'):
            storage.prepare_uid_runtime(self.source, self.source, self.destination)
        self.assertEqual(self.binary.stat().st_mode & 0o777, 0o750)

    def test_synthetic_runtime_remains_traversable_with_umask077(self):
        prior = os.umask(0o077)
        try:
            runtime, _ = storage.prepare_uid_runtime(self.source, self.source, self.destination)
        finally:
            os.umask(prior)
        for name in ('', 'bin', 'usr', 'lib', 'usr/lib'):
            self.assertEqual((runtime / name).stat().st_mode & 0o777, 0o755, name)

    def test_nonpublic_library_mode_is_rejected_not_repaired(self):
        self.loader.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError, 'unreadable or mode changed'):
            storage.prepare_uid_runtime(self.source, self.source, self.destination)

    def test_external_library_symlink_is_rejected(self):
        (self.source / 'lib/escape.so').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(RuntimeError, 'leaves copied runtime'):
            storage.prepare_uid_runtime(self.source, self.source, self.destination)

    def test_dangling_library_symlink_is_rejected(self):
        (self.source / 'lib/missing.so').symlink_to('missing-target.so')
        with self.assertRaisesRegex(RuntimeError, 'Invalid target library link'):
            storage.prepare_uid_runtime(self.source, self.source, self.destination)


if __name__ == '__main__':
    unittest.main()
