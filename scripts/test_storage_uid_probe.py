"""Real Linux uid/capability drop controls before the expensive target build."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith('linux'), 'Real Linux UID/capability probe requires Linux')
class StorageUIDProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='test-k2p-uid-', dir='/tmp')
        cls.root = Path(cls.temp.name)
        cls.root.chmod(0o755)
        cls.probe = cls.root / 'probe'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
                        str(Path(__file__).with_name('storage_uid_probe.c')), '-o', str(cls.probe)],
                       check=True, capture_output=True)
        cls.public = cls.root / 'public'
        cls.public.write_bytes(b'public DNS fixture\n'); cls.public.chmod(0o644)
        cls.secret = cls.root / 'secret'
        cls.secret.write_bytes(b'synthetic secret\n'); cls.secret.chmod(0o600)
        cls.parent = cls.root / 'private-parent'; cls.parent.mkdir(mode=0o700)
        (cls.parent / 'public').write_bytes(b'public DNS fixture\n')
        (cls.parent / 'public').chmod(0o644)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def read_as_uid99(self, path):
        prefix = [] if os.geteuid() == 0 else ['sudo', '-n']
        return subprocess.run([*prefix, str(self.probe), '/bin/cat', str(path)],
                              capture_output=True, timeout=10)

    def test_real_uid99_with_no_caps_reads_public_file(self):
        result = self.read_as_uid99(self.public)
        self.assertEqual((result.returncode, result.stdout), (0, b'public DNS fixture\n'), result.stderr)

    def test_real_uid99_private_file_read_is_denied(self):
        result = self.read_as_uid99(self.secret)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(result.stdout)
        self.assertIn(b'Permission denied', result.stderr)

    def test_real_uid99_private_parent_read_is_denied(self):
        result = self.read_as_uid99(self.parent / 'public')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(result.stdout)
        self.assertIn(b'Permission denied', result.stderr)


if __name__ == '__main__':
    unittest.main()
