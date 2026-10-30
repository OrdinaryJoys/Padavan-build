"""Profile routing must never turn missing4.4 permission coverage into PASS."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('storage', Path(__file__).with_name('check_target_storage.py'))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class TargetStorageProfileTests(unittest.TestCase):
    def test_44_requires_permission_backend(self):
        with mock.patch.object(storage, 'check_storage_access', return_value=[{'fixture': 'actual-target'}]) as backend:
            result = storage.permission_profile('k2p-4.4', Path('/rootfs'), Path('/libs'), Path('/fixture'))
        backend.assert_called_once_with(Path('/rootfs'), Path('/libs'), Path('/fixture'))
        self.assertEqual(result['new_permission_gate'], 'passed')
        self.assertEqual(result['checks'], [{'fixture': 'actual-target'}])

    def test_legacy_susu_is_explicitly_unfixed_not_a_permission_pass(self):
        with mock.patch.object(storage, 'check_storage_access', side_effect=AssertionError('must not invoke')):
            result = storage.permission_profile('k2p-susu', Path('/rootfs'), Path('/libs'), Path('/fixture'))
        self.assertEqual(result['new_permission_gate'], 'not-run-unfixed-legacy-source')
        self.assertEqual(result['checks'], [])
        self.assertTrue(result['known_limitations'])

    def test_old_44_without_migration_helper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'sbin').mkdir()
            (root / 'sbin/mtd_storage.sh').write_text('func_install_tar()\n{\n return 0\n}\n')
            with mock.patch.object(storage.shutil, 'which', return_value='/usr/bin/qemu-mipsel'):
                with self.assertRaisesRegex(RuntimeError, 'func_dns_directory_access'):
                    storage.permission_profile('k2p-4.4', root, root, root)

    def test_unknown_profile_never_defaults_to_legacy(self):
        with self.assertRaisesRegex(ValueError, 'Unknown Storage'):
            storage.permission_profile('unknown', Path('/rootfs'), Path('/libs'), Path('/fixture'))

    def test_runner_owned_initial_tree_is_rejected_and_mkdir_uses_root(self):
        calls = []
        def run(arguments, **options):
            calls.append(arguments)
            metadata = b'755:1001:2\n' if 'stat' in arguments else b''
            return subprocess.CompletedProcess(arguments, 0, metadata, b'')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'sbin').mkdir()
            (root / 'sbin/mtd_storage.sh').write_text(
                'func_dns_directory_access()\n{\n return 0\n}\n'
                'func_install_tar()\n{\n return 0\n}\n')
            with mock.patch.object(storage.os, 'geteuid', return_value=1001), \
                 mock.patch.object(storage.shutil, 'which', return_value='/usr/bin/qemu-mipsel'), \
                 mock.patch.object(storage.subprocess, 'run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'initial fixture directory is not root0755'):
                    storage.check_storage_access(root, root, root)
        mkdir = [arguments for arguments in calls if 'mkdir' in arguments]
        self.assertEqual(len(mkdir), 1)
        self.assertEqual(mkdir[0][:3], ['sudo', '-n', '/usr/bin/qemu-mipsel'])
        self.assertIn(str(root / 'bin/busybox'), mkdir[0])


if __name__ == '__main__':
    unittest.main()
