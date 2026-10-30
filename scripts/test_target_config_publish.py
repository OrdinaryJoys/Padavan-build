"""The privileged target worker must refuse host/global mount changes."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('target_config', Path(__file__).with_name('check_target_config_publish.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class TargetConfigNamespaceGuards(unittest.TestCase):
    def test_initial_mount_namespace_is_rejected_before_any_mount(self):
        with mock.patch.object(checker.sys, 'platform', 'linux'), \
             mock.patch.object(checker.os, 'geteuid', return_value=0), \
             mock.patch.object(checker.os, 'stat', return_value=SimpleNamespace(st_ino=1)), \
             mock.patch.object(checker.subprocess, 'run') as execute:
            with self.assertRaisesRegex(RuntimeError, 'initial mount namespace'):
                checker.worker(Path('/source'), Path('/runtime'), Path('/output'))
            execute.assert_not_called()

    def test_shared_mount_propagation_is_rejected_before_any_mount(self):
        with mock.patch.object(checker.sys, 'platform', 'linux'), \
             mock.patch.object(checker.os, 'geteuid', return_value=0), \
             mock.patch.object(checker.os, 'stat', side_effect=[SimpleNamespace(st_ino=2), SimpleNamespace(st_ino=1)]), \
             mock.patch.object(Path, 'read_text', return_value='1 0 0:1 / / rw shared:1 - rootfs rootfs rw\n'), \
             mock.patch.object(checker.subprocess, 'run') as execute:
            with self.assertRaisesRegex(RuntimeError, 'Private mount propagation'):
                checker.worker(Path('/source'), Path('/runtime'), Path('/output'))
            execute.assert_not_called()

    def test_parent_does_not_hide_its_own_input_under_tmp(self):
        args = ['check', '--rootfs', '/tmp/source', '--sysroot', '/runtime', '--output', '/output']
        with mock.patch.object(checker.sys, 'platform', 'linux'), \
             mock.patch.object(checker.sys, 'argv', args), \
             mock.patch.object(Path, 'resolve', lambda self: self), \
             mock.patch.object(checker.subprocess, 'run') as execute:
            with self.assertRaisesRegex(RuntimeError, 'may not live under /tmp'):
                checker.main()
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
