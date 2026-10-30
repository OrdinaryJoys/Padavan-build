import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='k2p-provenance-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.trees = {}
        for name in ('source', 'build'):
            tree = self.root / name
            subprocess.run(['git', 'init', '-q', str(tree)], check=True)
            (tree / 'tracked.c').write_text(name + ' input\n')
            subprocess.run(['git', '-C', str(tree), 'add', 'tracked.c'], check=True)
            subprocess.run(['git', '-C', str(tree), '-c', 'user.name=Fixture',
                            '-c', 'user.email=fixture@example.invalid',
                            '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture'], check=True)
            self.trees[name] = tree
        self.config = self.root / 'firmware.config'
        self.config.write_text('CONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')

    def snapshot(self, stage='validated_output'):
        script = Path(__file__).with_name('build_k2p.sh').read_text()
        start = script.index('  python3 - "$diagnostics/provenance.json"')
        start = script.index('\n', start) + 1
        code = script[start:script.index('\nPY\n', start)]
        commits = [subprocess.check_output(['git', '-C', str(self.trees[name]),
                                           'rev-parse', 'HEAD'], text=True).strip()
                   for name in ('source', 'build')]
        output = self.root / 'provenance.json'
        arguments = ['python3', '-', str(output), 'k2p-4.4', 'Fixture/source',
                     commits[0], commits[1], '4.4', 'a' * 64, 'candidate',
                     str(self.trees['source']), str(self.trees['build']),
                     str(self.config), stage]
        subprocess.run(arguments, input=code, text=True, check=True)
        return json.loads(output.read_text())

    def test_clean_commit_and_config_are_recorded(self):
        value = self.snapshot()
        self.assertFalse(value['source_worktree_dirty'])
        self.assertFalse(value['build_worktree_dirty'])
        self.assertEqual(value['firmware_config_sha256'], hashlib.sha256(self.config.read_bytes()).hexdigest())
        self.assertEqual(value['capture_stage'], 'validated_output')

    def test_changed_source_and_build_helpers_do_not_masquerade_as_head(self):
        for tree in self.trees.values():
            (tree / 'tracked.c').write_text('changed local implementation\n')
        value = self.snapshot()
        for name in ('source', 'build'):
            patch = (self.root / (name + '-worktree.patch')).read_bytes()
            self.assertTrue(value[name + '_worktree_dirty'])
            self.assertEqual(value[name + '_commit_role'], 'base_revision')
            self.assertIn(b'changed local implementation', patch)
            self.assertEqual(value[name + '_tracked_diff_sha256'], hashlib.sha256(patch).hexdigest())

    def test_untracked_inputs_mark_source_dirty(self):
        (self.trees['source'] / 'untracked-input.c').write_text('untracked source\n')
        value = self.snapshot()
        self.assertTrue(value['source_worktree_dirty'])
        self.assertIn('untracked-input.c', value['source_worktree_status'])

    def test_output_capture_preserves_configured_input(self):
        initial = self.snapshot('configured_input')
        self.config.write_text('CONFIG_FIRMWARE_PRODUCT_ID="K2P"\nCONFIG_CHANGED=y\n')
        final = self.snapshot('validated_output')
        recorded = json.loads((self.root / 'provenance.configured_input.json').read_text())
        self.assertEqual(recorded['firmware_config_sha256'], initial['firmware_config_sha256'])
        self.assertNotEqual(recorded['firmware_config_sha256'], final['firmware_config_sha256'])
        self.assertTrue((self.root / 'source-worktree.configured_input.patch').exists())


if __name__ == '__main__':
    unittest.main()
