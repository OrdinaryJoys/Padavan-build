import hashlib
import json
import os
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

    def baseline_fetch(self, flavor='k2p-4.4', fault=''):
        """Execute the actual fetch block with inert Git, before a suite marker."""
        script = Path(__file__).with_name('build_k2p.sh').read_text()
        marker = '# The full SPI queue suite independently compares its literal negative control'
        start = script.index(marker)
        end = script.index('build_commit=$(git -C "$root" rev-parse HEAD)', start)
        self.assertLess(end, script.index('TMPDIR=/tmp python3 -m unittest discover'))
        block = script[start:end]
        self.assertEqual(block.count('regression_baseline=3af01e18af99e4329a65636f6e854fedf94a9fc3'), 1)
        tools = self.root / 'inert-tools'
        tools.mkdir(exist_ok=True)
        git = tools / 'git'
        git.write_text('''#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
with open(os.environ['FETCH_LOG'],'a') as log:log.write(json.dumps(args)+'\\n')
fault=os.environ['FETCH_FAULT']
if args[2]=='fetch':sys.exit(1 if fault=='fetch' else 0)
if args[2]=='cat-file':sys.exit(1 if fault=='missing' else 0)
if args[2]=='rev-parse':
    value=('0'*40 if fault=='wrong-fetch' else '3af01e18af99e4329a65636f6e854fedf94a9fc3') if args[3]=='--verify' else ('0'*40 if fault=='changed-head' else '6e91276a33d1bd83d416fc8253feb01f30677743')
    print(value);sys.exit(0)
raise SystemExit('Unexpected Git call')
''')
        git.chmod(0o755)
        log = self.root / ('fetch-' + flavor + '-' + fault + '.jsonl')
        suite = self.root / ('suite-' + flavor + '-' + fault)
        env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                   FETCH_LOG=str(log), FETCH_FAULT=fault, root=str(self.root), flavor=flavor,
                   source_commit='6e91276a33d1bd83d416fc8253feb01f30677743', SUITE_MARKER=str(suite))
        result = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + block + '\ntouch "$SUITE_MARKER"\n'],
                                env=env, capture_output=True, text=True, timeout=10)
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, calls, suite.exists()

    def test_pinned_queue_baseline_fetch_precedes_suite_and_preserves_candidate_head(self):
        result, calls, suite = self.baseline_fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(suite)
        prefix = ['-C', str(self.root / 'source')]
        baseline = '3af01e18af99e4329a65636f6e854fedf94a9fc3'
        self.assertEqual(calls, [prefix + ['fetch', '--no-tags', '--depth=1', 'origin', baseline],
                                prefix + ['rev-parse', '--verify', 'FETCH_HEAD^{commit}'],
                                prefix + ['cat-file', '-e', baseline + '^{commit}'],
                                prefix + ['rev-parse', 'HEAD']])

    def test_failed_or_wrong_baseline_or_changed_candidate_stops_before_suite(self):
        for fault, expected_calls in (('fetch', 1), ('wrong-fetch', 2), ('missing', 3), ('changed-head', 4)):
            with self.subTest(fault=fault):
                result, calls, suite = self.baseline_fetch(fault=fault)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), expected_calls)
                self.assertFalse(suite)

    def test_susu_does_not_fetch_the_44_regression_baseline(self):
        result, calls, suite = self.baseline_fetch(flavor='k2p-susu')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])
        self.assertTrue(suite)


if __name__ == '__main__':
    unittest.main()
