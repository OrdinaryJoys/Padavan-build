import hashlib
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
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
        self.assertIn('for regression_baseline in 3af01e18af99e4329a65636f6e854fedf94a9fc3', block)
        self.assertEqual(block.count('3a404e1675467cab79af0ffac454061c1e9150ae'), 1)
        self.assertEqual(block.count('3ba292933a5cdbcaac3d5187d2454b387fbfbcc1'), 1)
        tools = self.root / 'inert-tools'
        tools.mkdir(exist_ok=True)
        git = tools / 'git'
        git.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open(os.environ['FETCH_LOG'],'a') as log:log.write(json.dumps(args)+'\\n')
state=Path(os.environ['FETCH_LOG']+'.state')
fault=os.environ['FETCH_FAULT']
if args[2]=='fetch':
    state.write_text(args[-1])
active=(not fault.startswith(('second-','third-')) or fault.startswith('second-') and state.read_text()=='3a404e1675467cab79af0ffac454061c1e9150ae' or fault.startswith('third-') and state.read_text()=='3ba292933a5cdbcaac3d5187d2454b387fbfbcc1')
fault=fault.removeprefix('second-').removeprefix('third-') if active else ''
if args[2]=='fetch':sys.exit(1 if fault=='fetch' else 0)
if args[2]=='cat-file':sys.exit(1 if fault=='missing' else 0)
if args[2]=='rev-parse':
    value=('0'*40 if fault=='wrong-fetch' else state.read_text()) if args[3]=='--verify' else ('0'*40 if fault=='changed-head' else '6e91276a33d1bd83d416fc8253feb01f30677743')
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
        expected=[]
        for baseline in ('3af01e18af99e4329a65636f6e854fedf94a9fc3',
                         '3a404e1675467cab79af0ffac454061c1e9150ae',
                         '3ba292933a5cdbcaac3d5187d2454b387fbfbcc1'):
            expected += [prefix + ['fetch', '--no-tags', '--depth=1', 'origin', baseline],
                         prefix + ['rev-parse', '--verify', 'FETCH_HEAD^{commit}'],
                         prefix + ['cat-file', '-e', baseline + '^{commit}'],
                         prefix + ['rev-parse', 'HEAD']]
        self.assertEqual(calls, expected)

    def test_failed_or_wrong_baseline_or_changed_candidate_stops_before_suite(self):
        for stage in ('','second-','third-'):
            for fault, expected_calls in (('fetch', 1), ('wrong-fetch', 2), ('missing', 3), ('changed-head', 4)):
                with self.subTest(fault=stage+fault):
                    result, calls, suite = self.baseline_fetch(fault=stage+fault)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(len(calls), expected_calls + (8 if stage=='third-'else 4 if stage else 0))
                    self.assertFalse(suite)

    def test_susu_does_not_fetch_the_44_regression_baseline(self):
        result, calls, suite = self.baseline_fetch(flavor='k2p-susu')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])
        self.assertTrue(suite)

    def new_target_gate_block(self, late=False, fault='', missing_parent=''):
        """Run the production shell block with inert compiler/gate entrypoints."""
        script=Path(__file__).with_name('build_k2p.sh').read_text()
        marker='  for extra_gate in controller_clock spi_dma spi_lifecycle nvram_mtd; do'
        start=script.index(marker,script.index('images=(') if late else 0)
        end=script.index('  python3 "$root/scripts/check_target_mtd_backup.py"',start)
        if not late:end=script.rfind('  test -f ',start,end)
        block=script[start:end]
        tools=self.root/'gate-tools';tools.mkdir(exist_ok=True)
        entry=tools/'python3'
        entry.write_text('#!'+sys.executable+'''\n
import json,os,sys
from pathlib import Path
with open(os.environ['GATE_LOG'],'a') as log:log.write(json.dumps(sys.argv[1:])+'\\n')
if '--preflight'not in sys.argv:
    required=('--wifi-report','--io-report')if 'check_target_wifi_calibration_integrity.py'in sys.argv[1]else('--wifi-report',)if any(name in sys.argv[1]for name in('check_target_wifi_file_io.py','check_target_rx_transport.py'))else()
    if any(flag not in sys.argv or not Path(sys.argv[sys.argv.index(flag)+1]).is_file()for flag in required):sys.exit(97)
if '--output'in sys.argv:
    output=Path(sys.argv[sys.argv.index('--output')+1]);output.parent.mkdir(parents=True,exist_ok=True)
    if output.name!=os.environ['GATE_MISSING_PARENT']:output.write_text('inert-gate-output')
sys.exit(23 if os.environ['GATE_FAULT'] and os.environ['GATE_FAULT'] in sys.argv[1] else 0)
''')
        entry.chmod(0o755)
        for name in('target-wifi-factory.json','target-wifi-file-io.json','target-wifi-calibration-integrity.json','target-rx-transport.json'):
            (self.root/'diagnostics'/name).unlink(missing_ok=True)
        log=self.root/'gate-calls.jsonl';log.unlink(missing_ok=True)
        finished=self.root/'gate-finished';finished.unlink(missing_ok=True)
        env=dict(os.environ,PATH=str(tools)+os.pathsep+os.environ['PATH'],root=str(self.root),
                 trunk=str(self.root/'source/trunk'),toolchain=str(self.root/'compiler'),
                 diagnostics=str(self.root/'diagnostics'),GATE_LOG=str(log),GATE_FAULT=fault,GATE_MISSING_PARENT=missing_parent,
                 GATE_FINISHED=str(finished))
        result=subprocess.run(['bash','-c','set -euo pipefail\n'+block+'\ntouch "$GATE_FINISHED"\n'],
                              env=env,capture_output=True,text=True,timeout=10)
        calls=[json.loads(row)for row in log.read_text().splitlines()]
        return result,calls,finished.exists()

    def test_new_preflight_gates_are_mandatory_before_expensive_build(self):
        names=['controller_clock','spi_dma','spi_lifecycle','nvram_mtd','mtd_mutation','wifi_factory','wifi_file_io','wifi_calibration_integrity','rx_transport']
        result,calls,done=self.new_target_gate_block()
        self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(done)
        self.assertEqual([Path(call[0]).stem for call in calls],['check_target_'+name for name in names])
        self.assertTrue(all('--preflight'in call for call in calls))
        for i,name in enumerate(names):
            with self.subTest(gate=name):
                result,calls,done=self.new_target_gate_block(fault=name)
                self.assertEqual(result.returncode,23);self.assertEqual(len(calls),i+1);self.assertFalse(done)

        # Run the real mandatory source-file block, before the source suite marker.
        script=Path(__file__).with_name('build_k2p.sh').read_text()
        start=script.index('if [ "$flavor" = "k2p-4.4" ]; then',script.index('for required_test in test_independent_http_edges'))
        end=script.index('# Keep Linux /tmp rewriting',start);block=script[start:end]
        required=tuple(word.rstrip(';')for word in block.split()if word.startswith('test_'))
        self.assertIn('test_flash_persist',required);self.assertIn('test_mcu_precal',required)
        self.assertTrue({'test_cmd_queue','test_rx_transport','test_rx_pool','test_rx_startup'}<=set(required))
        tests=self.root/'source/tests';tests.mkdir(parents=True,exist_ok=True)
        for name in required:(tests/(name+'.py')).touch()
        marker=self.root/'source-suite-started'
        for missing in('', 'test_flash_persist','test_mcu_precal','test_cmd_queue','test_rx_transport','test_rx_pool','test_rx_startup'):
            marker.unlink(missing_ok=True)
            if missing:(tests/(missing+'.py')).unlink()
            result=subprocess.run(['bash','-c','set -euo pipefail\n'+block+'\ntouch "$SUITE_MARKER"\n'],
              env=dict(os.environ,root=str(self.root),flavor='k2p-4.4',SUITE_MARKER=str(marker)),capture_output=True,text=True,timeout=10)
            with self.subTest(missing_source=missing):
                self.assertEqual(result.returncode==0,not bool(missing));self.assertEqual(marker.exists(),not bool(missing))
            if missing:(tests/(missing+'.py')).touch()

    def test_late_gates_require_image_or_rootfs_binding_and_stop_publication_on_failure(self):
        names=['controller_clock','spi_dma','spi_lifecycle','nvram_mtd','mtd_mutation','wifi_factory','wifi_file_io','wifi_calibration_integrity','rx_transport']
        result,calls,done=self.new_target_gate_block(late=True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(done)
        self.assertEqual([Path(call[0]).stem for call in calls],['check_target_'+name for name in names])
        self.assertTrue(all('--preflight'not in call for call in calls))
        self.assertTrue(all('--spi-report'in call for call in calls[:4]+calls[5:6]))
        self.assertTrue(all('--rootfs'in call for call in calls[4:6]))
        self.assertIn('--wifi-report',calls[6])
        self.assertEqual(calls[6][calls[6].index('--wifi-report')+1],str(self.root/'diagnostics/target-wifi-factory.json'))
        self.assertEqual(calls[7][calls[7].index('--wifi-report')+1],str(self.root/'diagnostics/target-wifi-factory.json'))
        self.assertEqual(calls[7][calls[7].index('--io-report')+1],str(self.root/'diagnostics/target-wifi-file-io.json'))
        self.assertIn('--wifi-report',calls[8])
        self.assertEqual(calls[8][calls[8].index('--wifi-report')+1],str(self.root/'diagnostics/target-wifi-factory.json'))
        for missing,count in(('target-wifi-factory.json',7),('target-wifi-file-io.json',8)):
            result,missing_calls,done=self.new_target_gate_block(late=True,missing_parent=missing)
            self.assertEqual(result.returncode,97);self.assertEqual(len(missing_calls),count);self.assertFalse(done)
        for i,name in enumerate(names):
            with self.subTest(gate=name):
                result,calls,done=self.new_target_gate_block(late=True,fault=name)
                self.assertEqual(result.returncode,23);self.assertEqual(len(calls),i+1);self.assertFalse(done)

    def test_wifi_module_and_object_evidence_is_copied_into_firmware_artifact(self):
        script=Path(__file__).with_name('build_k2p.sh').read_text()
        lines=[line for line in script.splitlines()if line.startswith('  cp "$diagnostics/target-wifi-')]
        self.assertEqual(len(lines),1)
        tree=ast.parse(Path(__file__).with_name('check_target_wifi_factory.py').read_text())
        objects=[node.value for node in tree.body if isinstance(node,ast.Assign) and
                 any(isinstance(target,ast.Name)and target.id=='OBJECTS' for target in node.targets)]
        self.assertEqual(len(objects),1)
        labels=ast.literal_eval(objects[0])
        names={'target-wifi-built.ko','target-wifi-shipped.ko','target-wifi-module.cmd','target-wifi-link.cmd'}
        for label in labels:names.update(('target-wifi-'+label+'.o','target-wifi-'+label+'.cmd'))
        self.assertEqual(len(names),14)
        names.add('target-wifi-factory.json')
        for profile in('', '-baseline', '-disabled'):
            stem='target-wifi-factory'+profile;names.update((stem,stem+'.c'))
        io_tree=ast.parse(Path(__file__).with_name('check_target_wifi_file_io.py').read_text())
        extra=next(ast.literal_eval(node.value)for node in io_tree.body if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='EXTRA_OBJECTS'for t in node.targets))
        for label in extra:names.update(('target-wifi-io-'+label+'.o','target-wifi-io-'+label+'.cmd'))
        for group,components in(('file-io',('bin','cal','meta')),('calibration-integrity',('mcu','flash'))):
            names.add('target-wifi-'+group+'.json')
            for component in components:
                for profile in('current','baseline','disabled'):
                    stem='target-wifi-'+group+'-'+component+'-'+profile;names.update((stem,stem+'.c'))
        self.assertEqual(len(names),65)
        workflow=Path(__file__).parents[1]/'.github/workflows/new-build-padavan.yml'
        upload=workflow.read_text().split('      - name: Upload build diagnostics',1)[1]
        self.assertIn('if: always()',upload);self.assertIn('path: diagnostics/',upload)
        diagnostics=self.root/'diagnostics';dist=self.root/'dist';diagnostics.mkdir();dist.mkdir()
        for name in names:(diagnostics/name).write_bytes(('evidence:'+name).encode())
        (diagnostics/'unrelated.log').write_text('separate diagnostic')
        result=subprocess.run(['bash','-c','set -euo pipefail\n'+lines[0]],
            env=dict(os.environ,diagnostics=str(diagnostics),dist=str(dist)),capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual({path.name for path in dist.iterdir()},names)
        for name in names:self.assertEqual((dist/name).read_bytes(),(diagnostics/name).read_bytes())


if __name__ == '__main__':
    unittest.main()
