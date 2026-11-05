"""Private synthetic contracts and native bounded IO; never execute MIPS."""
import base64
import bz2
import contextlib
import copy
import errno
import gzip
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import check_target_storage_cache as cache


def synthetic_sources():
    functions = {
        'func_save': 'func_save()\n{\n\tfunc_invalidate_hash || return 1\n\tmtd_write write "$archive" "$mtd_part_name"\n\tfunc_record_hash\n}',
        'func_record_hash': 'func_record_hash()\n{\n\t/sbin/storage_validate --replace-file "$pending" "$hsh"\n}',
        'func_invalidate_hash': 'func_invalidate_hash()\n{\n\tif ! rm -f "$hsh" || [ -e "$hsh" ] || [ -L "$hsh" ]; then\n\t\treturn 1\n\tfi\n}',
        'func_erase': 'func_erase()\n{\n\tif ! func_invalidate_hash; then\n\t\tresult=1\n\t\treturn 1\n\tfi\n\tmtd_write erase "$mtd_part_name"\n}',
    }
    inputs = {key: ('/* synthetic '+key+' source, never compiled */\n').encode()
              for key in cache.SOURCE_PATHS}
    inputs['storage'] = ('\n\n'.join(functions[n] for n in cache.FUNCTION_NAMES)+'\n').encode()
    inputs['busybox_template'] = ('\n'.join(cache.REQUIRED_CONFIG)+'\n').encode()
    return inputs, functions


def raw_records():
    records = []
    for case in cache.expected_records():
        for row in case['phases']:
            stdout = 'BEGIN\n'
            if row['raw_exit'] != -9:
                if not row['backend_calls'] and row['raw_exit'] == 0:
                    stdout += cache.SKIP_TEXT
                stdout += 'RESULT:%s\nDISPATCH:%s\n' % (row['function_result'], row['dispatcher_result'])
            flash = (cache.PARTIAL_TEXT.encode() if row['flash_kind'] == 'partial'
                     else bz2.compress(cache.fixture_inputs()[row['flash_kind']], compresslevel=9))
            records.append({'case': case['case'], 'phase': row['phase'], 'raw_exit': row['raw_exit'],
                            'stdout': stdout, 'stderr': '', 'events': ''.join(e+'\n' for e in row['events']),
                            'cache': None if row['cache_state'] is None else cache.cache_content(row['cache_state']),
                            'flash_base64': base64.b64encode(flash).decode()})
    return records


class TargetStorageCacheTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='k2p-cache-contract-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    @contextlib.contextmanager
    def owned_processes(self, deny_owned_signal=False, reject_join=False):
        """Track real private native children and retain exact-owned cleanup."""
        real_popen = cache.subprocess.Popen
        rows = []
        with contextlib.ExitStack() as stack:
            def start(*args, **kwargs):
                self.assertIs(kwargs.get('start_new_session'), True)
                child = real_popen(*args, **kwargs)
                row = dict(child=child, real_kill=child.kill, real_wait=child.wait)
                row['kill'] = stack.enter_context(mock.patch.object(child, 'kill', wraps=row['real_kill']))
                row['wait'] = stack.enter_context(mock.patch.object(child, 'wait', wraps=row['real_wait']))
                if deny_owned_signal:
                    row['kill'].side_effect = PermissionError(errno.EPERM, 'injected owned-child signal denial')
                if reject_join:
                    row['wait'].side_effect = cache.subprocess.TimeoutExpired(child.args, 5)
                rows.append(row)
                return child
            stack.enter_context(mock.patch.object(cache.subprocess, 'Popen', side_effect=start))
            try:
                yield rows
            finally:
                # Fault injection must not leave even this private test child.
                for row in rows:
                    child = row['child']
                    try:
                        if child.poll() is None:
                            row['real_kill']()
                        row['real_wait'](timeout=5)
                    finally:
                        child.stdout.close();child.stderr.close()

    @contextlib.contextmanager
    def pins(self, inputs, functions=None):
        functions = functions or {n: cache.boot.shell_function(inputs['storage'].decode(), n)
                                  for n in cache.FUNCTION_NAMES}
        with mock.patch.object(cache, 'EXPECTED_SOURCE_SHA256', {k: cache.sha(v) for k, v in inputs.items()}), \
                mock.patch.object(cache, 'EXPECTED_FUNCTION_SHA256', {k: cache.sha(v.encode()) for k, v in functions.items()}):
            yield

    def parent_fixture(self):
        storage = {'rootfs_path': 'sbin/mtd_storage.sh', 'bytes': 123, 'sha256': 'a'*64, 'mode': '0o755'}
        dev_init = {'rootfs_path': 'sbin/dev_init.sh', 'bytes': 45, 'sha256': 'c'*64, 'mode': '0o755'}
        config = b'private synthetic compiled config\n'
        runtime = {'busybox': {'ELF': {'sha256': 'b'*64}},
                   'busybox_dynamic': {'interpreter': '/lib/ld-uClibc.so.0', 'needed': ['libc.so.0']},
                   'libraries': {'lib/libc.so.0': {'identity': 'private synthetic runtime'}}}
        parent = {'status': 'PASS', 'profile': 'k2p-4.4', 'phase': 'final-shipped-busybox-private-quota',
                  'required_cases': [r[0] for r in cache.boot.CASES], 'checks': cache.boot.expected_rows(),
                  'diagnostics': [{'case': n, 'stdout_sha256': cache.sha(b'ARMED\nCOMPLETE\n' if s == 0 else b'ARMED\n'),
                                   'stderr_bytes': 0, 'stderr_sha256': cache.sha(b'')}
                                  for n, _, _, s, _ in cache.boot.CASES],
                  'rootfs_scripts': {'storage': storage, 'dev_init': dev_init},
                  'source_sha256': {'storage': storage['sha256'], 'dev_init': dev_init['sha256']},
                  'compiled_busybox_config': {'file': 'target-boot-storage-busybox.config', 'sha256': cache.sha(config)},
                  'runtime': runtime}
        return copy.deepcopy(parent), storage, runtime, dev_init, config

    def runtime_fixture(self):
        roots = (self.root/'rootfs', self.root/'sysroot')
        for root in roots:
            for name in ('bin', 'sbin', 'usr', 'lib', 'usr/lib'):
                (root/name).mkdir(parents=True, exist_ok=True)
        return roots

    def test_literal_thirteen_cases_twenty_six_typed_phase_contract(self):
        cache.model_contract()
        self.assertEqual([n for n, _ in cache.CASES], ['same-A-skip', 'changed-B-success-then-skip',
            'prewrite-invalidate-error', 'partial-B-error-then-A', 'zero-write-error-then-A',
            'kill-before-write-then-A', 'kill-partial-B-then-A', 'kill-complete-B-then-B',
            'hash-stage-error-then-B', 'hash-publish-error-then-A', 'kill-before-publish-then-A',
            'kill-after-publish-then-B-skip', 'erase-partial-error-then-A'])
        self.assertEqual([len(p) for _, p in cache.CASES], [1, 2, 1, 3, 2, 2, 2, 2, 2, 2, 2, 2, 3])
        rows = cache.expected_records(); cache.validate_records(rows)
        self.assertEqual(sum(len(c['phases']) for c in rows), 26)
        for case in rows:
            for i, row in enumerate(case['phases'], 1):
                self.assertEqual(set(row), set(cache.ROW_FIELDS)); self.assertEqual(row['phase'], i)
                for key in ('phase', 'raw_exit', 'backend_calls'):
                    self.assertIs(type(row[key]), int)
        self.assertEqual([p['backend_calls'] for p in rows[-1]['phases']], [1, 1, 0])
        erase = rows[-1]['phases'][0]
        self.assertEqual((erase['operation'], erase['function_result'], erase['dispatcher_result']), ('erase', 1, 1))

    def test_fixed_rows_reject_count_order_duplicates_extra_and_bool_int(self):
        rows = cache.expected_records(); variants = [rows[:-1], list(reversed(rows)), rows+rows[:1]]
        wrong = copy.deepcopy(rows); wrong[1] = copy.deepcopy(wrong[0]); variants.append(wrong)
        wrong = copy.deepcopy(rows); wrong[0]['phases'] *= 2; variants.append(wrong)
        for key, value in [('phase', True), ('raw_exit', False), ('backend_calls', 0.0), ('extra', 1),
                           ('function_result', False), ('dispatcher_result', False),
                           ('stdout_sha256', '0'*64), ('stderr_sha256', '0'*64)]:
            wrong = copy.deepcopy(rows); wrong[0]['phases'][0][key] = value; variants.append(wrong)
        for wrong in variants:
            with self.assertRaises(ValueError): cache.validate_records(wrong)

    def test_complete_raw_recomputes_twenty_six_rows_and_preserves_kill_exit(self):
        records = raw_records()
        self.assertEqual(len(records), 26)
        self.assertEqual(cache.observe_raw(records), cache.expected_records())
        killed = [r for r in records if r['raw_exit'] == -9]
        self.assertEqual(len(killed), 5); self.assertTrue(all(r['stdout'] == 'BEGIN\n' for r in killed))
        self.assertIn('RESULT:1\nDISPATCH:1\n', records[-3]['stdout'])

    def test_raw_rejects_missing_reordered_duplicate_extra_and_field_types(self):
        rows = raw_records(); variants = [rows[:-1], rows+rows[:1], list(reversed(rows))]
        wrong = copy.deepcopy(rows); wrong[1] = copy.deepcopy(wrong[0]); variants.append(wrong)
        for key, value in [('case', 1), ('phase', True), ('raw_exit', False), ('raw_exit', 137),
                           ('stdout', b'BEGIN\n'), ('stderr', None), ('events', []), ('cache', True),
                           ('flash_base64', {}), ('extra', 1)]:
            wrong = copy.deepcopy(rows); wrong[0][key] = value; variants.append(wrong)
        wrong = copy.deepcopy(rows); del wrong[0]['stderr']; variants.append(wrong)
        for wrong in variants:
            with self.assertRaises(ValueError): cache.observe_raw(wrong)

    def test_complete_stdout_tail_and_small_diagnostics_are_never_discarded(self):
        rows = raw_records()
        for key, tail in [('stdout', 'unexpected tail\n'), ('stderr', 'warning\n'), ('events', 'extra:event\n')]:
            wrong = copy.deepcopy(rows); wrong[0][key] += tail
            with self.subTest(stream=key), self.assertRaises(ValueError): cache.observe_raw(wrong)
        wrong = copy.deepcopy(rows); wrong[-3]['stdout'] = 'BEGIN\nRESULT:1\nDISPATCH:0\n'
        with self.assertRaises(ValueError): cache.observe_raw(wrong)

    def test_raw_stream_cache_flash_and_ascii_bounds(self):
        rows = raw_records()
        for key, bound in [('stdout', cache.MAX_STDOUT), ('stderr', cache.MAX_STDERR),
                           ('events', cache.MAX_EVENTS), ('cache', cache.MAX_CACHE)]:
            wrong = copy.deepcopy(rows); wrong[0][key] = 'X'*(bound+1)
            with self.subTest(field=key), self.assertRaises(ValueError): cache.observe_raw(wrong)
        wrong = copy.deepcopy(rows); wrong[0]['flash_base64'] = base64.b64encode(b'X'*(cache.MAX_FLASH+1)).decode()
        with self.assertRaises(ValueError): cache.observe_raw(wrong)
        wrong = copy.deepcopy(rows); wrong[0]['stdout'] += '\N{SNOWMAN}'
        with self.assertRaises(ValueError): cache.observe_raw(wrong)

    def test_flash_rejects_base64_corrupt_gzip_truncated_bzip2_tail_and_wrong_A_B(self):
        rows = raw_records(); a = cache.fixture_inputs()['A']; compressed = bz2.compress(a)
        for raw in [b'corrupt bz2', gzip.compress(a), compressed[:-1], compressed+b'tail',
                    compressed+compressed, bz2.compress(cache.fixture_inputs()['B']), bz2.compress(b'X'*16385)]:
            wrong = copy.deepcopy(rows); wrong[0]['flash_base64'] = base64.b64encode(raw).decode()
            with self.assertRaises((ValueError, OSError, EOFError)): cache.observe_raw(wrong)
        for encoded in ['not base64!', rows[0]['flash_base64']+'\n', rows[0]['flash_base64']+'====']:
            wrong = copy.deepcopy(rows); wrong[0]['flash_base64'] = encoded
            with self.assertRaises(ValueError): cache.observe_raw(wrong)
        index = next(i for i, r in enumerate(rows) if r['case'] == 'partial-B-error-then-A')
        wrong = copy.deepcopy(rows); wrong[index]['flash_base64'] = base64.b64encode(cache.PARTIAL_TEXT.encode()+b'tail').decode()
        with self.assertRaises(ValueError): cache.observe_raw(wrong)

    def test_cache_digest_format_and_invalidation_after_failure_are_exact(self):
        rows = raw_records()
        for value in [None, cache.cache_content('B'), cache.cache_content('A').rstrip(),
                      cache.cache_content('A').replace('/tmp/storage.tar', '/private/input')]:
            wrong = copy.deepcopy(rows); wrong[0]['cache'] = value
            with self.assertRaises(ValueError): cache.observe_raw(wrong)
        index = next(i for i, r in enumerate(rows) if r['case'] == 'partial-B-error-then-A')
        wrong = copy.deepcopy(rows); wrong[index]['cache'] = cache.cache_content('A')
        with self.assertRaises(ValueError): cache.observe_raw(wrong)

    def test_strict_json_and_fixed_model_reject_ambiguity_and_literal_drift(self):
        self.assertEqual(cache.strict_json('{"raw_exit":-9,"cache":null}'), {'raw_exit': -9, 'cache': None})
        for raw in ['{"status":"PASS","status":"FAIL"}', '{"x":NaN}', '{"x":Infinity}']:
            with self.assertRaises(ValueError): cache.strict_json(raw)
        for name, value in [('FIXTURE_REPEAT', cache.FIXTURE_REPEAT+1), ('MAX_STDOUT', cache.MAX_STDOUT+1),
                            ('CASES', cache.CASES[:-1]), ('DRIVER_SUFFIX', cache.DRIVER_SUFFIX+'\n')]:
            with mock.patch.object(cache, name, value), self.assertRaises(ValueError): cache.model_contract()

    def test_synthetic_source_manifest_binds_four_whole_and_executed_bodies(self):
        inputs, functions = synthetic_sources()
        with self.pins(inputs, functions): proof = cache.source_contract(inputs)
        self.assertEqual(set(proof['source_sha256']), set(cache.SOURCE_PATHS))
        self.assertEqual(set(proof['function_manifest']), set(cache.FUNCTION_NAMES))
        self.assertEqual(set(cache.SOURCE_PATHS), {'storage', 'validator', 'validator_header',
                                                'validator_makefile', 'busybox_template', 'shell_common'})
        for name, body in functions.items():
            row = proof['function_manifest'][name]
            self.assertEqual(row['full_body_sha256'], cache.sha(body.encode()))
            self.assertEqual(row['executed_body_sha256'], cache.sha(body.replace('/sbin/storage_validate', 'cache_validator').encode()))
            self.assertEqual(row['helper_command_rebindings'], 1 if name == 'func_record_hash' else 0)

    def test_source_set_file_and_whole_body_pins_must_be_finalized(self):
        inputs, functions = synthetic_sources()
        with self.assertRaises(ValueError): cache.source_contract(inputs)
        variants = []
        for key in cache.SOURCE_PATHS:
            wrong = dict(inputs); del wrong[key]; variants.append(wrong)
        wrong = dict(inputs); wrong['extra'] = b'not a source'; variants.append(wrong)
        wrong = dict(inputs); wrong['storage'] += b'# whole-file drift\n'; variants.append(wrong)
        for wrong in variants:
            with self.pins(inputs, functions), self.assertRaises(ValueError): cache.source_contract(wrong)
        wrong = dict(inputs); wrong['storage'] = wrong['storage'].replace(b'func_record_hash\n}', b':\n}', 1)
        with self.pins(wrong, functions), self.assertRaises(ValueError): cache.source_contract(wrong)

    def test_repinned_synthetic_semantic_and_unique_helper_mutants_reject(self):
        inputs, _ = synthetic_sources()
        changes = [('func_invalidate_hash || return 1\n\tmtd_write write', 'mtd_write write\n\tfunc_invalidate_hash || return 1'),
                   (' || [ -e "$hsh" ]', ''), (' || [ -L "$hsh" ]', ''),
                   ('/sbin/storage_validate --replace-file', ': --replace-file'),
                   ('/sbin/storage_validate --replace-file', '/sbin/storage_validate /sbin/storage_validate --replace-file'),
                   ('result=1\n\t\treturn 1', 'result=0\n\t\treturn 1')]
        for old, new in changes:
            wrong = dict(inputs); self.assertIn(old.encode(), wrong['storage'])
            wrong['storage'] = wrong['storage'].replace(old.encode(), new.encode(), 1)
            with self.subTest(change=old), self.pins(wrong), self.assertRaises(ValueError): cache.source_contract(wrong)

    def test_render_keeps_actual_bodies_and_only_rebinds_helper_command(self):
        inputs, functions = synthetic_sources()
        with self.pins(inputs, functions): actual = cache.render_script(inputs)
        expected = (cache.DRIVER_PREFIX+'\n'+'\n\n'.join(functions[n].replace('/sbin/storage_validate', 'cache_validator')
                    for n in cache.FUNCTION_NAMES)+'\n'+cache.DRIVER_SUFFIX).encode()
        self.assertEqual(actual, expected); self.assertNotIn(b'/sbin/storage_validate', actual)
        self.assertIn(b'"$qemu" -L "$runtime" "$runtime/bin/busybox" "$@"', actual)
        self.assertIn(b'function_result=$?\n dispatcher_result=$result', actual)
        self.assertIn(b'exit "$dispatcher_result"', actual)
        for name in cache.FUNCTION_NAMES: self.assertEqual(actual.count((name+'()').encode()), 1)

    def test_config_requires_each_actual_applet_once_and_ascii(self):
        good = ('\n'.join(cache.REQUIRED_CONFIG)+'\n').encode(); cache.config_contract(good)
        for option in cache.REQUIRED_CONFIG:
            with self.subTest(option=option), self.assertRaises(ValueError): cache.config_contract(good.replace((option+'\n').encode(), b''))
        with self.assertRaises(ValueError): cache.config_contract(good+b'CONFIG_ASH=y\n')
        with self.assertRaises(UnicodeError): cache.config_contract(good+b'\xff')

    def test_parent_reference_binds_boot_four_scripts_runtime_config_and_image(self):
        parent, storage, runtime, dev_init, config = self.parent_fixture(); raw = cache.canonical(parent); image = b'synthetic image'
        result = cache.parent_reference(raw, storage, runtime, image, dev_init, config)
        self.assertEqual((result['parent_cases'], result['report_sha256']), (4, cache.sha(raw)))
        self.assertEqual(result['storage_script'], storage); self.assertEqual(result['dev_init_script'], dev_init)
        self.assertEqual(result['busybox_sha256'], runtime['busybox']['ELF']['sha256'])
        self.assertEqual((result['image_sha256'], result['image_bytes']), (cache.sha(image), len(image)))
        self.assertIs(result['independent_image_extraction_required'], True)
        changed = cache.parent_reference(raw, storage, runtime, image+b'B', dev_init, config)
        self.assertNotEqual(changed['image_sha256'], result['image_sha256']); self.assertNotEqual(changed['image_bytes'], result['image_bytes'])

    def test_parent_rejects_wrong_cases_diagnostics_shared_scripts_config_runtime(self):
        parent, storage, runtime, dev_init, config = self.parent_fixture(); variants = []
        for key, value in [('status', 'FAIL'), ('profile', 'other'), ('phase', 'preflight'), ('required_cases', parent['required_cases'][:-1])]:
            wrong = copy.deepcopy(parent); wrong[key] = value; variants.append(wrong)
        wrong = copy.deepcopy(parent); wrong['checks'][0]['raw_exit'] = False; variants.append(wrong)
        wrong = copy.deepcopy(parent); wrong['checks'][1] = copy.deepcopy(wrong['checks'][0]); variants.append(wrong)
        wrong = copy.deepcopy(parent); wrong['diagnostics'][0]['stderr_bytes'] = False; variants.append(wrong)
        for role in ('storage', 'dev_init'):
            wrong = copy.deepcopy(parent); wrong['rootfs_scripts'][role]['sha256'] = '0'*64; variants.append(wrong)
            wrong = copy.deepcopy(parent); wrong['source_sha256'][role] = '0'*64; variants.append(wrong)
        wrong = copy.deepcopy(parent); wrong['compiled_busybox_config']['sha256'] = '0'*64; variants.append(wrong)
        for role in ('busybox', 'busybox_dynamic', 'libraries'):
            wrong = copy.deepcopy(parent); wrong['runtime'][role] = {'different': True}; variants.append(wrong)
        for wrong in variants:
            with self.assertRaises((ValueError, KeyError)): cache.parent_reference(cache.canonical(wrong), storage, runtime, b'image', dev_init, config)
        with self.assertRaises(ValueError): cache.parent_reference(cache.canonical(parent), storage, runtime, b'image', dev_init, config+b'drift')
        with self.assertRaises(TypeError): cache.parent_reference(cache.canonical(parent), storage, runtime, b'image')

    def test_private_runtime_inventory_has_no_device_copy(self):
        rootfs, sysroot = self.runtime_fixture(); data = b'private synthetic library'
        (sysroot/'lib/public-runtime').write_bytes(data)
        self.assertEqual(cache.safe_runtime_inputs(rootfs, sysroot), {'entries': 1, 'regular_bytes': len(data)})
        self.assertFalse((rootfs/'dev').exists()); self.assertFalse((sysroot/'proc').exists())

    def test_runtime_missing_directories_and_symlink_aliases_reject(self):
        rootfs, sysroot = self.runtime_fixture(); (rootfs/'sbin').rmdir()
        with self.assertRaises(ValueError): cache.safe_runtime_inputs(rootfs, sysroot)
        (rootfs/'sbin').mkdir(); alias = self.root/'alias'; alias.symlink_to(rootfs, target_is_directory=True)
        with self.assertRaises(ValueError): cache.safe_runtime_inputs(alias, sysroot)
        for root, name in ((rootfs, 'lib'), (sysroot, 'usr/lib')):
            path = root/name; moved = root/(name.replace('/', '-')+'-real'); path.rename(moved); path.symlink_to(moved, target_is_directory=True)
            with self.assertRaises(ValueError): cache.safe_runtime_inputs(rootfs, sysroot)
            path.unlink(); moved.rename(path)

    def test_missing_qemu_rejects_and_explicit_tool_resolves(self):
        with mock.patch.object(cache.shutil, 'which', return_value=None), self.assertRaises(ValueError): cache.tool_path('qemu-mipsel')
        target = self.root/'inert-tool'; target.write_bytes(b'not executed'); alias = self.root/'inert-alias'; alias.symlink_to(target)
        with mock.patch.object(cache.shutil, 'which', return_value=str(alias)):
            self.assertEqual(cache.tool_path('qemu-mipsel'), target.resolve())

    def test_bounded_native_run_preserves_complete_streams_and_nonzero_exit(self):
        for status in (0, 7):
            cmd = [sys.executable, '-c', 'import os,sys;os.write(1,b"complete stdout\\n");os.write(2,b"stderr\\n");sys.exit(%d)' % status]
            with self.subTest(status=status), self.owned_processes() as rows, \
                    mock.patch.object(cache.os, 'killpg', side_effect=AssertionError('Never signal a reaped process group')) as signal_group, \
                    mock.patch.object(cache.os, 'kill', side_effect=AssertionError('Never signal a reaped child')) as signal_child:
                self.assertEqual(cache.bounded_run(cmd, self.root, dict(os.environ, PATH=''), timeout=3),
                                 (status, b'complete stdout\n', b'stderr\n'))
                row = rows[0]; child = row['child']
                signal_group.assert_not_called(); row['kill'].assert_not_called(); signal_child.assert_not_called()
                self.assertEqual(row['wait'].call_args, mock.call(timeout=5))
                self.assertEqual(child.poll(), status)
                self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_bounded_native_run_rejects_both_stream_overflows(self):
        for fd, limit in ((1, cache.MAX_STDOUT), (2, cache.MAX_STDERR)):
            for mode in ('normal', 'group-already-gone', 'group-denied'):
                suffix = ';import time;time.sleep(30)' if mode == 'group-denied' else ''
                cmd = [sys.executable, '-c', 'import os;os.write(%d,b"X"*%d)' % (fd, limit+1)+suffix]
                effect = (ProcessLookupError() if mode == 'group-already-gone' else
                          PermissionError(errno.EPERM, 'injected group signal denial'))
                real_group_signal = cache.os.killpg
                actual_denials = []
                def real_group(pid, signum):
                    try:
                        return real_group_signal(pid, signum)
                    except PermissionError:
                        actual_denials.append(True)
                        raise
                group = (mock.patch.object(cache.os, 'killpg', side_effect=real_group) if mode == 'normal' else
                         mock.patch.object(cache.os, 'killpg', side_effect=effect))
                with self.subTest(stream=fd, mode=mode), self.owned_processes() as rows, group as signal_group, \
                        mock.patch.object(cache.os, 'kill', wraps=cache.os.kill) as signal_child:
                    with self.assertRaisesRegex(ValueError, 'output exceeded bound'):
                        cache.bounded_run(cmd, self.root, dict(os.environ, PATH=''), timeout=3)
                    row = rows[0]; child = row['child']
                    signal_group.assert_called_once_with(child.pid, cache.signal.SIGKILL)
                    fallback = mode == 'group-denied' or bool(actual_denials)
                    self.assertEqual(row['kill'].call_count, int(fallback))
                    if mode == 'group-denied':
                        signal_child.assert_called_once_with(child.pid, cache.signal.SIGKILL)
                    elif not fallback:
                        signal_child.assert_not_called()
                    # A real denied group may race a natural child exit:
                    # Popen.kill can correctly discover it already reaped.
                    self.assertLessEqual(signal_child.call_count, 1)
                    for call in signal_child.call_args_list:
                        self.assertEqual(call.args, (child.pid, cache.signal.SIGKILL))
                    self.assertEqual(row['wait'].call_args, mock.call(timeout=5))
                    self.assertIsNotNone(child.poll())
                    self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_bounded_native_run_deadline_prevents_late_private_side_effect(self):
        for denied in (False, True):
            marker = self.root/('late-side-effect-'+str(denied))
            cmd = [sys.executable, '-c', 'import pathlib,time;time.sleep(2);pathlib.Path(%r).write_text("late")' % str(marker)]
            real_group_signal = cache.os.killpg
            actual_denials = []
            def real_group(pid, signum):
                try:
                    return real_group_signal(pid, signum)
                except PermissionError:
                    actual_denials.append(True)
                    raise
            group = (mock.patch.object(cache.os, 'killpg', side_effect=PermissionError(errno.EPERM, 'injected group signal denial')) if denied else
                     mock.patch.object(cache.os, 'killpg', side_effect=real_group))
            with self.subTest(group_denied=denied), self.owned_processes() as rows, group:
                with self.assertRaisesRegex(ValueError, 'deadline exceeded'):
                    cache.bounded_run(cmd, self.root, dict(os.environ, PATH=''), timeout=0.15)
                row = rows[0]
                self.assertEqual(row['kill'].call_count, int(denied or bool(actual_denials)))
                self.assertEqual(row['wait'].call_args, mock.call(timeout=5))
                self.assertIsNotNone(row['child'].poll())
                self.assertFalse(marker.exists())
        # If both allowed signal routes fail and the bounded join cannot
        # confirm retirement, reject explicitly rather than return success.
        cmd = [sys.executable, '-c', 'import time;time.sleep(30)']
        with self.owned_processes(deny_owned_signal=True, reject_join=True) as rows, \
                mock.patch.object(cache.os, 'killpg', side_effect=PermissionError(errno.EPERM, 'injected group signal denial')):
            with self.assertRaises(cache.subprocess.TimeoutExpired) as refused:
                cache.bounded_run(cmd, self.root, dict(os.environ, PATH=''), timeout=0.05)
            row = rows[0]
            row['kill'].assert_called_once_with()
            row['wait'].assert_called_once_with(timeout=5)
            self.assertEqual(refused.exception.timeout, 5)
            self.assertIsNone(row['child'].poll())
            self.assertTrue(row['child'].stdout.closed and row['child'].stderr.closed)

    def test_cli_requires_six_explicit_arguments_and_rejects_preflight(self):
        names = ('trunk', 'rootfs', 'sysroot', 'image', 'boot-storage-report', 'output')
        for missing in names:
            argv = ['storage-cache']+[v for n in names if n != missing for v in ('--'+n, str(self.root/n))]
            with self.subTest(missing=missing), mock.patch.object(sys, 'argv', argv), mock.patch.object(cache, 'check') as run, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped: cache.main()
            self.assertEqual(stopped.exception.code, 2); run.assert_not_called()
        argv = ['storage-cache']+[v for n in names for v in ('--'+n, str(self.root/n))]+['--preflight']
        with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): cache.main()

    def test_cli_maps_all_paths_and_failure_never_prints_pass(self):
        names = ('trunk', 'rootfs', 'sysroot', 'image', 'boot-storage-report', 'output'); paths = [self.root/n for n in names]
        argv = ['storage-cache']+[v for n, p in zip(names, paths) for v in ('--'+n, str(p))]; out = io.StringIO()
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(cache, 'check', return_value={}) as run, contextlib.redirect_stdout(out):
            self.assertEqual(cache.main(), 0)
        run.assert_called_once_with(*paths)
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(cache, 'check', side_effect=ValueError('injected refusal')), contextlib.redirect_stdout(out):
            self.assertEqual(cache.main(), 1)
        report = json.loads(paths[-1].read_text()); self.assertEqual(report['status'], 'FAIL')
        self.assertIn('injected refusal', report['error']); self.assertNotIn('PASS', out.getvalue())


if __name__ == '__main__':
    unittest.main()
