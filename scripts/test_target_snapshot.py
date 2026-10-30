#!/usr/bin/env python3
"""Host controls for snapshot proof safety/schema; never mount or start DNS."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('target_snapshot', Path(__file__).with_name('check_target_snapshot.py'))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def records():
    result = []
    for case in gate.CASE_NAMES:
        have_flat = case not in ('busybox-exec-adapter-preflight', 'oversized-input',
                                 'managed-foreground', 'wrapper-migration-daemon-loopback', 'wrapper-graph-race')
        answer = '192.0.2.51' if case == 'wrapper-migration-daemon-loopback' else None
        result.append({'case': case, 'exit_code': 1 if case in gate.REJECT_CASES else 0,
                       'outcome': 'rejected-without-launch' if case in gate.REJECT_CASES else 'snapshot-policy-verified',
                       'generator_executions': 0 if case in ('busybox-exec-adapter-preflight', 'oversized-input') else 1,
                       'flat_sha256': 'a' * 64 if have_flat else None, 'flat_bytes': 50 if have_flat else 0,
                       'first_answer': answer, 'after_cleanup_answer': answer,
                       'workspaces_remaining': 0, 'daemon_stopped': True})
    return result


def report():
    return {'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4',
            'execution_roles': gate.ROLES.copy(), 'source_sha256': {'locked': 'a' * 64},
            'shipped': {'binary': {'sha256': 'b' * 64}}, 'filesystem_limits': gate.FILESYSTEM_LIMITS.copy(),
            'limits': gate.LIMITS.copy(), 'required_cases': list(gate.CASE_NAMES), 'checks': records(),
            'failure': None, 'isolation': {'namespaces': {name: {'parent_inode': 10 + i, 'worker_inode': 20 + i}
                                                       for i, name in enumerate(('mnt', 'net', 'pid'))},
                                         'worker_pid': 1, 'loopback_only': True, 'anchors_cloexec': True,
                                         'private_mount_propagation': True, 'namespace_exit_confirmed': True}}


class TargetSnapshotControls(unittest.TestCase):
    def test_native_tool_adapter_survives_a_masked_alternatives_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); real = root / 'real-awk'; covered = root / 'etc/alternatives'
            covered.mkdir(parents=True); public = root / 'awk'; alternative = covered / 'awk'
            real.write_text('#!/bin/sh\nprintf "RESOLVED:%s\\n" "$1"\n');real.chmod(0o700)
            alternative.symlink_to(real);public.symlink_to(alternative)
            with mock.patch.object(gate.shutil, 'which', return_value=str(public)):
                bindings = gate.resolve_native_tools(('awk',))
            self.assertEqual(bindings, {'awk': real.resolve()})
            alternative.unlink();self.assertFalse(public.exists())
            tools = root / 'tools';tools.mkdir()
            gate.install_native_tools(tools, bindings)
            ran = subprocess.run([str(tools / 'awk'), 'argument with spaces'], capture_output=True, text=True, check=True)
            self.assertEqual(ran.stdout, 'RESOLVED:argument with spaces\n')

    def test_fixture_install_stages_on_destination_filesystem_and_keeps_candidate(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory(
                dir='/dev/shm' if sys.platform.startswith('linux') and Path('/dev/shm').is_dir() else None) as target_dir:
            candidate, destination = Path(source_dir) / 'candidate', Path(target_dir) / 'custom'
            candidate.write_bytes(b'public candidate\n')
            destination.write_bytes(b'old policy\n')
            original = gate.os.replace
            def checked_replace(stage, target):
                self.assertEqual(stage.parent, target.parent)
                self.assertEqual(stage.stat().st_dev, target.parent.stat().st_dev)
                return original(stage, target)
            with mock.patch.object(gate.os, 'replace', side_effect=checked_replace) as renamed:
                gate.install_fixture_config(candidate, destination)
                renamed.assert_called_once()
            self.assertEqual(candidate.read_bytes(), b'public candidate\n')
            self.assertEqual(destination.read_bytes(), candidate.read_bytes())
            self.assertFalse((destination.parent / '.snapshot-test-install').exists())

    def test_corruption_fixture_can_modify_its_owned0400_leaf_without_root(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'flat.conf'
            gate.regular(path, b'public policy\n', 0o400)
            gate.tamper_flat(path)
            self.assertTrue(path.read_bytes().startswith(b'public policy\n'))
            self.assertIn(b'deliberate fixture corruption', path.read_bytes())
            self.assertEqual(path.stat().st_mode & 0o7777, 0o400)

    def test_static_preflight_uses_only_production_objects_and_strict_new_modules(self):
        text = 'objs = dnsmasq.o option.o \\\n dynamic_conf.o conf_snapshot.o\n'
        self.assertEqual(gate.production_objects(text), ['dnsmasq.c', 'option.c', 'dynamic_conf.c', 'conf_snapshot.c'])
        for value in (text.replace('conf_snapshot.o', ''), text + text,
                      text.replace('option.o', '$(shell dangerous)'), text.replace('option.o', '../option.o')):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                gate.production_objects(value)

    def test_static_preflight_uses_firmware_ipv6_usb_and_ipset_flags(self):
        text = 'CONFIG_LINUXDIR=linux-4.4.x\nCONFIG_FIRMWARE_ENABLE_IPV6=y\nCONFIG_FIRMWARE_ENABLE_USB=n\n'
        flags = gate.production_copts(text)
        self.assertIn('-DNO_TFTP', flags)
        self.assertIn('-DNO_IPSET', flags)
        self.assertNotIn('-DNO_IPV6', flags)
        with self.assertRaises(RuntimeError):
            gate.production_copts(text + 'CONFIG_LINUXDIR=linux-3.4.x\n')

    def test_preflight_cli_does_not_require_romfs_or_call_namespace_worker(self):
        args = ['check_target_snapshot.py', '--preflight', '--trunk', '/fixture/trunk',
                '--compiler', '/fixture/gcc', '--output', '/fixture/preflight.json']
        with mock.patch.object(sys, 'argv', args), mock.patch.object(gate, 'preflight') as early, \
                mock.patch.object(gate, 'worker') as worker, mock.patch.object(gate, 'root_parent') as root:
            gate.main()
            self.assertIsNone(early.call_args.args[0].rootfs)
            self.assertIsNone(early.call_args.args[0].sysroot)
            worker.assert_not_called()
            root.assert_not_called()

    def test_exact_records_and_report_positive_control(self):
        value = report()
        self.assertTrue(gate.validate_records(value['checks']))
        self.assertTrue(gate.validate_report(value, value['source_sha256'], value['shipped']))

    def test_missing_reordered_duplicate_and_extra_cases_fail(self):
        valid = records()
        for value in (valid[:-1], valid[::-1], valid + [valid[0]], valid[:-1] + [valid[0]]):
            with self.subTest(count=len(value)), self.assertRaises(RuntimeError):
                gate.validate_records(value)

    def test_deduplicated_file_and_directory_alias_rejections_are_mandatory(self):
        for name in ('changed-deduplicated-file-alias', 'changed-deduplicated-directory-alias'):
            valid = records()
            index = gate.CASE_NAMES.index(name)
            self.assertEqual(valid[index]['exit_code'], 1)
            self.assertEqual(valid[index]['generator_executions'], 1)
            for status in (0, -9, 127):
                bad = copy.deepcopy(valid)
                bad[index]['exit_code'] = status
                with self.subTest(case=name, status=status), self.assertRaises(RuntimeError):
                    gate.validate_records(bad)
            with self.assertRaises(RuntimeError):
                gate.validate_records([row for row in valid if row['case'] != name])

    def test_exec_signal_and_false_rejection_statuses_fail(self):
        for status in (0, 127, 126, -9, 21, True):
            value = records()
            value[2]['exit_code'] = status
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                gate.validate_records(value)

    def test_repeated_generator_wrong_answer_and_unclean_daemon_fail(self):
        for key, value in (('generator_executions', 2), ('after_cleanup_answer', '192.0.2.52'),
                           ('daemon_stopped', False), ('workspaces_remaining', 1)):
            rows = records()
            rows[-2][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                gate.validate_records(rows)

    def test_flat_proof_must_exist_only_in_captured_cases(self):
        for index in (0, 1):
            rows = records()
            rows[index]['flat_sha256'] = None if index else 'a' * 64
            rows[index]['flat_bytes'] = 0 if index else 1
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                gate.validate_records(rows)

    def test_report_rejects_weaker_namespace_roles_and_source_binding(self):
        for mutate in (lambda r: r['isolation'].update(namespace_exit_confirmed=False),
                       lambda r: r['isolation'].update(worker_pid=True),
                       lambda r: r['isolation']['namespaces']['net'].update(worker_inode=11),
                       lambda r: r['execution_roles'].update(wrapper='native shell fallback'),
                       lambda r: r.update(source_sha256={'changed': 'c' * 64}),
                       lambda r: r.update(shipped={'changed': 'd' * 64})):
            value = copy.deepcopy(report())
            mutate(value)
            with self.assertRaises(RuntimeError):
                gate.validate_report(value, report()['source_sha256'], report()['shipped'])

    def test_parent_output_is_exclusive_and_worker_keeps_inode_owner_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            identity = gate.prepare_output(path)
            gate.write_output(path, identity, {'worker': 'fixture'})
            self.assertEqual(gate.output_identity(path), identity)
            self.assertEqual(json.loads(path.read_text()), {'worker': 'fixture'})
            with self.assertRaises(FileExistsError):
                gate.prepare_output(path)

    def test_report_alias_existing_path_and_changed_inode_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            target.write_bytes(b'keep')
            alias = root / 'alias'
            alias.symlink_to(target)
            with self.assertRaises(FileExistsError):
                gate.prepare_output(alias)
            self.assertEqual(target.read_bytes(), b'keep')
            output = root / 'report'
            expected = gate.prepare_output(output)
            output.unlink()
            output.symlink_to(target)
            with self.assertRaises(RuntimeError):
                gate.write_output(output, expected, {})
            self.assertEqual(target.read_bytes(), b'keep')

    def test_guard_refuses_nonlinux_nonroot_or_non_pid1_before_proc_or_mount(self):
        for platform, uid, pid in (('darwin', 0, 1), ('linux', 1001, 1), ('linux', 0, 20)):
            with mock.patch.object(gate.sys, 'platform', platform), mock.patch.object(gate.os, 'geteuid', return_value=uid), \
                    mock.patch.object(gate.os, 'getpid', return_value=pid), mock.patch.object(gate.os, 'readlink') as readlink:
                with self.assertRaises(RuntimeError):
                    gate.namespace_guard({'mnt': 3, 'net': 4, 'pid': 5})
                readlink.assert_not_called()

    def test_guard_refuses_regular_fd_anchor_and_initial_namespace(self):
        with mock.patch.object(gate.sys, 'platform', 'linux'), mock.patch.object(gate.os, 'geteuid', return_value=0), \
                mock.patch.object(gate.os, 'getpid', return_value=1):
            with mock.patch.object(gate.os, 'readlink', return_value='/tmp/ordinary-file'):
                with self.assertRaises(RuntimeError):
                    gate.namespace_guard({'mnt': 3, 'net': 4, 'pid': 5})
            inode = SimpleNamespace(st_dev=1, st_ino=10)
            with mock.patch.object(gate.os, 'readlink', return_value='mnt:[10]'), \
                    mock.patch.object(gate.os, 'fstat', return_value=inode), \
                    mock.patch.object(gate.os, 'stat', return_value=inode):
                with self.assertRaises(RuntimeError):
                    gate.namespace_guard({'mnt': 3, 'net': 4, 'pid': 5})

    def test_guard_refuses_shared_mount_and_non_loopback_interface(self):
        anchors = {'mnt': 3, 'net': 4, 'pid': 5}
        def link(path):
            return {3: 'mnt:[10]', 4: 'net:[11]', 5: 'pid:[12]'}[int(path.rsplit('/', 1)[1])]
        with mock.patch.object(gate.sys, 'platform', 'linux'), mock.patch.object(gate.os, 'geteuid', return_value=0), \
                mock.patch.object(gate.os, 'getpid', return_value=1), mock.patch.object(gate.os, 'readlink', side_effect=link), \
                mock.patch.object(gate.os, 'fstat', return_value=SimpleNamespace(st_dev=1, st_ino=10)), \
                mock.patch.object(gate.os, 'stat', return_value=SimpleNamespace(st_dev=1, st_ino=20)), \
                mock.patch.object(gate.fcntl, 'fcntl', return_value=0):
            with mock.patch.object(Path, 'read_text', return_value='1 0 0:1 / / rw shared:1 - ext4 /dev/root rw\n'):
                with self.assertRaises(RuntimeError):
                    gate.namespace_guard(anchors)
            with mock.patch.object(Path, 'read_text', return_value='1 0 0:1 / / rw - ext4 /dev/root rw\n'), \
                    mock.patch.object(gate.socket, 'if_nameindex', return_value=[(1, 'lo'), (2, 'eth0')]):
                with self.assertRaises(RuntimeError):
                    gate.namespace_guard(anchors)

    def test_inert_output_flood_and_sleep_fail_instead_of_passing(self):
        with self.assertRaisesRegex(RuntimeError, 'output cap'):
            gate.run_bounded([sys.executable, '-c', 'import os;os.write(1,b"x"*200000)'])
        with mock.patch.dict(gate.LIMITS, {'command_seconds': 0.1}):
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                gate.run_bounded([sys.executable, '-c', 'import time;time.sleep(2)'])

    def test_real_dns_packet_parser_accepts_only_first_snapshot_policy(self):
        head = struct.pack('!6H', 0x4b32, 0x8180, 1, 1, 0, 0)
        question = b'\x08snapshot\x07fixture\0\0\x01\0\x01'
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + bytes([192, 0, 2, 51])
        packet = head + question + answer
        self.assertEqual(gate.parse_answer(packet, 0x4b32), '192.0.2.51')
        for data in (packet[:-1], packet[:-1] + b'\x34', b'', b'\0' * 5000):
            with self.assertRaises(RuntimeError):
                gate.parse_answer(data, 0x4b32)
        with self.assertRaises(RuntimeError):
            gate.parse_answer(packet, 0x1234)

    def test_shipped_elf_identity_rejects_wrong_class_arch_and_byte_order(self):
        data = bytearray(52)
        data[:7] = b'\x7fELF\x01\x01\x01'
        struct.pack_into('<HH', data, 16, 2, 8)
        self.assertEqual(gate.elf(data)['e_machine'], 8)
        for offset, value in ((4, 2), (5, 2), (18, 62)):
            bad = bytearray(data)
            bad[offset] = value
            with self.assertRaises(RuntimeError):
                gate.elf(bad)

    def test_source_function_binding_requires_unique_actual_body(self):
        text = 'int start_dns_dhcpd(int mode) { return mode; }'
        self.assertEqual(gate.function(text, 'start_dns_dhcpd'), text)
        for value in ('int other(void) { return 0; }', text + '\n' + text):
            with self.assertRaises(RuntimeError):
                gate.function(value, 'start_dns_dhcpd')


if __name__ == '__main__':
    unittest.main()
