"""Pure corruption/packet controls; no mounts, daemon, MIPS or device execution."""
import copy
from pathlib import Path
import socket
import struct
import sys
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_target_log_reload as gate


def rows():
    result = []
    for name in gate.CASE_NAMES:
        value = dict(case=name, elapsed_ms=20, daemon_stopped=True, **gate.case_contract(name))
        if name == 'shared-literal-pressure-recovery':
            value['probe_results'] = [dict(calls=calls, fd_before=4, fd_after=4, errno_preserved=True, elapsed_ms=10)
                                      for calls in (1, 256, 1)]
        result.append(value)
    return result


def report():
    return dict(schema_version=1, status='PASS', profile='k2p-4.4', execution_role=gate.ROLE,
                source_sha256={'locked': 'a' * 64}, shipped={'libshared': {'sha256': 'b' * 64}},
                required_cases=list(gate.CASE_NAMES), checks=rows(), filesystem_limits=gate.FILESYSTEM_LIMITS,
                limits=gate.LIMITS, contract=gate.CONTRACT, failure=None,
                isolation=dict(worker_pid=1, loopback_only=True, private_mount_propagation=True,
                    anchors_cloexec=True, namespace_exit_confirmed=True, private_dev_log=True,
                    namespaces={name: dict(parent_inode=10 + i, worker_inode=20 + i)
                                for i, name in enumerate(('mnt', 'net', 'pid'))}),
                probe=dict(source_sha256=gate.sha(gate.generate_source().encode()), sha256='c' * 64, bytes=1000,
                    elf=dict(elf_class=32, byte_order='little', e_machine=8, e_type=2),
                    dynamic=dict(interpreter='/lib/ld-uClibc.so.0', needed=['libshared.so', 'libc.so.0']),
                    libraries={name: dict(resolved=name, sha256=('b' if name == 'lib/libshared.so' else 'd') * 64,
                        bytes=1000, elf_class=32, byte_order='little', e_machine=8, e_type=3)
                        for name in ('lib/libshared.so', 'lib/libc.so.0', 'lib/ld-uClibc.so.0', 'lib/ld-uClibc.so.1')},
                    library_dynamic={name: dict(interpreter='/lib/ld-uClibc.so.1' if name == 'lib/libc.so.0' else None,
                        needed=['ld-uClibc.so.1'] if name == 'lib/libc.so.0' else [])
                        for name in ('lib/libshared.so', 'lib/libc.so.0', 'lib/ld-uClibc.so.0', 'lib/ld-uClibc.so.1')}))


def ack(value=b'old.fixture', extra=b''):
    data = bytearray(gate.inform_packet()[:240]); data[0] = 2
    data[20:24] = socket.inet_aton('127.0.0.1')
    return bytes(data) + bytes((53, 1, 5, 15, len(value))) + value + extra + b'\xff'


class TargetLogReloadControls(unittest.TestCase):
    def test_exact_twentyfour_cases_report_and_export_source_accept(self):
        value = report()
        self.assertEqual(len(gate.CASE_NAMES), 24)
        self.assertTrue(gate.validate_report(value, value['source_sha256'], value['shipped']))
        source = gate.generate_source()
        self.assertIn('logmessage("K2P_SHARED","%s",argv[2])', source)
        self.assertNotIn('syslog(', source)
        self.assertIn('errno=E2BIG', source)
        self.assertIn('/proc/self/fd', source)

    def test_every_case_exact_order_and_no_extra_fields(self):
        for index in range(len(gate.CASE_NAMES)):
            value = rows(); del value[index]
            with self.subTest(index=index), self.assertRaises(RuntimeError):gate.validate_records(value)
        for value in (rows()[::-1], rows() + [rows()[0]]):
            with self.assertRaises(RuntimeError):gate.validate_records(value)
        value = rows(); value[0]['unchecked'] = True
        with self.assertRaises(RuntimeError):gate.validate_records(value)

    def test_old_policy_leaks_partial_commit_and_failed_repair_rejected(self):
        for name in gate.CASE_NAMES:
            if not name.startswith(('hosts-', 'dhcp-', 'cross-', 'ethers-')):continue
            for field in ('before', 'after', 'repaired'):
                value = rows(); record = value[gate.CASE_NAMES.index(name)]
                if isinstance(record[field], dict):record[field] = dict(record[field], **{'leak.fixture': '192.0.2.99'})
                else:record[field] = 'leak.fixture'
                with self.subTest(name=name, field=field), self.assertRaises(RuntimeError):gate.validate_records(value)
        for name in ('cross-hosts-reject-preserves-dhcp', 'cross-dhcp-reject-preserves-hosts'):
            value = rows(); value[gate.CASE_NAMES.index(name)]['after']['dhcp'] = 'new.fixture'
            with self.assertRaises(RuntimeError):gate.validate_records(value)

    def test_queue_pressure_literal_errno_and_fd_leak_controls(self):
        index = gate.CASE_NAMES.index('shared-literal-pressure-recovery')
        for key, wrong in [('queue_full', False), ('receiver_recovered', False), ('before', 'literal normal'),
                           ('daemon_stopped', False), ('elapsed_ms', True), ('elapsed_ms', 30001)]:
            value = rows(); value[index][key] = wrong
            with self.subTest(key=key), self.assertRaises(RuntimeError):gate.validate_records(value)
        for key, wrong in [('calls', 0), ('calls', True), ('fd_after', 5), ('errno_preserved', False),
                           ('fd_before', 2), ('elapsed_ms', 3001), ('elapsed_ms', True)]:
            value = rows(); value[index]['probe_results'][1][key] = wrong
            with self.subTest(key=key), self.assertRaises(RuntimeError):gate.validate_records(value)
        value = rows(); value[index]['probe_results'].pop()
        with self.assertRaises(RuntimeError):gate.validate_records(value)
        # A failed later case must retain completed rows in the caller's
        # report list, but never print PASS for the failed case or accept it.
        partial = []; first = rows()[0]
        cases = ('syslog-full-responsive-recovery', 'dhcp-hosts-fifo-preserved')
        with mock.patch.object(gate, 'CASE_NAMES', cases), mock.patch.object(gate.runtime, 'Upstream'), \
             mock.patch.object(gate.runtime, 'quiescent', return_value=True), \
             mock.patch.object(gate.Path, 'mkdir'), mock.patch.object(gate.shutil, 'rmtree'), \
             mock.patch.object(gate, 'exercise_log', return_value=first), \
             mock.patch.object(gate, 'exercise_dhcp', side_effect=RuntimeError('inert later failure')), \
             mock.patch('builtins.print') as output:
            with self.assertRaisesRegex(RuntimeError, 'inert later failure'):gate.worker_cases(None, partial)
        self.assertEqual(partial, [first])
        self.assertIn(mock.call('Target log/reload PASS ' + cases[0], flush=True), output.call_args_list)
        self.assertNotIn(mock.call('Target log/reload PASS ' + cases[1], flush=True), output.call_args_list)

    def test_contract_sources_profile_and_shipped_library_bound(self):
        original = report()
        for key, wrong in [('source_sha256', {}), ('shipped', {}), ('contract', {}), ('filesystem_limits', {}),
                           ('limits', {}), ('execution_role', 'native stub'), ('schema_version', True),
                           ('profile', 'k2p-susu'), ('status', 'SKIP'), ('failure', 'ignored'),
                           ('required_cases', list(gate.CASE_NAMES[:-1]))]:
            value = copy.deepcopy(original); value[key] = wrong
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                gate.validate_report(value, original['source_sha256'], original['shipped'])
        for key, wrong in [('sha256', 'bad'), ('source_sha256', 'bad'), ('bytes', True), ('bytes', 0),
                           ('dynamic', dict(interpreter='/lib/other.so', needed=['libshared.so'])),
                           ('libraries', {'lib/libshared.so': {'sha256': 'd' * 64}})]:
            value = copy.deepcopy(original);value['probe'][key] = wrong
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                gate.validate_report(value, original['source_sha256'], original['shipped'])
        value = copy.deepcopy(original);value['probe']['elf']['e_machine'] = 62
        with self.assertRaises(RuntimeError):gate.validate_report(value, original['source_sha256'], original['shipped'])

    def test_runtime_closure_missing_extra_unsafe_or_wrong_elf_rejected(self):
        original = report()
        for role in ('missing', 'extra', 'unsafe', 'wrong-machine', 'unbound-needed'):
            value = copy.deepcopy(original)
            if role == 'missing':del value['probe']['libraries']['lib/libc.so.0']
            elif role == 'extra':
                value['probe']['libraries']['lib/unchecked.so'] = copy.deepcopy(value['probe']['libraries']['lib/libc.so.0'])
                value['probe']['library_dynamic']['lib/unchecked.so'] = dict(interpreter=None, needed=[])
            elif role == 'unsafe':value['probe']['library_dynamic']['lib/libc.so.0']['needed'] = ['../../host']
            elif role == 'wrong-machine':value['probe']['libraries']['lib/libc.so.0']['e_machine'] = 62
            else:value['probe']['library_dynamic']['lib/libc.so.0']['needed'] = ['missing.so']
            with self.subTest(role=role), self.assertRaises(RuntimeError):
                gate.validate_report(value, original['source_sha256'], original['shipped'])

    def test_ethers_both_mac_identities_distinguish_clear_from_replacement(self):
        self.assertEqual(gate.CASE_NAMES[-4:], ('ethers-fifo-preserved', 'ethers-malformed-preserved',
                                              'ethers-empty-commit', 'cross-ethers-reject-preserves-hosts'))
        for name in gate.CASE_NAMES[-4:]:
            for field, peer, wrong in [('before', 'new_peer', 'old.fixture'),
                                       ('repaired', 'old_peer', 'old.fixture'),
                                       ('repaired', 'new_peer', 'fallback.fixture')]:
                value = rows();value[gate.CASE_NAMES.index(name)][field][peer] = wrong
                with self.subTest(name=name, field=field, peer=peer), self.assertRaises(RuntimeError):
                    gate.validate_records(value)
        value = gate.case_contract('ethers-fifo-preserved');value['before']['old_peer'] = 'wrong'
        self.assertEqual(gate.case_contract('ethers-fifo-preserved')['before'], gate.OLD_ETHERS)
        value = gate.case_contract('hosts-fifo-group-preserved');value['before']['first.fixture'] = 'wrong'
        self.assertEqual(gate.case_contract('hosts-fifo-group-preserved')['before'], gate.OLD_HOSTS)
        packet = gate.inform_packet(gate.NEW_HARDWARE)
        self.assertEqual(packet[28:34], gate.NEW_HARDWARE)
        reply = bytearray(ack());reply[28:34] = gate.NEW_HARDWARE
        self.assertEqual(gate.parse_inform(bytes(reply), gate.NEW_HARDWARE), 'old.fixture')
        with self.assertRaises(RuntimeError):gate.parse_inform(bytes(reply), gate.OLD_HARDWARE)

    def test_private_namespace_dev_and_confirmed_teardown_mandatory(self):
        original = report()
        for key, wrong in [('private_dev_log', False), ('namespace_exit_confirmed', False), ('worker_pid', 2),
                           ('worker_pid', True), ('loopback_only', False), ('anchors_cloexec', False),
                           ('private_mount_propagation', False)]:
            value = copy.deepcopy(original);value['isolation'][key] = wrong
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                gate.validate_report(value, original['source_sha256'], original['shipped'])
        for name in ('mnt', 'net', 'pid'):
            value = copy.deepcopy(original);item = value['isolation']['namespaces'][name];item['worker_inode'] = item['parent_inode']
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                gate.validate_report(value, original['source_sha256'], original['shipped'])

    def test_inform_packet_has_no_allocation_request_and_ack_parser(self):
        request = gate.inform_packet()
        self.assertEqual(request[:4], bytes((1, 1, 6, 0)))
        self.assertEqual(request[12:16], socket.inet_aton('127.0.0.2'))
        self.assertEqual(request[28:34], bytes.fromhex('020000000051'))
        self.assertEqual(request[240:], bytes((53, 1, 8, 55, 1, 15, 255)))
        self.assertEqual(gate.parse_inform(ack()), 'old.fixture')
        bad = bytearray(ack());bad[4] ^= 1
        wrong_flags = bytearray(ack());wrong_flags[10] = 0x80
        zero_server = bytearray(ack());zero_server[20:24] = b'\0' * 4
        wrong_server = bytearray(ack());wrong_server[20:24] = socket.inet_aton('127.0.0.9')
        for value in (bytes(bad), bytes(wrong_flags), bytes(zero_server), bytes(wrong_server), ack()[:-1], ack() + b'x', ack()[:240], ack(extra=bytes((51, 4, 0, 0, 0, 60))),
                      ack(extra=bytes((15, 1, 65))), ack()[:244] + b'\xff'):
            with self.subTest(payload=value.hex()[:80]), self.assertRaises(RuntimeError):gate.parse_inform(value)
        with self.assertRaisesRegex(RuntimeError, 'header\\[0:44\\]=') as observed:
            gate.parse_inform(bytes(wrong_server) + b'x' * 4096)
        self.assertLess(len(str(observed.exception)), 512)

    def test_queue_full_requires_positive_native_fill_then_actual_eagain(self):
        class Sender:
            def __init__(self, accepted):self.accepted = accepted
            def __enter__(self):return self
            def __exit__(self, *args):pass
            def setblocking(self, value):assert value is False
            def sendto(self, payload, address):
                self.accepted -= 1
                if self.accepted < 0:raise BlockingIOError()
                return len(payload)
        receiver = object.__new__(gate.Receiver);receiver.drain = lambda: b''
        with mock.patch.object(gate.socket, 'socket', return_value=Sender(2)):
            self.assertTrue(receiver.fill())
        with mock.patch.object(gate.socket, 'socket', return_value=Sender(0)):
            with self.assertRaises(RuntimeError):receiver.fill()
        with mock.patch.object(gate.socket, 'socket', return_value=Sender(1024)):
            with self.assertRaises(RuntimeError):receiver.fill()

    def test_rejection_and_empty_commit_are_distinct_and_counts_strict(self):
        for name in ('hosts-empty-commit', 'dhcp-hosts-empty-commit', 'dhcp-options-empty-commit'):
            value = rows();value[gate.CASE_NAMES.index(name)]['rejection_observed'] = True
            with self.assertRaises(RuntimeError):gate.validate_records(value)
        for name in gate.CASE_NAMES:
            value = rows();index = gate.CASE_NAMES.index(name);value[index]['query_count'] = True
            with self.subTest(name=name), self.assertRaises(RuntimeError):gate.validate_records(value)


if __name__ == '__main__':unittest.main()
