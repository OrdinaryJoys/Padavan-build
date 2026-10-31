"""Contract corruption controls only: no mounts, daemon, upstream or target execution."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_target_runtime_dns as gate


def records():
    result = []
    for name in gate.CASE_NAMES:
        fatal = name in gate.PARSER_CASES | gate.FATAL_CASES
        first = None if fatal else '192.0.2.51'
        result.append(dict(case=name, exit_code=17 if name == 'lease-init-exit7' else (3 if fatal else 0), rejected=name in gate.REJECT_CASES,
                           diagnostic_observed=True, first_answer=first,
                           after_answer=None if fatal else ('192.0.2.52' if name == 'atomic-servers-reload' else first),
                           daemon_stopped=True, elapsed_ms=10000 if name == 'lease-init-timeout' else 10,
                           null_identity_preserved=True if 'null-' in name else None))
    return result


def report():
    return dict(schema_version=1, status='PASS', profile='k2p-4.4', execution_role=gate.ROLE,
                source_sha256={'locked': 'a' * 64}, shipped={'dnsmasq': {'sha256': 'b' * 64}},
                required_cases=list(gate.CASE_NAMES), checks=records(), filesystem_limits=gate.FILESYSTEM_LIMITS,
                limits=gate.LIMITS, failure=None, isolation=dict(worker_pid=1, loopback_only=True,
                private_mount_propagation=True, anchors_cloexec=True, namespace_exit_confirmed=True,
                namespaces={name: dict(parent_inode=10 + i, worker_inode=20 + i) for i, name in enumerate(('mnt', 'net', 'pid'))}))


class RuntimeDNSControls(unittest.TestCase):
    def test_exact_report_accepts_without_executing_target(self):
        value = report()
        self.assertTrue(gate.validate_report(value, value['source_sha256'], value['shipped']))

    def test_every_case_and_exact_order_are_required(self):
        for index in range(len(gate.CASE_NAMES)):
            value = records(); del value[index]
            with self.subTest(index=index), self.assertRaises(RuntimeError): gate.validate_records(value)
        for value in (records()[::-1], records() + [records()[0]]):
            with self.assertRaises(RuntimeError): gate.validate_records(value)

    def test_false_rejection_wrong_raw_status_and_cleanup_failures_rejected(self):
        for name, field, wrong in [('fifo-servers-reload', 'rejected', False),
                                   ('fifo-resolv-domain-test', 'exit_code', 0),
                                   ('fifo-log-startup', 'exit_code', 1),
                                   ('regular-servers', 'exit_code', False),
                                   ('fifo-addn-hosts', 'diagnostic_observed', False),
                                   ('fifo-live-resolv', 'daemon_stopped', False),
                                   ('regular-servers', 'elapsed_ms', True),
                                   ('lease-init-timeout', 'elapsed_ms', 0),
                                   ('lease-init-timeout', 'elapsed_ms', 15001),
                                   ('null-log-startup', 'null_identity_preserved', False),
                                   ('null-lease-startup', 'null_identity_preserved', None),
                                   ('regular-servers', 'null_identity_preserved', True),
                                   ('regular-servers', 'elapsed_ms', 20001)]:
            value = records(); value[gate.CASE_NAMES.index(name)][field] = wrong
            with self.subTest(name=name, field=field), self.assertRaises(RuntimeError): gate.validate_records(value)

    def test_live_queries_must_preserve_or_replace_exact_policy(self):
        for name, field, wrong in [('fifo-servers-reload', 'after_answer', None),
                                   ('oversize-servers-reload', 'after_answer', '192.0.2.52'),
                                   ('atomic-servers-reload', 'after_answer', '192.0.2.51'),
                                   ('fifo-resolv-domain-capture', 'first_answer', '192.0.2.51')]:
            value = records(); value[gate.CASE_NAMES.index(name)][field] = wrong
            with self.subTest(name=name), self.assertRaises(RuntimeError): gate.validate_records(value)

    def test_source_image_scope_and_production_limits_are_bound(self):
        original = report()
        for key, wrong in [('source_sha256', {'locked': 'c' * 64}), ('shipped', {}),
                           ('execution_role', 'host stub'), ('limits', {}), ('filesystem_limits', {}),
                           ('required_cases', list(gate.CASE_NAMES[:-1])), ('schema_version', True),
                           ('failure', 'ignored error')]:
            value = copy.deepcopy(original); value[key] = wrong
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                gate.validate_report(value, original['source_sha256'], original['shipped'])

    def test_initial_namespaces_and_unconfirmed_teardown_cannot_pass(self):
        original = report()
        for name in ('mnt', 'net', 'pid'):
            value = copy.deepcopy(original); x = value['isolation']['namespaces'][name]; x['worker_inode'] = x['parent_inode']
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                gate.validate_report(value, original['source_sha256'], original['shipped'])
        for field, wrong in [('worker_pid', 2), ('worker_pid', True), ('loopback_only', False),
                             ('anchors_cloexec', False), ('namespace_exit_confirmed', False),
                             ('private_mount_propagation', False)]:
            value = copy.deepcopy(original); value['isolation'][field] = wrong
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                gate.validate_report(value, original['source_sha256'], original['shipped'])

    def test_extra_report_and_case_fields_cannot_hide_missing_evidence(self):
        value = report(); value['unchecked'] = 'data'
        with self.assertRaises(RuntimeError): gate.validate_report(value, value['source_sha256'], value['shipped'])
        value = records(); value[0]['unchecked'] = True
        with self.assertRaises(RuntimeError): gate.validate_records(value)


if __name__ == '__main__':
    unittest.main()
