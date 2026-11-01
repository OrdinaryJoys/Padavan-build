#!/usr/bin/env python3
"""Source-only MIPS cross-module upgrade admission/signal proof.

This is an inert source adapter, never a real router PID1, flash writer,
watchdog operation, signal sender or reboot launcher.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import types

HARNESS_SOURCE_PATHS = {'guard': 'trunk/user/shared/upgrade_guard.h',
 'httpd': 'trunk/user/httpd/httpd.c',
 'http_header': 'trunk/user/httpd/httpd.h',
 'origin': 'trunk/user/httpd/http_origin_guard.c',
 'web': 'trunk/user/httpd/web_ex.c',
 'upload': 'trunk/user/httpd/upload.c',
 'buttons': 'trunk/user/rc/btn_action.c',
 'gpio': 'trunk/user/rc/gpio_btn.c',
 'rc': 'trunk/user/rc/rc.c',
 'init': 'trunk/user/rc/init.c',
 'watchdog': 'trunk/user/rc/watchdog.c',
 'upgrade_fixture': 'tests/upgrade_gate_harness.py',
 'http_fixture': 'tests/test_httpd_regressions.py'}
SOURCE_PATHS = {'guard': 'trunk/user/shared/upgrade_guard.h',
 'httpd': 'trunk/user/httpd/httpd.c',
 'http_header': 'trunk/user/httpd/httpd.h',
 'origin': 'trunk/user/httpd/http_origin_guard.c',
 'web': 'trunk/user/httpd/web_ex.c',
 'upload': 'trunk/user/httpd/upload.c',
 'buttons': 'trunk/user/rc/btn_action.c',
 'gpio': 'trunk/user/rc/gpio_btn.c',
 'rc': 'trunk/user/rc/rc.c',
 'init': 'trunk/user/rc/init.c',
 'watchdog': 'trunk/user/rc/watchdog.c',
 'upgrade_fixture': 'tests/upgrade_gate_harness.py',
 'http_fixture': 'tests/test_httpd_regressions.py',
 'rc_header': 'trunk/user/rc/rc.h',
 'rc_makefile': 'trunk/user/rc/Makefile',
 'shared_makefile': 'trunk/user/shared/Makefile',
 'upgrade_transaction_harness.py': 'tests/upgrade_transaction_harness.py'}
# Independently frozen expected results, copied for review before target execution.
COMPONENT_EXPECTED = {'query-idle': {'case': 'query-idle',
                'trace': ['blocked:0', 'errno-preserved:1', 'final-exclusive:free', 'effects:0']},
 'query-missing-directory': {'case': 'query-missing-directory',
                             'trace': ['blocked:0', 'lease-refused:1', 'final-exclusive:free', 'effects:0']},
 'unsafe-directory': {'case': 'unsafe-directory',
                      'trace': ['blocked:1', 'lease-refused:1', 'final-exclusive:free', 'effects:0']},
 'shared-excludes-transaction': {'case': 'shared-excludes-transaction',
                                 'trace': ['during-shared:blocked',
                                           'second-shared:1',
                                           'final-exclusive:free',
                                           'effects:0']},
 'transaction-excludes-action': {'case': 'transaction-excludes-action',
                                 'trace': ['action-refused:1', 'final-exclusive:free', 'effects:0']},
 'marker-rejects-action': {'case': 'marker-rejects-action',
                           'trace': ['blocked:1',
                                     'lease-refused:1',
                                     'marker-retained:1',
                                     'final-exclusive:free',
                                     'effects:0']},
 'http-idle-write': {'case': 'http-idle-write',
                     'trace': ['input',
                               'input-exclusive:blocked',
                               'output',
                               'output-exclusive:blocked',
                               'http:200',
                               'final-exclusive:free',
                               'effects:0']},
 'http-busy-write': {'case': 'http-busy-write',
                     'trace': ['http:503', 'marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'http-busy-auth-failure': {'case': 'http-busy-auth-failure',
                            'trace': ['http:401', 'marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'http-busy-cross-origin': {'case': 'http-busy-cross-origin',
                            'trace': ['http:403', 'marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'http-busy-status': {'case': 'http-busy-status',
                      'trace': ['output',
                                'output-exclusive:blocked',
                                'http:200',
                                'marker-retained:1',
                                'final-exclusive:free',
                                'effects:0']},
 'http-busy-status-head': {'case': 'http-busy-status-head',
                           'trace': ['http:200', 'marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'http-busy-backup-head': {'case': 'http-busy-backup-head',
                           'trace': ['http:503', 'marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'http-backup-prepare-failure': {'case': 'http-backup-prepare-failure',
                                 'trace': ['prepare',
                                           'prepare-exclusive:blocked',
                                           'cleanup',
                                           'http:500',
                                           'final-exclusive:free',
                                           'effects:0']},
 'http-backup-head-release': {'case': 'http-backup-head-release',
                              'trace': ['prepare',
                                        'prepare-exclusive:blocked',
                                        'cleanup',
                                        'http:200',
                                        'final-exclusive:free',
                                        'effects:0']},
 'direct-reboot-busy': {'case': 'direct-reboot-busy',
                        'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'direct-reboot-idle': {'case': 'direct-reboot-idle',
                        'trace': ['PID1-TERM',
                                  'effect-exclusive:blocked',
                                  'final-exclusive:free',
                                  'effects:1']},
 'apply-reset-busy': {'case': 'apply-reset-busy',
                      'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'apply-reset-idle': {'case': 'apply-reset-idle',
                      'trace': ['Restarting.asp',
                                'nvram-set',
                                'effect-exclusive:blocked',
                                'nvram-commit',
                                'effect-exclusive:blocked',
                                'PID1-TERM',
                                'effect-exclusive:blocked',
                                'final-exclusive:free',
                                'effects:3']},
 'restore-nv-busy': {'case': 'restore-nv-busy',
                     'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'restore-storage-busy': {'case': 'restore-storage-busy',
                          'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'upgrade-busy-preserves-upload': {'case': 'upgrade-busy-preserves-upload',
                                   'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'upgrade-request-handoff': {'case': 'upgrade-request-handoff',
                             'trace': ['input',
                                       'input-exclusive:blocked',
                                       'output',
                                       'output-exclusive:blocked',
                                       'notify-flash',
                                       'handoff-exclusive:free',
                                       'Updating.asp',
                                       'http:200',
                                       'request-fd-cleared:1',
                                       'final-exclusive:free',
                                       'effects:0']},
 'upload-busy': {'case': 'upload-busy', 'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'restore-upload-busy': {'case': 'restore-upload-busy',
                         'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'gpio-short-busy': {'case': 'gpio-short-busy',
                     'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'gpio-long-busy': {'case': 'gpio-long-busy',
                    'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'gpio-reset-busy': {'case': 'gpio-reset-busy',
                     'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'gpio-long-idle': {'case': 'gpio-long-idle',
                    'trace': ['LED',
                              'effect-exclusive:blocked',
                              'PID1-TERM',
                              'effect-exclusive:blocked',
                              'final-exclusive:free',
                              'effects:2']},
 'gpio-reset-idle': {'case': 'gpio-reset-idle',
                     'trace': ['erase-nvram',
                               'effect-exclusive:blocked',
                               'erase-storage',
                               'effect-exclusive:blocked',
                               'PID1-TERM',
                               'effect-exclusive:blocked',
                               'final-exclusive:free',
                               'effects:3']},
 'safe-release-reopens-action': {'case': 'safe-release-reopens-action',
                                 'trace': ['active-action-refused:1',
                                           'PID1-TERM',
                                           'effect-exclusive:blocked',
                                           'final-exclusive:free',
                                           'effects:1']},
 'cross-process-sh-exclusion': {'case': 'cross-process-sh-exclusion',
                                'trace': ['child-exclusive-refused:1', 'final-exclusive:free', 'effects:0']},
 'apply-group-percent-literal': {'case': 'apply-group-percent-literal',
                                 'trace': ['group-literal:1',
                                           'apply-group',
                                           'effect-exclusive:blocked',
                                           'validate-cgi',
                                           'effect-exclusive:blocked',
                                           'redirect',
                                           'final-exclusive:free',
                                           'effects:2']},
 'cli-reboot-busy': {'case': 'cli-reboot-busy',
                     'trace': ['cli-refused:1', 'marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'cli-halt-busy': {'case': 'cli-halt-busy',
                   'trace': ['cli-refused:1', 'marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'cli-reset-busy': {'case': 'cli-reset-busy',
                    'trace': ['cli-refused:1', 'marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'cli-reset-idle': {'case': 'cli-reset-idle',
                    'trace': ['erase-nvram',
                              'effect-exclusive:blocked',
                              'PID1-TERM',
                              'effect-exclusive:blocked',
                              'cli-result:0',
                              'final-exclusive:free',
                              'effects:2']},
 'phase-active-TERM': {'case': 'phase-active-TERM',
                       'trace': ['fault-latch:0', 'term-latch:0', 'final-exclusive:free', 'effects:0']},
 'phase-active-QUIT': {'case': 'phase-active-QUIT',
                       'trace': ['fault-latch:0', 'term-latch:0', 'final-exclusive:free', 'effects:0']},
 'phase-active-SEGV': {'case': 'phase-active-SEGV',
                       'trace': ['fault-quarantine',
                                 'fault-latch:1',
                                 'term-latch:1',
                                 'final-exclusive:free',
                                 'effects:0']},
 'phase-idle-TERM': {'case': 'phase-idle-TERM',
                     'trace': ['diagnostic',
                               'reset-signals',
                               'shutdown:reboot',
                               'broadcast-TERM',
                               'effect-exclusive:free',
                               'sync',
                               'reboot',
                               'fault-latch:0',
                               'term-latch:1',
                               'final-exclusive:free',
                               'effects:1']},
 'phase-idle-QUIT': {'case': 'phase-idle-QUIT',
                     'trace': ['diagnostic',
                               'shutdown:halt',
                               'fault-latch:0',
                               'term-latch:1',
                               'final-exclusive:free',
                               'effects:0']},
 'phase-events-active': {'case': 'phase-events-active',
                         'trace': ['usr1-latch:1', 'alarm-latch:1', 'final-exclusive:free', 'effects:0']},
 'phase-events-idle': {'case': 'phase-events-idle',
                       'trace': ['diagnostic',
                                 'diagnostic',
                                 'diagnostic',
                                 'notify-shutdown',
                                 'usr1-latch:1',
                                 'alarm-latch:1',
                                 'final-exclusive:free',
                                 'effects:0']},
 'phase-reap-active': {'case': 'phase-reap-active',
                       'trace': ['wait-calls:2', 'final-exclusive:free', 'effects:0']},
 'phase-reap-idle': {'case': 'phase-reap-idle',
                     'trace': ['reap-diagnostic', 'wait-calls:2', 'final-exclusive:free', 'effects:0']},
 'gpio-release-busy': {'case': 'gpio-release-busy',
                       'trace': ['marker-retained:1', 'final-exclusive:free', 'effects:0']},
 'gpio-event-busy-clears-latch': {'case': 'gpio-event-busy-clears-latch',
                                  'trace': ['button-count:0',
                                            'event-cleared:1',
                                            'marker-retained:1',
                                            'final-exclusive:free',
                                            'effects:0']},
 'gpio-release-idle': {'case': 'gpio-release-idle',
                       'trace': ['LED',
                                 'effect-exclusive:blocked',
                                 'erase-nvram',
                                 'effect-exclusive:blocked',
                                 'erase-storage',
                                 'effect-exclusive:blocked',
                                 'PID1-TERM',
                                 'effect-exclusive:blocked',
                                 'final-exclusive:free',
                                 'effects:4']},
 'init-signal-masks': {'case': 'init-signal-masks',
                       'trace': ['fatal-mask-calls:11',
                                 'event-mask-calls:4',
                                 'reap-mask-calls:1',
                                 'masks-valid:1',
                                 'final-exclusive:free',
                                 'effects:0']}}
FLASH_EXPECTED = {'flash-safe-prewrite-return': {'case': 'flash-safe-prewrite-return',
                                'trace': ['phase:0',
                                          'active:0',
                                          'marker:0',
                                          'action-refused:0',
                                          'writer:1',
                                          'reboot:0',
                                          'raw-shared-after:1',
                                          'prepare-checks:1',
                                          'prepare-admission-valid:1']},
 'flash-unknown-return': {'case': 'flash-unknown-return',
                          'trace': ['phase:1',
                                    'active:1',
                                    'marker:1',
                                    'action-refused:1',
                                    'writer:1',
                                    'reboot:0',
                                    'raw-shared-after:0',
                                    'prepare-checks:1',
                                    'prepare-admission-valid:1']},
 'flash-verified-worker-exit': {'case': 'flash-verified-worker-exit',
                                  'trace': ['phase:1',
                                            'active:1',
                                            'marker:1',
                                            'action-refused:1',
                                            'writer:1',
                                            'reboot:0',
                                            'raw-shared-after:0',
                                            'prepare-checks:1',
                                            'prepare-admission-valid:1']},
 'flash-save-abort': {'case': 'flash-save-abort',
                      'trace': ['phase:0',
                                'active:0',
                                'marker:0',
                                'action-refused:0',
                                'writer:0',
                                'reboot:0',
                                'raw-shared-after:1',
                                'prepare-checks:1',
                                'prepare-admission-valid:1']},
 'flash-hook-abort': {'case': 'flash-hook-abort',
                      'trace': ['phase:0',
                                'active:0',
                                'marker:0',
                                'action-refused:0',
                                'writer:0',
                                'reboot:0',
                                'raw-shared-after:1',
                                'prepare-checks:1',
                                'prepare-admission-valid:1']},
 'flash-action-already-admitted': {'case': 'flash-action-already-admitted',
                                   'trace': ['phase:0',
                                             'active:0',
                                             'marker:0',
                                             'action-refused:0',
                                             'writer:0',
                                             'reboot:0',
                                             'raw-shared-after:1',
                                             'prepare-checks:0',
                                             'prepare-admission-valid:1']}}
CASES = (('query-idle', {'adapter': 'components', 'case': 'query-idle'}),
 ('query-missing-directory', {'adapter': 'components', 'case': 'query-missing-directory'}),
 ('unsafe-directory', {'adapter': 'components', 'case': 'unsafe-directory'}),
 ('shared-excludes-transaction', {'adapter': 'components', 'case': 'shared-excludes-transaction'}),
 ('transaction-excludes-action', {'adapter': 'components', 'case': 'transaction-excludes-action'}),
 ('marker-rejects-action', {'adapter': 'components', 'case': 'marker-rejects-action'}),
 ('http-idle-write', {'adapter': 'components', 'case': 'http-idle-write'}),
 ('http-busy-write', {'adapter': 'components', 'case': 'http-busy-write'}),
 ('http-busy-auth-failure', {'adapter': 'components', 'case': 'http-busy-auth-failure'}),
 ('http-busy-cross-origin', {'adapter': 'components', 'case': 'http-busy-cross-origin'}),
 ('http-busy-status', {'adapter': 'components', 'case': 'http-busy-status'}),
 ('http-busy-status-head', {'adapter': 'components', 'case': 'http-busy-status-head'}),
 ('http-busy-backup-head', {'adapter': 'components', 'case': 'http-busy-backup-head'}),
 ('http-backup-prepare-failure', {'adapter': 'components', 'case': 'http-backup-prepare-failure'}),
 ('http-backup-head-release', {'adapter': 'components', 'case': 'http-backup-head-release'}),
 ('direct-reboot-busy', {'adapter': 'components', 'case': 'direct-reboot-busy'}),
 ('direct-reboot-idle', {'adapter': 'components', 'case': 'direct-reboot-idle'}),
 ('apply-reset-busy', {'adapter': 'components', 'case': 'apply-reset-busy'}),
 ('apply-reset-idle', {'adapter': 'components', 'case': 'apply-reset-idle'}),
 ('restore-nv-busy', {'adapter': 'components', 'case': 'restore-nv-busy'}),
 ('restore-storage-busy', {'adapter': 'components', 'case': 'restore-storage-busy'}),
 ('upgrade-busy-preserves-upload', {'adapter': 'components', 'case': 'upgrade-busy-preserves-upload'}),
 ('upgrade-request-handoff', {'adapter': 'components', 'case': 'upgrade-request-handoff'}),
 ('upload-busy', {'adapter': 'components', 'case': 'upload-busy'}),
 ('restore-upload-busy', {'adapter': 'components', 'case': 'restore-upload-busy'}),
 ('gpio-short-busy', {'adapter': 'components', 'case': 'gpio-short-busy'}),
 ('gpio-long-busy', {'adapter': 'components', 'case': 'gpio-long-busy'}),
 ('gpio-reset-busy', {'adapter': 'components', 'case': 'gpio-reset-busy'}),
 ('gpio-long-idle', {'adapter': 'components', 'case': 'gpio-long-idle'}),
 ('gpio-reset-idle', {'adapter': 'components', 'case': 'gpio-reset-idle'}),
 ('safe-release-reopens-action', {'adapter': 'components', 'case': 'safe-release-reopens-action'}),
 ('cross-process-sh-exclusion', {'adapter': 'components', 'case': 'cross-process-sh-exclusion'}),
 ('apply-group-percent-literal', {'adapter': 'components', 'case': 'apply-group-percent-literal'}),
 ('cli-reboot-busy', {'adapter': 'components', 'case': 'cli-reboot-busy'}),
 ('cli-halt-busy', {'adapter': 'components', 'case': 'cli-halt-busy'}),
 ('cli-reset-busy', {'adapter': 'components', 'case': 'cli-reset-busy'}),
 ('cli-reset-idle', {'adapter': 'components', 'case': 'cli-reset-idle'}),
 ('phase-active-TERM', {'adapter': 'components', 'case': 'phase-active-TERM'}),
 ('phase-active-QUIT', {'adapter': 'components', 'case': 'phase-active-QUIT'}),
 ('phase-active-SEGV', {'adapter': 'components', 'case': 'phase-active-SEGV'}),
 ('phase-idle-TERM', {'adapter': 'components', 'case': 'phase-idle-TERM'}),
 ('phase-idle-QUIT', {'adapter': 'components', 'case': 'phase-idle-QUIT'}),
 ('phase-events-active', {'adapter': 'components', 'case': 'phase-events-active'}),
 ('phase-events-idle', {'adapter': 'components', 'case': 'phase-events-idle'}),
 ('phase-reap-active', {'adapter': 'components', 'case': 'phase-reap-active'}),
 ('phase-reap-idle', {'adapter': 'components', 'case': 'phase-reap-idle'}),
 ('gpio-release-busy', {'adapter': 'components', 'case': 'gpio-release-busy'}),
 ('gpio-event-busy-clears-latch', {'adapter': 'components', 'case': 'gpio-event-busy-clears-latch'}),
 ('gpio-release-idle', {'adapter': 'components', 'case': 'gpio-release-idle'}),
 ('init-signal-masks', {'adapter': 'components', 'case': 'init-signal-masks'}),
 ('flash-safe-prewrite-return', {'adapter': 'flash', 'case': 'flash-safe-prewrite-return'}),
 ('flash-unknown-return', {'adapter': 'flash', 'case': 'flash-unknown-return'}),
 ('flash-verified-worker-exit', {'adapter': 'flash', 'case': 'flash-verified-worker-exit'}),
 ('flash-save-abort', {'adapter': 'flash', 'case': 'flash-save-abort'}),
 ('flash-hook-abort', {'adapter': 'flash', 'case': 'flash-hook-abort'}),
 ('flash-action-already-admitted', {'adapter': 'flash', 'case': 'flash-action-already-admitted'}))
EXPECTED = {**COMPONENT_EXPECTED, **FLASH_EXPECTED}
FUNCTION_SOURCES = {'firmware_upgrade_signal_inhibited': 'rc',
 'firmware_upgrade_signal_fault': 'rc',
 'reset_to_defaults': 'rc',
 'sys_exit': 'init',
 'sys_stop': 'init',
 'catch_sig_fatal': 'init',
 'catch_sig_event': 'init',
 'catch_sig_reap': 'init',
 'init_signals': 'init',
 'http_upgrade_action_acquire': 'httpd',
 'http_upgrade_action_handoff': 'httpd',
 'http_upgrade_action_release': 'httpd',
 'parse_content_length': 'httpd',
 'parse_multipart_boundary': 'httpd',
 'trim_header_value': 'httpd',
 'handle_request': 'httpd',
 'sys_reboot': 'web',
 'apply_cgi': 'web',
 'do_upgrade_fw_cgi': 'web',
 'do_restore_nv_cgi': 'web',
 'do_restore_st_cgi': 'web',
 'do_upgrade_fw_post': 'upload',
 'do_restore_nv_post': 'upload',
 'do_restore_st_post': 'upload',
 'upgrade_gpio_action_release': 'buttons',
 'btn_event_short': 'buttons',
 'btn_event_long': 'buttons',
 'btn_reset_action': 'buttons',
 'upgrade_gpio_event_release': 'gpio',
 'btn_released_handle': 'gpio',
 'btn_ev_handle': 'gpio',
 'upgrade_guard_directory': 'guard',
 'upgrade_actions_blocked': 'guard',
 'upgrade_action_leave': 'guard',
 'upgrade_guard_enter': 'guard',
 'upgrade_action_enter': 'guard',
 'upgrade_transaction_enter': 'guard'}
FLASH_FUNCTION_SOURCES = {'write_storage_to_mtd': 'rc',
 'firmware_upgrade_signal_inhibited': 'rc',
 'firmware_upgrade_signal_fault': 'rc',
 'firmware_upgrade_inhibited': 'rc',
 'firmware_upgrade_inhibit': 'rc',
 'firmware_upgrade_stage_writer': 'rc',
 'firmware_upgrade_number': 'rc',
 'firmware_upgrade_result': 'rc',
 'firmware_upgrade_run': 'rc',
 'firmware_upgrade_start_networkmap': 'rc',
 'firmware_upgrade_start_detect': 'rc',
 'firmware_upgrade_stop_watchdog': 'rc',
 'firmware_upgrade_disable_watchdog': 'rc',
 'firmware_upgrade_services': 'rc',
 'flash_firmware': 'rc',
 'start_watchdog': 'watchdog',
 'notify_watchdog_time': 'watchdog',
 'watchdog_main': 'watchdog',
 'upgrade_guard_directory': 'guard',
 'upgrade_actions_blocked': 'guard',
 'upgrade_action_leave': 'guard',
 'upgrade_guard_enter': 'guard',
 'upgrade_action_enter': 'guard',
 'upgrade_transaction_enter': 'guard'}
PROFILE = 'k2p-4.4'
ROLE = ('Locked production-source MIPS adapter; ordinary private fixture files '
        'and action leases are real; flash, watchdog, management effects, '
        'PID1 signal delivery and reset effects are inert.')
LIMITS = (
    'No actual shipped rc/httpd/GPIO whole program or router PID1 is executed.',
    'No real MTD, hardware watchdog, network listener, host PID1 signal, firmware write or reboot occurs.',
    'Component fixture OWNER is a compile-time effective-UID override; flash adapter uses the documented old-core fstat/fstatat UID-to-root model. Neither changes real credentials.',
    'Fatal parking is observed through the explicit inert fixture boundary, not an injected physical hardware fault.',
    'BIND_NOW is checked for the rc and libshared objects themselves, not recursively asserted for libc/loader dependencies.',
    'This does not prove complete memory residency, kernel/SoC reset, management survival, power-loss recovery or automatic rollback.',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mask_c(text):
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*',
                  lambda match: ' ' * len(match.group()), text)


def extract_function(text, name):
    pattern = (r'(?:static\s+)?(?:inline\s+)?(?:void|int|ssize_t|char\s*\*|FILE\s*\*)\s*\b' +
               re.escape(name) + r'\s*\([^;{}]*\)\s*\{')
    matches = list(re.finditer(pattern, mask_c(text)))
    require(len(matches) == 1, 'Missing/ambiguous actual transaction helper: ' + name)
    match = matches[0]
    opening, depth = text.index('{', match.start()), 0
    for token in re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|[{}]',
                             text[opening:]):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if depth == 0:
                return text[match.start():opening + token.end()]
    raise ValueError('Unclosed transaction helper: ' + name)


def read_source_inputs(trunk):
    return {key: (trunk.parent / relative).read_bytes().decode()
            for key, relative in SOURCE_PATHS.items()}


def load_checked_harness(text):
    """Compile the exact supplied source bytes, never a cached pyc/import fallback."""
    ast.parse(text)
    name = '_locked_upgrade_transaction_harness'
    module = types.ModuleType(name)
    module.__file__ = '<locked-upgrade-transaction-harness>'
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(text, module.__file__, 'exec'), module.__dict__)
    finally:
        if previous is None:
            del sys.modules[name]
        else:
            sys.modules[name] = previous
    require(callable(getattr(module, 'generate_source', None)),
            'Missing pure transaction source generator')
    return module


def generate_source(inputs, fixture_root, owner_uid=0, adapter='components'):
    require(set(inputs) == set(SOURCE_PATHS), 'Transaction source set changed')
    require(CASES and set(EXPECTED) == {name for name, _ in CASES} and FUNCTION_SOURCES,
            'Cross-module transaction contract has not been frozen')
    module = load_checked_harness(inputs['upgrade_transaction_harness.py'])
    require(type(owner_uid) is int and 0 <= owner_uid < 2 ** 32,
            'Invalid compiled fixture owner')
    rc_masked = mask_c(inputs['rc'])
    for variable in ('firmware_upgrade_pid1_active', 'firmware_upgrade_pid1_fault'):
        require(re.search(r'^\s*static\s+volatile\s+sig_atomic_t\s+' + variable +
                          r'\s*(?:=\s*0\s*)?;', rc_masked, re.M),
                'Production signal latch must remain static volatile sig_atomic_t: ' + variable)
    header = mask_c(inputs['rc_header'])
    for result, name in (('int', 'firmware_upgrade_signal_inhibited'),
                         ('void', 'firmware_upgrade_signal_fault')):
        require(re.search(r'\b' + result + r'\s+' + name + r'\s*\(\s*void\s*\)\s*;', header),
                'Missing/wrong production signal prototype: ' + name)
    query = extract_function(inputs['rc'], 'firmware_upgrade_signal_inhibited')
    setter = extract_function(inputs['rc'], 'firmware_upgrade_signal_fault')
    for body, statement in ((query, r'return\s+firmware_upgrade_pid1_active\s*;'),
                            (setter, r'firmware_upgrade_pid1_fault\s*=\s*1\s*;')):
        masked = mask_c(body)
        require(re.fullmatch(r'\s*' + statement + r'\s*',
                             masked[masked.index('{') + 1:masked.rindex('}')]) is not None,
                'Signal guard query/setter must be memory-only')
    require('-Wl,-z,now' in inputs['rc_makefile'],
            'rc must request immediate dynamic symbol binding')
    require(re.search(r'^\s*\$\(LD\).*?-z\s+now\b', inputs['shared_makefile'], re.M),
            'libshared direct linker command must request immediate binding')
    require(module.SOURCE_PATHS == HARNESS_SOURCE_PATHS,
            'Source adapter input mapping changed')
    expected_components = tuple(COMPONENT_EXPECTED.items())
    expected_flash = tuple(FLASH_EXPECTED.items())
    require(json.dumps(module.CASES) == json.dumps(expected_components) and
            json.dumps(module.FLASH_CASES) == json.dumps(expected_flash),
            'Source fixture contract differs from independent fixed target expectations')
    texts = {key: inputs[key] for key in HARNESS_SOURCE_PATHS}
    require(adapter in ('components', 'flash'), 'Unknown transaction adapter')
    generator = module.generate_source if adapter == 'components' else module.generate_flash_source
    generated = generator(texts, str(fixture_root), owner_uid=owner_uid)
    require(type(generated) is str and 0 < len(generated) <= 2 * 1024 * 1024,
            'Invalid/oversized transaction source adapter')
    function_sources = FUNCTION_SOURCES if adapter == 'components' else FLASH_FUNCTION_SOURCES
    functions = {name: extract_function(inputs[key], name)
                 for name, key in function_sources.items()}
    for name, body in functions.items():
        require(generated.count(body) == 1,
                'Adapter omitted/duplicated actual transaction helper: ' + name)
    boundaries = (
        ('#define kill fixture_kill', '#define reboot fixture_reboot', '#define pause fixture_pause')
        if adapter == 'components' else
        ('#define ioctl fixture_ioctl', '#define reboot fake_reboot',
         '#define mlockall fixture_mlockall', '#define sync fake_sync',
         'static int firmware_upgrade_spawn(', 'static int doSystem('))
    for boundary in boundaries:
        require(boundary in generated, 'Missing explicit inert adapter boundary: ' + boundary)
    return generated, functions


def validate_records(records):
    require(CASES and set(EXPECTED) == {name for name, _ in CASES},
            'Cross-module transaction contract has not been frozen')
    require(type(records) is list and
            all(type(row) is dict and set(row) == {'case', 'inputs', 'observed'} for row in records),
            'Invalid transaction record schema')
    require([row['case'] for row in records] == [name for name, _ in CASES],
            'Missing, duplicate, reordered or unexpected transaction case')
    for row, (name, inputs) in zip(records, CASES):
        require(json.dumps(row['inputs'], sort_keys=True) == json.dumps(inputs, sort_keys=True),
                'Transaction input mismatch: ' + name)
        require(json.dumps(row['observed'], sort_keys=True) ==
                json.dumps(EXPECTED[name], sort_keys=True),
                'Transaction phase/effect/trace mismatch: ' + name)


def program_headers(data, expected_type=2):
    require(len(data) >= 52 and data[:7] == b'\x7fELF\x01\x01\x01',
            'Probe must be ELF32 little-endian MIPS')
    fields = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
    require(fields[0] == expected_type and fields[1] == 8 and fields[2] == 1,
            'Unexpected MIPS ELF object type')
    phoff, phentsize, phnum = fields[4], fields[8], fields[9]
    require(phentsize == 32 and 0 < phnum <= 128 and
            52 <= phoff <= len(data) and phnum * phentsize <= len(data) - phoff,
            'Invalid MIPS probe program headers')
    headers = []
    for index in range(phnum):
        kind, offset, _, _, filesz, memsz, _, _ = struct.unpack_from(
            '<IIIIIIII', data, phoff + index * phentsize)
        require(offset <= len(data) and filesz <= len(data) - offset and memsz >= filesz,
                'Truncated MIPS probe segment')
        headers.append(struct.unpack_from('<IIIIIIII', data, phoff + index * phentsize))
    require(any(header[0] == 1 for header in headers), 'MIPS executable has no load segment')
    if expected_type == 2:
        entry = fields[3]
        require(any(header[0] == 1 and header[6] & 1 and
                    header[2] <= entry < header[2] + header[4] for header in headers),
                'MIPS executable entry is outside file-backed executable LOAD')
    return headers


def validate_mips_elf(data):
    headers = program_headers(data)
    types_found = [header[0] for header in headers]
    require(1 in types_found and 2 not in types_found and 3 not in types_found,
            'Transaction adapter must be static, with no PT_INTERP/PT_DYNAMIC')
    return {'elf_class':32, 'byte_order':'little', 'e_machine':8,
            'e_type':2, 'entry_address':hex(struct.unpack_from('<I', data, 24)[0]),
            'static_no_interpreter_or_dynamic_segment':True}


def validate_shipped_dynamic(data, object_type, require_interpreter):
    headers = program_headers(data, expected_type=object_type)
    interpreters = [header for header in headers if header[0] == 3]
    dynamic = [header for header in headers if header[0] == 2]
    require(len(interpreters) == int(require_interpreter) and len(dynamic) == 1,
            'Shipped object dynamic binding is missing/ambiguous')
    name = None
    if require_interpreter:
        interp = interpreters[0]
        value = data[interp[1]:interp[1] + interp[4]]
        require(value.endswith(b'\0') and b'\0' not in value[:-1],
                'Malformed shipped object interpreter')
        name = value[:-1].decode('ascii')
    dyn = dynamic[0]
    require(dyn[4] % 8 == 0 and dyn[4] <= 65536, 'Malformed shipped rc dynamic table')
    tags = []
    for offset in range(dyn[1], dyn[1] + dyn[4], 8):
        tag, value = struct.unpack_from('<II', data, offset)
        if tag == 0:
            break
        tags.append((tag, value))
    else:
        raise ValueError('Unterminated shipped rc dynamic table')
    now = any(tag == 24 or (tag == 30 and value & 8) or
              (tag == 0x6ffffffb and value & 1) for tag, value in tags)
    require(now, 'Shipped object must have BIND_NOW; a Makefile string alone is insufficient')
    strings = [value for tag, value in tags if tag == 5]
    sizes = [value for tag, value in tags if tag == 10]
    require(len(strings) == len(sizes) == 1 and 0 < sizes[0] <= len(data),
            'Invalid shipped rc dynamic strings')
    locations = [header[1] + strings[0] - header[2] for header in headers
                 if header[0] == 1 and header[2] <= strings[0] and
                 strings[0] - header[2] <= header[4] - sizes[0]]
    require(len(locations) == 1, 'Unmapped shipped rc dynamic strings')
    pool = data[locations[0]:locations[0] + sizes[0]]
    needed = []
    for tag, value in tags:
        if tag == 1:
            require(value < len(pool) and b'\0' in pool[value:],
                    'Invalid shipped rc DT_NEEDED')
            needed.append(pool[value:pool.index(0, value)].decode('ascii'))
    return {'bytes':len(data), 'sha256':sha(data), 'elf_class':32,
            'byte_order':'little', 'e_machine':8, 'e_type':object_type,
            'PT_INTERP':name, 'DT_NEEDED':needed,
            'BIND_NOW':True, 'whole_object_executed':False}


def validate_shipped_rc(data):
    value = validate_shipped_dynamic(data, 2, True)
    value['whole_rc_executed'] = False
    return value


def validate_shipped_libshared(data):
    value = validate_shipped_dynamic(data, 3, False)
    value['whole_libshared_executed'] = False
    return value


def export_probe(output, generated, binary, adapter='components'):
    require(adapter in ('components', 'flash'), 'Unknown export adapter')
    name = 'target-upgrade-transaction-' + adapter
    (output.parent / (name + '.c')).write_bytes(generated)
    target = output.parent / name
    target.write_bytes(binary)
    target.chmod(0o755)


def execute_cases(command, adapter, fixture):
    records = []
    for name, options in CASES:
        if options['adapter'] != adapter:
            continue
        # Only this controller-created, private subtree is reset. Flash cases
        # intentionally retain unresolved marker/lease artifacts until exit.
        if fixture.exists():
            require(fixture.is_dir() and not fixture.is_symlink(),
                    'Fixture root was replaced by an unsafe object')
            shutil.rmtree(fixture)
        fixture.mkdir(mode=0o700)
        result = subprocess.run([*command, name], capture_output=True, text=True, timeout=20)
        require(result.returncode == 0 and not result.stderr,
                f'{name}: probe exit={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}')
        try:
            observed = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ValueError('Invalid transaction probe JSON: ' + name) from error
        records.append({'case':name, 'inputs':options.copy(), 'observed':observed})
    return records


def check(trunk, compiler, sysroot, output, preflight=False, rootfs=None):
    config = (trunk / '.config').read_text()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M),
            'Transaction proof requires configured K2P4.4')
    inputs = read_source_inputs(trunk)
    require(preflight or rootfs is not None,
            'Final transaction proof requires actual shipped --rootfs rc binding')
    shipped_rc = None
    shipped_libshared = None
    if rootfs is not None:
        shipped_rc = validate_shipped_rc((rootfs / 'sbin/rc').read_bytes())
        shipped_libshared = validate_shipped_libshared((rootfs / 'lib/libshared.so').read_bytes())
    qemu = shutil.which('qemu-mipsel')
    require(qemu is not None, 'qemu-mipsel is required')
    with tempfile.TemporaryDirectory(prefix='k2p-upgrade-transaction-', dir='/tmp') as temp:
        root = Path(temp)
        owner_uid = os.geteuid()
        probes, exports, functions_by_adapter, records = {}, {}, {}, []
        for adapter in ('components', 'flash'):
            fixture = root / (adapter + '-fixture')
            generated, functions = generate_source(inputs, fixture, owner_uid=owner_uid,
                                                    adapter=adapter)
            source, binary = root / (adapter + '.c'), root / adapter
            source.write_text(generated)
            compiled = subprocess.run(
                [str(compiler), '-std=gnu99', '-Os', '-static', '-Wall', '-Wextra', '-Werror',
                 '-Wno-unused-function', '-Wno-unused-parameter', str(source), '-o', str(binary)],
                capture_output=True, text=True, timeout=90)
            require(compiled.returncode == 0,
                    'Transaction MIPS compile failed: ' + compiled.stdout + compiled.stderr)
            binary_data = binary.read_bytes()
            elf = validate_mips_elf(binary_data)
            # Both adapters are static. Deliberately omit -L so a sysroot /tmp
            # alias cannot redirect ordinary fixture files into a stale tree.
            records += execute_cases([qemu, str(binary)], adapter, fixture)
            generated_data = generated.encode()
            exports[adapter] = (generated_data, binary_data)
            functions_by_adapter[adapter] = {name:sha(body.encode()) for name,body in functions.items()}
            probes[adapter] = {
                'source_file':'target-upgrade-transaction-' + adapter + '.c',
                'binary_file':'target-upgrade-transaction-' + adapter,
                'fixture_root':str(fixture),
                'generated_source_sha256':sha(generated_data),
                'mips_probe_sha256':sha(binary_data), 'probe_elf':elf,
                'owner_model':('compiled UPGRADE_GUARD_OWNER=' + str(owner_uid)
                               if adapter == 'components' else
                               'production OWNER=0; documented old-core fstat/fstatat synthetic UID mapping'),
                'owner_uid':owner_uid}
        validate_records(records)
    output.parent.mkdir(parents=True, exist_ok=True)
    for adapter, (generated_data, binary_data) in exports.items():
        export_probe(output, generated_data, binary_data, adapter)
    report = {
        'schema_version':1, 'status':'PASS', 'profile':PROFILE,
        'phase':'early-source-only' if preflight else 'final-source-only',
        'execution_role':ROLE,
        'shipped_rc_binding':shipped_rc,
        'shipped_libshared_binding':shipped_libshared,
        'required_cases':[name for name, _ in CASES], 'checks':records,
        'source_files':SOURCE_PATHS,
        'source_sha256':{key:sha(value.encode()) for key,value in inputs.items()},
        'source_functions_sha256':functions_by_adapter,
        'probes':probes,
        'compiler':str(compiler), 'limits':list(LIMITS)}
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Target upgrade transaction: {len(records)} source-only cross-module cases PASS')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('trunk', 'compiler', 'sysroot', 'output'):
        parser.add_argument('--'+option, type=Path, required=True)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--rootfs', type=Path)
    args = parser.parse_args()
    try:
        check(args.trunk.resolve(), args.compiler.resolve(), args.sysroot.resolve(),
              args.output, args.preflight, args.rootfs.resolve() if args.rootfs else None)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Target upgrade transaction validation failed: ' + str(error) + '\n')
