#!/usr/bin/env python3
"""Actual-source mutation MIPS models, late-bound to shipped legacy mtd_write.

Only configured Linux CI compiles/runs inert adapters; no device operation.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import check_target_resident_upgrade as resident
import check_target_dynamic_dns as dns

checked_module=resident.checked_module
SOURCE_PATHS = {'mtd': 'trunk/user/mtd_write/mtd.c',
 'legacy_guard': 'trunk/user/mtd_write/legacy_guard.h',
 'harness': 'tests/mtd_mutation_harness.py',
 'legacy_harness': 'tests/legacy_firmware_harness.py',
 'makefile': 'trunk/user/mtd_write/Makefile'}
HARNESS_SOURCE_PATHS = {'mtd': 'trunk/user/mtd_write/mtd.c', 'legacy_guard': 'trunk/user/mtd_write/legacy_guard.h'}
FUNCTION_SOURCES = {'mtd_unlock': 'mtd', 'mtd_erase': 'mtd', 'do_reboot': 'mtd', 'main': 'mtd'}
BASELINE_COMMIT = '6e91276a33d1bd83d416fc8253feb01f30677743'
ROLE = ('Actual legacy unlock/erase/reset/main bodies in inert static MIPS adapters; current, fixed6e baseline and '
 'disabled execution controls')
LIMITS = ('No router connection, flash write, device reset, host proc write, or private mutation payload is used.',
 'The focused generic legacy model disables K2P admission only to exercise error-to-reboot suppression; the '
 'separate mandatory admission gate enforces the shipped K2P guard.',
 'Metadata and flash ioctl/close effects are inert; primary write and JFFS append are recording callbacks, '
 'covered separately by their full IO regressions.',
 'A failed or partially completed erase cannot be rolled back by this error propagation; the caller must '
 'retain its live configuration and report failure.',
 'Each ELF and C source is bound to its own original metadata; no early/late byte normalization is accepted.',
 'Unbounded kernel/device calls do not acquire a hard deadline from this change.',
 'The running old efd2 first-hop kernel/PID1/writer is not retroactively repaired, and historical loss of '
 'connectivity has no newly established unique cause.')
FLAGS = ('-std=gnu99',
 '-Os',
 '-static',
 '-s',
 '-Wall',
 '-Wextra',
 '-Werror',
 '-Wno-unused-parameter',
 '-Wno-unused-function',
 '-Wno-sign-compare')
MAX_SOURCE = 1048576
MAX_REPORT = 2097152
MAX_PROBE = 8388608
CASE_ARGS = {'erase-ok': ['erase', 'Storage'],
 'unlock-ok': ['unlock', 'Storage'],
 'unlock-error': ['erase', 'Storage'],
 'block-unlock-error': ['erase', 'Storage'],
 'unlock-unsupported': ['erase', 'Storage'],
 'unlock-enotty': ['erase', 'Storage'],
 'erase-error-first': ['erase', 'Storage'],
 'erase-error-second': ['erase', 'Storage'],
 'unlock-close-error': ['erase', 'Storage'],
 'erase-close-error': ['erase', 'Storage'],
 'open-error': ['erase', 'Storage'],
 'erase-open-error': ['erase', 'Storage'],
 'zero-size': ['erase', 'Storage'],
 'zero-erase': ['erase', 'Storage'],
 'negative-size': ['erase', 'Storage'],
 'negative-erase': ['erase', 'Storage'],
 'unaligned-size': ['erase', 'Storage'],
 'oversized-erase': ['erase', 'Storage'],
 'preerase-failure': ['-e', 'Storage', 'write', '@IMAGE', 'Config'],
 'preunlock-failure': ['-e', 'Storage', 'write', '@IMAGE', 'Config'],
 'write-unlock-failure': ['write', '@IMAGE', 'Storage'],
 'jffs-unlock-failure': ['jffs2write', '@IMAGE', 'Storage'],
 'colon-unlock-ok': ['unlock', 'Storage:Config'],
 'colon-unlock-second-error': ['unlock', 'Storage:Config'],
 'colon-alloc-error': ['unlock', 'Storage:Config'],
 'other-board-reboot-error': ['-r', 'erase', 'Storage']}
BASELINE_CASES = ('erase-ok',
 'unlock-error',
 'block-unlock-error',
 'erase-error-first',
 'erase-error-second',
 'unlock-close-error',
 'erase-close-error',
 'preerase-failure',
 'preunlock-failure',
 'write-unlock-failure',
 'jffs-unlock-failure',
 'other-board-reboot-error')
BASELINE_FUNCTION_HASHES = {'mtd_unlock': 'fd773815ac9bbbf70d460da4e619da05aa899afc6ec676f63d38f203b7ab8224',
 'mtd_erase': '2b071665543a53f94370f5a1a10b46fb48b9b316ec3acd08c999f81d966975eb',
 'main': '478d67ce44d3e3f2638a0f271b8070b9a97f204f6eeeae0f31529badd523a36d',
 'do_reboot': '5de54df63578744f1ae75ea668361c821c2bfaa0f85c165ab142d3b6c81b70c5'}
CASES = (('current:erase-ok', {'mode': 'current', 'selector': 'erase-ok'}),
 ('current:unlock-ok', {'mode': 'current', 'selector': 'unlock-ok'}),
 ('current:unlock-error', {'mode': 'current', 'selector': 'unlock-error'}),
 ('current:block-unlock-error', {'mode': 'current', 'selector': 'block-unlock-error'}),
 ('current:unlock-unsupported', {'mode': 'current', 'selector': 'unlock-unsupported'}),
 ('current:unlock-enotty', {'mode': 'current', 'selector': 'unlock-enotty'}),
 ('current:erase-error-first', {'mode': 'current', 'selector': 'erase-error-first'}),
 ('current:erase-error-second', {'mode': 'current', 'selector': 'erase-error-second'}),
 ('current:unlock-close-error', {'mode': 'current', 'selector': 'unlock-close-error'}),
 ('current:erase-close-error', {'mode': 'current', 'selector': 'erase-close-error'}),
 ('current:open-error', {'mode': 'current', 'selector': 'open-error'}),
 ('current:erase-open-error', {'mode': 'current', 'selector': 'erase-open-error'}),
 ('current:zero-size', {'mode': 'current', 'selector': 'zero-size'}),
 ('current:zero-erase', {'mode': 'current', 'selector': 'zero-erase'}),
 ('current:negative-size', {'mode': 'current', 'selector': 'negative-size'}),
 ('current:negative-erase', {'mode': 'current', 'selector': 'negative-erase'}),
 ('current:unaligned-size', {'mode': 'current', 'selector': 'unaligned-size'}),
 ('current:oversized-erase', {'mode': 'current', 'selector': 'oversized-erase'}),
 ('current:preerase-failure', {'mode': 'current', 'selector': 'preerase-failure'}),
 ('current:preunlock-failure', {'mode': 'current', 'selector': 'preunlock-failure'}),
 ('current:write-unlock-failure', {'mode': 'current', 'selector': 'write-unlock-failure'}),
 ('current:jffs-unlock-failure', {'mode': 'current', 'selector': 'jffs-unlock-failure'}),
 ('current:colon-unlock-ok', {'mode': 'current', 'selector': 'colon-unlock-ok'}),
 ('current:colon-unlock-second-error', {'mode': 'current', 'selector': 'colon-unlock-second-error'}),
 ('current:colon-alloc-error', {'mode': 'current', 'selector': 'colon-alloc-error'}),
 ('current:other-board-reboot-error', {'mode': 'current', 'selector': 'other-board-reboot-error'}),
 ('baseline:erase-ok', {'mode': 'baseline', 'selector': 'erase-ok'}),
 ('baseline:unlock-error', {'mode': 'baseline', 'selector': 'unlock-error'}),
 ('baseline:block-unlock-error', {'mode': 'baseline', 'selector': 'block-unlock-error'}),
 ('baseline:erase-error-first', {'mode': 'baseline', 'selector': 'erase-error-first'}),
 ('baseline:erase-error-second', {'mode': 'baseline', 'selector': 'erase-error-second'}),
 ('baseline:unlock-close-error', {'mode': 'baseline', 'selector': 'unlock-close-error'}),
 ('baseline:erase-close-error', {'mode': 'baseline', 'selector': 'erase-close-error'}),
 ('baseline:preerase-failure', {'mode': 'baseline', 'selector': 'preerase-failure'}),
 ('baseline:preunlock-failure', {'mode': 'baseline', 'selector': 'preunlock-failure'}),
 ('baseline:write-unlock-failure', {'mode': 'baseline', 'selector': 'write-unlock-failure'}),
 ('baseline:jffs-unlock-failure', {'mode': 'baseline', 'selector': 'jffs-unlock-failure'}),
 ('baseline:other-board-reboot-error', {'mode': 'baseline', 'selector': 'other-board-reboot-error'}),
 ('disabled:erase-ok', {'mode': 'disabled', 'selector': 'erase-ok'}),
 ('disabled:erase-error-first', {'mode': 'disabled', 'selector': 'erase-error-first'}))
EXPECTED = {'current:erase-ok': {'case': 'erase-ok',
                      'returncode': 0,
                      'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync',
                      'opens': 2,
                      'closes': 2,
                      'unlocks': 5,
                      'erases': 4,
                      'bad_range': 0,
                      'allocs': 0,
                      'frees': 0},
 'current:unlock-ok': {'case': 'unlock-ok',
                       'returncode': 0,
                       'trace': 'sync,writable-open,unlock,close,sync',
                       'opens': 1,
                       'closes': 1,
                       'unlocks': 1,
                       'erases': 0,
                       'bad_range': 0,
                       'allocs': 0,
                       'frees': 0},
 'current:unlock-error': {'case': 'unlock-error',
                          'returncode': 1,
                          'trace': 'sync,writable-open,unlock,close',
                          'opens': 1,
                          'closes': 1,
                          'unlocks': 1,
                          'erases': 0,
                          'bad_range': 0,
                          'allocs': 0,
                          'frees': 0},
 'current:block-unlock-error': {'case': 'block-unlock-error',
                                'returncode': 1,
                                'trace': 'sync,writable-open,unlock,close,writable-open,unlock,close',
                                'opens': 2,
                                'closes': 2,
                                'unlocks': 2,
                                'erases': 0,
                                'bad_range': 0,
                                'allocs': 0,
                                'frees': 0},
 'current:unlock-unsupported': {'case': 'unlock-unsupported',
                                'returncode': 0,
                                'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync',
                                'opens': 2,
                                'closes': 2,
                                'unlocks': 5,
                                'erases': 4,
                                'bad_range': 0,
                                'allocs': 0,
                                'frees': 0},
 'current:unlock-enotty': {'case': 'unlock-enotty',
                           'returncode': 0,
                           'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync',
                           'opens': 2,
                           'closes': 2,
                           'unlocks': 5,
                           'erases': 4,
                           'bad_range': 0,
                           'allocs': 0,
                           'frees': 0},
 'current:erase-error-first': {'case': 'erase-error-first',
                               'returncode': 1,
                               'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,close',
                               'opens': 2,
                               'closes': 2,
                               'unlocks': 2,
                               'erases': 1,
                               'bad_range': 0,
                               'allocs': 0,
                               'frees': 0},
 'current:erase-error-second': {'case': 'erase-error-second',
                                'returncode': 1,
                                'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,close',
                                'opens': 2,
                                'closes': 2,
                                'unlocks': 3,
                                'erases': 2,
                                'bad_range': 0,
                                'allocs': 0,
                                'frees': 0},
 'current:unlock-close-error': {'case': 'unlock-close-error',
                                'returncode': 1,
                                'trace': 'sync,writable-open,unlock,close',
                                'opens': 1,
                                'closes': 1,
                                'unlocks': 1,
                                'erases': 0,
                                'bad_range': 0,
                                'allocs': 0,
                                'frees': 0},
 'current:erase-close-error': {'case': 'erase-close-error',
                               'returncode': 1,
                               'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close',
                               'opens': 2,
                               'closes': 2,
                               'unlocks': 5,
                               'erases': 4,
                               'bad_range': 0,
                               'allocs': 0,
                               'frees': 0},
 'current:open-error': {'case': 'open-error',
                        'returncode': 1,
                        'trace': 'sync,writable-open',
                        'opens': 1,
                        'closes': 0,
                        'unlocks': 0,
                        'erases': 0,
                        'bad_range': 0,
                        'allocs': 0,
                        'frees': 0},
 'current:erase-open-error': {'case': 'erase-open-error',
                              'returncode': 1,
                              'trace': 'sync,writable-open,unlock,close,writable-open',
                              'opens': 2,
                              'closes': 1,
                              'unlocks': 1,
                              'erases': 0,
                              'bad_range': 0,
                              'allocs': 0,
                              'frees': 0},
 'current:zero-size': {'case': 'zero-size',
                       'returncode': 1,
                       'trace': 'sync,writable-open,close',
                       'opens': 1,
                       'closes': 1,
                       'unlocks': 0,
                       'erases': 0,
                       'bad_range': 0,
                       'allocs': 0,
                       'frees': 0},
 'current:zero-erase': {'case': 'zero-erase',
                        'returncode': 1,
                        'trace': 'sync,writable-open,unlock,close,writable-open,close',
                        'opens': 2,
                        'closes': 2,
                        'unlocks': 1,
                        'erases': 0,
                        'bad_range': 0,
                        'allocs': 0,
                        'frees': 0},
 'current:negative-size': {'case': 'negative-size',
                           'returncode': 1,
                           'trace': 'sync,writable-open,close',
                           'opens': 1,
                           'closes': 1,
                           'unlocks': 0,
                           'erases': 0,
                           'bad_range': 0,
                           'allocs': 0,
                           'frees': 0},
 'current:negative-erase': {'case': 'negative-erase',
                            'returncode': 1,
                            'trace': 'sync,writable-open,unlock,close,writable-open,close',
                            'opens': 2,
                            'closes': 2,
                            'unlocks': 1,
                            'erases': 0,
                            'bad_range': 0,
                            'allocs': 0,
                            'frees': 0},
 'current:unaligned-size': {'case': 'unaligned-size',
                            'returncode': 1,
                            'trace': 'sync,writable-open,unlock,close,writable-open,close',
                            'opens': 2,
                            'closes': 2,
                            'unlocks': 1,
                            'erases': 0,
                            'bad_range': 0,
                            'allocs': 0,
                            'frees': 0},
 'current:oversized-erase': {'case': 'oversized-erase',
                             'returncode': 1,
                             'trace': 'sync,writable-open,unlock,close,writable-open,close',
                             'opens': 2,
                             'closes': 2,
                             'unlocks': 1,
                             'erases': 0,
                             'bad_range': 0,
                             'allocs': 0,
                             'frees': 0},
 'current:preerase-failure': {'case': 'preerase-failure',
                              'returncode': 1,
                              'trace': 'mtd-check,sync,writable-open,unlock,close,writable-open,unlock,erase,close',
                              'opens': 2,
                              'closes': 2,
                              'unlocks': 2,
                              'erases': 1,
                              'bad_range': 0,
                              'allocs': 0,
                              'frees': 0},
 'current:preunlock-failure': {'case': 'preunlock-failure',
                               'returncode': 1,
                               'trace': 'mtd-check,sync,writable-open,unlock,close',
                               'opens': 1,
                               'closes': 1,
                               'unlocks': 1,
                               'erases': 0,
                               'bad_range': 0,
                               'allocs': 0,
                               'frees': 0},
 'current:write-unlock-failure': {'case': 'write-unlock-failure',
                                  'returncode': 1,
                                  'trace': 'mtd-check,sync,writable-open,unlock,close',
                                  'opens': 1,
                                  'closes': 1,
                                  'unlocks': 1,
                                  'erases': 0,
                                  'bad_range': 0,
                                  'allocs': 0,
                                  'frees': 0},
 'current:jffs-unlock-failure': {'case': 'jffs-unlock-failure',
                                 'returncode': 1,
                                 'trace': 'mtd-check,sync,writable-open,unlock,close',
                                 'opens': 1,
                                 'closes': 1,
                                 'unlocks': 1,
                                 'erases': 0,
                                 'bad_range': 0,
                                 'allocs': 0,
                                 'frees': 0},
 'current:colon-unlock-ok': {'case': 'colon-unlock-ok',
                             'returncode': 0,
                             'trace': 'sync,writable-open,unlock,close,writable-open,unlock,close,sync',
                             'opens': 2,
                             'closes': 2,
                             'unlocks': 2,
                             'erases': 0,
                             'bad_range': 0,
                             'allocs': 1,
                             'frees': 1},
 'current:colon-unlock-second-error': {'case': 'colon-unlock-second-error',
                                       'returncode': 1,
                                       'trace': 'sync,writable-open,unlock,close,writable-open,unlock,close',
                                       'opens': 2,
                                       'closes': 2,
                                       'unlocks': 2,
                                       'erases': 0,
                                       'bad_range': 0,
                                       'allocs': 1,
                                       'frees': 1},
 'current:colon-alloc-error': {'case': 'colon-alloc-error',
                               'returncode': 1,
                               'trace': 'sync',
                               'opens': 0,
                               'closes': 0,
                               'unlocks': 0,
                               'erases': 0,
                               'bad_range': 0,
                               'allocs': 1,
                               'frees': 0},
 'current:other-board-reboot-error': {'case': 'other-board-reboot-error',
                                      'returncode': 1,
                                      'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,close',
                                      'opens': 2,
                                      'closes': 2,
                                      'unlocks': 2,
                                      'erases': 1,
                                      'bad_range': 0,
                                      'allocs': 0,
                                      'frees': 0},
 'baseline:erase-ok': {'case': 'erase-ok',
                       'returncode': 0,
                       'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync',
                       'opens': 2,
                       'closes': 2,
                       'unlocks': 5,
                       'erases': 4,
                       'bad_range': 0,
                       'allocs': 0,
                       'frees': 0},
 'baseline:unlock-error': {'case': 'unlock-error',
                           'returncode': 0,
                           'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync',
                           'opens': 2,
                           'closes': 2,
                           'unlocks': 5,
                           'erases': 4,
                           'bad_range': 0,
                           'allocs': 0,
                           'frees': 0},
 'baseline:block-unlock-error': {'case': 'block-unlock-error',
                                 'returncode': 0,
                                 'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync',
                                 'opens': 2,
                                 'closes': 2,
                                 'unlocks': 5,
                                 'erases': 4,
                                 'bad_range': 0,
                                 'allocs': 0,
                                 'frees': 0},
 'baseline:erase-error-first': {'case': 'erase-error-first',
                                'returncode': 0,
                                'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync',
                                'opens': 2,
                                'closes': 2,
                                'unlocks': 5,
                                'erases': 4,
                                'bad_range': 0,
                                'allocs': 0,
                                'frees': 0},
 'baseline:erase-error-second': {'case': 'erase-error-second',
                                 'returncode': 0,
                                 'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync',
                                 'opens': 2,
                                 'closes': 2,
                                 'unlocks': 5,
                                 'erases': 4,
                                 'bad_range': 0,
                                 'allocs': 0,
                                 'frees': 0},
 'baseline:unlock-close-error': {'case': 'unlock-close-error',
                                 'returncode': 0,
                                 'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync',
                                 'opens': 2,
                                 'closes': 2,
                                 'unlocks': 5,
                                 'erases': 4,
                                 'bad_range': 0,
                                 'allocs': 0,
                                 'frees': 0},
 'baseline:erase-close-error': {'case': 'erase-close-error',
                                'returncode': 0,
                                'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync',
                                'opens': 2,
                                'closes': 2,
                                'unlocks': 5,
                                'erases': 4,
                                'bad_range': 0,
                                'allocs': 0,
                                'frees': 0},
 'baseline:preerase-failure': {'case': 'preerase-failure',
                               'returncode': 0,
                               'trace': 'mtd-check,sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,writable-open,unlock,close,primary-write,sync',
                               'opens': 3,
                               'closes': 3,
                               'unlocks': 6,
                               'erases': 4,
                               'bad_range': 0,
                               'allocs': 0,
                               'frees': 0},
 'baseline:preunlock-failure': {'case': 'preunlock-failure',
                                'returncode': 0,
                                'trace': 'mtd-check,sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,writable-open,unlock,close,primary-write,sync',
                                'opens': 3,
                                'closes': 3,
                                'unlocks': 6,
                                'erases': 4,
                                'bad_range': 0,
                                'allocs': 0,
                                'frees': 0},
 'baseline:write-unlock-failure': {'case': 'write-unlock-failure',
                                   'returncode': 0,
                                   'trace': 'mtd-check,sync,writable-open,unlock,close,primary-write,sync',
                                   'opens': 1,
                                   'closes': 1,
                                   'unlocks': 1,
                                   'erases': 0,
                                   'bad_range': 0,
                                   'allocs': 0,
                                   'frees': 0},
 'baseline:jffs-unlock-failure': {'case': 'jffs-unlock-failure',
                                  'returncode': 0,
                                  'trace': 'mtd-check,sync,writable-open,unlock,close,jffs2write,sync',
                                  'opens': 1,
                                  'closes': 1,
                                  'unlocks': 1,
                                  'erases': 0,
                                  'bad_range': 0,
                                  'allocs': 0,
                                  'frees': 0},
 'baseline:other-board-reboot-error': {'case': 'other-board-reboot-error',
                                       'returncode': 0,
                                       'trace': 'sync,writable-open,unlock,close,writable-open,unlock,erase,unlock,erase,unlock,erase,unlock,erase,close,sync,system-reboot,sleep2,raw-reboot',
                                       'opens': 2,
                                       'closes': 2,
                                       'unlocks': 5,
                                       'erases': 4,
                                       'bad_range': 0,
                                       'allocs': 0,
                                       'frees': 0},
 'disabled:erase-ok': {'case': 'erase-ok',
                       'returncode': 0,
                       'trace': '',
                       'opens': 0,
                       'closes': 0,
                       'unlocks': 0,
                       'erases': 0,
                       'bad_range': 0,
                       'allocs': 0,
                       'frees': 0},
 'disabled:erase-error-first': {'case': 'erase-error-first',
                                'returncode': 0,
                                'trace': '',
                                'opens': 0,
                                'closes': 0,
                                'unlocks': 0,
                                'erases': 0,
                                'bad_range': 0,
                                'allocs': 0,
                                'frees': 0}}

def require(value,message):
    if not value:raise ValueError(message)

def sha(data):return hashlib.sha256(data).hexdigest()

def exact(left,right,message):
    require(json.dumps(left,sort_keys=True)==json.dumps(right,sort_keys=True),message)

def function(text,name):
    token=r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*'
    masked=re.sub(token,lambda m:' '*len(m.group()),text)
    pattern=r'(?m)^(?:static\s+)?(?:inline\s+)?(?:void|int|ssize_t|FILE\s*\*|char\s*\*)\s*\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{'
    found=list(re.finditer(pattern,masked));require(len(found)==1,'Missing/ambiguous mutation function: '+name)
    opening=masked.index('{',found[0].start());depth=0
    for item in re.finditer(token+r'|[{}]',text[opening:]):
        if item.group()=='{':depth+=1
        elif item.group()=='}':
            depth-=1
            if not depth:return text[found[0].start():opening+item.end()]
    raise ValueError('Unterminated mutation function')

def load_generator(inputs):
    # Both modules are trusted locked source strings, never imported by path.
    legacy=checked_module(inputs['legacy_harness'],'mutation-legacy')
    previous=sys.modules.get('legacy_firmware_harness')
    sys.modules['legacy_firmware_harness']=legacy
    try:module=checked_module(inputs['harness'],'mutation')
    finally:
        if previous is None:del sys.modules['legacy_firmware_harness']
        else:sys.modules['legacy_firmware_harness']=previous
    return module

def regenerate(inputs,fixture_root,owner_uid,mode):
    require(type(inputs) is dict and set(inputs)==set(SOURCE_PATHS),'Mutation source set')
    require(mode in ('current','baseline','disabled'),'Mutation model mode')
    require(type(owner_uid) is int and 0<=owner_uid<2**32,'Mutation fixture UID')
    require(type(fixture_root) is str and fixture_root.startswith('/') and len(fixture_root)<4096 and not any(ord(c)<32 for c in fixture_root),'Mutation fixture root')
    require('-DMTD_K2P_LEGACY_GUARD=1' in inputs['makefile'],'Mutation legacy guard build option')
    module=load_generator(inputs)
    exact(module.SOURCE_PATHS,HARNESS_SOURCE_PATHS,'Mutation harness source contract')
    exact(module.CASE_ARGS,CASE_ARGS,'Mutation argv contract')
    exact(module.BASELINE_CASES,BASELINE_CASES,'Mutation baseline case contract')
    require(module.BASELINE_COMMIT==BASELINE_COMMIT,'Mutation baseline revision')
    exact({n:sha(body.encode()) for n,body in module.BASELINE_FUNCTIONS.items()},BASELINE_FUNCTION_HASHES,'Mutation literal baseline function hashes')
    bodies=module.BASELINE_FUNCTIONS if mode=='baseline' else {n:function(inputs[key],n) for n,key in FUNCTION_SOURCES.items()}
    texts={key:inputs[key] for key in HARNESS_SOURCE_PATHS}
    code=module.generate_source(texts,fixture_root,owner_uid,baseline=mode=='baseline',disabled_oracle=mode=='disabled')
    require(type(code) is str and 0<len(code.encode())<=MAX_SOURCE,'Mutation generated source budget')
    # Disabled oracle deliberately omits the actual main invocation, but keeps
    # the source bodies so body hashing alone cannot make the oracle pass.
    for name,body in bodies.items():require(code.count(body)==1,'Mutation actual body omitted/duplicated: '+name)
    require(code.count(inputs['legacy_guard'])==1,'Mutation legacy guard body omitted/duplicated')
    return code,bodies

def fixed_records(rows):
    require(type(rows) is list and len(rows)==len(CASES),'Mutation record set')
    for row,(name,options) in zip(rows,CASES):
        require(type(row) is dict and set(row)=={'case','inputs','observed'} and row['case']==name,'Mutation record schema/order')
        exact(row['inputs'],options,'Mutation fixed typed input: '+name)
        observed=row['observed']
        require(type(observed) is dict and set(observed)==set(EXPECTED[name]),'Mutation observation schema')
        exact(observed,EXPECTED[name],'Mutation fixed typed outcome: '+name)

def regular(path,limit):
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit,'Mutation artifact must be bounded single regular file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        opened=os.fstat(fd)
        identity=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink==1 and identity(before)==identity(opened),'Mutation artifact changed on open')
        chunks=[];remain=limit+1
        while remain:
            data=os.read(fd,min(remain,1024*1024))
            if not data:break
            chunks.append(data);remain-=len(data)
        result=b''.join(chunks)
        require(len(result)==before.st_size and identity(opened)==identity(os.fstat(fd)),'Mutation artifact changed/truncated')
        return result
    finally:os.close(fd)

def generate_source(inputs,fixture_root,owner_uid,mode='current'):
    return regenerate(inputs,str(fixture_root),owner_uid,mode)

def validate_records(rows):return fixed_records(rows)

def check(trunk,compiler,output,preflight=False,rootfs=None):
    require(type(preflight) is bool and ((preflight and rootfs is None) or (not preflight and rootfs is not None)),'Mutation gate needs preflight alone or final rootfs')
    config=(trunk/'.config').read_text()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$',config,re.M) and re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$',config,re.M),'Mutation gate requires K2P4.4')
    qemu=shutil.which('qemu-mipsel');require(qemu is not None,'Mutation gate requires qemu-mipsel')
    inputs={key:(trunk.parent/path).read_text() for key,path in SOURCE_PATHS.items()}
    rows=[];probes={};hashes={};exports={}
    with tempfile.TemporaryDirectory(prefix='k2p-mtd-mutation-',dir='/tmp') as temporary:
        base=Path(temporary).resolve()
        for mode in ('current','baseline','disabled'):
            fixture=base/(mode+'-fixture')
            generated,bodies=regenerate(inputs,str(fixture),os.geteuid(),mode)
            source=base/(mode+'.c');binary=base/mode;source.write_text(generated)
            run=subprocess.run([str(compiler),*FLAGS,str(source),'-o',str(binary)],capture_output=True,text=True,timeout=90)
            require(run.returncode==0,'Mutation MIPS compile failed: '+run.stdout+run.stderr)
            data=binary.read_bytes();metadata=resident.validate_static_helper(data)
            for name,options in CASES:
                if options['mode']!=mode:continue
                run=subprocess.run([qemu,str(binary),options['selector']],capture_output=True,text=True,timeout=10)
                require(run.returncode==0,'Mutation inert model failed '+name+': '+run.stdout+run.stderr)
                rows.append({'case':name,'inputs':options,'observed':json.loads(run.stdout)})
            stem='target-mtd-mutation'+('' if mode=='current' else '-'+mode)
            exports[stem+'.c']=generated.encode();exports[stem]=data
            hashes[mode]={name:sha(body.encode()) for name,body in bodies.items()}
            probes[mode]={'source_file':stem+'.c','source_sha256':sha(generated.encode()),
                'binary_file':stem,'binary_sha256':sha(data),'ELF':metadata,
                'compile_flags':list(FLAGS),'fixture_root':str(fixture),'owner_uid':os.geteuid()}
    fixed_records(rows)
    shipped=None
    if not preflight:
        data=regular(rootfs/'bin/mtd_write',MAX_PROBE)
        shipped={'path':'bin/mtd_write','bytes':len(data),'sha256':sha(data),'ELF':dns.elf(data,True),
                 'source_sha256':sha(inputs['mtd'].encode()),'guard_sha256':sha(inputs['legacy_guard'].encode()),
                 'image_byte_binding_required':True,'execution_performed':False}
    output.parent.mkdir(parents=True,exist_ok=True)
    for name,data in exports.items():
        path=output.parent/name;path.write_bytes(data)
        if not name.endswith('.c'):path.chmod(0o755)
    report={'schema_version':1,'status':'PASS','profile':'k2p-4.4',
        'phase':'early-source-only' if preflight else 'final-shipped-image-reference-bound',
        'execution_role':ROLE,'required_cases':[n for n,_ in CASES],'checks':rows,
        'source_files':SOURCE_PATHS,'source_sha256':{k:sha(v.encode()) for k,v in inputs.items()},
        'baseline_source_commit':BASELINE_COMMIT,'actual_functions_sha256':hashes,'probes':probes,
        'shipped_legacy':shipped,'compiler':str(compiler),'limits':list(LIMITS)}
    output.write_text(json.dumps(report,indent=2)+'\n')
    print('MTD mutation: '+str(len(rows))+' inert actual-source MIPS cases PASS')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('trunk','compiler','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--preflight',action='store_true');parser.add_argument('--rootfs',type=Path)
    args=parser.parse_args()
    try:check(args.trunk.resolve(),args.compiler.resolve(),args.output.resolve(),args.preflight,args.rootfs.resolve() if args.rootfs else None)
    except (OSError,ValueError,subprocess.SubprocessError) as error:parser.exit(1,'MTD mutation validation failed: '+str(error)+'\n')
