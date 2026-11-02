#!/usr/bin/env python3
"""Actual-source MT7621 controller MIPS controls, bound to the full kernel proof.

No firmware, kernel module, host proc setting, SPI device or reboot is executed.
The compiled adapter uses only explicitly inert low-level callbacks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

import check_target_resident_upgrade as resident
import check_target_spi_nor as spi

# Frozen from reviewed source controls before any candidate artifact is read.
SOURCE_PATHS = {'controller': 'trunk/linux-4.4.x/drivers/spi/spi-mt7621.c',
                'harness': 'tests/controller_harness.py'}
HARNESS_SOURCE_PATHS = {'controller': 'trunk/linux-4.4.x/drivers/spi/spi-mt7621.c'}
FUNCTION_SOURCES = {name: 'controller' for name in
                    ('mt7621_spi_read', 'mt7621_spi_write',
                     'mt7621_spi_probe', 'mt7621_spi_remove')}
BASELINE_COMMIT = 'e8c4f633d6e7912e2310836e6844f782c87f3a39'
BASELINE_FUNCTION_HASHES = {'mt7621_spi_read': 'aed29c826bd8cf9e0e7e43ac3fded20c89362ed3acc198d8164f9230c409b5bc',
 'mt7621_spi_write': 'f6e0a38ff7cfac843a87f3c9701ab3fc450d7414300900e700f7f5bc4f8bcc68',
 'mt7621_spi_probe': '0feb3856c859a08e88cd8c2e5ab1c39d7e444046c10da284dcd4724e73bb47de',
 'mt7621_spi_remove': '4e644f0dfda26caf30c9603e490b420c6d3d586dc2574a585d457e7f09cbd80e'}
PRODUCTION_FRAGMENT_SHA256 = 'c75829f0090ac44e00323036a734735b3e96c5b1d1882188e5fed3254e73b0f2'
CASES = (('current:probe-normal', {'baseline': False, 'selector': 'probe-normal'}),
 ('current:probe-map-error',
  {'baseline': False, 'selector': 'probe-map-error'}),
 ('current:probe-clock-get-error',
  {'baseline': False, 'selector': 'probe-clock-get-error'}),
 ('current:probe-clock-enable-error',
  {'baseline': False, 'selector': 'probe-clock-enable-error'}),
 ('current:probe-clock-zero',
  {'baseline': False, 'selector': 'probe-clock-zero'}),
 ('current:probe-clock-one',
  {'baseline': False, 'selector': 'probe-clock-one'}),
 ('current:probe-clock-two',
  {'baseline': False, 'selector': 'probe-clock-two'}),
 ('current:probe-alloc-error',
  {'baseline': False, 'selector': 'probe-alloc-error'}),
 ('current:probe-reset-defer',
  {'baseline': False, 'selector': 'probe-reset-defer'}),
 ('current:probe-reset-error',
  {'baseline': False, 'selector': 'probe-reset-error'}),
 ('current:probe-reset-absent-error',
  {'baseline': False, 'selector': 'probe-reset-absent-error'}),
 ('current:probe-reset-disabled-error',
  {'baseline': False, 'selector': 'probe-reset-disabled-error'}),
 ('current:probe-register-error',
  {'baseline': False, 'selector': 'probe-register-error'}),
 ('current:remove-normal', {'baseline': False, 'selector': 'remove-normal'}),
 ('current:remove-retained-ref',
  {'baseline': False, 'selector': 'remove-retained-ref'}),
 ('current:read-zero', {'baseline': False, 'selector': 'read-zero'}),
 ('current:read-one', {'baseline': False, 'selector': 'read-one'}),
 ('current:read-31', {'baseline': False, 'selector': 'read-31'}),
 ('current:read-32', {'baseline': False, 'selector': 'read-32'}),
 ('current:read-33', {'baseline': False, 'selector': 'read-33'}),
 ('current:read-64', {'baseline': False, 'selector': 'read-64'}),
 ('current:read-error-first',
  {'baseline': False, 'selector': 'read-error-first'}),
 ('current:read-error-second',
  {'baseline': False, 'selector': 'read-error-second'}),
 ('current:write-zero', {'baseline': False, 'selector': 'write-zero'}),
 ('current:write-one', {'baseline': False, 'selector': 'write-one'}),
 ('current:write-four', {'baseline': False, 'selector': 'write-four'}),
 ('current:write-five', {'baseline': False, 'selector': 'write-five'}),
 ('current:write-seven', {'baseline': False, 'selector': 'write-seven'}),
 ('current:write-eight-high',
  {'baseline': False, 'selector': 'write-eight-high'}),
 ('current:write-36', {'baseline': False, 'selector': 'write-36'}),
 ('current:write-37', {'baseline': False, 'selector': 'write-37'}),
 ('current:write-error-first',
  {'baseline': False, 'selector': 'write-error-first'}),
 ('current:write-error-second',
  {'baseline': False, 'selector': 'write-error-second'}),
 ('current:write-ff-word', {'baseline': False, 'selector': 'write-ff-word'}),
 ('baseline:probe-normal', {'baseline': True, 'selector': 'probe-normal'}),
 ('baseline:probe-alloc-error',
  {'baseline': True, 'selector': 'probe-alloc-error'}),
 ('baseline:probe-register-error',
  {'baseline': True, 'selector': 'probe-register-error'}),
 ('baseline:probe-reset-defer',
  {'baseline': True, 'selector': 'probe-reset-defer'}),
 ('baseline:probe-reset-error',
  {'baseline': True, 'selector': 'probe-reset-error'}),
 ('baseline:probe-clock-zero',
  {'baseline': True, 'selector': 'probe-clock-zero'}),
 ('baseline:probe-clock-one',
  {'baseline': True, 'selector': 'probe-clock-one'}),
 ('baseline:remove-normal', {'baseline': True, 'selector': 'remove-normal'}))
EXPECTED = {'current:probe-normal': {'case': 'probe-normal',
                          'result': 0,
                          'enabled': 1,
                          'prepared': 1,
                          'master_refs': 1,
                          'drvdata_set': 1,
                          'registrations': 1,
                          'unregisters': 0,
                          'clock_at_unregister': 0,
                          'reset_calls': 1,
                          'busy_calls': 0,
                          'mmio_writes': 0,
                          'rx_sum': 0,
                          'dido0': 0,
                          'opcode': 0,
                          'sequence': 'MGERADXT'},
 'current:probe-map-error': {'case': 'probe-map-error',
                             'result': -5,
                             'enabled': 0,
                             'prepared': 0,
                             'master_refs': 0,
                             'drvdata_set': 0,
                             'registrations': 0,
                             'unregisters': 0,
                             'clock_at_unregister': 0,
                             'reset_calls': 0,
                             'busy_calls': 0,
                             'mmio_writes': 0,
                             'rx_sum': 0,
                             'dido0': 0,
                             'opcode': 0,
                             'sequence': 'M'},
 'current:probe-clock-get-error': {'case': 'probe-clock-get-error',
                                   'result': -517,
                                   'enabled': 0,
                                   'prepared': 0,
                                   'master_refs': 0,
                                   'drvdata_set': 0,
                                   'registrations': 0,
                                   'unregisters': 0,
                                   'clock_at_unregister': 0,
                                   'reset_calls': 0,
                                   'busy_calls': 0,
                                   'mmio_writes': 0,
                                   'rx_sum': 0,
                                   'dido0': 0,
                                   'opcode': 0,
                                   'sequence': 'MG'},
 'current:probe-clock-enable-error': {'case': 'probe-clock-enable-error',
                                      'result': -11,
                                      'enabled': 0,
                                      'prepared': 0,
                                      'master_refs': 0,
                                      'drvdata_set': 0,
                                      'registrations': 0,
                                      'unregisters': 0,
                                      'clock_at_unregister': 0,
                                      'reset_calls': 0,
                                      'busy_calls': 0,
                                      'mmio_writes': 0,
                                      'rx_sum': 0,
                                      'dido0': 0,
                                      'opcode': 0,
                                      'sequence': 'MGE'},
 'current:probe-clock-zero': {'case': 'probe-clock-zero',
                              'result': -22,
                              'enabled': 0,
                              'prepared': 0,
                              'master_refs': 0,
                              'drvdata_set': 0,
                              'registrations': 0,
                              'unregisters': 0,
                              'clock_at_unregister': 0,
                              'reset_calls': 0,
                              'busy_calls': 0,
                              'mmio_writes': 0,
                              'rx_sum': 0,
                              'dido0': 0,
                              'opcode': 0,
                              'sequence': 'MGERLU'},
 'current:probe-clock-one': {'case': 'probe-clock-one',
                             'result': -22,
                             'enabled': 0,
                             'prepared': 0,
                             'master_refs': 0,
                             'drvdata_set': 0,
                             'registrations': 0,
                             'unregisters': 0,
                             'clock_at_unregister': 0,
                             'reset_calls': 0,
                             'busy_calls': 0,
                             'mmio_writes': 0,
                             'rx_sum': 0,
                             'dido0': 0,
                             'opcode': 0,
                             'sequence': 'MGERLU'},
 'current:probe-clock-two': {'case': 'probe-clock-two',
                             'result': 0,
                             'enabled': 1,
                             'prepared': 1,
                             'master_refs': 1,
                             'drvdata_set': 1,
                             'registrations': 1,
                             'unregisters': 0,
                             'clock_at_unregister': 0,
                             'reset_calls': 1,
                             'busy_calls': 0,
                             'mmio_writes': 0,
                             'rx_sum': 0,
                             'dido0': 0,
                             'opcode': 0,
                             'sequence': 'MGERADXT'},
 'current:probe-alloc-error': {'case': 'probe-alloc-error',
                               'result': -12,
                               'enabled': 0,
                               'prepared': 0,
                               'master_refs': 0,
                               'drvdata_set': 0,
                               'registrations': 0,
                               'unregisters': 0,
                               'clock_at_unregister': 0,
                               'reset_calls': 0,
                               'busy_calls': 0,
                               'mmio_writes': 0,
                               'rx_sum': 0,
                               'dido0': 0,
                               'opcode': 0,
                               'sequence': 'MGERALU'},
 'current:probe-reset-defer': {'case': 'probe-reset-defer',
                               'result': -517,
                               'enabled': 0,
                               'prepared': 0,
                               'master_refs': 0,
                               'drvdata_set': 0,
                               'registrations': 0,
                               'unregisters': 0,
                               'clock_at_unregister': 0,
                               'reset_calls': 1,
                               'busy_calls': 0,
                               'mmio_writes': 0,
                               'rx_sum': 0,
                               'dido0': 0,
                               'opcode': 0,
                               'sequence': 'MGERADXFCPLU'},
 'current:probe-reset-error': {'case': 'probe-reset-error',
                               'result': -5,
                               'enabled': 0,
                               'prepared': 0,
                               'master_refs': 0,
                               'drvdata_set': 0,
                               'registrations': 0,
                               'unregisters': 0,
                               'clock_at_unregister': 0,
                               'reset_calls': 1,
                               'busy_calls': 0,
                               'mmio_writes': 0,
                               'rx_sum': 0,
                               'dido0': 0,
                               'opcode': 0,
                               'sequence': 'MGERADXFCPLU'},
 'current:probe-reset-absent-error': {'case': 'probe-reset-absent-error',
                                      'result': 0,
                                      'enabled': 1,
                                      'prepared': 1,
                                      'master_refs': 1,
                                      'drvdata_set': 1,
                                      'registrations': 1,
                                      'unregisters': 0,
                                      'clock_at_unregister': 0,
                                      'reset_calls': 1,
                                      'busy_calls': 0,
                                      'mmio_writes': 0,
                                      'rx_sum': 0,
                                      'dido0': 0,
                                      'opcode': 0,
                                      'sequence': 'MGERADXFT'},
 'current:probe-reset-disabled-error': {'case': 'probe-reset-disabled-error',
                                        'result': 0,
                                        'enabled': 1,
                                        'prepared': 1,
                                        'master_refs': 1,
                                        'drvdata_set': 1,
                                        'registrations': 1,
                                        'unregisters': 0,
                                        'clock_at_unregister': 0,
                                        'reset_calls': 1,
                                        'busy_calls': 0,
                                        'mmio_writes': 0,
                                        'rx_sum': 0,
                                        'dido0': 0,
                                        'opcode': 0,
                                        'sequence': 'MGERADXT'},
 'current:probe-register-error': {'case': 'probe-register-error',
                                  'result': -16,
                                  'enabled': 0,
                                  'prepared': 0,
                                  'master_refs': 0,
                                  'drvdata_set': 0,
                                  'registrations': 1,
                                  'unregisters': 0,
                                  'clock_at_unregister': 0,
                                  'reset_calls': 1,
                                  'busy_calls': 0,
                                  'mmio_writes': 0,
                                  'rx_sum': 0,
                                  'dido0': 0,
                                  'opcode': 0,
                                  'sequence': 'MGERADXTCPLU'},
 'current:remove-normal': {'case': 'remove-normal',
                           'result': 0,
                           'enabled': 0,
                           'prepared': 0,
                           'master_refs': 0,
                           'drvdata_set': 0,
                           'registrations': 1,
                           'unregisters': 1,
                           'clock_at_unregister': 1,
                           'reset_calls': 1,
                           'busy_calls': 0,
                           'mmio_writes': 0,
                           'rx_sum': 0,
                           'dido0': 0,
                           'opcode': 0,
                           'sequence': 'MGERADXTNPCLU'},
 'current:remove-retained-ref': {'case': 'remove-retained-ref',
                                 'result': 0,
                                 'enabled': 0,
                                 'prepared': 0,
                                 'master_refs': 1,
                                 'drvdata_set': 0,
                                 'registrations': 1,
                                 'unregisters': 1,
                                 'clock_at_unregister': 1,
                                 'reset_calls': 1,
                                 'busy_calls': 0,
                                 'mmio_writes': 0,
                                 'rx_sum': 0,
                                 'dido0': 0,
                                 'opcode': 0,
                                 'sequence': 'MGERADXTNPCLU'},
 'current:read-zero': {'case': 'read-zero',
                       'result': 0,
                       'enabled': 0,
                       'prepared': 0,
                       'master_refs': 0,
                       'drvdata_set': 0,
                       'registrations': 0,
                       'unregisters': 0,
                       'clock_at_unregister': 0,
                       'reset_calls': 0,
                       'busy_calls': 0,
                       'mmio_writes': 0,
                       'rx_sum': 0,
                       'dido0': 0,
                       'opcode': 0,
                       'sequence': ''},
 'current:read-one': {'case': 'read-one',
                      'result': 0,
                      'enabled': 0,
                      'prepared': 0,
                      'master_refs': 0,
                      'drvdata_set': 0,
                      'registrations': 0,
                      'unregisters': 0,
                      'clock_at_unregister': 0,
                      'reset_calls': 0,
                      'busy_calls': 1,
                      'mmio_writes': 2,
                      'rx_sum': 17,
                      'dido0': 0,
                      'opcode': 0,
                      'sequence': ''},
 'current:read-31': {'case': 'read-31',
                     'result': 0,
                     'enabled': 0,
                     'prepared': 0,
                     'master_refs': 0,
                     'drvdata_set': 0,
                     'registrations': 0,
                     'unregisters': 0,
                     'clock_at_unregister': 0,
                     'reset_calls': 0,
                     'busy_calls': 1,
                     'mmio_writes': 2,
                     'rx_sum': 1292,
                     'dido0': 0,
                     'opcode': 0,
                     'sequence': ''},
 'current:read-32': {'case': 'read-32',
                     'result': 0,
                     'enabled': 0,
                     'prepared': 0,
                     'master_refs': 0,
                     'drvdata_set': 0,
                     'registrations': 0,
                     'unregisters': 0,
                     'clock_at_unregister': 0,
                     'reset_calls': 0,
                     'busy_calls': 1,
                     'mmio_writes': 2,
                     'rx_sum': 1360,
                     'dido0': 0,
                     'opcode': 0,
                     'sequence': ''},
 'current:read-33': {'case': 'read-33',
                     'result': 0,
                     'enabled': 0,
                     'prepared': 0,
                     'master_refs': 0,
                     'drvdata_set': 0,
                     'registrations': 0,
                     'unregisters': 0,
                     'clock_at_unregister': 0,
                     'reset_calls': 0,
                     'busy_calls': 2,
                     'mmio_writes': 4,
                     'rx_sum': 1377,
                     'dido0': 0,
                     'opcode': 0,
                     'sequence': ''},
 'current:read-64': {'case': 'read-64',
                     'result': 0,
                     'enabled': 0,
                     'prepared': 0,
                     'master_refs': 0,
                     'drvdata_set': 0,
                     'registrations': 0,
                     'unregisters': 0,
                     'clock_at_unregister': 0,
                     'reset_calls': 0,
                     'busy_calls': 2,
                     'mmio_writes': 4,
                     'rx_sum': 2720,
                     'dido0': 0,
                     'opcode': 0,
                     'sequence': ''},
 'current:read-error-first': {'case': 'read-error-first',
                              'result': -110,
                              'enabled': 0,
                              'prepared': 0,
                              'master_refs': 0,
                              'drvdata_set': 0,
                              'registrations': 0,
                              'unregisters': 0,
                              'clock_at_unregister': 0,
                              'reset_calls': 0,
                              'busy_calls': 1,
                              'mmio_writes': 2,
                              'rx_sum': 0,
                              'dido0': 0,
                              'opcode': 0,
                              'sequence': ''},
 'current:read-error-second': {'case': 'read-error-second',
                               'result': -110,
                               'enabled': 0,
                               'prepared': 0,
                               'master_refs': 0,
                               'drvdata_set': 0,
                               'registrations': 0,
                               'unregisters': 0,
                               'clock_at_unregister': 0,
                               'reset_calls': 0,
                               'busy_calls': 2,
                               'mmio_writes': 4,
                               'rx_sum': 1360,
                               'dido0': 0,
                               'opcode': 0,
                               'sequence': ''},
 'current:write-zero': {'case': 'write-zero',
                        'result': 0,
                        'enabled': 0,
                        'prepared': 0,
                        'master_refs': 0,
                        'drvdata_set': 0,
                        'registrations': 0,
                        'unregisters': 0,
                        'clock_at_unregister': 0,
                        'reset_calls': 0,
                        'busy_calls': 0,
                        'mmio_writes': 0,
                        'rx_sum': 0,
                        'dido0': 0,
                        'opcode': 0,
                        'sequence': ''},
 'current:write-one': {'case': 'write-one',
                       'result': 0,
                       'enabled': 0,
                       'prepared': 0,
                       'master_refs': 0,
                       'drvdata_set': 0,
                       'registrations': 0,
                       'unregisters': 0,
                       'clock_at_unregister': 0,
                       'reset_calls': 0,
                       'busy_calls': 1,
                       'mmio_writes': 3,
                       'rx_sum': 0,
                       'dido0': 0,
                       'opcode': 1,
                       'sequence': ''},
 'current:write-four': {'case': 'write-four',
                        'result': 0,
                        'enabled': 0,
                        'prepared': 0,
                        'master_refs': 0,
                        'drvdata_set': 0,
                        'registrations': 0,
                        'unregisters': 0,
                        'clock_at_unregister': 0,
                        'reset_calls': 0,
                        'busy_calls': 1,
                        'mmio_writes': 3,
                        'rx_sum': 0,
                        'dido0': 0,
                        'opcode': 16909060,
                        'sequence': ''},
 'current:write-five': {'case': 'write-five',
                        'result': 0,
                        'enabled': 0,
                        'prepared': 0,
                        'master_refs': 0,
                        'drvdata_set': 0,
                        'registrations': 0,
                        'unregisters': 0,
                        'clock_at_unregister': 0,
                        'reset_calls': 0,
                        'busy_calls': 1,
                        'mmio_writes': 4,
                        'rx_sum': 0,
                        'dido0': 5,
                        'opcode': 16909060,
                        'sequence': ''},
 'current:write-seven': {'case': 'write-seven',
                         'result': 0,
                         'enabled': 0,
                         'prepared': 0,
                         'master_refs': 0,
                         'drvdata_set': 0,
                         'registrations': 0,
                         'unregisters': 0,
                         'clock_at_unregister': 0,
                         'reset_calls': 0,
                         'busy_calls': 1,
                         'mmio_writes': 4,
                         'rx_sum': 0,
                         'dido0': 460293,
                         'opcode': 16909060,
                         'sequence': ''},
 'current:write-eight-high': {'case': 'write-eight-high',
                              'result': 0,
                              'enabled': 0,
                              'prepared': 0,
                              'master_refs': 0,
                              'drvdata_set': 0,
                              'registrations': 0,
                              'unregisters': 0,
                              'clock_at_unregister': 0,
                              'reset_calls': 0,
                              'busy_calls': 1,
                              'mmio_writes': 4,
                              'rx_sum': 0,
                              'dido0': 2147943941,
                              'opcode': 16909060,
                              'sequence': ''},
 'current:write-36': {'case': 'write-36',
                      'result': 0,
                      'enabled': 0,
                      'prepared': 0,
                      'master_refs': 0,
                      'drvdata_set': 0,
                      'registrations': 0,
                      'unregisters': 0,
                      'clock_at_unregister': 0,
                      'reset_calls': 0,
                      'busy_calls': 1,
                      'mmio_writes': 11,
                      'rx_sum': 0,
                      'dido0': 134678021,
                      'opcode': 16909060,
                      'sequence': ''},
 'current:write-37': {'case': 'write-37',
                      'result': 0,
                      'enabled': 0,
                      'prepared': 0,
                      'master_refs': 0,
                      'drvdata_set': 0,
                      'registrations': 0,
                      'unregisters': 0,
                      'clock_at_unregister': 0,
                      'reset_calls': 0,
                      'busy_calls': 2,
                      'mmio_writes': 14,
                      'rx_sum': 0,
                      'dido0': 134678021,
                      'opcode': 37,
                      'sequence': ''},
 'current:write-error-first': {'case': 'write-error-first',
                               'result': -110,
                               'enabled': 0,
                               'prepared': 0,
                               'master_refs': 0,
                               'drvdata_set': 0,
                               'registrations': 0,
                               'unregisters': 0,
                               'clock_at_unregister': 0,
                               'reset_calls': 0,
                               'busy_calls': 1,
                               'mmio_writes': 11,
                               'rx_sum': 0,
                               'dido0': 134678021,
                               'opcode': 16909060,
                               'sequence': ''},
 'current:write-error-second': {'case': 'write-error-second',
                                'result': -110,
                                'enabled': 0,
                                'prepared': 0,
                                'master_refs': 0,
                                'drvdata_set': 0,
                                'registrations': 0,
                                'unregisters': 0,
                                'clock_at_unregister': 0,
                                'reset_calls': 0,
                                'busy_calls': 2,
                                'mmio_writes': 14,
                                'rx_sum': 0,
                                'dido0': 134678021,
                                'opcode': 37,
                                'sequence': ''},
 'current:write-ff-word': {'case': 'write-ff-word',
                           'result': 0,
                           'enabled': 0,
                           'prepared': 0,
                           'master_refs': 0,
                           'drvdata_set': 0,
                           'registrations': 0,
                           'unregisters': 0,
                           'clock_at_unregister': 0,
                           'reset_calls': 0,
                           'busy_calls': 1,
                           'mmio_writes': 4,
                           'rx_sum': 0,
                           'dido0': 4294967295,
                           'opcode': 16909060,
                           'sequence': ''},
 'baseline:probe-normal': {'case': 'probe-normal',
                           'result': 0,
                           'enabled': 1,
                           'prepared': 1,
                           'master_refs': 1,
                           'drvdata_set': 1,
                           'registrations': 1,
                           'unregisters': 0,
                           'clock_at_unregister': 0,
                           'reset_calls': 1,
                           'busy_calls': 0,
                           'mmio_writes': 0,
                           'rx_sum': 0,
                           'dido0': 0,
                           'opcode': 0,
                           'sequence': 'MGERADXT'},
 'baseline:probe-alloc-error': {'case': 'probe-alloc-error',
                                'result': -12,
                                'enabled': 1,
                                'prepared': 1,
                                'master_refs': 0,
                                'drvdata_set': 0,
                                'registrations': 0,
                                'unregisters': 0,
                                'clock_at_unregister': 0,
                                'reset_calls': 0,
                                'busy_calls': 0,
                                'mmio_writes': 0,
                                'rx_sum': 0,
                                'dido0': 0,
                                'opcode': 0,
                                'sequence': 'MGERA'},
 'baseline:probe-register-error': {'case': 'probe-register-error',
                                   'result': -16,
                                   'enabled': 1,
                                   'prepared': 1,
                                   'master_refs': 1,
                                   'drvdata_set': 1,
                                   'registrations': 1,
                                   'unregisters': 0,
                                   'clock_at_unregister': 0,
                                   'reset_calls': 1,
                                   'busy_calls': 0,
                                   'mmio_writes': 0,
                                   'rx_sum': 0,
                                   'dido0': 0,
                                   'opcode': 0,
                                   'sequence': 'MGERADXT'},
 'baseline:probe-reset-defer': {'case': 'probe-reset-defer',
                                'result': 0,
                                'enabled': 1,
                                'prepared': 1,
                                'master_refs': 1,
                                'drvdata_set': 1,
                                'registrations': 1,
                                'unregisters': 0,
                                'clock_at_unregister': 0,
                                'reset_calls': 1,
                                'busy_calls': 0,
                                'mmio_writes': 0,
                                'rx_sum': 0,
                                'dido0': 0,
                                'opcode': 0,
                                'sequence': 'MGERADXT'},
 'baseline:probe-reset-error': {'case': 'probe-reset-error',
                                'result': 0,
                                'enabled': 1,
                                'prepared': 1,
                                'master_refs': 1,
                                'drvdata_set': 1,
                                'registrations': 1,
                                'unregisters': 0,
                                'clock_at_unregister': 0,
                                'reset_calls': 1,
                                'busy_calls': 0,
                                'mmio_writes': 0,
                                'rx_sum': 0,
                                'dido0': 0,
                                'opcode': 0,
                                'sequence': 'MGERADXT'},
 'baseline:probe-clock-zero': {'case': 'probe-clock-zero',
                               'result': 0,
                               'enabled': 1,
                               'prepared': 1,
                               'master_refs': 1,
                               'drvdata_set': 1,
                               'registrations': 1,
                               'unregisters': 0,
                               'clock_at_unregister': 0,
                               'reset_calls': 1,
                               'busy_calls': 0,
                               'mmio_writes': 0,
                               'rx_sum': 0,
                               'dido0': 0,
                               'opcode': 0,
                               'sequence': 'MGERADXT'},
 'baseline:probe-clock-one': {'case': 'probe-clock-one',
                              'result': 0,
                              'enabled': 1,
                              'prepared': 1,
                              'master_refs': 1,
                              'drvdata_set': 1,
                              'registrations': 1,
                              'unregisters': 0,
                              'clock_at_unregister': 0,
                              'reset_calls': 1,
                              'busy_calls': 0,
                              'mmio_writes': 0,
                              'rx_sum': 0,
                              'dido0': 0,
                              'opcode': 0,
                              'sequence': 'MGERADXT'},
 'baseline:remove-normal': {'case': 'remove-normal',
                            'result': 0,
                            'enabled': 0,
                            'prepared': 1,
                            'master_refs': 0,
                            'drvdata_set': 1,
                            'registrations': 1,
                            'unregisters': 1,
                            'clock_at_unregister': 0,
                            'reset_calls': 1,
                            'busy_calls': 0,
                            'mmio_writes': 0,
                            'rx_sum': 0,
                            'dido0': 0,
                            'opcode': 0,
                            'sequence': 'MGERADXTLNP'}}

ROLE = ('Actual MT7621 controller source compiled as static MIPS userspace '
        'with inert MMIO, clock, allocation, reset and registration callbacks.')
LIMITS = (
    'This userspace MIPS adapter is not a running kernel or physical SPI/reset fault injection.',
    'The simulated MMIO/register/reset/lifetime observations do not prove hardware behavior or timing.',
    'The setup and transfer_one_message callbacks stored by probe are inert placeholders in this adapter; their actual linked symbols are separately bound.',
    'Reset-error propagation is modeled only for declared OF resets with controller support; absent properties and disabled support preserve optional behavior.',
    'Old zero-read undefined return and high-bit signed-shift UB are compiler/sanitizer controls outside the fixed MIPS rows; errno values are normalized model values.',
    'The existing SPI queue/completion wait remains without an end-to-end hard timeout.',
    'Kernel symbol/object membership relies on the clean locked build; the separate mandatory SPI proof binds complete vmlinux/vendor/image bytes.',
    'No router boot, post-write warm reset, system memory-pressure survival or efd2 first-hop upgrade safety is established.',
)
MAX_SOURCE = 4 * 1024 * 1024
MAX_REPORT = 16 * 1024 * 1024
MAX_COMMAND_SECONDS = 20
FLAGS = ('-std=gnu99', '-Os', '-static', '-s', '-Wall', '-Wextra', '-Werror',
         '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-sign-compare', '-Wno-pointer-sign')
KERNEL_SYMBOLS = {'mt7621': ('mt7621_spi_probe', 'mt7621_spi_remove', 'mt7621_spi_transfer_one_message')}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact(left, right, message):
    require(json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True), message)


def validate_contract():
    require(SOURCE_PATHS and HARNESS_SOURCE_PATHS and FUNCTION_SOURCES and
            BASELINE_FUNCTION_HASHES and CASES and EXPECTED and
            type(PRODUCTION_FRAGMENT_SHA256) is str and re.fullmatch("[0-9a-f]{64}", PRODUCTION_FRAGMENT_SHA256),
            'Controller source contract has not been frozen')
    require(len({name for name, _ in CASES}) == len(CASES) and
            set(EXPECTED) == {name for name, _ in CASES}, 'Incomplete Controller case contract')


def generate_source(inputs, fixture_root, owner_uid, baseline=False):
    validate_contract()
    require(set(inputs) == set(SOURCE_PATHS), 'Controller source mapping changed')
    require(type(owner_uid) is int and 0 <= owner_uid < 2**32, 'Invalid Controller fixture owner')
    require(type(baseline) is bool, 'Invalid Controller baseline profile')
    module = resident.checked_module(inputs['harness'], 'mt7621-controller')
    exact(module.SOURCE_PATHS, HARNESS_SOURCE_PATHS, 'Controller fixture source contract changed')
    exact(module.BASELINE_COMMIT, BASELINE_COMMIT, 'Controller public baseline source identity changed')
    for profile, contract in ((False, module.CASES), (True, module.BASELINE_CASES)):
        expected = tuple((options['selector'], EXPECTED[name]) for name, options in CASES
                         if options['baseline'] is profile)
        exact(contract, expected, 'Controller fixture expected contract changed')
    exact(module.BASELINE_FUNCTIONS_SHA256, BASELINE_FUNCTION_HASHES,
          'Public old Controller baseline changed')
    texts = {key: inputs[key] for key in HARNESS_SOURCE_PATHS}
    fragments = module.production_fragments(texts)
    require(type(fragments) is str and 0 < len(fragments.encode()) <= MAX_SOURCE and
            sha(fragments.encode()) == PRODUCTION_FRAGMENT_SHA256,
            'Controller production macro/struct fragments changed')
    generated = module.generate_source(texts, str(fixture_root), owner_uid=owner_uid, baseline=baseline)
    require(type(generated) is str and 0 < len(generated.encode()) <= MAX_SOURCE,
            'Invalid Controller generated source')
    require(generated.count(fragments) == 1, 'Controller adapter omitted/duplicated production fragments')
    bodies = (module.BASELINE_FUNCTIONS if baseline else
              {name: resident.function(inputs[key], name) for name, key in FUNCTION_SOURCES.items()})
    if baseline:
        exact({name: sha(body.encode()) for name, body in bodies.items()}, BASELINE_FUNCTION_HASHES,
              'Old Controller body bytes differ from reviewed public baseline')
    for name, body in bodies.items():
        require(generated.count(body) == 1, 'Controller adapter omitted/duplicated actual body: ' + name)
    return generated, bodies


def validate_records(rows):
    validate_contract()
    require(type(rows) is list and len(rows) == len(CASES), 'Controller cases missing/extra')
    for row, (name, inputs) in zip(rows, CASES):
        require(type(row) is dict and set(row) == {'case', 'inputs', 'observed'} and
                row['case'] == name, 'Controller record order/schema differs')
        exact(row['inputs'], inputs, 'Controller inputs differ: ' + name)
        exact(row['observed'], EXPECTED[name], 'Controller outcome/ready/registration differs: ' + name)


def read_regular(path, limit):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError('Controller artifact cannot be opened without following aliases') from error
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit,
                'Controller artifact must be a bounded regular file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(descriptor)
    require(len(data) == info.st_size, 'Controller artifact changed or exceeds budget')
    return data


def kernel_reference(inputs, report_path):
    """Reuse the separately required whole-image proof, export compact identities.

    This checks the existing sidecar bytes and selected public functions instead
    of duplicating all kernel bytes or asserting static-inline symbol presence.
    """
    raw = read_regular(report_path, MAX_REPORT)
    report = json.loads(raw)
    require(type(report.get('schema_version')) is int and report['schema_version'] == 1 and report.get('status') == 'PASS' and
            report.get('profile') == 'k2p-4.4' and report.get('phase') == 'final-kernel-image-bound',
            'Controller final proof requires the completed SPI kernel/image gate')
    exact(report.get('required_cases'), [name for name, _ in spi.CASES], 'SPI case set differs')
    spi.validate_records(report.get('checks'))
    for key in ('controller',):
        require(report.get('source_sha256', {}).get(key) == sha(inputs[key].encode()),
                'Controller and SPI source identities differ: ' + key)
    binding = report.get('kernel_binding')
    require(type(binding) is dict and binding.get('whole_byte_equality') is True,
            'Controller requires exact whole kernel/image binding')
    expected_exports = {'target-spi-kernel-vmlinux.elf', 'target-spi-kernel-raw.bin',
                        'target-spi-kernel-vendor.bin', 'target-spi-vmlinux.cmd'}
    for label in spi.OBJECTS:
        expected_exports.update(('target-spi-' + label + '.o', 'target-spi-' + label + '.cmd'))
    exports = binding.get('exports')
    require(type(exports) is dict and set(exports) == expected_exports,
            'Controller SPI kernel sidecar set differs')
    for name, value in exports.items():
        require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
                'Malformed SPI sidecar SHA256')
        require(sha(read_regular(report_path.parent / name, spi.MAX_ELF)) == value,
                'Controller referenced SPI sidecar bytes differ: ' + name)
    linked = spi.inspect_elf(read_regular(report_path.parent / 'target-spi-kernel-vmlinux.elf', spi.MAX_ELF), 2)
    exact(linked, binding.get('vmlinux'), 'Controller linked kernel metadata differs from sidecar')
    selected = binding.get('selected_objects')
    require(type(selected) is dict and set(selected) == set(spi.OBJECTS), 'SPI selected objects differ')
    symbols = {}
    for label, names in KERNEL_SYMBOLS.items():
        row = selected[label]
        object_name = 'target-spi-' + label + '.o'
        require(row.get('object_file') == object_name, 'Controller selected object filename differs')
        obj = spi.inspect_elf(read_regular(report_path.parent / object_name, spi.MAX_ELF), 1)
        exact(obj, row.get('ELF'), 'Controller selected object metadata differs from sidecar')
        command_name = 'target-spi-' + label + '.cmd'
        command = read_regular(report_path.parent / command_name, 2 * 1024 * 1024)
        require(row.get('command_file') == command_name and
                row.get('command_sha256') == sha(command) and
                Path(spi.OBJECTS[label][0]).with_suffix('.c').name.encode() in command,
                'Controller selected object command/source binding differs')
        for name in names:
            require(len(obj['function_symbols'].get(name, [])) == 1 and
                    len(linked['function_symbols'].get(name, [])) == 1 and
                    obj['function_symbols'][name][0]['bytes'] > 0 and
                    linked['function_symbols'][name][0]['bytes'] > 0,
                    'Controller actual controller implementation symbol absent: ' + name)
            require(name in row.get('required_symbols', []), 'SPI proof does not require Controller caller: ' + name)
            symbols[name] = {'object': label, 'object_symbol': obj['function_symbols'][name][0],
                             'linked_symbol': linked['function_symbols'][name][0]}
    return {'role': 'Reference to separately mandatory exact whole-kernel SPI proof',
            'report_file': report_path.name, 'report_sha256': sha(raw),
            'image_sha256': binding['image']['image_sha256'],
            'vmlinux_sha256': linked['sha256'], 'required_symbols': symbols,
            'source_sha256': {key: sha(inputs[key].encode()) for key in ('controller',)},
            'kernel_exports_sha256': exports, 'whole_kernel_image_equality': True,
            'object_to_link_scope': binding['object_to_link_scope']}


def check(trunk, compiler, output, preflight=False, spi_report=None):
    validate_contract()
    require(type(preflight) is bool, 'Controller preflight selection must be boolean')
    require((preflight and spi_report is None) or (not preflight and spi_report is not None),
            'Controller requires preflight alone or a final SPI report')
    config = (trunk / '.config').read_text()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M),
            'Controller gate requires configured K2P4.4')
    qemu = shutil.which('qemu-mipsel')
    require(qemu is not None, 'qemu-mipsel required')
    inputs = {key: (trunk.parent / relative).read_text() for key, relative in SOURCE_PATHS.items()}
    rows, probes, exports, function_hashes = [], {}, {}, {}
    with tempfile.TemporaryDirectory(prefix='k2p-controller-source-', dir='/tmp') as temporary:
        base = Path(temporary).resolve()
        for baseline in (False, True):
            profile = 'baseline' if baseline else 'current'
            fixture = base / (profile + '-fixture')
            generated, bodies = generate_source(inputs, fixture, os.geteuid(), baseline)
            source, binary = base / (profile + '.c'), base / profile
            source.write_text(generated)
            run = subprocess.run([str(compiler), *FLAGS, str(source), '-o', str(binary)],
                                 capture_output=True, text=True, timeout=90)
            require(run.returncode == 0, 'Controller MIPS source compile failed: ' + run.stdout + run.stderr)
            data = binary.read_bytes()
            elf = resident.validate_static_helper(data)
            for name, options in CASES:
                if options['baseline'] is not baseline:
                    continue
                run = subprocess.run([qemu, str(binary), options['selector']],
                                     capture_output=True, text=True, timeout=MAX_COMMAND_SECONDS)
                require(run.returncode == 0 and not run.stderr,
                        'Controller fixture failed ' + name + ': ' + run.stdout + run.stderr)
                rows.append({'case': name, 'inputs': options, 'observed': json.loads(run.stdout)})
            name = 'target-controller' + ('-baseline' if baseline else '')
            exports[name + '.c'], exports[name] = generated.encode(), data
            function_hashes[profile] = {name: sha(body.encode()) for name, body in bodies.items()}
            probes[profile] = {'source_file': name + '.c', 'source_sha256': sha(generated.encode()),
                               'binary_file': name, 'binary_sha256': sha(data), 'ELF': elf,
                               'compile_flags': list(FLAGS), 'fixture_root': str(fixture),
                               'owner_uid': os.geteuid()}
    validate_records(rows)
    reference = kernel_reference(inputs, spi_report) if spi_report is not None else None
    output.parent.mkdir(parents=True, exist_ok=True)
    for name, data in exports.items():
        path = output.parent / name
        path.write_bytes(data)
        if not name.endswith('.c'):
            path.chmod(0o755)
    report = {'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4',
              'phase': 'early-source-only' if preflight else 'final-kernel-reference-bound',
              'execution_role': ROLE, 'required_cases': [name for name, _ in CASES], 'checks': rows,
              'source_files': SOURCE_PATHS,
              'source_sha256': {key: sha(text.encode()) for key, text in inputs.items()},
              'baseline_source_commit': BASELINE_COMMIT,
              'production_fragments_sha256': PRODUCTION_FRAGMENT_SHA256,
              'actual_functions_sha256': function_hashes, 'probes': probes,
              'kernel_reference': reference, 'compiler': str(compiler), 'limits': list(LIMITS)}
    output.write_text(json.dumps(report, indent=2) + '\n')
    print('MT7621 controller: ' + str(len(rows)) + ' inert actual-source MIPS cases PASS')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--spi-report', type=Path)
    args = parser.parse_args()
    try:
        check(args.trunk.resolve(), args.compiler.resolve(), args.output.resolve(), args.preflight,
              args.spi_report.resolve() if args.spi_report else None)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Controller target validation failed: ' + str(error) + '\n')
