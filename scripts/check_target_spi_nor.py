#!/usr/bin/env python3
"""Inert actual-source MIPS SPI regression and exact kernel/image binding."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

import check_target_resident_upgrade as resident

# These contracts must be frozen from independently reviewed source controls,
# before compiling/running target fixtures. Empty contracts fail closed.
SOURCE_PATHS = {'m25p': 'trunk/linux-4.4.x/drivers/mtd/devices/m25p80.c',
 'nor': 'trunk/linux-4.4.x/drivers/mtd/spi-nor/spi-nor.c',
 'core': 'trunk/linux-4.4.x/drivers/mtd/mtdcore.c',
 'char': 'trunk/linux-4.4.x/drivers/mtd/mtdchar.c',
 'harness': 'tests/spi_completion_harness.py',
 'vendor_makefile': 'trunk/vendors/Ralink/Makefile',
 'board_config': 'trunk/configs/boards/K2P/kernel-4.4.x.config',
 'dtb': 'trunk/linux-4.4.x/arch/mips/boot/dts/ralink/k2p.dts',
 'dt_layout': 'trunk/linux-4.4.x/arch/mips/boot/dts/ralink/mt7621-spi-16m-layout.dtsi',
 'dt_soc': 'trunk/linux-4.4.x/arch/mips/boot/dts/ralink/mt7621.dtsi'}
HARNESS_SOURCE_PATHS = {'m25p': 'trunk/linux-4.4.x/drivers/mtd/devices/m25p80.c',
 'nor': 'trunk/linux-4.4.x/drivers/mtd/spi-nor/spi-nor.c',
 'core': 'trunk/linux-4.4.x/drivers/mtd/mtdcore.c',
 'char': 'trunk/linux-4.4.x/drivers/mtd/mtdchar.c'}
FUNCTION_SOURCES = {'m25p_cmdsz': 'm25p',
 'm25p80_write': 'm25p',
 'm25p80_read': 'm25p',
 'm25p80_erase': 'm25p',
 'spi_nor_write_page': 'nor',
 'spi_nor_write': 'nor',
 'spi_nor_erase': 'nor',
 'mtd_write': 'core',
 'mtdchar_read': 'char',
 'mtdchar_write': 'char'}
BASELINE_FUNCTION_HASHES = {'m25p_cmdsz': '06164946643d0788f2dd0ef853227c20cd94ded58c46a36cb7ec6f5515d0c136',
 'm25p80_write': '35d0263e4e8a4adfb41d9908bfaa6a76a9ecc423e3e11aa523eb153263525e6d',
 'm25p80_read': 'd8fd78d2679243e70a10f725ceea0c1f8ff40bce4ddf21397e80253ba27a3a47',
 'm25p80_erase': 'debc17f9fa6d28a8d2560ee87824889faeb845c2d922ceec45e30c34786db77f',
 'spi_nor_write': '82be47a0d911e88c696f6fc247112af2ee0774a4b3cbe9fb104b8ca51f4cc09d',
 'spi_nor_erase': '69cdb8906e2f216724510ec35d6cb6b6794e2b722e07b1a39b8bdfe17939dbaf',
 'mtd_write': 'f473169da18e2f4b15b85699ae056d3a5ffeeb8d00dc8f7fd9793cc4855a5d9d',
 'mtdchar_read': '97daea2681f6f1fcee1f4830ac2015566c6fa3c0af280cb1dbd40da85812a96c',
 'mtdchar_write': '3904ab46df4c35f98fb012eb66c6100c12a41fd496a6b534b8eaf4e5843c9332'}
CASES = (('current:write-single', {'baseline': False, 'selector': 'write-single'}),
 ('current:write-cross-page', {'baseline': False, 'selector': 'write-cross-page'}),
 ('current:write-multiple', {'baseline': False, 'selector': 'write-multiple'}),
 ('current:write-final-ready-error', {'baseline': False, 'selector': 'write-final-ready-error'}),
 ('current:write-data-error', {'baseline': False, 'selector': 'write-data-error'}),
 ('current:write-command-error', {'baseline': False, 'selector': 'write-command-error'}),
 ('current:write-short-completion', {'baseline': False, 'selector': 'write-short-completion'}),
 ('current:write-overlong-completion', {'baseline': False, 'selector': 'write-overlong-completion'}),
 ('current:write-second-page-error', {'baseline': False, 'selector': 'write-second-page-error'}),
 ('current:write-enable-first-error', {'baseline': False, 'selector': 'write-enable-first-error'}),
 ('current:write-enable-second-error', {'baseline': False, 'selector': 'write-enable-second-error'}),
 ('current:write-callback-zero', {'baseline': False, 'selector': 'write-callback-zero'}),
 ('current:write-callback-overlong', {'baseline': False, 'selector': 'write-callback-overlong'}),
 ('current:write-callback-wrap', {'baseline': False, 'selector': 'write-callback-wrap'}),
 ('current:read-normal', {'baseline': False, 'selector': 'read-normal'}),
 ('current:read-data-error', {'baseline': False, 'selector': 'read-data-error'}),
 ('current:read-command-error', {'baseline': False, 'selector': 'read-command-error'}),
 ('current:read-short-completion', {'baseline': False, 'selector': 'read-short-completion'}),
 ('current:read-overlong-completion', {'baseline': False, 'selector': 'read-overlong-completion'}),
 ('current:read-fast-normal', {'baseline': False, 'selector': 'read-fast-normal'}),
 ('current:read-fast-command-error', {'baseline': False, 'selector': 'read-fast-command-error'}),
 ('current:erase-normal', {'baseline': False, 'selector': 'erase-normal'}),
 ('current:erase-error', {'baseline': False, 'selector': 'erase-error'}),
 ('current:erase-sector-normal', {'baseline': False, 'selector': 'erase-sector-normal'}),
 ('current:erase-sector-enable-first-error',
  {'baseline': False, 'selector': 'erase-sector-enable-first-error'}),
 ('current:erase-sector-enable-second-error',
  {'baseline': False, 'selector': 'erase-sector-enable-second-error'}),
 ('current:erase-sector-transport-error', {'baseline': False, 'selector': 'erase-sector-transport-error'}),
 ('current:erase-chip-normal', {'baseline': False, 'selector': 'erase-chip-normal'}),
 ('current:erase-chip-enable-error', {'baseline': False, 'selector': 'erase-chip-enable-error'}),
 ('current:char-write-normal', {'baseline': False, 'selector': 'char-write-normal'}),
 ('current:char-write-transport-error', {'baseline': False, 'selector': 'char-write-transport-error'}),
 ('current:char-write-zero', {'baseline': False, 'selector': 'char-write-zero'}),
 ('current:char-write-overlong', {'baseline': False, 'selector': 'char-write-overlong'}),
 ('current:char-write-short', {'baseline': False, 'selector': 'char-write-short'}),
 ('current:char-write-raw-zero', {'baseline': False, 'selector': 'char-write-raw-zero'}),
 ('current:char-read-normal', {'baseline': False, 'selector': 'char-read-normal'}),
 ('current:char-read-overlong', {'baseline': False, 'selector': 'char-read-overlong'}),
 ('current:char-read-ecc-valid', {'baseline': False, 'selector': 'char-read-ecc-valid'}),
 ('current:char-read-ecc-overlong', {'baseline': False, 'selector': 'char-read-ecc-overlong'}),
 ('current:char-read-zero-eof', {'baseline': False, 'selector': 'char-read-zero-eof'}),
 ('current:char-read-short', {'baseline': False, 'selector': 'char-read-short'}),
 ('current:char-read-raw-zero', {'baseline': False, 'selector': 'char-read-raw-zero'}),
 ('baseline:write-data-error', {'baseline': True, 'selector': 'write-data-error'}),
 ('baseline:write-command-error', {'baseline': True, 'selector': 'write-command-error'}),
 ('baseline:read-fast-command-error', {'baseline': True, 'selector': 'read-fast-command-error'}),
 ('baseline:read-overlong-completion', {'baseline': True, 'selector': 'read-overlong-completion'}),
 ('baseline:erase-error', {'baseline': True, 'selector': 'erase-error'}),
 ('baseline:write-enable-first-error', {'baseline': True, 'selector': 'write-enable-first-error'}),
 ('baseline:erase-sector-enable-first-error',
  {'baseline': True, 'selector': 'erase-sector-enable-first-error'}),
 ('baseline:erase-chip-enable-error', {'baseline': True, 'selector': 'erase-chip-enable-error'}),
 ('baseline:char-write-zero', {'baseline': True, 'selector': 'char-write-zero'}))
EXPECTED = {'current:write-single': {'case': 'write-single',
                          'result': 0,
                          'retlen': 32,
                          'transport_calls': 1,
                          'ready_calls': 1,
                          'write_enable_calls': 1,
                          'unlock_calls': 1,
                          'pending': 0,
                          'position': 0,
                          'copied_bytes': 0,
                          'lower_calls': 0,
                          'erase_callbacks': 0,
                          'erase_state': 0,
                          'sequence': 'AWPTU',
                          'allocations': 0,
                          'raw_zeroed': True},
 'current:write-cross-page': {'case': 'write-cross-page',
                              'result': 0,
                              'retlen': 32,
                              'transport_calls': 2,
                              'ready_calls': 2,
                              'write_enable_calls': 2,
                              'unlock_calls': 1,
                              'pending': 0,
                              'position': 0,
                              'copied_bytes': 0,
                              'lower_calls': 0,
                              'erase_callbacks': 0,
                              'erase_state': 0,
                              'sequence': 'AWPTWPTU',
                              'allocations': 0,
                              'raw_zeroed': True},
 'current:write-multiple': {'case': 'write-multiple',
                            'result': 0,
                            'retlen': 600,
                            'transport_calls': 3,
                            'ready_calls': 3,
                            'write_enable_calls': 3,
                            'unlock_calls': 1,
                            'pending': 0,
                            'position': 0,
                            'copied_bytes': 0,
                            'lower_calls': 0,
                            'erase_callbacks': 0,
                            'erase_state': 0,
                            'sequence': 'AWPTWPTWPTU',
                            'allocations': 0,
                            'raw_zeroed': True},
 'current:write-final-ready-error': {'case': 'write-final-ready-error',
                                     'result': -110,
                                     'retlen': 32,
                                     'transport_calls': 1,
                                     'ready_calls': 1,
                                     'write_enable_calls': 1,
                                     'unlock_calls': 1,
                                     'pending': 1,
                                     'position': 0,
                                     'copied_bytes': 0,
                                     'lower_calls': 0,
                                     'erase_callbacks': 0,
                                     'erase_state': 0,
                                     'sequence': 'AWPTU',
                                     'allocations': 0,
                                     'raw_zeroed': True},
 'current:write-data-error': {'case': 'write-data-error',
                              'result': -5,
                              'retlen': 0,
                              'transport_calls': 1,
                              'ready_calls': 0,
                              'write_enable_calls': 1,
                              'unlock_calls': 1,
                              'pending': 1,
                              'position': 0,
                              'copied_bytes': 0,
                              'lower_calls': 0,
                              'erase_callbacks': 0,
                              'erase_state': 0,
                              'sequence': 'AWPU',
                              'allocations': 0,
                              'raw_zeroed': True},
 'current:write-command-error': {'case': 'write-command-error',
                                 'result': -5,
                                 'retlen': 0,
                                 'transport_calls': 1,
                                 'ready_calls': 0,
                                 'write_enable_calls': 1,
                                 'unlock_calls': 1,
                                 'pending': 1,
                                 'position': 0,
                                 'copied_bytes': 0,
                                 'lower_calls': 0,
                                 'erase_callbacks': 0,
                                 'erase_state': 0,
                                 'sequence': 'AWPU',
                                 'allocations': 0,
                                 'raw_zeroed': True},
 'current:write-short-completion': {'case': 'write-short-completion',
                                    'result': -5,
                                    'retlen': 0,
                                    'transport_calls': 1,
                                    'ready_calls': 0,
                                    'write_enable_calls': 1,
                                    'unlock_calls': 1,
                                    'pending': 1,
                                    'position': 0,
                                    'copied_bytes': 0,
                                    'lower_calls': 0,
                                    'erase_callbacks': 0,
                                    'erase_state': 0,
                                    'sequence': 'AWPU',
                                    'allocations': 0,
                                    'raw_zeroed': True},
 'current:write-overlong-completion': {'case': 'write-overlong-completion',
                                       'result': -5,
                                       'retlen': 0,
                                       'transport_calls': 1,
                                       'ready_calls': 0,
                                       'write_enable_calls': 1,
                                       'unlock_calls': 1,
                                       'pending': 1,
                                       'position': 0,
                                       'copied_bytes': 0,
                                       'lower_calls': 0,
                                       'erase_callbacks': 0,
                                       'erase_state': 0,
                                       'sequence': 'AWPU',
                                       'allocations': 0,
                                       'raw_zeroed': True},
 'current:write-second-page-error': {'case': 'write-second-page-error',
                                     'result': -5,
                                     'retlen': 256,
                                     'transport_calls': 2,
                                     'ready_calls': 1,
                                     'write_enable_calls': 2,
                                     'unlock_calls': 1,
                                     'pending': 1,
                                     'position': 0,
                                     'copied_bytes': 0,
                                     'lower_calls': 0,
                                     'erase_callbacks': 0,
                                     'erase_state': 0,
                                     'sequence': 'AWPTWPU',
                                     'allocations': 0,
                                     'raw_zeroed': True},
 'current:write-enable-first-error': {'case': 'write-enable-first-error',
                                      'result': -5,
                                      'retlen': 0,
                                      'transport_calls': 0,
                                      'ready_calls': 0,
                                      'write_enable_calls': 1,
                                      'unlock_calls': 1,
                                      'pending': 0,
                                      'position': 0,
                                      'copied_bytes': 0,
                                      'lower_calls': 0,
                                      'erase_callbacks': 0,
                                      'erase_state': 0,
                                      'sequence': 'AWU',
                                      'allocations': 0,
                                      'raw_zeroed': True},
 'current:write-enable-second-error': {'case': 'write-enable-second-error',
                                       'result': -5,
                                       'retlen': 256,
                                       'transport_calls': 1,
                                       'ready_calls': 1,
                                       'write_enable_calls': 2,
                                       'unlock_calls': 1,
                                       'pending': 0,
                                       'position': 0,
                                       'copied_bytes': 0,
                                       'lower_calls': 0,
                                       'erase_callbacks': 0,
                                       'erase_state': 0,
                                       'sequence': 'AWPTWU',
                                       'allocations': 0,
                                       'raw_zeroed': True},
 'current:write-callback-zero': {'case': 'write-callback-zero',
                                 'result': -5,
                                 'retlen': 0,
                                 'transport_calls': 0,
                                 'ready_calls': 0,
                                 'write_enable_calls': 1,
                                 'unlock_calls': 1,
                                 'pending': 0,
                                 'position': 0,
                                 'copied_bytes': 0,
                                 'lower_calls': 0,
                                 'erase_callbacks': 0,
                                 'erase_state': 0,
                                 'sequence': 'AWBU',
                                 'allocations': 0,
                                 'raw_zeroed': True},
 'current:write-callback-overlong': {'case': 'write-callback-overlong',
                                     'result': -5,
                                     'retlen': 33,
                                     'transport_calls': 0,
                                     'ready_calls': 0,
                                     'write_enable_calls': 1,
                                     'unlock_calls': 1,
                                     'pending': 0,
                                     'position': 0,
                                     'copied_bytes': 0,
                                     'lower_calls': 0,
                                     'erase_callbacks': 0,
                                     'erase_state': 0,
                                     'sequence': 'AWBU',
                                     'allocations': 0,
                                     'raw_zeroed': True},
 'current:write-callback-wrap': {'case': 'write-callback-wrap',
                                 'result': -5,
                                 'retlen': 29,
                                 'transport_calls': 0,
                                 'ready_calls': 0,
                                 'write_enable_calls': 1,
                                 'unlock_calls': 1,
                                 'pending': 0,
                                 'position': 0,
                                 'copied_bytes': 0,
                                 'lower_calls': 0,
                                 'erase_callbacks': 0,
                                 'erase_state': 0,
                                 'sequence': 'AWBU',
                                 'allocations': 0,
                                 'raw_zeroed': True},
 'current:read-normal': {'case': 'read-normal',
                         'result': 0,
                         'retlen': 32,
                         'transport_calls': 1,
                         'ready_calls': 0,
                         'write_enable_calls': 0,
                         'unlock_calls': 0,
                         'pending': 1,
                         'position': 0,
                         'copied_bytes': 0,
                         'lower_calls': 0,
                         'erase_callbacks': 0,
                         'erase_state': 0,
                         'sequence': 'R',
                         'allocations': 0,
                         'raw_zeroed': True},
 'current:read-data-error': {'case': 'read-data-error',
                             'result': -5,
                             'retlen': 0,
                             'transport_calls': 1,
                             'ready_calls': 0,
                             'write_enable_calls': 0,
                             'unlock_calls': 0,
                             'pending': 1,
                             'position': 0,
                             'copied_bytes': 0,
                             'lower_calls': 0,
                             'erase_callbacks': 0,
                             'erase_state': 0,
                             'sequence': 'R',
                             'allocations': 0,
                             'raw_zeroed': True},
 'current:read-command-error': {'case': 'read-command-error',
                                'result': -5,
                                'retlen': 0,
                                'transport_calls': 1,
                                'ready_calls': 0,
                                'write_enable_calls': 0,
                                'unlock_calls': 0,
                                'pending': 1,
                                'position': 0,
                                'copied_bytes': 0,
                                'lower_calls': 0,
                                'erase_callbacks': 0,
                                'erase_state': 0,
                                'sequence': 'R',
                                'allocations': 0,
                                'raw_zeroed': True},
 'current:read-short-completion': {'case': 'read-short-completion',
                                   'result': -5,
                                   'retlen': 0,
                                   'transport_calls': 1,
                                   'ready_calls': 0,
                                   'write_enable_calls': 0,
                                   'unlock_calls': 0,
                                   'pending': 1,
                                   'position': 0,
                                   'copied_bytes': 0,
                                   'lower_calls': 0,
                                   'erase_callbacks': 0,
                                   'erase_state': 0,
                                   'sequence': 'R',
                                   'allocations': 0,
                                   'raw_zeroed': True},
 'current:read-overlong-completion': {'case': 'read-overlong-completion',
                                      'result': -5,
                                      'retlen': 0,
                                      'transport_calls': 1,
                                      'ready_calls': 0,
                                      'write_enable_calls': 0,
                                      'unlock_calls': 0,
                                      'pending': 1,
                                      'position': 0,
                                      'copied_bytes': 0,
                                      'lower_calls': 0,
                                      'erase_callbacks': 0,
                                      'erase_state': 0,
                                      'sequence': 'R',
                                      'allocations': 0,
                                      'raw_zeroed': True},
 'current:read-fast-normal': {'case': 'read-fast-normal',
                              'result': 0,
                              'retlen': 32,
                              'transport_calls': 1,
                              'ready_calls': 0,
                              'write_enable_calls': 0,
                              'unlock_calls': 0,
                              'pending': 1,
                              'position': 0,
                              'copied_bytes': 0,
                              'lower_calls': 0,
                              'erase_callbacks': 0,
                              'erase_state': 0,
                              'sequence': 'R',
                              'allocations': 0,
                              'raw_zeroed': True},
 'current:read-fast-command-error': {'case': 'read-fast-command-error',
                                     'result': -5,
                                     'retlen': 0,
                                     'transport_calls': 1,
                                     'ready_calls': 0,
                                     'write_enable_calls': 0,
                                     'unlock_calls': 0,
                                     'pending': 1,
                                     'position': 0,
                                     'copied_bytes': 0,
                                     'lower_calls': 0,
                                     'erase_callbacks': 0,
                                     'erase_state': 0,
                                     'sequence': 'R',
                                     'allocations': 0,
                                     'raw_zeroed': True},
 'current:erase-normal': {'case': 'erase-normal',
                          'result': 0,
                          'retlen': 0,
                          'transport_calls': 1,
                          'ready_calls': 0,
                          'write_enable_calls': 0,
                          'unlock_calls': 0,
                          'pending': 0,
                          'position': 0,
                          'copied_bytes': 0,
                          'lower_calls': 0,
                          'erase_callbacks': 0,
                          'erase_state': 0,
                          'sequence': 'E',
                          'allocations': 0,
                          'raw_zeroed': True},
 'current:erase-error': {'case': 'erase-error',
                         'result': -5,
                         'retlen': 0,
                         'transport_calls': 1,
                         'ready_calls': 0,
                         'write_enable_calls': 0,
                         'unlock_calls': 0,
                         'pending': 0,
                         'position': 0,
                         'copied_bytes': 0,
                         'lower_calls': 0,
                         'erase_callbacks': 0,
                         'erase_state': 0,
                         'sequence': 'E',
                         'allocations': 0,
                         'raw_zeroed': True},
 'current:erase-sector-normal': {'case': 'erase-sector-normal',
                                 'result': 0,
                                 'retlen': 0,
                                 'transport_calls': 2,
                                 'ready_calls': 2,
                                 'write_enable_calls': 2,
                                 'unlock_calls': 1,
                                 'pending': 0,
                                 'position': 0,
                                 'copied_bytes': 0,
                                 'lower_calls': 0,
                                 'erase_callbacks': 1,
                                 'erase_state': 8,
                                 'sequence': 'AWETWETDUC',
                                 'allocations': 0,
                                 'raw_zeroed': True},
 'current:erase-sector-enable-first-error': {'case': 'erase-sector-enable-first-error',
                                             'result': -5,
                                             'retlen': 0,
                                             'transport_calls': 0,
                                             'ready_calls': 0,
                                             'write_enable_calls': 1,
                                             'unlock_calls': 1,
                                             'pending': 0,
                                             'position': 0,
                                             'copied_bytes': 0,
                                             'lower_calls': 0,
                                             'erase_callbacks': 0,
                                             'erase_state': 16,
                                             'sequence': 'AWU',
                                             'allocations': 0,
                                             'raw_zeroed': True},
 'current:erase-sector-enable-second-error': {'case': 'erase-sector-enable-second-error',
                                              'result': -5,
                                              'retlen': 0,
                                              'transport_calls': 1,
                                              'ready_calls': 1,
                                              'write_enable_calls': 2,
                                              'unlock_calls': 1,
                                              'pending': 0,
                                              'position': 0,
                                              'copied_bytes': 0,
                                              'lower_calls': 0,
                                              'erase_callbacks': 0,
                                              'erase_state': 16,
                                              'sequence': 'AWETWU',
                                              'allocations': 0,
                                              'raw_zeroed': True},
 'current:erase-sector-transport-error': {'case': 'erase-sector-transport-error',
                                          'result': -5,
                                          'retlen': 0,
                                          'transport_calls': 1,
                                          'ready_calls': 0,
                                          'write_enable_calls': 1,
                                          'unlock_calls': 1,
                                          'pending': 0,
                                          'position': 0,
                                          'copied_bytes': 0,
                                          'lower_calls': 0,
                                          'erase_callbacks': 0,
                                          'erase_state': 16,
                                          'sequence': 'AWEU',
                                          'allocations': 0,
                                          'raw_zeroed': True},
 'current:erase-chip-normal': {'case': 'erase-chip-normal',
                               'result': 0,
                               'retlen': 0,
                               'transport_calls': 1,
                               'ready_calls': 1,
                               'write_enable_calls': 1,
                               'unlock_calls': 1,
                               'pending': 0,
                               'position': 0,
                               'copied_bytes': 0,
                               'lower_calls': 0,
                               'erase_callbacks': 1,
                               'erase_state': 8,
                               'sequence': 'AWETDUC',
                               'allocations': 0,
                               'raw_zeroed': True},
 'current:erase-chip-enable-error': {'case': 'erase-chip-enable-error',
                                     'result': -5,
                                     'retlen': 0,
                                     'transport_calls': 0,
                                     'ready_calls': 0,
                                     'write_enable_calls': 1,
                                     'unlock_calls': 1,
                                     'pending': 0,
                                     'position': 0,
                                     'copied_bytes': 0,
                                     'lower_calls': 0,
                                     'erase_callbacks': 0,
                                     'erase_state': 16,
                                     'sequence': 'AWU',
                                     'allocations': 0,
                                     'raw_zeroed': True},
 'current:char-write-normal': {'case': 'char-write-normal',
                               'result': 32,
                               'retlen': 0,
                               'transport_calls': 1,
                               'ready_calls': 1,
                               'write_enable_calls': 1,
                               'unlock_calls': 1,
                               'pending': 0,
                               'position': 32,
                               'copied_bytes': 0,
                               'lower_calls': 0,
                               'erase_callbacks': 0,
                               'erase_state': 0,
                               'sequence': 'AWPTU',
                               'allocations': 0,
                               'raw_zeroed': True},
 'current:char-write-transport-error': {'case': 'char-write-transport-error',
                                        'result': -5,
                                        'retlen': 0,
                                        'transport_calls': 1,
                                        'ready_calls': 0,
                                        'write_enable_calls': 1,
                                        'unlock_calls': 1,
                                        'pending': 1,
                                        'position': 0,
                                        'copied_bytes': 0,
                                        'lower_calls': 0,
                                        'erase_callbacks': 0,
                                        'erase_state': 0,
                                        'sequence': 'AWPU',
                                        'allocations': 0,
                                        'raw_zeroed': True},
 'current:char-write-zero': {'case': 'char-write-zero',
                             'result': -5,
                             'retlen': 0,
                             'transport_calls': 0,
                             'ready_calls': 0,
                             'write_enable_calls': 0,
                             'unlock_calls': 0,
                             'pending': 0,
                             'position': 0,
                             'copied_bytes': 0,
                             'lower_calls': 1,
                             'erase_callbacks': 0,
                             'erase_state': 0,
                             'sequence': 'L',
                             'allocations': 0,
                             'raw_zeroed': True},
 'current:char-write-overlong': {'case': 'char-write-overlong',
                                 'result': -5,
                                 'retlen': 0,
                                 'transport_calls': 0,
                                 'ready_calls': 0,
                                 'write_enable_calls': 0,
                                 'unlock_calls': 0,
                                 'pending': 0,
                                 'position': 0,
                                 'copied_bytes': 0,
                                 'lower_calls': 1,
                                 'erase_callbacks': 0,
                                 'erase_state': 0,
                                 'sequence': 'L',
                                 'allocations': 0,
                                 'raw_zeroed': True},
 'current:char-write-short': {'case': 'char-write-short',
                              'result': 32,
                              'retlen': 0,
                              'transport_calls': 0,
                              'ready_calls': 0,
                              'write_enable_calls': 0,
                              'unlock_calls': 0,
                              'pending': 0,
                              'position': 32,
                              'copied_bytes': 0,
                              'lower_calls': 2,
                              'erase_callbacks': 0,
                              'erase_state': 0,
                              'sequence': 'LL',
                              'allocations': 0,
                              'raw_zeroed': True},
 'current:char-write-raw-zero': {'case': 'char-write-raw-zero',
                                 'result': -5,
                                 'retlen': 0,
                                 'transport_calls': 0,
                                 'ready_calls': 0,
                                 'write_enable_calls': 0,
                                 'unlock_calls': 0,
                                 'pending': 0,
                                 'position': 0,
                                 'copied_bytes': 0,
                                 'lower_calls': 1,
                                 'erase_callbacks': 0,
                                 'erase_state': 0,
                                 'sequence': 'L',
                                 'allocations': 0,
                                 'raw_zeroed': True},
 'current:char-read-normal': {'case': 'char-read-normal',
                              'result': 32,
                              'retlen': 0,
                              'transport_calls': 0,
                              'ready_calls': 0,
                              'write_enable_calls': 0,
                              'unlock_calls': 0,
                              'pending': 0,
                              'position': 32,
                              'copied_bytes': 32,
                              'lower_calls': 1,
                              'erase_callbacks': 0,
                              'erase_state': 0,
                              'sequence': 'L',
                              'allocations': 0,
                              'raw_zeroed': True},
 'current:char-read-overlong': {'case': 'char-read-overlong',
                                'result': -5,
                                'retlen': 0,
                                'transport_calls': 0,
                                'ready_calls': 0,
                                'write_enable_calls': 0,
                                'unlock_calls': 0,
                                'pending': 0,
                                'position': 0,
                                'copied_bytes': 0,
                                'lower_calls': 1,
                                'erase_callbacks': 0,
                                'erase_state': 0,
                                'sequence': 'L',
                                'allocations': 0,
                                'raw_zeroed': True},
 'current:char-read-ecc-valid': {'case': 'char-read-ecc-valid',
                                 'result': 32,
                                 'retlen': 0,
                                 'transport_calls': 0,
                                 'ready_calls': 0,
                                 'write_enable_calls': 0,
                                 'unlock_calls': 0,
                                 'pending': 0,
                                 'position': 32,
                                 'copied_bytes': 32,
                                 'lower_calls': 1,
                                 'erase_callbacks': 0,
                                 'erase_state': 0,
                                 'sequence': 'L',
                                 'allocations': 0,
                                 'raw_zeroed': True},
 'current:char-read-ecc-overlong': {'case': 'char-read-ecc-overlong',
                                    'result': -5,
                                    'retlen': 0,
                                    'transport_calls': 0,
                                    'ready_calls': 0,
                                    'write_enable_calls': 0,
                                    'unlock_calls': 0,
                                    'pending': 0,
                                    'position': 0,
                                    'copied_bytes': 0,
                                    'lower_calls': 1,
                                    'erase_callbacks': 0,
                                    'erase_state': 0,
                                    'sequence': 'L',
                                    'allocations': 0,
                                    'raw_zeroed': True},
 'current:char-read-zero-eof': {'case': 'char-read-zero-eof',
                                'result': 0,
                                'retlen': 0,
                                'transport_calls': 0,
                                'ready_calls': 0,
                                'write_enable_calls': 0,
                                'unlock_calls': 0,
                                'pending': 0,
                                'position': 0,
                                'copied_bytes': 0,
                                'lower_calls': 1,
                                'erase_callbacks': 0,
                                'erase_state': 0,
                                'sequence': 'L',
                                'allocations': 0,
                                'raw_zeroed': True},
 'current:char-read-short': {'case': 'char-read-short',
                             'result': 32,
                             'retlen': 0,
                             'transport_calls': 0,
                             'ready_calls': 0,
                             'write_enable_calls': 0,
                             'unlock_calls': 0,
                             'pending': 0,
                             'position': 32,
                             'copied_bytes': 32,
                             'lower_calls': 2,
                             'erase_callbacks': 0,
                             'erase_state': 0,
                             'sequence': 'LL',
                             'allocations': 0,
                             'raw_zeroed': True},
 'current:char-read-raw-zero': {'case': 'char-read-raw-zero',
                                'result': 0,
                                'retlen': 0,
                                'transport_calls': 0,
                                'ready_calls': 0,
                                'write_enable_calls': 0,
                                'unlock_calls': 0,
                                'pending': 0,
                                'position': 0,
                                'copied_bytes': 0,
                                'lower_calls': 1,
                                'erase_callbacks': 0,
                                'erase_state': 0,
                                'sequence': 'L',
                                'allocations': 0,
                                'raw_zeroed': True},
 'baseline:write-data-error': {'case': 'write-data-error',
                               'result': 0,
                               'retlen': 0,
                               'transport_calls': 1,
                               'ready_calls': 1,
                               'write_enable_calls': 1,
                               'unlock_calls': 1,
                               'pending': 0,
                               'position': 0,
                               'copied_bytes': 0,
                               'lower_calls': 0,
                               'erase_callbacks': 0,
                               'erase_state': 0,
                               'sequence': 'AWPTU',
                               'allocations': 0,
                               'raw_zeroed': True},
 'baseline:write-command-error': {'case': 'write-command-error',
                                  'result': 0,
                                  'retlen': 4294967292,
                                  'transport_calls': 1,
                                  'ready_calls': 1,
                                  'write_enable_calls': 1,
                                  'unlock_calls': 1,
                                  'pending': 0,
                                  'position': 0,
                                  'copied_bytes': 0,
                                  'lower_calls': 0,
                                  'erase_callbacks': 0,
                                  'erase_state': 0,
                                  'sequence': 'AWPTU',
                                  'allocations': 0,
                                  'raw_zeroed': True},
 'baseline:read-fast-command-error': {'case': 'read-fast-command-error',
                                      'result': 0,
                                      'retlen': 4294967291,
                                      'transport_calls': 1,
                                      'ready_calls': 0,
                                      'write_enable_calls': 0,
                                      'unlock_calls': 0,
                                      'pending': 1,
                                      'position': 0,
                                      'copied_bytes': 0,
                                      'lower_calls': 0,
                                      'erase_callbacks': 0,
                                      'erase_state': 0,
                                      'sequence': 'R',
                                      'allocations': 0,
                                      'raw_zeroed': True},
 'baseline:read-overlong-completion': {'case': 'read-overlong-completion',
                                       'result': 0,
                                       'retlen': 33,
                                       'transport_calls': 1,
                                       'ready_calls': 0,
                                       'write_enable_calls': 0,
                                       'unlock_calls': 0,
                                       'pending': 1,
                                       'position': 0,
                                       'copied_bytes': 0,
                                       'lower_calls': 0,
                                       'erase_callbacks': 0,
                                       'erase_state': 0,
                                       'sequence': 'R',
                                       'allocations': 0,
                                       'raw_zeroed': True},
 'baseline:erase-error': {'case': 'erase-error',
                          'result': 0,
                          'retlen': 0,
                          'transport_calls': 1,
                          'ready_calls': 0,
                          'write_enable_calls': 0,
                          'unlock_calls': 0,
                          'pending': 0,
                          'position': 0,
                          'copied_bytes': 0,
                          'lower_calls': 0,
                          'erase_callbacks': 0,
                          'erase_state': 0,
                          'sequence': 'E',
                          'allocations': 0,
                          'raw_zeroed': True},
 'baseline:write-enable-first-error': {'case': 'write-enable-first-error',
                                       'result': 0,
                                       'retlen': 32,
                                       'transport_calls': 1,
                                       'ready_calls': 1,
                                       'write_enable_calls': 1,
                                       'unlock_calls': 1,
                                       'pending': 0,
                                       'position': 0,
                                       'copied_bytes': 0,
                                       'lower_calls': 0,
                                       'erase_callbacks': 0,
                                       'erase_state': 0,
                                       'sequence': 'AWPTU',
                                       'allocations': 0,
                                       'raw_zeroed': True},
 'baseline:erase-sector-enable-first-error': {'case': 'erase-sector-enable-first-error',
                                              'result': 0,
                                              'retlen': 0,
                                              'transport_calls': 2,
                                              'ready_calls': 2,
                                              'write_enable_calls': 2,
                                              'unlock_calls': 1,
                                              'pending': 0,
                                              'position': 0,
                                              'copied_bytes': 0,
                                              'lower_calls': 0,
                                              'erase_callbacks': 1,
                                              'erase_state': 8,
                                              'sequence': 'AWETWETDUC',
                                              'allocations': 0,
                                              'raw_zeroed': True},
 'baseline:erase-chip-enable-error': {'case': 'erase-chip-enable-error',
                                      'result': 0,
                                      'retlen': 0,
                                      'transport_calls': 1,
                                      'ready_calls': 1,
                                      'write_enable_calls': 1,
                                      'unlock_calls': 1,
                                      'pending': 0,
                                      'position': 0,
                                      'copied_bytes': 0,
                                      'lower_calls': 0,
                                      'erase_callbacks': 1,
                                      'erase_state': 8,
                                      'sequence': 'AWETDUC',
                                      'allocations': 0,
                                      'raw_zeroed': True},
 'baseline:char-write-zero': {'case': 'char-write-zero',
                              'result': -40,
                              'retlen': 0,
                              'transport_calls': 0,
                              'ready_calls': 0,
                              'write_enable_calls': 0,
                              'unlock_calls': 0,
                              'pending': 0,
                              'position': 0,
                              'copied_bytes': 0,
                              'lower_calls': 3,
                              'erase_callbacks': 0,
                              'erase_state': 0,
                              'sequence': 'LLL',
                              'allocations': 0,
                              'raw_zeroed': True}}
ROLE = ('Actual kernel-source MIPS regression with explicitly inert SPI/MMIO/MTD '
        'transport and memory callbacks; no kernel module, device access or reboot.')
LIMITS = (
    'The fixture is a static MIPS userspace program, not a running MIPS kernel or hardware fault injection.',
    'Actual SPI transport/status/locking effects are fixture substitutions; source bodies remain bound exactly.',
    'Selected objects and linker commands attest the clean locked build; object-to-vmlinux relocation is not independently reconstructed.',
    'Exact vmlinux-to-vendor-binary-to-decoded-image equality does not establish warm-reset, power-loss or hardware boot reliability.',
)
MAX_ELF = 64*1024*1024
MAX_KERNEL = 48*1024*1024
OBJECTS = {
    'm25p80': ('drivers/mtd/devices/m25p80.o',('m25p80_read','m25p80_write','m25p80_erase')),
    'spi-nor': ('drivers/mtd/spi-nor/spi-nor.o',('spi_nor_write',)),
    'mtdchar': ('drivers/mtd/mtdchar.o',('mtdchar_read','mtdchar_write')),
}


def require(value,message):
    if not value:raise ValueError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


def exact(left,right,message):
    require(json.dumps(left,sort_keys=True)==json.dumps(right,sort_keys=True),message)


def inspect_elf(data,kind):
    """Bounded ELF32LE/MIPS metadata; symbol bytes are reported, not relocated."""
    require(type(data) in (bytes,bytearray) and 52<=len(data)<=MAX_ELF and
            data[:7]==b'\x7fELF\x01\x01\x01','Expected bounded ELF32LE/MIPS kernel artifact')
    fields=struct.unpack_from('<HHIIIIIHHHHHH',data,16)
    etype,machine,version,entry,phoff,shoff,flags,ehsize,phentsize,phnum,shentsize,shnum,shstrndx=fields
    require((etype,machine,version,ehsize)==(kind,8,1,52),'Wrong kernel ELF type/architecture')
    require(shentsize==40 and 0<shnum<=65535 and shoff>=52 and shoff+shnum*40<=len(data),
            'Invalid kernel ELF section table')
    sections=[struct.unpack_from('<10I',data,shoff+i*40) for i in range(shnum)]
    require(0<shstrndx<shnum and sections[shstrndx][1]==3,'Invalid kernel section names')
    def pool_at(section):
        offset,size=section[4:6]
        require(offset<=len(data) and size<=len(data)-offset,'Invalid kernel section bytes')
        return data[offset:offset+size]
    names=pool_at(sections[shstrndx])
    def string(pool,offset):
        require(offset<len(pool),'ELF string offset outside table')
        end=pool.find(b'\0',offset);require(end>=offset,'Unterminated ELF string')
        return pool[offset:end].decode('ascii')
    listing=[];symbols={};programs=[]
    for index,section in enumerate(sections):
        label=string(names,section[0]);_,stype,sflags,address,offset,size,link,info,align,entsize=section
        if stype!=8:pool_at(section)
        require(address+size<=2**32,'Kernel section address overflow')
        listing.append({'index':index,'name':label,'type':stype,'flags':sflags,'address':address,
                        'offset':offset,'bytes':size,'link':link,'alignment':align})
        if stype!=2:continue
        require(entsize==16 and size%16==0 and link<shnum and sections[link][1]==3,
                'Invalid kernel symbol table')
        strings=pool_at(sections[link])
        for at in range(offset,offset+size,16):
            name,value,length,sinfo,other,shndx=struct.unpack_from('<IIIBBH',data,at)
            label=string(strings,name)
            if not label or sinfo&15!=2 or shndx==0:continue
            require(shndx<shnum,'Function symbol section is not ordinary')
            target=sections[shndx]
            relative=value if kind==1 else value-target[3]
            require(relative>=0 and relative<=target[5] and length<=target[5]-relative and target[1]!=8,
                    'Function symbol is outside file-backed kernel section')
            position=target[4]+relative
            symbols.setdefault(label,[]).append({'value':value,'bytes':length,'section':shndx,
                'offset':position,'sha256':sha(data[position:position+length])})
    if phnum:
        require(phentsize==32 and phnum<=4096 and phoff>=52 and phoff+phnum*32<=len(data),
                'Invalid kernel program table')
        for at in range(phoff,phoff+phnum*32,32):
            ptype,offset,vaddr,paddr,filesz,memsz,pflags,align=struct.unpack_from('<8I',data,at)
            require(ptype not in (2,3),'Kernel ELF must not depend on a runtime loader')
            require(offset<=len(data) and filesz<=len(data)-offset and filesz<=memsz,
                    'Invalid kernel program bytes')
            programs.append({'type':ptype,'offset':offset,'vaddr':vaddr,'paddr':paddr,
                             'file_bytes':filesz,'memory_bytes':memsz,'flags':pflags,'alignment':align})
    require(kind!=2 or programs,'Linked kernel has no program headers')
    return {'sha256':sha(data),'bytes':len(data),'ELF_class':32,'byte_order':'little','machine':8,
            'type':'ET_REL' if kind==1 else 'ET_EXEC','entry':entry,'flags':flags,
            'sections':listing,'programs':programs,'function_symbols':symbols}


def decoded_image_kernel(data):
    require(type(data) is bytes and 64<len(data)<=15925248,'Invalid SPI binding firmware length')
    magic,hcrc,timestamp,payload,load,entry,dcrc=struct.unpack_from('>7I',data)
    require(magic==0x27051956 and payload==len(data)-64 and load==0x81001000,
            'Wrong K2P4.4 image geometry')
    header=bytearray(data[:64]);header[4:8]=bytes(4)
    import zlib
    require(zlib.crc32(header)&0xffffffff==hcrc and zlib.crc32(data[64:])&0xffffffff==dcrc,
            'Firmware CRC differs during kernel binding')
    require(data[28:32]==bytes((5,5,2,3)) and data[32:34]==bytes((4,4)) and
            data[36:59].split(b'\0',1)[0]==b'K2P','Expected LZMA Linux/MIPS K2P4.4 image')
    boundary=struct.unpack_from('>I',data,60)[0]
    require(64<boundary<len(data) and boundary%16==0 and data[boundary:boundary+4]==b'hsqs',
            'Invalid kernel/rootfs boundary')
    compressed=data[64:boundary];require(len(compressed)>=13,'Truncated kernel compression')
    declared=int.from_bytes(compressed[5:13],'little')
    require(declared==2**64-1 or 0<declared<=MAX_KERNEL,'Excessive declared kernel length')
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE,memlimit=96*1024*1024)
    raw=decoder.decompress(compressed,max_length=MAX_KERNEL+1)
    require(decoder.eof and 1024<=len(raw)<=MAX_KERNEL and
            (declared==2**64-1 or declared==len(raw)),'Invalid decoded kernel length/EOF')
    require(len(decoder.unused_data)<=15 and all(value==255 for value in decoder.unused_data),
            'Unexpected post-compression kernel padding')
    require(entry%4==0 and load<=entry<=load+len(raw)-4,'Kernel entry outside bound image')
    return raw,{'image_sha256':sha(data),'kernel_boundary':boundary,'load':load,'entry':entry,
                'decoded_bytes':len(raw),'decoded_sha256':sha(raw),'padding_bytes':len(decoder.unused_data)}


def kernel_binding(trunk,compiler,image,kernel_binary,output):
    kernel=trunk/'linux-4.4.x';vendor=(trunk/'vendors/Ralink/Makefile').read_text()
    rule='$(CROSS_COMPILE)objcopy -O binary -R .note -R .comment -S $(ROOTDIR)/$(LINUXDIR)/vmlinux $(KERNELZ)'
    require(vendor.count(rule)==1,'Actual vendor objcopy rule changed; review required')
    require(compiler.name.endswith('gcc'),'Cannot determine matching toolchain objcopy')
    objcopy=compiler.with_name(compiler.name[:-3]+'objcopy')
    require(objcopy.is_file() and os.access(objcopy,os.X_OK),'Missing matching kernel objcopy')
    files={};metadata={};vmlinux=(kernel/'vmlinux').read_bytes()
    linked=inspect_elf(vmlinux,2)
    files['target-spi-kernel-vmlinux.elf']=vmlinux
    for label,(relative,names) in OBJECTS.items():
        path=kernel/relative;data=path.read_bytes();elf=inspect_elf(data,1)
        for name in names:
            require(len(elf['function_symbols'].get(name,[]))==1 and linked['function_symbols'].get(name),
                    'Required SPI implementation symbol absent: '+name)
        object_file='target-spi-'+label+'.o';files[object_file]=data
        command=path.with_name('.'+path.name+'.cmd').read_bytes()
        require(len(command)<=2*1024*1024 and path.with_suffix('.c').name.encode() in command,
                'Missing selected object source command/dependency record')
        command_file='target-spi-'+label+'.cmd';files[command_file]=command
        metadata[label]={'object_file':object_file,'ELF':elf,'required_symbols':list(names),
                         'command_file':command_file,'command_sha256':sha(command)}
    link_command=(kernel/'.vmlinux.cmd').read_bytes()
    require(0<len(link_command)<=2*1024*1024 and b'vmlinux' in link_command,'Missing full kernel link record')
    files['target-spi-vmlinux.cmd']=link_command
    with tempfile.TemporaryDirectory(prefix='k2p-spi-kernel-bind-',dir='/tmp') as temporary:
        rebuilt=Path(temporary)/'raw.bin'
        flags=['-O','binary','-R','.note','-R','.comment','-S']
        run=subprocess.run([str(objcopy),*flags,str(kernel/'vmlinux'),str(rebuilt)],
                           capture_output=True,text=True,timeout=90)
        require(run.returncode==0,'Exact vendor objcopy replay failed: '+run.stdout+run.stderr)
        raw=rebuilt.read_bytes()
    vendor_raw=kernel_binary.read_bytes();decoded,packed=decoded_image_kernel(image.read_bytes())
    require(raw==vendor_raw==decoded,'Linked ELF/vendor kernel/decoded image differ byte-for-byte')
    require(linked['entry']==packed['entry'],'ELF and packed kernel entry differ')
    files['target-spi-kernel-raw.bin']=raw;files['target-spi-kernel-vendor.bin']=vendor_raw
    for name,data in files.items():(output.parent/name).write_bytes(data)
    return {'role':'Exact vendor objcopy replay and whole-byte equality with actual vendor zImage and decoded image',
            'whole_byte_equality':True,'vendor_rule_sha256':sha(vendor.encode()),
            'objcopy':{'name':objcopy.name,'sha256':sha(objcopy.read_bytes()),'flags':flags,
                       'stdout':run.stdout,'stderr':run.stderr},'vmlinux':linked,'selected_objects':metadata,
            'image':packed,'exports':{name:sha(data) for name,data in files.items()},
            'object_to_link_scope':'Relocated machine-code equivalence is not independently proved; selected objects/commands rely on the clean locked full-build provenance.'}


def read_source_inputs(trunk):
    return {key:(trunk.parent/relative).read_text() for key,relative in SOURCE_PATHS.items()}


def validate_contract():
    require(SOURCE_PATHS and HARNESS_SOURCE_PATHS and FUNCTION_SOURCES and BASELINE_FUNCTION_HASHES and CASES and EXPECTED,
            'SPI source contract has not been frozen')
    require(len({name for name,_ in CASES})==len(CASES) and set(EXPECTED)=={name for name,_ in CASES},
            'Incomplete SPI case contract')


def generate_source(inputs,fixture_root,owner_uid,baseline=False):
    validate_contract();require(set(inputs)==set(SOURCE_PATHS),'SPI source mapping changed')
    require(type(owner_uid) is int and 0<=owner_uid<2**32,'Invalid SPI fixture owner')
    require(type(baseline) is bool,'Invalid SPI baseline profile')
    module=resident.checked_module(inputs['harness'],'spi-nor-errors')
    exact(module.SOURCE_PATHS,HARNESS_SOURCE_PATHS,'SPI fixture source contract changed')
    for profile,contract in ((False,module.CASES),(True,module.BASELINE_CASES)):
        expected=tuple((options['selector'],EXPECTED[name]) for name,options in CASES if options['baseline'] is profile)
        exact(contract,expected,'SPI fixture expected contract changed')
    exact(module.BASELINE_FUNCTIONS_SHA256,BASELINE_FUNCTION_HASHES,'Public old SPI baseline changed')
    texts={key:inputs[key] for key in HARNESS_SOURCE_PATHS}
    generated=module.generate_source(texts,str(fixture_root),owner_uid=owner_uid,baseline=baseline)
    require(type(generated) is str and 0<len(generated.encode())<=2*1024*1024,'Invalid SPI generated source')
    bodies=(module.BASELINE_FUNCTIONS if baseline else
            {name:resident.function(inputs[key],name) for name,key in FUNCTION_SOURCES.items()})
    if baseline:
        exact({name:sha(body.encode()) for name,body in bodies.items()},BASELINE_FUNCTION_HASHES,
              'Old SPI body bytes differ from reviewed public baseline')
    for name,body in bodies.items():require(generated.count(body)==1,'SPI adapter omitted/duplicated actual body: '+name)
    return generated,bodies


def validate_records(rows):
    validate_contract();require(type(rows) is list and len(rows)==len(CASES),'SPI cases missing/extra')
    for row,(name,options) in zip(rows,CASES):
        require(type(row) is dict and set(row)=={'case','inputs','observed'} and row['case']==name,
                'SPI record order/schema differs')
        exact(row['inputs'],options,'SPI input differs: '+name)
        exact(row['observed'],EXPECTED[name],'SPI result/length/progress differs: '+name)


def check(trunk,compiler,output,preflight=False,image=None,kernel_binary=None):
    validate_contract();config=(trunk/'.config').read_text()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$',config,re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$',config,re.M),'SPI gate requires configured K2P4.4')
    require(preflight or image is not None,'Final SPI gate requires actual firmware image')
    qemu=shutil.which('qemu-mipsel');require(qemu is not None,'qemu-mipsel required')
    inputs=read_source_inputs(trunk);rows=[];probes={};exports={};function_hashes={}
    with tempfile.TemporaryDirectory(prefix='k2p-spi-source-',dir='/tmp') as temporary:
        base=Path(temporary).resolve()
        flags=['-std=gnu99','-Os','-static','-s','-Wall','-Wextra','-Werror','-Wno-unused-function',
               '-Wno-unused-parameter','-Wno-sign-compare','-Wno-pointer-sign']
        for baseline in (False,True):
            profile='baseline' if baseline else 'current';fixture=base/(profile+'-fixture')
            source,bodies=generate_source(inputs,fixture,os.geteuid(),baseline)
            c=base/(profile+'.c');binary=base/profile;c.write_text(source)
            run=subprocess.run([str(compiler),*flags,str(c),'-o',str(binary)],capture_output=True,text=True,timeout=90)
            require(run.returncode==0,'SPI MIPS source compile failed: '+run.stdout+run.stderr)
            data=binary.read_bytes();elf=resident.validate_static_helper(data)
            for name,options in CASES:
                if options['baseline'] is not baseline:continue
                if fixture.exists():shutil.rmtree(fixture)
                fixture.mkdir(mode=0o700)
                run=subprocess.run([qemu,str(binary),options['selector']],capture_output=True,text=True,timeout=20)
                require(run.returncode==0 and not run.stderr,'SPI fixture failed '+name+': '+run.stdout+run.stderr)
                observed=json.loads(run.stdout);rows.append({'case':name,'inputs':options,'observed':observed})
            name='target-spi-nor'+('-baseline' if baseline else '')
            exports[name+'.c']=source.encode();exports[name]=data
            function_hashes[profile]={name:sha(body.encode()) for name,body in bodies.items()}
            probes[profile]={'source_file':name+'.c','source_sha256':sha(source.encode()),'binary_file':name,
                             'binary_sha256':sha(data),'ELF':elf,'compile_flags':flags,
                             'fixture_root':str(fixture),'owner_uid':os.geteuid()}
    validate_records(rows);output.parent.mkdir(parents=True,exist_ok=True)
    for name,data in exports.items():
        path=output.parent/name;path.write_bytes(data)
        if not name.endswith('.c'):path.chmod(0o755)
    binding=kernel_binding(trunk,compiler,image,kernel_binary or image.parent/'zImage',output) if image else None
    report={'schema_version':1,'status':'PASS','profile':'k2p-4.4','phase':'early-source-only' if preflight else 'final-kernel-image-bound',
            'execution_role':ROLE,'required_cases':[name for name,_ in CASES],'checks':rows,
            'source_files':SOURCE_PATHS,'source_sha256':{key:sha(text.encode()) for key,text in inputs.items()},
            'actual_functions_sha256':function_hashes,'probes':probes,
            'kernel_binding':binding,'compiler':str(compiler),'limits':list(LIMITS)}
    output.write_text(json.dumps(report,indent=2)+'\n');print('SPI NOR: '+str(len(rows))+' inert MIPS cases PASS')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('trunk','compiler','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--preflight',action='store_true');parser.add_argument('--image',type=Path)
    parser.add_argument('--kernel-binary',type=Path)
    args=parser.parse_args()
    try:check(args.trunk.resolve(),args.compiler.resolve(),args.output,args.preflight,
              args.image.resolve() if args.image else None,args.kernel_binary.resolve() if args.kernel_binary else None)
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        parser.exit(1,'SPI target validation failed: '+str(error)+'\n')
