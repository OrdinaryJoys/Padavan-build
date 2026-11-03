#!/usr/bin/env python3
"""MIPS NVRAM MTD controls bound to the actual kernel image.
No router, kernel module, host proc, device or reboot is executed.
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
import sys
import tempfile
import check_target_resident_upgrade as resident
import check_target_spi_nor as spi

SOURCE_PATHS = {'nvram_mtd': 'trunk/linux-4.4.x/drivers/net/wireless/wifi_utility/mt_wifi_mtd.c',
 'harness': 'tests/nvram_mtd_harness.py'}

HARNESS_SOURCE_PATHS = {'nvram_mtd': 'trunk/linux-4.4.x/drivers/net/wireless/wifi_utility/mt_wifi_mtd.c'}

FUNCTION_SOURCES = {'mt_mtd_erase_complete_wifi': 'nvram_mtd', 'mt_mtd_write_nm_wifi': 'nvram_mtd', 'mt_mtd_read_nm_wifi': 'nvram_mtd'}

BASELINE_COMMIT = '6e91276a33d1bd83d416fc8253feb01f30677743'

BASELINE_FUNCTION_HASHES = {'mt_mtd_write_nm_wifi': '95f7b668e6a6e59f4464723a03cb09f8ac4907dab35151f4446cfcb15bcecf27',
 'mt_mtd_read_nm_wifi': 'cfcd0e8a72c2dc8cef71745afaffcf246c052250f95ef2f453b6cc0633266a13'}

DISABLED_STUBS = {'mt_mtd_write_nm_wifi': 'int mt_mtd_write_nm_wifi(char*n,loff_t o,size_t l,const '
                         'u_char*b){(void)n;(void)o;(void)l;(void)b;return 0;}',
 'mt_mtd_read_nm_wifi': 'int mt_mtd_read_nm_wifi(char*n,loff_t o,size_t '
                        'l,u_char*b){(void)n;(void)o;(void)l;(void)b;return 0;}'}

DISABLED_STUB_SHA256 = '2ddb8c84f7d182bfb3a2f86cfb88bdf2890e50589dd5e69acacb4256dcf066f5'

CASES = (('current:write-ok', {'mode': 'current', 'selector': 'write-ok'}),
 ('current:write-offset', {'mode': 'current', 'selector': 'write-offset'}),
 ('current:write-boundary', {'mode': 'current', 'selector': 'write-boundary'}),
 ('current:write-negative', {'mode': 'current', 'selector': 'write-negative'}),
 ('current:write-past-block', {'mode': 'current', 'selector': 'write-past-block'}),
 ('current:write-overflow', {'mode': 'current', 'selector': 'write-overflow'}),
 ('current:write-too-large', {'mode': 'current', 'selector': 'write-too-large'}),
 ('current:write-zero', {'mode': 'current', 'selector': 'write-zero'}),
 ('current:write-zero-end', {'mode': 'current', 'selector': 'write-zero-end'}),
 ('current:write-null', {'mode': 'current', 'selector': 'write-null'}),
 ('current:write-name-null', {'mode': 'current', 'selector': 'write-name-null'}),
 ('current:write-zero-erase', {'mode': 'current', 'selector': 'write-zero-erase'}),
 ('current:write-small-device', {'mode': 'current', 'selector': 'write-small-device'}),
 ('current:write-lookup-failure', {'mode': 'current', 'selector': 'write-lookup-failure'}),
 ('current:write-allocation-failure', {'mode': 'current', 'selector': 'write-allocation-failure'}),
 ('current:write-read-error', {'mode': 'current', 'selector': 'write-read-error'}),
 ('current:write-short-read', {'mode': 'current', 'selector': 'write-short-read'}),
 ('current:write-erase-error', {'mode': 'current', 'selector': 'write-erase-error'}),
 ('current:write-erase-failed-state', {'mode': 'current', 'selector': 'write-erase-failed-state'}),
 ('current:write-async', {'mode': 'current', 'selector': 'write-async'}),
 ('current:write-async-failed', {'mode': 'current', 'selector': 'write-async-failed'}),
 ('current:write-io-error', {'mode': 'current', 'selector': 'write-io-error'}),
 ('current:write-short-io', {'mode': 'current', 'selector': 'write-short-io'}),
 ('current:read-ok', {'mode': 'current', 'selector': 'read-ok'}),
 ('current:read-offset', {'mode': 'current', 'selector': 'read-offset'}),
 ('current:read-negative', {'mode': 'current', 'selector': 'read-negative'}),
 ('current:read-overflow', {'mode': 'current', 'selector': 'read-overflow'}),
 ('current:read-past-end', {'mode': 'current', 'selector': 'read-past-end'}),
 ('current:read-short', {'mode': 'current', 'selector': 'read-short'}),
 ('current:read-io-error', {'mode': 'current', 'selector': 'read-io-error'}),
 ('current:read-zero-end', {'mode': 'current', 'selector': 'read-zero-end'}),
 ('current:read-lookup-failure', {'mode': 'current', 'selector': 'read-lookup-failure'}),
 ('baseline:write-ok', {'mode': 'baseline', 'selector': 'write-ok'}),
 ('baseline:write-offset', {'mode': 'baseline', 'selector': 'write-offset'}),
 ('baseline:write-short-read', {'mode': 'baseline', 'selector': 'write-short-read'}),
 ('baseline:write-short-io', {'mode': 'baseline', 'selector': 'write-short-io'}),
 ('baseline:write-async', {'mode': 'baseline', 'selector': 'write-async'}),
 ('baseline:write-async-failed', {'mode': 'baseline', 'selector': 'write-async-failed'}),
 ('baseline:read-ok', {'mode': 'baseline', 'selector': 'read-ok'}),
 ('baseline:read-short', {'mode': 'baseline', 'selector': 'read-short'}),
 ('baseline:read-io-error', {'mode': 'baseline', 'selector': 'read-io-error'}),
 ('baseline:read-lookup-failure', {'mode': 'baseline', 'selector': 'read-lookup-failure'}),
 ('disabled:write-ok', {'mode': 'disabled', 'selector': 'write-ok'}),
 ('disabled:write-short-read', {'mode': 'disabled', 'selector': 'write-short-read'}))

EXPECTED = {'current:write-ok': {'case': 'write-ok',
                      'result': 0,
                      'trace': 'get,alloc,read,erase,complete,wait,write,free,put',
                      'gets': 1,
                      'puts': 1,
                      'allocs': 1,
                      'frees': 1,
                      'reads': 1,
                      'erases': 1,
                      'writes': 1,
                      'waits': 1,
                      'premature': 0,
                      'byte0': 160,
                      'byte8': 8,
                      'byte15': 15},
 'current:write-offset': {'case': 'write-offset',
                          'result': 0,
                          'trace': 'get,alloc,read,erase,complete,wait,write,free,put',
                          'gets': 1,
                          'puts': 1,
                          'allocs': 1,
                          'frees': 1,
                          'reads': 1,
                          'erases': 1,
                          'writes': 1,
                          'waits': 1,
                          'premature': 0,
                          'byte0': 0,
                          'byte8': 160,
                          'byte15': 15},
 'current:write-boundary': {'case': 'write-boundary',
                            'result': 0,
                            'trace': 'get,alloc,read,erase,complete,wait,write,free,put',
                            'gets': 1,
                            'puts': 1,
                            'allocs': 1,
                            'frees': 1,
                            'reads': 1,
                            'erases': 1,
                            'writes': 1,
                            'waits': 1,
                            'premature': 0,
                            'byte0': 0,
                            'byte8': 8,
                            'byte15': 163},
 'current:write-negative': {'case': 'write-negative',
                            'result': -22,
                            'trace': 'get,put',
                            'gets': 1,
                            'puts': 1,
                            'allocs': 0,
                            'frees': 0,
                            'reads': 0,
                            'erases': 0,
                            'writes': 0,
                            'waits': 0,
                            'premature': 0,
                            'byte0': 0,
                            'byte8': 8,
                            'byte15': 15},
 'current:write-past-block': {'case': 'write-past-block',
                              'result': -22,
                              'trace': 'get,put',
                              'gets': 1,
                              'puts': 1,
                              'allocs': 0,
                              'frees': 0,
                              'reads': 0,
                              'erases': 0,
                              'writes': 0,
                              'waits': 0,
                              'premature': 0,
                              'byte0': 0,
                              'byte8': 8,
                              'byte15': 15},
 'current:write-overflow': {'case': 'write-overflow',
                            'result': -22,
                            'trace': 'get,put',
                            'gets': 1,
                            'puts': 1,
                            'allocs': 0,
                            'frees': 0,
                            'reads': 0,
                            'erases': 0,
                            'writes': 0,
                            'waits': 0,
                            'premature': 0,
                            'byte0': 0,
                            'byte8': 8,
                            'byte15': 15},
 'current:write-too-large': {'case': 'write-too-large',
                             'result': -7,
                             'trace': 'get,put',
                             'gets': 1,
                             'puts': 1,
                             'allocs': 0,
                             'frees': 0,
                             'reads': 0,
                             'erases': 0,
                             'writes': 0,
                             'waits': 0,
                             'premature': 0,
                             'byte0': 0,
                             'byte8': 8,
                             'byte15': 15},
 'current:write-zero': {'case': 'write-zero',
                        'result': 0,
                        'trace': 'get,put',
                        'gets': 1,
                        'puts': 1,
                        'allocs': 0,
                        'frees': 0,
                        'reads': 0,
                        'erases': 0,
                        'writes': 0,
                        'waits': 0,
                        'premature': 0,
                        'byte0': 0,
                        'byte8': 8,
                        'byte15': 15},
 'current:write-zero-end': {'case': 'write-zero-end',
                            'result': 0,
                            'trace': 'get,put',
                            'gets': 1,
                            'puts': 1,
                            'allocs': 0,
                            'frees': 0,
                            'reads': 0,
                            'erases': 0,
                            'writes': 0,
                            'waits': 0,
                            'premature': 0,
                            'byte0': 0,
                            'byte8': 8,
                            'byte15': 15},
 'current:write-null': {'case': 'write-null',
                        'result': -22,
                        'trace': '',
                        'gets': 0,
                        'puts': 0,
                        'allocs': 0,
                        'frees': 0,
                        'reads': 0,
                        'erases': 0,
                        'writes': 0,
                        'waits': 0,
                        'premature': 0,
                        'byte0': 0,
                        'byte8': 8,
                        'byte15': 15},
 'current:write-name-null': {'case': 'write-name-null',
                             'result': -22,
                             'trace': '',
                             'gets': 0,
                             'puts': 0,
                             'allocs': 0,
                             'frees': 0,
                             'reads': 0,
                             'erases': 0,
                             'writes': 0,
                             'waits': 0,
                             'premature': 0,
                             'byte0': 0,
                             'byte8': 8,
                             'byte15': 15},
 'current:write-zero-erase': {'case': 'write-zero-erase',
                              'result': -7,
                              'trace': 'get,put',
                              'gets': 1,
                              'puts': 1,
                              'allocs': 0,
                              'frees': 0,
                              'reads': 0,
                              'erases': 0,
                              'writes': 0,
                              'waits': 0,
                              'premature': 0,
                              'byte0': 0,
                              'byte8': 8,
                              'byte15': 15},
 'current:write-small-device': {'case': 'write-small-device',
                                'result': -22,
                                'trace': 'get,put',
                                'gets': 1,
                                'puts': 1,
                                'allocs': 0,
                                'frees': 0,
                                'reads': 0,
                                'erases': 0,
                                'writes': 0,
                                'waits': 0,
                                'premature': 0,
                                'byte0': 0,
                                'byte8': 8,
                                'byte15': 15},
 'current:write-lookup-failure': {'case': 'write-lookup-failure',
                                  'result': -19,
                                  'trace': 'get',
                                  'gets': 1,
                                  'puts': 0,
                                  'allocs': 0,
                                  'frees': 0,
                                  'reads': 0,
                                  'erases': 0,
                                  'writes': 0,
                                  'waits': 0,
                                  'premature': 0,
                                  'byte0': 0,
                                  'byte8': 8,
                                  'byte15': 15},
 'current:write-allocation-failure': {'case': 'write-allocation-failure',
                                      'result': -12,
                                      'trace': 'get,alloc,put',
                                      'gets': 1,
                                      'puts': 1,
                                      'allocs': 1,
                                      'frees': 0,
                                      'reads': 0,
                                      'erases': 0,
                                      'writes': 0,
                                      'waits': 0,
                                      'premature': 0,
                                      'byte0': 0,
                                      'byte8': 8,
                                      'byte15': 15},
 'current:write-read-error': {'case': 'write-read-error',
                              'result': -74,
                              'trace': 'get,alloc,read,free,put',
                              'gets': 1,
                              'puts': 1,
                              'allocs': 1,
                              'frees': 1,
                              'reads': 1,
                              'erases': 0,
                              'writes': 0,
                              'waits': 0,
                              'premature': 0,
                              'byte0': 0,
                              'byte8': 8,
                              'byte15': 15},
 'current:write-short-read': {'case': 'write-short-read',
                              'result': -5,
                              'trace': 'get,alloc,read,free,put',
                              'gets': 1,
                              'puts': 1,
                              'allocs': 1,
                              'frees': 1,
                              'reads': 1,
                              'erases': 0,
                              'writes': 0,
                              'waits': 0,
                              'premature': 0,
                              'byte0': 0,
                              'byte8': 8,
                              'byte15': 15},
 'current:write-erase-error': {'case': 'write-erase-error',
                               'result': -5,
                               'trace': 'get,alloc,read,erase,free,put',
                               'gets': 1,
                               'puts': 1,
                               'allocs': 1,
                               'frees': 1,
                               'reads': 1,
                               'erases': 1,
                               'writes': 0,
                               'waits': 0,
                               'premature': 0,
                               'byte0': 0,
                               'byte8': 8,
                               'byte15': 15},
 'current:write-erase-failed-state': {'case': 'write-erase-failed-state',
                                      'result': -5,
                                      'trace': 'get,alloc,read,erase,complete,wait,free,put',
                                      'gets': 1,
                                      'puts': 1,
                                      'allocs': 1,
                                      'frees': 1,
                                      'reads': 1,
                                      'erases': 1,
                                      'writes': 0,
                                      'waits': 1,
                                      'premature': 0,
                                      'byte0': 0,
                                      'byte8': 8,
                                      'byte15': 15},
 'current:write-async': {'case': 'write-async',
                         'result': 0,
                         'trace': 'get,alloc,read,erase,wait,complete,write,free,put',
                         'gets': 1,
                         'puts': 1,
                         'allocs': 1,
                         'frees': 1,
                         'reads': 1,
                         'erases': 1,
                         'writes': 1,
                         'waits': 1,
                         'premature': 0,
                         'byte0': 160,
                         'byte8': 8,
                         'byte15': 15},
 'current:write-async-failed': {'case': 'write-async-failed',
                                'result': -5,
                                'trace': 'get,alloc,read,erase,wait,complete,free,put',
                                'gets': 1,
                                'puts': 1,
                                'allocs': 1,
                                'frees': 1,
                                'reads': 1,
                                'erases': 1,
                                'writes': 0,
                                'waits': 1,
                                'premature': 0,
                                'byte0': 0,
                                'byte8': 8,
                                'byte15': 15},
 'current:write-io-error': {'case': 'write-io-error',
                            'result': -30,
                            'trace': 'get,alloc,read,erase,complete,wait,write,free,put',
                            'gets': 1,
                            'puts': 1,
                            'allocs': 1,
                            'frees': 1,
                            'reads': 1,
                            'erases': 1,
                            'writes': 1,
                            'waits': 1,
                            'premature': 0,
                            'byte0': 255,
                            'byte8': 255,
                            'byte15': 255},
 'current:write-short-io': {'case': 'write-short-io',
                            'result': -5,
                            'trace': 'get,alloc,read,erase,complete,wait,write,free,put',
                            'gets': 1,
                            'puts': 1,
                            'allocs': 1,
                            'frees': 1,
                            'reads': 1,
                            'erases': 1,
                            'writes': 1,
                            'waits': 1,
                            'premature': 0,
                            'byte0': 160,
                            'byte8': 8,
                            'byte15': 255},
 'current:read-ok': {'case': 'read-ok',
                     'result': 0,
                     'trace': 'get,read,put',
                     'gets': 1,
                     'puts': 1,
                     'allocs': 0,
                     'frees': 0,
                     'reads': 1,
                     'erases': 0,
                     'writes': 0,
                     'waits': 0,
                     'premature': 0,
                     'byte0': 0,
                     'byte8': 8,
                     'byte15': 15},
 'current:read-offset': {'case': 'read-offset',
                         'result': 0,
                         'trace': 'get,read,put',
                         'gets': 1,
                         'puts': 1,
                         'allocs': 0,
                         'frees': 0,
                         'reads': 1,
                         'erases': 0,
                         'writes': 0,
                         'waits': 0,
                         'premature': 0,
                         'byte0': 0,
                         'byte8': 8,
                         'byte15': 15},
 'current:read-negative': {'case': 'read-negative',
                           'result': -22,
                           'trace': 'get,put',
                           'gets': 1,
                           'puts': 1,
                           'allocs': 0,
                           'frees': 0,
                           'reads': 0,
                           'erases': 0,
                           'writes': 0,
                           'waits': 0,
                           'premature': 0,
                           'byte0': 0,
                           'byte8': 8,
                           'byte15': 15},
 'current:read-overflow': {'case': 'read-overflow',
                           'result': -22,
                           'trace': 'get,put',
                           'gets': 1,
                           'puts': 1,
                           'allocs': 0,
                           'frees': 0,
                           'reads': 0,
                           'erases': 0,
                           'writes': 0,
                           'waits': 0,
                           'premature': 0,
                           'byte0': 0,
                           'byte8': 8,
                           'byte15': 15},
 'current:read-past-end': {'case': 'read-past-end',
                           'result': -22,
                           'trace': 'get,put',
                           'gets': 1,
                           'puts': 1,
                           'allocs': 0,
                           'frees': 0,
                           'reads': 0,
                           'erases': 0,
                           'writes': 0,
                           'waits': 0,
                           'premature': 0,
                           'byte0': 0,
                           'byte8': 8,
                           'byte15': 15},
 'current:read-short': {'case': 'read-short',
                        'result': -5,
                        'trace': 'get,read,put',
                        'gets': 1,
                        'puts': 1,
                        'allocs': 0,
                        'frees': 0,
                        'reads': 1,
                        'erases': 0,
                        'writes': 0,
                        'waits': 0,
                        'premature': 0,
                        'byte0': 0,
                        'byte8': 8,
                        'byte15': 15},
 'current:read-io-error': {'case': 'read-io-error',
                           'result': -74,
                           'trace': 'get,read,put',
                           'gets': 1,
                           'puts': 1,
                           'allocs': 0,
                           'frees': 0,
                           'reads': 1,
                           'erases': 0,
                           'writes': 0,
                           'waits': 0,
                           'premature': 0,
                           'byte0': 0,
                           'byte8': 8,
                           'byte15': 15},
 'current:read-zero-end': {'case': 'read-zero-end',
                           'result': 0,
                           'trace': 'get,put',
                           'gets': 1,
                           'puts': 1,
                           'allocs': 0,
                           'frees': 0,
                           'reads': 0,
                           'erases': 0,
                           'writes': 0,
                           'waits': 0,
                           'premature': 0,
                           'byte0': 0,
                           'byte8': 8,
                           'byte15': 15},
 'current:read-lookup-failure': {'case': 'read-lookup-failure',
                                 'result': -19,
                                 'trace': 'get',
                                 'gets': 1,
                                 'puts': 0,
                                 'allocs': 0,
                                 'frees': 0,
                                 'reads': 0,
                                 'erases': 0,
                                 'writes': 0,
                                 'waits': 0,
                                 'premature': 0,
                                 'byte0': 0,
                                 'byte8': 8,
                                 'byte15': 15},
 'baseline:write-ok': {'case': 'write-ok',
                       'result': 0,
                       'trace': 'get,alloc,read,erase,write,put,free',
                       'gets': 1,
                       'puts': 1,
                       'allocs': 1,
                       'frees': 1,
                       'reads': 1,
                       'erases': 1,
                       'writes': 1,
                       'waits': 0,
                       'premature': 0,
                       'byte0': 160,
                       'byte8': 8,
                       'byte15': 15},
 'baseline:write-offset': {'case': 'write-offset',
                           'result': 0,
                           'trace': 'get,alloc,read,erase,write,put,free',
                           'gets': 1,
                           'puts': 1,
                           'allocs': 1,
                           'frees': 1,
                           'reads': 1,
                           'erases': 1,
                           'writes': 1,
                           'waits': 0,
                           'premature': 0,
                           'byte0': 0,
                           'byte8': 160,
                           'byte15': 15},
 'baseline:write-short-read': {'case': 'write-short-read',
                               'result': 0,
                               'trace': 'get,alloc,read,erase,write,put,free',
                               'gets': 1,
                               'puts': 1,
                               'allocs': 1,
                               'frees': 1,
                               'reads': 1,
                               'erases': 1,
                               'writes': 1,
                               'waits': 0,
                               'premature': 0,
                               'byte0': 160,
                               'byte8': 8,
                               'byte15': 204},
 'baseline:write-short-io': {'case': 'write-short-io',
                             'result': 0,
                             'trace': 'get,alloc,read,erase,write,put,free',
                             'gets': 1,
                             'puts': 1,
                             'allocs': 1,
                             'frees': 1,
                             'reads': 1,
                             'erases': 1,
                             'writes': 1,
                             'waits': 0,
                             'premature': 0,
                             'byte0': 160,
                             'byte8': 8,
                             'byte15': 255},
 'baseline:write-async': {'case': 'write-async',
                          'result': 0,
                          'trace': 'get,alloc,read,erase,write,put,free',
                          'gets': 1,
                          'puts': 1,
                          'allocs': 1,
                          'frees': 1,
                          'reads': 1,
                          'erases': 1,
                          'writes': 1,
                          'waits': 0,
                          'premature': 1,
                          'byte0': 160,
                          'byte8': 8,
                          'byte15': 15},
 'baseline:write-async-failed': {'case': 'write-async-failed',
                                 'result': 0,
                                 'trace': 'get,alloc,read,erase,write,put,free',
                                 'gets': 1,
                                 'puts': 1,
                                 'allocs': 1,
                                 'frees': 1,
                                 'reads': 1,
                                 'erases': 1,
                                 'writes': 1,
                                 'waits': 0,
                                 'premature': 1,
                                 'byte0': 160,
                                 'byte8': 8,
                                 'byte15': 15},
 'baseline:read-ok': {'case': 'read-ok',
                      'result': 0,
                      'trace': 'get,read,put',
                      'gets': 1,
                      'puts': 1,
                      'allocs': 0,
                      'frees': 0,
                      'reads': 1,
                      'erases': 0,
                      'writes': 0,
                      'waits': 0,
                      'premature': 0,
                      'byte0': 0,
                      'byte8': 8,
                      'byte15': 15},
 'baseline:read-short': {'case': 'read-short',
                         'result': 0,
                         'trace': 'get,read,put',
                         'gets': 1,
                         'puts': 1,
                         'allocs': 0,
                         'frees': 0,
                         'reads': 1,
                         'erases': 0,
                         'writes': 0,
                         'waits': 0,
                         'premature': 0,
                         'byte0': 0,
                         'byte8': 8,
                         'byte15': 15},
 'baseline:read-io-error': {'case': 'read-io-error',
                            'result': -74,
                            'trace': 'get,read,put',
                            'gets': 1,
                            'puts': 1,
                            'allocs': 0,
                            'frees': 0,
                            'reads': 1,
                            'erases': 0,
                            'writes': 0,
                            'waits': 0,
                            'premature': 0,
                            'byte0': 0,
                            'byte8': 8,
                            'byte15': 15},
 'baseline:read-lookup-failure': {'case': 'read-lookup-failure',
                                  'result': -1,
                                  'trace': 'get',
                                  'gets': 1,
                                  'puts': 0,
                                  'allocs': 0,
                                  'frees': 0,
                                  'reads': 0,
                                  'erases': 0,
                                  'writes': 0,
                                  'waits': 0,
                                  'premature': 0,
                                  'byte0': 0,
                                  'byte8': 8,
                                  'byte15': 15},
 'disabled:write-ok': {'case': 'write-ok',
                       'result': 0,
                       'trace': '',
                       'gets': 0,
                       'puts': 0,
                       'allocs': 0,
                       'frees': 0,
                       'reads': 0,
                       'erases': 0,
                       'writes': 0,
                       'waits': 0,
                       'premature': 0,
                       'byte0': 0,
                       'byte8': 8,
                       'byte15': 15},
 'disabled:write-short-read': {'case': 'write-short-read',
                               'result': 0,
                               'trace': '',
                               'gets': 0,
                               'puts': 0,
                               'allocs': 0,
                               'frees': 0,
                               'reads': 0,
                               'erases': 0,
                               'writes': 0,
                               'waits': 0,
                               'premature': 0,
                               'byte0': 0,
                               'byte8': 8,
                               'byte15': 15}}

ROLE = ('Actual NVRAM/WiFi MTD source compiled as inert static MIPS userspace; current, fixed baseline and execution-disabled '
 'controls.')

LIMITS = ('Current three and fixed old two actual NVRAM/WiFi MTD functions execute over inert RAM MTD, allocation and '
 'completion callbacks; disabled controls execute only pinned stubs.',
 'Short reads/writes, invalid ranges and asynchronous erase completion are modeled, not actual flash timing or '
 'electrical success.',
 'If a kernel erase callback never arrives, the checked lifetime may still block; no stack-abandoning completion '
 'timeout or end-to-end deadline is claimed.',
 'The old out-of-block ASan heap-overrun control is separate and excluded from all44 target passing cases.',
 'No router connection, device, host proc, private backup, flash write or reboot occurs in this probe.',
 'The late kernel object and whole-image reference binds the actual implementation; it does not execute a complete '
 'router kernel or repair the old efd2 first hop.')

MAX_SOURCE = 4194304

MAX_REPORT = 16777216

MAX_COMMAND_SECONDS = 20

FLAGS = ('-std=gnu89',
 '-Os',
 '-static',
 '-s',
 '-Wall',
 '-Wextra',
 '-Werror',
 '-Wno-unused-function',
 '-Wno-unused-parameter',
 '-Wno-sign-compare',
 '-Wno-pointer-sign')

KERNEL_SYMBOLS = {'wifi-mtd': ('mt_mtd_read_nm_wifi', 'mt_mtd_write_nm_wifi')}

SPI_SOURCE_KEYS = {'nvram_mtd': 'nvram_mtd'}

def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact(left, right, message):
    require(json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True), message)


def validate_contract():
    require(SOURCE_PATHS and HARNESS_SOURCE_PATHS and FUNCTION_SOURCES and BASELINE_FUNCTION_HASHES and CASES and EXPECTED,'NVRAM MTD contract not frozen')
    require(len(CASES)==44 and len({n for n,_ in CASES})==44 and set(EXPECTED)=={n for n,_ in CASES},'NVRAM MTD case contract differs')



def actual_function(inputs, key, name):
    text = inputs[key]
    if key == 'pm_header' and name == 'pm_runtime_put_noidle':
        text = text[text.index('#ifdef CONFIG_PM'):text.index('#else')]
    if key == 'core' and name == '__spi_unmap_msg':
        text = text[text.index('#ifdef CONFIG_HAS_DMA'):text.index('#else /* !CONFIG_HAS_DMA */')]
    return resident.function(text, name)


def generate_source(inputs,fixture_root,owner_uid,mode='current'):
    validate_contract();require(set(inputs)==set(SOURCE_PATHS),'NVRAM MTD source mapping changed')
    require(mode in ('current','baseline','disabled') and type(owner_uid) is int and 0<=owner_uid<2**32,'Typed NVRAM MTD fixture/profile required')
    module=resident.checked_module(inputs['harness'],'nvram-mtd')
    exact(module.SOURCE_PATHS,HARNESS_SOURCE_PATHS,'NVRAM MTD harness paths differ')
    exact(module.BASELINE_COMMIT,BASELINE_COMMIT,'NVRAM MTD baseline differs')
    exact(module.BASELINE_FUNCTIONS_SHA256,BASELINE_FUNCTION_HASHES,'NVRAM MTD old body hashes differ')
    for profile,selectors in (('current',module.CASE_NAMES),('baseline',module.BASELINE_CASES),('disabled',module.DISABLED_CASES)):
        exact(selectors,tuple(options['selector']for name,options in CASES if options['mode']==profile),'NVRAM MTD case set differs')
    texts={key:inputs[key]for key in HARNESS_SOURCE_PATHS}
    generated=module.generate_source(texts,str(fixture_root),owner_uid=owner_uid,baseline=mode=='baseline',disabled_oracle=mode=='disabled')
    require(type(generated) is str and 0<len(generated.encode())<=MAX_SOURCE,'Invalid NVRAM MTD adapter')
    bodies=module.BASELINE_FUNCTIONS if mode=='baseline' else {} if mode=='disabled' else {name:actual_function(inputs,key,name)for name,key in FUNCTION_SOURCES.items()}
    if mode=='baseline':exact({name:sha(body.encode())for name,body in bodies.items()},BASELINE_FUNCTION_HASHES,'NVRAM MTD baseline bytes differ')
    for name,body in bodies.items():require(generated.count(body)==1,'Actual NVRAM MTD body omitted/duplicated: '+name)
    if mode=='disabled':
        require(sha('\n'.join(DISABLED_STUBS.values()).encode())==DISABLED_STUB_SHA256,'Disabled NVRAM stub hash differs')
        for name,body in DISABLED_STUBS.items():require(generated.count(body)==1,'Disabled NVRAM stub omitted/duplicated: '+name)
        for name,key in FUNCTION_SOURCES.items():require(generated.count(actual_function(inputs,key,name))==0,'Disabled control unexpectedly includes actual backend')
    return generated,bodies


def validate_records(rows):
    validate_contract()
    require(type(rows) is list and len(rows) == len(CASES), 'NVRAM MTD cases missing/extra')
    for row, (name, inputs) in zip(rows, CASES):
        require(type(row) is dict and set(row) == {'case', 'inputs', 'observed'} and
                row['case'] == name, 'NVRAM MTD record order/schema differs')
        exact(row['inputs'], inputs, 'NVRAM MTD inputs differ: ' + name)
        exact(row['observed'], EXPECTED[name], 'NVRAM MTD outcome/completion/PM/FIFO differs: ' + name)


def read_regular(path, limit):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError('NVRAM MTD artifact cannot be opened without following aliases') from error
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit,
                'NVRAM MTD artifact must be a bounded regular file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(descriptor)
    require(len(data) == info.st_size, 'NVRAM MTD artifact changed or exceeds budget')
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
            'NVRAM MTD final proof requires the completed SPI kernel/image gate')
    exact(report.get('required_cases'), [name for name, _ in spi.CASES], 'SPI case set differs')
    spi.validate_records(report.get('checks'))
    for key, spi_key in SPI_SOURCE_KEYS.items():
        require(report.get('source_sha256', {}).get(spi_key) == sha(inputs[key].encode()),
                'NVRAM MTD and SPI source identities differ: ' + key)
    binding = report.get('kernel_binding')
    require(type(binding) is dict and binding.get('whole_byte_equality') is True,
            'NVRAM MTD requires exact whole kernel/image binding')
    expected_exports = {'target-spi-kernel-vmlinux.elf', 'target-spi-kernel-raw.bin',
                        'target-spi-kernel-vendor.bin', 'target-spi-vmlinux.cmd'}
    for label in spi.OBJECTS:
        expected_exports.update(('target-spi-' + label + '.o', 'target-spi-' + label + '.cmd'))
    exports = binding.get('exports')
    require(type(exports) is dict and set(exports) == expected_exports,
            'NVRAM MTD SPI kernel sidecar set differs')
    for name, value in exports.items():
        require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
                'Malformed SPI sidecar SHA256')
        require(sha(read_regular(report_path.parent / name, spi.MAX_ELF)) == value,
                'NVRAM MTD referenced SPI sidecar bytes differ: ' + name)
    linked = spi.inspect_elf(read_regular(report_path.parent / 'target-spi-kernel-vmlinux.elf', spi.MAX_ELF), 2)
    exact(linked, binding.get('vmlinux'), 'NVRAM MTD linked kernel metadata differs from sidecar')
    selected = binding.get('selected_objects')
    require(type(selected) is dict and set(selected) == set(spi.OBJECTS), 'SPI selected objects differ')
    symbols = {}
    for label, names in KERNEL_SYMBOLS.items():
        row = selected[label]
        object_name = 'target-spi-' + label + '.o'
        require(row.get('object_file') == object_name, 'NVRAM MTD selected object filename differs')
        obj = spi.inspect_elf(read_regular(report_path.parent / object_name, spi.MAX_ELF), 1)
        exact(obj, row.get('ELF'), 'NVRAM MTD selected object metadata differs from sidecar')
        command_name = 'target-spi-' + label + '.cmd'
        command = read_regular(report_path.parent / command_name, 2 * 1024 * 1024)
        require(row.get('command_file') == command_name and
                row.get('command_sha256') == sha(command) and
                Path(spi.OBJECTS[label][0]).with_suffix('.c').name.encode() in command,
                'NVRAM MTD selected object command/source binding differs')
        for name in names:
            require(len(obj['function_symbols'].get(name, [])) == 1 and
                    len(linked['function_symbols'].get(name, [])) == 1 and
                    obj['function_symbols'][name][0]['bytes'] > 0 and
                    linked['function_symbols'][name][0]['bytes'] > 0,
                    'NVRAM MTD actual implementation symbol absent: ' + name)
            require(name in row.get('required_symbols', []), 'SPI proof does not require NVRAM MTD caller: ' + name)
            symbols[name] = {'object': label, 'object_symbol': obj['function_symbols'][name][0],
                             'linked_symbol': linked['function_symbols'][name][0]}
    return {'role': 'Reference to separately mandatory exact whole-kernel SPI proof',
            'report_file': report_path.name, 'report_sha256': sha(raw),
            'image_sha256': binding['image']['image_sha256'],
            'vmlinux_sha256': linked['sha256'], 'required_symbols': symbols,
            'source_sha256': {SPI_SOURCE_KEYS[key]: sha(inputs[key].encode()) for key in SPI_SOURCE_KEYS},
            'kernel_exports_sha256': exports, 'whole_kernel_image_equality': True,
            'object_to_link_scope': binding['object_to_link_scope']}


def check(trunk, compiler, output, preflight=False, spi_report=None):
    validate_contract()
    require(type(preflight) is bool, 'NVRAM MTD preflight selection must be boolean')
    require((preflight and spi_report is None) or (not preflight and spi_report is not None),
            'NVRAM MTD requires preflight alone or a final SPI report')
    config = (trunk / '.config').read_text()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M),
            'NVRAM MTD gate requires configured K2P4.4')
    qemu = shutil.which('qemu-mipsel')
    require(qemu is not None, 'qemu-mipsel required')
    inputs = {key: (trunk.parent / relative).read_text() for key, relative in SOURCE_PATHS.items()}
    rows, probes, exports, function_hashes = [], {}, {}, {}
    with tempfile.TemporaryDirectory(prefix='k2p-nvram-mtd-source-', dir='/tmp') as temporary:
        base = Path(temporary).resolve()
        for profile in ('current','baseline','disabled'):
            fixture = base / (profile + '-fixture')
            generated, bodies = generate_source(inputs, fixture, os.geteuid(), profile)
            source, binary = base / (profile + '.c'), base / profile
            source.write_text(generated)
            run = subprocess.run([str(compiler), *FLAGS, str(source), '-o', str(binary)],
                                 capture_output=True, text=True, timeout=90)
            require(run.returncode == 0, 'NVRAM MTD MIPS source compile failed: ' + run.stdout + run.stderr)
            data = binary.read_bytes()
            elf = resident.validate_static_helper(data)
            for name, options in CASES:
                if options['mode'] != profile:
                    continue
                run = subprocess.run([qemu, str(binary), options['selector']],
                                     capture_output=True, text=True, timeout=MAX_COMMAND_SECONDS)
                require(run.returncode == 0 and not run.stderr,
                        'NVRAM MTD fixture failed ' + name + ': ' + run.stdout + run.stderr)
                rows.append({'case': name, 'inputs': options, 'observed': json.loads(run.stdout)})
            name = 'target-nvram-mtd' + ('' if profile=='current' else '-'+profile)
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
              'disabled_stub_sha256': DISABLED_STUB_SHA256,
              'actual_functions_sha256': function_hashes, 'probes': probes,
              'kernel_reference': reference, 'compiler': str(compiler), 'limits': list(LIMITS)}
    output.write_text(json.dumps(report, indent=2) + '\n')
    print('NVRAM MTD: ' + str(len(rows)) + ' inert actual-source MIPS cases PASS')
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
        parser.exit(1, 'NVRAM MTD target validation failed: ' + str(error) + '\n')
