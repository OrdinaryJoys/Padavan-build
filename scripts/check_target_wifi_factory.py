#!/usr/bin/env python3
"""Configured MT7615 Factory/startup MIPS and exact shipped-module controls; no device IO."""
import argparse,ast,hashlib,json,os,re,shutil,stat,struct,subprocess,tempfile
from pathlib import Path
import check_target_resident_upgrade as resident
import check_target_spi_nor as spi

SOURCE_PATHS = {'wifi_flash': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/ee_flash.c', 'wifi_eeprom': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/eeprom.c', 'wifi_init': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.c', 'wifi_hw': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.c', 'wifi_ate': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/ate/mt_mac/mt_ate.c', 'wifi_testmode': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/ate/mt_mac/mt_testmode.c', 'harness': 'tests/wifi_factory_harness.py', 'nvram_mtd': 'trunk/linux-4.4.x/drivers/net/wireless/wifi_utility/mt_wifi_mtd.c', 'wifi_makefile': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615_ap/Makefile', 'wifi_config': 'trunk/configs/boards/K2P/kernel-4.4.x.config'}
HARNESS_SOURCE_PATHS = {'wifi_flash': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/ee_flash.c', 'wifi_eeprom': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/eeprom.c', 'wifi_init': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.c', 'wifi_hw': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.c', 'wifi_ate': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/ate/mt_mac/mt_ate.c', 'wifi_testmode': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/ate/mt_mac/mt_testmode.c'}
OBJECTS = {'ee-flash': ('drivers/net/wireless/mediatek/mt7615/embedded/common/ee_flash.o', 'wifi_flash', 'rtmp_nv_init'), 'eeprom': ('drivers/net/wireless/mediatek/mt7615/embedded/common/eeprom.o', 'wifi_eeprom', 'NICReadEEPROMParameters'), 'rtmp-init': ('drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.o', 'wifi_init', 'WfEPROMSysInit'), 'hw-init': ('drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.o', 'wifi_hw', 'WfEPROMInit'), 'testmode': ('drivers/net/wireless/mediatek/mt7615/ate/mt_mac/mt_testmode.o', 'wifi_testmode', 'pci_ate_leave')}
SHIPPED_MODULE = 'lib/modules/4.4.198/kernel/drivers/net/wireless/mediatek/mt7615_ap/mt_7615e.ko'
BUILT_MODULE = 'drivers/net/wireless/mediatek/mt7615_ap/mt_7615e.ko'
SPI_SOURCE_KEYS = {'nvram_mtd':'nvram_mtd'}
KERNEL_SYMBOLS = {'wifi-mtd':('mt_mtd_read_nm_wifi','mt_mtd_write_nm_wifi')}
BASELINE_COMMIT = '6e91276a33d1bd83d416fc8253feb01f30677743'
FLAGS = ('-std=gnu89','-O2','-static','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter')
ROLE = 'Actual configured MT7615 startup and default-loader functions in inert static MIPS userspace; three explicitly delimited consumer sections; no physical Factory or radio access.'
LIMITS = (
 'Whole functions and exact early sections have separate manifests; later NIC parsing and ATE teardown are not executed by this adapter.',
 'RAM allocation, file IO, Factory backend and radio operations are inert recording seams; native and MIPS helper results do not prove hardware timing or physical flash integrity.',
 'The complete configured object files and module commands are byte-bound to the locked source build. Source-to-machine-code compilation and object-to-module relocation remain clean full-build attestations.',
 'Built-to-shipped module comparison requires unchanged allocated section bytes and semantic runtime relocations across stripping. It does not mask code/data differences or relax exact shipped-image byte identity.',
 'The alternate mt_ate.c consumer is source/section-tested but is not a configured object; mt_testmode.o is the selected ATE implementation.',
 'This gate never executes a kernel module, contacts a router, changes Factory contents, flashes firmware or reboots a device.')
MAX_SOURCE=4*1024*1024
MAX_REPORT=16*1024*1024
MAX_ELF=32*1024*1024
MAX_COMMAND_SECONDS=20
FUNCTION_SOURCES = {'RtmpFlashRead': 'wifi_flash',
 'RtmpFlashWrite': 'wifi_flash',
 'rtmp_ee_flash_read': 'wifi_flash',
 'validFlashEepromID': 'wifi_flash',
 'rtmp_ee_flash_write_all': 'wifi_flash',
 'rtmp_ee_flash_reset': 'wifi_flash',
 'rtmp_ee_flash_init': 'wifi_flash',
 'rtmp_nv_init': 'wifi_flash',
 'NICReadEEPROMParameters': 'wifi_eeprom',
 'WfEPROMSysInit': 'wifi_init',
 'WfEPROMInit': 'wifi_hw',
 'ate_pci_ate_leave': 'wifi_ate',
 'testmode_pci_ate_leave': 'wifi_testmode'}
BASELINE_FUNCTION_HASHES = {'RtmpFlashRead': 'b96e7a2abf27c7e1514a565f9a403ba400aef554b97e3026dddc5c3c0a8e04ba',
 'RtmpFlashWrite': 'd065c4742e7f51e52a14233a3ceb9f56e78ffdc131a18817737a1e7f194e6565',
 'rtmp_ee_flash_read': 'ec5f0eb4733323b8bbf6a7f940a7abde85e8286c163a4c500cbe2a653e50ab25',
 'validFlashEepromID': 'f5752b55e5ca32e5ec0aea05b532f4451c1a15b6833f28c0c4e084bea1aefabd',
 'rtmp_ee_flash_write_all': '9db48e528f4dd8c76c78cb1bdb7aa1d9c01055139c6e2ae7c633c21c42745792',
 'rtmp_ee_flash_init': '882d236f06220b19b36077449d8f424a7cec1ada4070a5cc7790e886957775f8',
 'rtmp_nv_init': '82a88be3758713dc0857a2340fd4383611988d929f6d72137213a483cc219b8c',
 'NICReadEEPROMParameters': 'fb5a31fd0ab052c9cb7af69e4973df830a5d3a616914e918073fa04dfbf1f020',
 'WfEPROMSysInit': '78ecfb7a56c79b1a90a01fd22c4402854e91c2476756375a5208507b29bb6d97',
 'WfEPROMInit': '95d3ae4458f93a61a7c807115098e5f94ea44289919db30a80b6b430c4993799',
 'ate_pci_ate_leave': 'fed2202de2727e59a770702a40400bf7ac9bed7752749f9559095b099dcf3675',
 'testmode_pci_ate_leave': '184f002656ddb2c452b9f0d5ff956fa83434d0155bc5bed28bace5428dfb369b',
 'rtmp_ee_flash_reset': 'e9b4287e72481a0743d14146380161f4c0061b32db0a75f05307f43e2bfdf3c8'}
BODY_ORDER = ('RtmpFlashRead',
 'RtmpFlashWrite',
 'rtmp_ee_flash_read',
 'validFlashEepromID',
 'rtmp_ee_flash_write_all',
 'rtmp_ee_flash_reset',
 'rtmp_ee_flash_init',
 'rtmp_nv_init',
 'NICReadEEPROMParameters',
 'WfEPROMSysInit',
 'WfEPROMInit',
 'ate_pci_ate_leave',
 'testmode_pci_ate_leave')
PROJECTIONS = {'NICReadEEPROMParameters': {'start': '\tstruct _RTMP_CHIP_OP *ops =',
                             'end': '\n#ifdef PRE_CAL_MT7622_SUPPORT\n\tif',
                             'include_end': False,
                             'prefix': 'INT NICReadEEPROMParameters(RTMP_ADAPTER*pAd,RTMP_STRING*mac_addr){\n'
                                       '(void)mac_addr;\n',
                             'suffix': '\nparse_calls++;event("parse");return TRUE;\n}'},
 'ate_pci_ate_leave': {'start': '\tMTWF_LOG(',
                       'end': '\tNICInitAsicFromEEPROM(pAd);',
                       'include_end': True,
                       'prefix': 'static INT32 ate_pci_ate_leave(RTMP_ADAPTER*pAd){\n',
                       'suffix': '\nreturn NDIS_STATUS_SUCCESS;\n}'},
 'testmode_pci_ate_leave': {'start': '\tMTWF_LOG(',
                            'end': '\tNICInitAsicFromEEPROM(pAd);',
                            'include_end': True,
                            'prefix': 'static INT32 testmode_pci_ate_leave(RTMP_ADAPTER*pAd){\n',
                            'suffix': '\nreturn NDIS_STATUS_SUCCESS;\n}'}}
MODEL_FRAGMENTS_SHA256 = '6ea9e4faad1727241831d90261d4337cf4cb9466b731858b5b6f217b4f62aa22'
CASES = (('current:direct-read-ok', {'profile': 'current', 'selector': 'direct-read-ok'}),
 ('current:direct-read-error', {'profile': 'current', 'selector': 'direct-read-error'}),
 ('current:direct-read-short', {'profile': 'current', 'selector': 'direct-read-short'}),
 ('current:direct-read-erased', {'profile': 'current', 'selector': 'direct-read-erased'}),
 ('current:direct-allocation-failure', {'profile': 'current', 'selector': 'direct-allocation-failure'}),
 ('current:direct-existing-error', {'profile': 'current', 'selector': 'direct-existing-error'}),
 ('current:direct-reset-failure', {'profile': 'current', 'selector': 'direct-reset-failure'}),
 ('current:boot-read-ok', {'profile': 'current', 'selector': 'boot-read-ok'}),
 ('current:boot-read-error', {'profile': 'current', 'selector': 'boot-read-error'}),
 ('current:boot-read-short', {'profile': 'current', 'selector': 'boot-read-short'}),
 ('current:boot-allocation-failure', {'profile': 'current', 'selector': 'boot-allocation-failure'}),
 ('current:boot-read-erased', {'profile': 'current', 'selector': 'boot-read-erased'}),
 ('current:ate-read-ok', {'profile': 'current', 'selector': 'ate-read-ok'}),
 ('current:ate-read-error', {'profile': 'current', 'selector': 'ate-read-error'}),
 ('current:testmode-read-ok', {'profile': 'current', 'selector': 'testmode-read-ok'}),
 ('current:testmode-read-error', {'profile': 'current', 'selector': 'testmode-read-error'}),
 ('current:direct-default-write-error', {'profile': 'current', 'selector': 'direct-default-write-error'}),
 ('current:boot-default-write-error', {'profile': 'current', 'selector': 'boot-default-write-error'}),
 ('current:direct-default-file-ok', {'profile': 'current', 'selector': 'direct-default-file-ok'}),
 ('current:direct-default-file-error', {'profile': 'current', 'selector': 'direct-default-file-error'}),
 ('current:direct-default-short-file-error',
  {'profile': 'current', 'selector': 'direct-default-short-file-error'}),
 ('current:direct-default-close-error', {'profile': 'current', 'selector': 'direct-default-close-error'}),
 ('current:direct-default-missing-error', {'profile': 'current', 'selector': 'direct-default-missing-error'}),
 ('current:direct-default-short-cache-error',
  {'profile': 'current', 'selector': 'direct-default-short-cache-error'}),
 ('current:direct-default-invalid-id-error',
  {'profile': 'current', 'selector': 'direct-default-invalid-id-error'}),
 ('current:direct-default-empty-path-error',
  {'profile': 'current', 'selector': 'direct-default-empty-path-error'}),
 ('current:direct-small-buffer-error', {'profile': 'current', 'selector': 'direct-small-buffer-error'}),
 ('current:direct-default-oversized-read-error',
  {'profile': 'current', 'selector': 'direct-default-oversized-read-error'}),
 ('current:direct-default-long-cache-ok', {'profile': 'current', 'selector': 'direct-default-long-cache-ok'}),
 ('baseline:direct-read-ok', {'profile': 'baseline', 'selector': 'direct-read-ok'}),
 ('baseline:direct-read-error', {'profile': 'baseline', 'selector': 'direct-read-error'}),
 ('baseline:direct-read-short', {'profile': 'baseline', 'selector': 'direct-read-short'}),
 ('baseline:direct-existing-error', {'profile': 'baseline', 'selector': 'direct-existing-error'}),
 ('baseline:boot-read-error', {'profile': 'baseline', 'selector': 'boot-read-error'}),
 ('baseline:boot-allocation-failure', {'profile': 'baseline', 'selector': 'boot-allocation-failure'}),
 ('baseline:ate-read-error', {'profile': 'baseline', 'selector': 'ate-read-error'}),
 ('baseline:testmode-read-error', {'profile': 'baseline', 'selector': 'testmode-read-error'}),
 ('baseline:direct-default-write-error', {'profile': 'baseline', 'selector': 'direct-default-write-error'}),
 ('baseline:boot-default-write-error', {'profile': 'baseline', 'selector': 'boot-default-write-error'}),
 ('baseline:direct-default-file-error', {'profile': 'baseline', 'selector': 'direct-default-file-error'}),
 ('baseline:direct-default-short-file-error',
  {'profile': 'baseline', 'selector': 'direct-default-short-file-error'}),
 ('baseline:direct-default-close-error', {'profile': 'baseline', 'selector': 'direct-default-close-error'}),
 ('baseline:direct-default-missing-error',
  {'profile': 'baseline', 'selector': 'direct-default-missing-error'}),
 ('baseline:direct-default-short-cache-error',
  {'profile': 'baseline', 'selector': 'direct-default-short-cache-error'}),
 ('baseline:direct-default-invalid-id-error',
  {'profile': 'baseline', 'selector': 'direct-default-invalid-id-error'}),
 ('baseline:direct-default-empty-path-error',
  {'profile': 'baseline', 'selector': 'direct-default-empty-path-error'}),
 ('baseline:direct-default-oversized-read-error',
  {'profile': 'baseline', 'selector': 'direct-default-oversized-read-error'}),
 ('disabled:direct-read-ok', {'profile': 'disabled', 'selector': 'direct-read-ok'}),
 ('disabled:direct-read-error', {'profile': 'disabled', 'selector': 'direct-read-error'}))
EXPECTED = {'current:direct-read-ok': {'case': 'direct-read-ok',
                            'status': 0,
                            'reads': 1,
                            'factorywrites': 0,
                            'defaults': 0,
                            'parse': 0,
                            'radio': 0,
                            'asic': 0,
                            'exits': 0,
                            'capinit': 1,
                            'image': 1,
                            'mode': 2,
                            'source': 2,
                            'calibrated': 1,
                            'allocs': 1,
                            'frees': 0,
                            'fsdepth': 0,
                            'fileopens': 0,
                            'filereads': 0,
                            'filecloses': 0,
                            'trace': 'alloc,read'},
 'current:direct-read-error': {'case': 'direct-read-error',
                               'status': 1,
                               'reads': 1,
                               'factorywrites': 0,
                               'defaults': 0,
                               'parse': 0,
                               'radio': 0,
                               'asic': 0,
                               'exits': 0,
                               'capinit': 0,
                               'image': 0,
                               'mode': 0,
                               'source': 0,
                               'calibrated': 0,
                               'allocs': 1,
                               'frees': 1,
                               'fsdepth': 0,
                               'fileopens': 0,
                               'filereads': 0,
                               'filecloses': 0,
                               'trace': 'alloc,read,free'},
 'current:direct-read-short': {'case': 'direct-read-short',
                               'status': 1,
                               'reads': 1,
                               'factorywrites': 0,
                               'defaults': 0,
                               'parse': 0,
                               'radio': 0,
                               'asic': 0,
                               'exits': 0,
                               'capinit': 0,
                               'image': 0,
                               'mode': 0,
                               'source': 0,
                               'calibrated': 0,
                               'allocs': 1,
                               'frees': 1,
                               'fsdepth': 0,
                               'fileopens': 0,
                               'filereads': 0,
                               'filecloses': 0,
                               'trace': 'alloc,read,free'},
 'current:direct-read-erased': {'case': 'direct-read-erased',
                                'status': 0,
                                'reads': 1,
                                'factorywrites': 1,
                                'defaults': 1,
                                'parse': 0,
                                'radio': 0,
                                'asic': 0,
                                'exits': 0,
                                'capinit': 1,
                                'image': 1,
                                'mode': 2,
                                'source': 8,
                                'calibrated': 1,
                                'allocs': 1,
                                'frees': 0,
                                'fsdepth': 0,
                                'fileopens': 1,
                                'filereads': 0,
                                'filecloses': 0,
                                'trace': 'alloc,read,fs-enter,file-open,fs-restore,factory-write'},
 'current:direct-allocation-failure': {'case': 'direct-allocation-failure',
                                       'status': 1,
                                       'reads': 0,
                                       'factorywrites': 0,
                                       'defaults': 0,
                                       'parse': 0,
                                       'radio': 0,
                                       'asic': 0,
                                       'exits': 0,
                                       'capinit': 0,
                                       'image': 0,
                                       'mode': 0,
                                       'source': 0,
                                       'calibrated': 0,
                                       'allocs': 1,
                                       'frees': 0,
                                       'fsdepth': 0,
                                       'fileopens': 0,
                                       'filereads': 0,
                                       'filecloses': 0,
                                       'trace': 'alloc'},
 'current:direct-existing-error': {'case': 'direct-existing-error',
                                   'status': 1,
                                   'reads': 1,
                                   'factorywrites': 0,
                                   'defaults': 0,
                                   'parse': 0,
                                   'radio': 0,
                                   'asic': 0,
                                   'exits': 0,
                                   'capinit': 0,
                                   'image': 0,
                                   'mode': 0,
                                   'source': 0,
                                   'calibrated': 0,
                                   'allocs': 1,
                                   'frees': 2,
                                   'fsdepth': 0,
                                   'fileopens': 0,
                                   'filereads': 0,
                                   'filecloses': 0,
                                   'trace': 'free,alloc,read,free'},
 'current:direct-reset-failure': {'case': 'direct-reset-failure',
                                  'status': 1,
                                  'reads': 1,
                                  'factorywrites': 0,
                                  'defaults': 1,
                                  'parse': 0,
                                  'radio': 0,
                                  'asic': 0,
                                  'exits': 0,
                                  'capinit': 0,
                                  'image': 0,
                                  'mode': 0,
                                  'source': 0,
                                  'calibrated': 0,
                                  'allocs': 1,
                                  'frees': 1,
                                  'fsdepth': 0,
                                  'fileopens': 1,
                                  'filereads': 0,
                                  'filecloses': 0,
                                  'trace': 'alloc,read,fs-enter,file-open,fs-restore,free'},
 'current:boot-read-ok': {'case': 'boot-read-ok',
                          'status': 0,
                          'reads': 1,
                          'factorywrites': 0,
                          'defaults': 0,
                          'parse': 1,
                          'radio': 1,
                          'asic': 1,
                          'exits': 0,
                          'capinit': 1,
                          'image': 1,
                          'mode': 2,
                          'source': 2,
                          'calibrated': 1,
                          'allocs': 1,
                          'frees': 0,
                          'fsdepth': 0,
                          'fileopens': 0,
                          'filereads': 0,
                          'filecloses': 0,
                          'trace': 'hook,alloc,read,antenna-check,parse,radio,hw'},
 'current:boot-read-error': {'case': 'boot-read-error',
                             'status': 1,
                             'reads': 1,
                             'factorywrites': 0,
                             'defaults': 0,
                             'parse': 0,
                             'radio': 0,
                             'asic': 0,
                             'exits': 1,
                             'capinit': 0,
                             'image': 0,
                             'mode': 0,
                             'source': 0,
                             'calibrated': 0,
                             'allocs': 1,
                             'frees': 1,
                             'fsdepth': 0,
                             'fileopens': 0,
                             'filereads': 0,
                             'filecloses': 0,
                             'trace': 'hook,alloc,read,free,exit'},
 'current:boot-read-short': {'case': 'boot-read-short',
                             'status': 1,
                             'reads': 1,
                             'factorywrites': 0,
                             'defaults': 0,
                             'parse': 0,
                             'radio': 0,
                             'asic': 0,
                             'exits': 1,
                             'capinit': 0,
                             'image': 0,
                             'mode': 0,
                             'source': 0,
                             'calibrated': 0,
                             'allocs': 1,
                             'frees': 1,
                             'fsdepth': 0,
                             'fileopens': 0,
                             'filereads': 0,
                             'filecloses': 0,
                             'trace': 'hook,alloc,read,free,exit'},
 'current:boot-allocation-failure': {'case': 'boot-allocation-failure',
                                     'status': 1,
                                     'reads': 0,
                                     'factorywrites': 0,
                                     'defaults': 0,
                                     'parse': 0,
                                     'radio': 0,
                                     'asic': 0,
                                     'exits': 1,
                                     'capinit': 0,
                                     'image': 0,
                                     'mode': 0,
                                     'source': 0,
                                     'calibrated': 0,
                                     'allocs': 1,
                                     'frees': 0,
                                     'fsdepth': 0,
                                     'fileopens': 0,
                                     'filereads': 0,
                                     'filecloses': 0,
                                     'trace': 'hook,alloc,exit'},
 'current:boot-read-erased': {'case': 'boot-read-erased',
                              'status': 0,
                              'reads': 1,
                              'factorywrites': 1,
                              'defaults': 1,
                              'parse': 1,
                              'radio': 1,
                              'asic': 1,
                              'exits': 0,
                              'capinit': 1,
                              'image': 1,
                              'mode': 2,
                              'source': 8,
                              'calibrated': 1,
                              'allocs': 1,
                              'frees': 0,
                              'fsdepth': 0,
                              'fileopens': 1,
                              'filereads': 0,
                              'filecloses': 0,
                              'trace': 'hook,alloc,read,fs-enter,file-open,fs-restore,factory-write,antenna-check,parse,radio,hw'},
 'current:ate-read-ok': {'case': 'ate-read-ok',
                         'status': 0,
                         'reads': 1,
                         'factorywrites': 0,
                         'defaults': 0,
                         'parse': 1,
                         'radio': 0,
                         'asic': 1,
                         'exits': 0,
                         'capinit': 1,
                         'image': 1,
                         'mode': 2,
                         'source': 2,
                         'calibrated': 1,
                         'allocs': 1,
                         'frees': 0,
                         'fsdepth': 0,
                         'fileopens': 0,
                         'filereads': 0,
                         'filecloses': 0,
                         'trace': 'alloc,read,antenna-check,parse,asic'},
 'current:ate-read-error': {'case': 'ate-read-error',
                            'status': 1,
                            'reads': 1,
                            'factorywrites': 0,
                            'defaults': 0,
                            'parse': 0,
                            'radio': 0,
                            'asic': 0,
                            'exits': 0,
                            'capinit': 0,
                            'image': 0,
                            'mode': 0,
                            'source': 0,
                            'calibrated': 0,
                            'allocs': 1,
                            'frees': 1,
                            'fsdepth': 0,
                            'fileopens': 0,
                            'filereads': 0,
                            'filecloses': 0,
                            'trace': 'alloc,read,free'},
 'current:testmode-read-ok': {'case': 'testmode-read-ok',
                              'status': 0,
                              'reads': 1,
                              'factorywrites': 0,
                              'defaults': 0,
                              'parse': 1,
                              'radio': 0,
                              'asic': 1,
                              'exits': 0,
                              'capinit': 1,
                              'image': 1,
                              'mode': 2,
                              'source': 2,
                              'calibrated': 1,
                              'allocs': 1,
                              'frees': 0,
                              'fsdepth': 0,
                              'fileopens': 0,
                              'filereads': 0,
                              'filecloses': 0,
                              'trace': 'alloc,read,antenna-check,parse,asic'},
 'current:testmode-read-error': {'case': 'testmode-read-error',
                                 'status': 1,
                                 'reads': 1,
                                 'factorywrites': 0,
                                 'defaults': 0,
                                 'parse': 0,
                                 'radio': 0,
                                 'asic': 0,
                                 'exits': 0,
                                 'capinit': 0,
                                 'image': 0,
                                 'mode': 0,
                                 'source': 0,
                                 'calibrated': 0,
                                 'allocs': 1,
                                 'frees': 1,
                                 'fsdepth': 0,
                                 'fileopens': 0,
                                 'filereads': 0,
                                 'filecloses': 0,
                                 'trace': 'alloc,read,free'},
 'current:direct-default-write-error': {'case': 'direct-default-write-error',
                                        'status': 1,
                                        'reads': 1,
                                        'factorywrites': 1,
                                        'defaults': 1,
                                        'parse': 0,
                                        'radio': 0,
                                        'asic': 0,
                                        'exits': 0,
                                        'capinit': 0,
                                        'image': 0,
                                        'mode': 0,
                                        'source': 0,
                                        'calibrated': 0,
                                        'allocs': 1,
                                        'frees': 1,
                                        'fsdepth': 0,
                                        'fileopens': 1,
                                        'filereads': 0,
                                        'filecloses': 0,
                                        'trace': 'alloc,read,fs-enter,file-open,fs-restore,factory-write,free'},
 'current:boot-default-write-error': {'case': 'boot-default-write-error',
                                      'status': 1,
                                      'reads': 1,
                                      'factorywrites': 1,
                                      'defaults': 1,
                                      'parse': 0,
                                      'radio': 0,
                                      'asic': 0,
                                      'exits': 1,
                                      'capinit': 0,
                                      'image': 0,
                                      'mode': 0,
                                      'source': 0,
                                      'calibrated': 0,
                                      'allocs': 1,
                                      'frees': 1,
                                      'fsdepth': 0,
                                      'fileopens': 1,
                                      'filereads': 0,
                                      'filecloses': 0,
                                      'trace': 'hook,alloc,read,fs-enter,file-open,fs-restore,factory-write,free,exit'},
 'current:direct-default-file-ok': {'case': 'direct-default-file-ok',
                                    'status': 0,
                                    'reads': 1,
                                    'factorywrites': 1,
                                    'defaults': 1,
                                    'parse': 0,
                                    'radio': 0,
                                    'asic': 0,
                                    'exits': 0,
                                    'capinit': 1,
                                    'image': 1,
                                    'mode': 2,
                                    'source': 8,
                                    'calibrated': 1,
                                    'allocs': 1,
                                    'frees': 0,
                                    'fsdepth': 0,
                                    'fileopens': 1,
                                    'filereads': 1,
                                    'filecloses': 1,
                                    'trace': 'alloc,read,fs-enter,file-open,file-read,file-close,fs-restore,factory-write'},
 'current:direct-default-file-error': {'case': 'direct-default-file-error',
                                       'status': 1,
                                       'reads': 1,
                                       'factorywrites': 0,
                                       'defaults': 1,
                                       'parse': 0,
                                       'radio': 0,
                                       'asic': 0,
                                       'exits': 0,
                                       'capinit': 0,
                                       'image': 0,
                                       'mode': 0,
                                       'source': 0,
                                       'calibrated': 0,
                                       'allocs': 1,
                                       'frees': 1,
                                       'fsdepth': 0,
                                       'fileopens': 1,
                                       'filereads': 1,
                                       'filecloses': 1,
                                       'trace': 'alloc,read,fs-enter,file-open,file-read,file-close,fs-restore,free'},
 'current:direct-default-short-file-error': {'case': 'direct-default-short-file-error',
                                             'status': 1,
                                             'reads': 1,
                                             'factorywrites': 0,
                                             'defaults': 1,
                                             'parse': 0,
                                             'radio': 0,
                                             'asic': 0,
                                             'exits': 0,
                                             'capinit': 0,
                                             'image': 0,
                                             'mode': 0,
                                             'source': 0,
                                             'calibrated': 0,
                                             'allocs': 1,
                                             'frees': 1,
                                             'fsdepth': 0,
                                             'fileopens': 1,
                                             'filereads': 1,
                                             'filecloses': 1,
                                             'trace': 'alloc,read,fs-enter,file-open,file-read,file-close,fs-restore,free'},
 'current:direct-default-close-error': {'case': 'direct-default-close-error',
                                        'status': 1,
                                        'reads': 1,
                                        'factorywrites': 0,
                                        'defaults': 1,
                                        'parse': 0,
                                        'radio': 0,
                                        'asic': 0,
                                        'exits': 0,
                                        'capinit': 0,
                                        'image': 0,
                                        'mode': 0,
                                        'source': 0,
                                        'calibrated': 0,
                                        'allocs': 1,
                                        'frees': 1,
                                        'fsdepth': 0,
                                        'fileopens': 1,
                                        'filereads': 1,
                                        'filecloses': 1,
                                        'trace': 'alloc,read,fs-enter,file-open,file-read,file-close,fs-restore,free'},
 'current:direct-default-missing-error': {'case': 'direct-default-missing-error',
                                          'status': 1,
                                          'reads': 1,
                                          'factorywrites': 0,
                                          'defaults': 1,
                                          'parse': 0,
                                          'radio': 0,
                                          'asic': 0,
                                          'exits': 0,
                                          'capinit': 0,
                                          'image': 0,
                                          'mode': 0,
                                          'source': 0,
                                          'calibrated': 0,
                                          'allocs': 1,
                                          'frees': 1,
                                          'fsdepth': 0,
                                          'fileopens': 1,
                                          'filereads': 0,
                                          'filecloses': 0,
                                          'trace': 'alloc,read,fs-enter,file-open,fs-restore,free'},
 'current:direct-default-short-cache-error': {'case': 'direct-default-short-cache-error',
                                              'status': 1,
                                              'reads': 1,
                                              'factorywrites': 0,
                                              'defaults': 1,
                                              'parse': 0,
                                              'radio': 0,
                                              'asic': 0,
                                              'exits': 0,
                                              'capinit': 0,
                                              'image': 0,
                                              'mode': 0,
                                              'source': 0,
                                              'calibrated': 0,
                                              'allocs': 1,
                                              'frees': 1,
                                              'fsdepth': 0,
                                              'fileopens': 1,
                                              'filereads': 0,
                                              'filecloses': 0,
                                              'trace': 'alloc,read,fs-enter,file-open,fs-restore,free'},
 'current:direct-default-invalid-id-error': {'case': 'direct-default-invalid-id-error',
                                             'status': 1,
                                             'reads': 1,
                                             'factorywrites': 0,
                                             'defaults': 1,
                                             'parse': 0,
                                             'radio': 0,
                                             'asic': 0,
                                             'exits': 0,
                                             'capinit': 0,
                                             'image': 0,
                                             'mode': 0,
                                             'source': 0,
                                             'calibrated': 0,
                                             'allocs': 1,
                                             'frees': 1,
                                             'fsdepth': 0,
                                             'fileopens': 1,
                                             'filereads': 0,
                                             'filecloses': 0,
                                             'trace': 'alloc,read,fs-enter,file-open,fs-restore,free'},
 'current:direct-default-empty-path-error': {'case': 'direct-default-empty-path-error',
                                             'status': 1,
                                             'reads': 1,
                                             'factorywrites': 0,
                                             'defaults': 0,
                                             'parse': 0,
                                             'radio': 0,
                                             'asic': 0,
                                             'exits': 0,
                                             'capinit': 0,
                                             'image': 0,
                                             'mode': 0,
                                             'source': 0,
                                             'calibrated': 0,
                                             'allocs': 1,
                                             'frees': 1,
                                             'fsdepth': 0,
                                             'fileopens': 0,
                                             'filereads': 0,
                                             'filecloses': 0,
                                             'trace': 'alloc,read,fs-enter,fs-restore,free'},
 'current:direct-small-buffer-error': {'case': 'direct-small-buffer-error',
                                       'status': 1,
                                       'reads': 0,
                                       'factorywrites': 0,
                                       'defaults': 0,
                                       'parse': 0,
                                       'radio': 0,
                                       'asic': 0,
                                       'exits': 0,
                                       'capinit': 0,
                                       'image': 0,
                                       'mode': 0,
                                       'source': 0,
                                       'calibrated': 0,
                                       'allocs': 0,
                                       'frees': 0,
                                       'fsdepth': 0,
                                       'fileopens': 0,
                                       'filereads': 0,
                                       'filecloses': 0,
                                       'trace': ''},
 'current:direct-default-oversized-read-error': {'case': 'direct-default-oversized-read-error',
                                                 'status': 1,
                                                 'reads': 1,
                                                 'factorywrites': 0,
                                                 'defaults': 1,
                                                 'parse': 0,
                                                 'radio': 0,
                                                 'asic': 0,
                                                 'exits': 0,
                                                 'capinit': 0,
                                                 'image': 0,
                                                 'mode': 0,
                                                 'source': 0,
                                                 'calibrated': 0,
                                                 'allocs': 1,
                                                 'frees': 1,
                                                 'fsdepth': 0,
                                                 'fileopens': 1,
                                                 'filereads': 1,
                                                 'filecloses': 1,
                                                 'trace': 'alloc,read,fs-enter,file-open,file-read,file-close,fs-restore,free'},
 'current:direct-default-long-cache-ok': {'case': 'direct-default-long-cache-ok',
                                          'status': 0,
                                          'reads': 1,
                                          'factorywrites': 1,
                                          'defaults': 1,
                                          'parse': 0,
                                          'radio': 0,
                                          'asic': 0,
                                          'exits': 0,
                                          'capinit': 1,
                                          'image': 1,
                                          'mode': 2,
                                          'source': 8,
                                          'calibrated': 1,
                                          'allocs': 1,
                                          'frees': 0,
                                          'fsdepth': 0,
                                          'fileopens': 1,
                                          'filereads': 0,
                                          'filecloses': 0,
                                          'trace': 'alloc,read,fs-enter,file-open,fs-restore,factory-write'},
 'baseline:direct-read-ok': {'case': 'direct-read-ok',
                             'status': 0,
                             'reads': 1,
                             'factorywrites': 0,
                             'defaults': 0,
                             'parse': 0,
                             'radio': 0,
                             'asic': 0,
                             'exits': 0,
                             'capinit': 1,
                             'image': 1,
                             'mode': 2,
                             'source': 2,
                             'calibrated': 1,
                             'allocs': 1,
                             'frees': 0,
                             'fsdepth': 0,
                             'fileopens': 0,
                             'filereads': 0,
                             'filecloses': 0,
                             'trace': 'alloc,read'},
 'baseline:direct-read-error': {'case': 'direct-read-error',
                                'status': 0,
                                'reads': 1,
                                'factorywrites': 1,
                                'defaults': 1,
                                'parse': 0,
                                'radio': 0,
                                'asic': 0,
                                'exits': 0,
                                'capinit': 1,
                                'image': 1,
                                'mode': 2,
                                'source': 8,
                                'calibrated': 1,
                                'allocs': 1,
                                'frees': 0,
                                'fsdepth': 1,
                                'fileopens': 1,
                                'filereads': 0,
                                'filecloses': 0,
                                'trace': 'alloc,read,fs-enter,file-open,factory-write'},
 'baseline:direct-read-short': {'case': 'direct-read-short',
                                'status': 0,
                                'reads': 1,
                                'factorywrites': 1,
                                'defaults': 1,
                                'parse': 0,
                                'radio': 0,
                                'asic': 0,
                                'exits': 0,
                                'capinit': 1,
                                'image': 1,
                                'mode': 2,
                                'source': 8,
                                'calibrated': 1,
                                'allocs': 1,
                                'frees': 0,
                                'fsdepth': 1,
                                'fileopens': 1,
                                'filereads': 0,
                                'filecloses': 0,
                                'trace': 'alloc,read,fs-enter,file-open,factory-write'},
 'baseline:direct-existing-error': {'case': 'direct-existing-error',
                                    'status': 0,
                                    'reads': 1,
                                    'factorywrites': 1,
                                    'defaults': 1,
                                    'parse': 0,
                                    'radio': 0,
                                    'asic': 0,
                                    'exits': 0,
                                    'capinit': 1,
                                    'image': 1,
                                    'mode': 2,
                                    'source': 8,
                                    'calibrated': 1,
                                    'allocs': 1,
                                    'frees': 1,
                                    'fsdepth': 1,
                                    'fileopens': 1,
                                    'filereads': 0,
                                    'filecloses': 0,
                                    'trace': 'free,alloc,read,fs-enter,file-open,factory-write'},
 'baseline:boot-read-error': {'case': 'boot-read-error',
                              'status': 0,
                              'reads': 1,
                              'factorywrites': 1,
                              'defaults': 1,
                              'parse': 1,
                              'radio': 1,
                              'asic': 1,
                              'exits': 0,
                              'capinit': 1,
                              'image': 1,
                              'mode': 2,
                              'source': 8,
                              'calibrated': 1,
                              'allocs': 1,
                              'frees': 0,
                              'fsdepth': 1,
                              'fileopens': 1,
                              'filereads': 0,
                              'filecloses': 0,
                              'trace': 'hook,alloc,read,fs-enter,file-open,factory-write,antenna-check,parse,radio,hw'},
 'baseline:boot-allocation-failure': {'case': 'boot-allocation-failure',
                                      'status': 0,
                                      'reads': 0,
                                      'factorywrites': 0,
                                      'defaults': 0,
                                      'parse': 1,
                                      'radio': 1,
                                      'asic': 1,
                                      'exits': 0,
                                      'capinit': 1,
                                      'image': 0,
                                      'mode': 2,
                                      'source': 2,
                                      'calibrated': 1,
                                      'allocs': 1,
                                      'frees': 0,
                                      'fsdepth': 0,
                                      'fileopens': 0,
                                      'filereads': 0,
                                      'filecloses': 0,
                                      'trace': 'hook,alloc,antenna-check,parse,radio,hw'},
 'baseline:ate-read-error': {'case': 'ate-read-error',
                             'status': 0,
                             'reads': 1,
                             'factorywrites': 1,
                             'defaults': 1,
                             'parse': 1,
                             'radio': 0,
                             'asic': 1,
                             'exits': 0,
                             'capinit': 1,
                             'image': 1,
                             'mode': 2,
                             'source': 8,
                             'calibrated': 1,
                             'allocs': 1,
                             'frees': 0,
                             'fsdepth': 1,
                             'fileopens': 1,
                             'filereads': 0,
                             'filecloses': 0,
                             'trace': 'alloc,read,fs-enter,file-open,factory-write,antenna-check,parse,asic'},
 'baseline:testmode-read-error': {'case': 'testmode-read-error',
                                  'status': 0,
                                  'reads': 1,
                                  'factorywrites': 1,
                                  'defaults': 1,
                                  'parse': 1,
                                  'radio': 0,
                                  'asic': 1,
                                  'exits': 0,
                                  'capinit': 1,
                                  'image': 1,
                                  'mode': 2,
                                  'source': 8,
                                  'calibrated': 1,
                                  'allocs': 1,
                                  'frees': 0,
                                  'fsdepth': 1,
                                  'fileopens': 1,
                                  'filereads': 0,
                                  'filecloses': 0,
                                  'trace': 'alloc,read,fs-enter,file-open,factory-write,antenna-check,parse,asic'},
 'baseline:direct-default-write-error': {'case': 'direct-default-write-error',
                                         'status': 0,
                                         'reads': 1,
                                         'factorywrites': 1,
                                         'defaults': 1,
                                         'parse': 0,
                                         'radio': 0,
                                         'asic': 0,
                                         'exits': 0,
                                         'capinit': 1,
                                         'image': 1,
                                         'mode': 2,
                                         'source': 8,
                                         'calibrated': 1,
                                         'allocs': 1,
                                         'frees': 0,
                                         'fsdepth': 1,
                                         'fileopens': 1,
                                         'filereads': 0,
                                         'filecloses': 0,
                                         'trace': 'alloc,read,fs-enter,file-open,factory-write'},
 'baseline:boot-default-write-error': {'case': 'boot-default-write-error',
                                       'status': 0,
                                       'reads': 1,
                                       'factorywrites': 1,
                                       'defaults': 1,
                                       'parse': 1,
                                       'radio': 1,
                                       'asic': 1,
                                       'exits': 0,
                                       'capinit': 1,
                                       'image': 1,
                                       'mode': 2,
                                       'source': 8,
                                       'calibrated': 1,
                                       'allocs': 1,
                                       'frees': 0,
                                       'fsdepth': 1,
                                       'fileopens': 1,
                                       'filereads': 0,
                                       'filecloses': 0,
                                       'trace': 'hook,alloc,read,fs-enter,file-open,factory-write,antenna-check,parse,radio,hw'},
 'baseline:direct-default-file-error': {'case': 'direct-default-file-error',
                                        'status': 1,
                                        'reads': 1,
                                        'factorywrites': 1,
                                        'defaults': 1,
                                        'parse': 0,
                                        'radio': 0,
                                        'asic': 0,
                                        'exits': 0,
                                        'capinit': 1,
                                        'image': 1,
                                        'mode': 2,
                                        'source': 8,
                                        'calibrated': 1,
                                        'allocs': 1,
                                        'frees': 0,
                                        'fsdepth': 0,
                                        'fileopens': 1,
                                        'filereads': 1,
                                        'filecloses': 1,
                                        'trace': 'alloc,read,fs-enter,file-open,file-read,file-close,fs-restore,factory-write'},
 'baseline:direct-default-short-file-error': {'case': 'direct-default-short-file-error',
                                              'status': 0,
                                              'reads': 1,
                                              'factorywrites': 1,
                                              'defaults': 1,
                                              'parse': 0,
                                              'radio': 0,
                                              'asic': 0,
                                              'exits': 0,
                                              'capinit': 1,
                                              'image': 1,
                                              'mode': 2,
                                              'source': 8,
                                              'calibrated': 1,
                                              'allocs': 1,
                                              'frees': 0,
                                              'fsdepth': 0,
                                              'fileopens': 1,
                                              'filereads': 1,
                                              'filecloses': 1,
                                              'trace': 'alloc,read,fs-enter,file-open,file-read,file-close,fs-restore,factory-write'},
 'baseline:direct-default-close-error': {'case': 'direct-default-close-error',
                                         'status': 0,
                                         'reads': 1,
                                         'factorywrites': 1,
                                         'defaults': 1,
                                         'parse': 0,
                                         'radio': 0,
                                         'asic': 0,
                                         'exits': 0,
                                         'capinit': 1,
                                         'image': 1,
                                         'mode': 2,
                                         'source': 8,
                                         'calibrated': 1,
                                         'allocs': 1,
                                         'frees': 0,
                                         'fsdepth': 0,
                                         'fileopens': 1,
                                         'filereads': 1,
                                         'filecloses': 1,
                                         'trace': 'alloc,read,fs-enter,file-open,file-read,file-close,fs-restore,factory-write'},
 'baseline:direct-default-missing-error': {'case': 'direct-default-missing-error',
                                           'status': 1,
                                           'reads': 1,
                                           'factorywrites': 0,
                                           'defaults': 1,
                                           'parse': 0,
                                           'radio': 0,
                                           'asic': 0,
                                           'exits': 0,
                                           'capinit': 1,
                                           'image': 1,
                                           'mode': 2,
                                           'source': 8,
                                           'calibrated': 1,
                                           'allocs': 1,
                                           'frees': 0,
                                           'fsdepth': 1,
                                           'fileopens': 1,
                                           'filereads': 0,
                                           'filecloses': 0,
                                           'trace': 'alloc,read,fs-enter,file-open'},
 'baseline:direct-default-short-cache-error': {'case': 'direct-default-short-cache-error',
                                               'status': 0,
                                               'reads': 1,
                                               'factorywrites': 1,
                                               'defaults': 1,
                                               'parse': 0,
                                               'radio': 0,
                                               'asic': 0,
                                               'exits': 0,
                                               'capinit': 1,
                                               'image': 1,
                                               'mode': 2,
                                               'source': 8,
                                               'calibrated': 1,
                                               'allocs': 1,
                                               'frees': 0,
                                               'fsdepth': 1,
                                               'fileopens': 1,
                                               'filereads': 0,
                                               'filecloses': 0,
                                               'trace': 'alloc,read,fs-enter,file-open,factory-write'},
 'baseline:direct-default-invalid-id-error': {'case': 'direct-default-invalid-id-error',
                                              'status': 1,
                                              'reads': 1,
                                              'factorywrites': 1,
                                              'defaults': 1,
                                              'parse': 0,
                                              'radio': 0,
                                              'asic': 0,
                                              'exits': 0,
                                              'capinit': 1,
                                              'image': 1,
                                              'mode': 2,
                                              'source': 8,
                                              'calibrated': 1,
                                              'allocs': 1,
                                              'frees': 0,
                                              'fsdepth': 1,
                                              'fileopens': 1,
                                              'filereads': 0,
                                              'filecloses': 0,
                                              'trace': 'alloc,read,fs-enter,file-open,factory-write'},
 'baseline:direct-default-empty-path-error': {'case': 'direct-default-empty-path-error',
                                              'status': 1,
                                              'reads': 1,
                                              'factorywrites': 1,
                                              'defaults': 0,
                                              'parse': 0,
                                              'radio': 0,
                                              'asic': 0,
                                              'exits': 0,
                                              'capinit': 1,
                                              'image': 1,
                                              'mode': 2,
                                              'source': 8,
                                              'calibrated': 1,
                                              'allocs': 1,
                                              'frees': 0,
                                              'fsdepth': 0,
                                              'fileopens': 0,
                                              'filereads': 0,
                                              'filecloses': 0,
                                              'trace': 'alloc,read,fs-enter,fs-restore,factory-write'},
 'baseline:direct-default-oversized-read-error': {'case': 'direct-default-oversized-read-error',
                                                  'status': 0,
                                                  'reads': 1,
                                                  'factorywrites': 1,
                                                  'defaults': 1,
                                                  'parse': 0,
                                                  'radio': 0,
                                                  'asic': 0,
                                                  'exits': 0,
                                                  'capinit': 1,
                                                  'image': 1,
                                                  'mode': 2,
                                                  'source': 8,
                                                  'calibrated': 1,
                                                  'allocs': 1,
                                                  'frees': 0,
                                                  'fsdepth': 0,
                                                  'fileopens': 1,
                                                  'filereads': 1,
                                                  'filecloses': 1,
                                                  'trace': 'alloc,read,fs-enter,file-open,file-read,file-close,fs-restore,factory-write'},
 'disabled:direct-read-ok': {'case': 'direct-read-ok',
                             'status': 0,
                             'reads': 0,
                             'factorywrites': 0,
                             'defaults': 0,
                             'parse': 0,
                             'radio': 0,
                             'asic': 0,
                             'exits': 0,
                             'capinit': 1,
                             'image': 0,
                             'mode': 2,
                             'source': 2,
                             'calibrated': 1,
                             'allocs': 0,
                             'frees': 0,
                             'fsdepth': 0,
                             'fileopens': 0,
                             'filereads': 0,
                             'filecloses': 0,
                             'trace': ''},
 'disabled:direct-read-error': {'case': 'direct-read-error',
                                'status': 0,
                                'reads': 0,
                                'factorywrites': 0,
                                'defaults': 0,
                                'parse': 0,
                                'radio': 0,
                                'asic': 0,
                                'exits': 0,
                                'capinit': 1,
                                'image': 0,
                                'mode': 2,
                                'source': 2,
                                'calibrated': 1,
                                'allocs': 0,
                                'frees': 0,
                                'fsdepth': 0,
                                'fileopens': 0,
                                'filereads': 0,
                                'filecloses': 0,
                                'trace': ''}}
def require(value, message):
    if not value:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def exact(left, right, message):
    require(json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True), message)

def read_regular(path, limit):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError('WiFi Factory artifact cannot be opened without following aliases') from error
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit,
                'WiFi Factory artifact must be a bounded regular file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(descriptor)
    require(len(data) == info.st_size, 'WiFi Factory artifact changed or exceeds budget')
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
            'WiFi Factory final proof requires the completed SPI kernel/image gate')
    exact(report.get('required_cases'), [name for name, _ in spi.CASES], 'SPI case set differs')
    spi.validate_records(report.get('checks'))
    for key, spi_key in SPI_SOURCE_KEYS.items():
        require(report.get('source_sha256', {}).get(spi_key) == sha(inputs[key].encode()),
                'WiFi Factory and SPI source identities differ: ' + key)
    binding = report.get('kernel_binding')
    require(type(binding) is dict and binding.get('whole_byte_equality') is True,
            'WiFi Factory requires exact whole kernel/image binding')
    expected_exports = {'target-spi-kernel-vmlinux.elf', 'target-spi-kernel-raw.bin',
                        'target-spi-kernel-vendor.bin', 'target-spi-vmlinux.cmd'}
    for label in spi.OBJECTS:
        expected_exports.update(('target-spi-' + label + '.o', 'target-spi-' + label + '.cmd'))
    exports = binding.get('exports')
    require(type(exports) is dict and set(exports) == expected_exports,
            'WiFi Factory SPI kernel sidecar set differs')
    for name, value in exports.items():
        require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
                'Malformed SPI sidecar SHA256')
        require(sha(read_regular(report_path.parent / name, spi.MAX_ELF)) == value,
                'WiFi Factory referenced SPI sidecar bytes differ: ' + name)
    linked = spi.inspect_elf(read_regular(report_path.parent / 'target-spi-kernel-vmlinux.elf', spi.MAX_ELF), 2)
    exact(linked, binding.get('vmlinux'), 'WiFi Factory linked kernel metadata differs from sidecar')
    selected = binding.get('selected_objects')
    require(type(selected) is dict and set(selected) == set(spi.OBJECTS), 'SPI selected objects differ')
    symbols = {}
    for label, names in KERNEL_SYMBOLS.items():
        row = selected[label]
        object_name = 'target-spi-' + label + '.o'
        require(row.get('object_file') == object_name, 'WiFi Factory selected object filename differs')
        obj = spi.inspect_elf(read_regular(report_path.parent / object_name, spi.MAX_ELF), 1)
        exact(obj, row.get('ELF'), 'WiFi Factory selected object metadata differs from sidecar')
        command_name = 'target-spi-' + label + '.cmd'
        command = read_regular(report_path.parent / command_name, 2 * 1024 * 1024)
        require(row.get('command_file') == command_name and
                row.get('command_sha256') == sha(command) and
                Path(spi.OBJECTS[label][0]).with_suffix('.c').name.encode() in command,
                'WiFi Factory selected object command/source binding differs')
        for name in names:
            require(len(obj['function_symbols'].get(name, [])) == 1 and
                    len(linked['function_symbols'].get(name, [])) == 1 and
                    obj['function_symbols'][name][0]['bytes'] > 0 and
                    linked['function_symbols'][name][0]['bytes'] > 0,
                    'WiFi Factory actual implementation symbol absent: ' + name)
            require(name in row.get('required_symbols', []), 'SPI proof does not require WiFi Factory caller: ' + name)
            symbols[name] = {'object': label, 'object_symbol': obj['function_symbols'][name][0],
                             'linked_symbol': linked['function_symbols'][name][0]}
    return {'role': 'Reference to separately mandatory exact whole-kernel SPI proof',
            'report_file': report_path.name, 'report_sha256': sha(raw),
            'image_sha256': binding['image']['image_sha256'],
            'vmlinux_sha256': linked['sha256'], 'required_symbols': symbols,
            'source_sha256': {SPI_SOURCE_KEYS[key]: sha(inputs[key].encode()) for key in SPI_SOURCE_KEYS},
            'kernel_exports_sha256': exports, 'whole_kernel_image_equality': True,
            'object_to_link_scope': binding['object_to_link_scope']}


MAX_SYMBOLS=262144
MAX_SYMBOL_NAME_BYTES=16*1024*1024
def _cstring(pool, at, maximum=4096):
    require(0 <= at < len(pool), 'ELF string offset')
    end = pool.find(b'\0', at, min(len(pool), at + maximum + 1))
    require(end >= at, 'Unterminated/oversized ELF string')
    try:
        return pool[at:end].decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('Non-ASCII ELF symbol/section name') from error

def parse_module_elf(data, expected_type=None):
    require(type(data) is bytes and 52 <= len(data) <= MAX_ELF and
         data[:7] == b'\x7fELF\x01\x01\x01', 'Bounded ELF32 little-endian required')
    values = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstrings = values
    require(kind in (1, 2) and machine == 8 and version == 1 and ehsize == 52 and
         (expected_type is None or kind == expected_type), 'MIPS ELF type/version')
    require(0 < shnum <= 16384 and shsize == 40 and 52 <= shoff <= len(data) - shnum * 40 and
         0 < shstrings < shnum, 'ELF section table bounds/extended numbering unsupported')
    raw_sections = [struct.unpack_from('<10I', data, shoff + i * 40) for i in range(shnum)]
    for row in raw_sections:
        _, stype, _, addr, offset, size, link, info, align, stride = row
        require(stype == 8 or offset <= len(data) and size <= len(data) - offset, 'ELF section payload range')
        require(addr + size <= 2**32 and (align in (0, 1) or align & (align - 1) == 0), 'ELF section address/alignment')
    strings = raw_sections[shstrings]
    require(strings[1] == 3, 'ELF section-name table type')
    pool = data[strings[4]:strings[4] + strings[5]]
    sections = []
    seen = set()
    for i, row in enumerate(raw_sections):
        name = _cstring(pool, row[0], 255)
        require(name not in seen, 'Duplicate ELF section name')
        seen.add(name)
        sections.append(dict(index=i, name=name, type=row[1], flags=row[2], address=row[3],
                             offset=row[4], bytes=row[5], link=row[6], info=row[7],
                             alignment=row[8], entry_bytes=row[9]))
    segments = []
    if phnum:
        require(phnum <= 128 and phsize == 32 and 52 <= phoff <= len(data) - phnum * 32, 'ELF program header bounds')
        for i in range(phnum):
            t, off, va, pa, fs, ms, pf, al = struct.unpack_from('<8I', data, phoff + i * 32)
            require(off <= len(data) and fs <= len(data) - off and fs <= ms and
                 max(va + ms, pa + ms) <= 2**32, 'ELF segment bounds')
            require(t not in (2, 3), 'Kernel cannot have runtime loader/dynamic segment')
            segments.append(dict(index=i, type=t, offset=off, vaddr=va, paddr=pa,
                                 file_bytes=fs, memory_bytes=ms, flags=pf, alignment=al))
    else:
        require(kind == 1, 'Executable requires program headers')
    symbols = []
    symbol_name_bytes = 0
    relocations = []
    for section in sections:
        if section['type'] in (2, 11):
            require(section['entry_bytes'] == 16 and section['bytes'] % 16 == 0 and
                 section['link'] < len(sections), 'ELF symbol table structure')
            names = sections[section['link']]
            require(names['type'] == 3, 'ELF symbol-name table type')
            names_pool = data[names['offset']:names['offset'] + names['bytes']]
            for ordinal, at in enumerate(range(section['offset'], section['offset'] + section['bytes'], 16)):
                require(len(symbols) < MAX_SYMBOLS, 'ELF aggregate symbol budget')
                name, value, size, info, other, target = struct.unpack_from('<IIIBBH', data, at)
                label = _cstring(names_pool, name)
                symbol_name_bytes += len(label)
                require(symbol_name_bytes <= MAX_SYMBOL_NAME_BYTES, 'ELF aggregate symbol-name budget')
                require(target < len(sections) or target >= 0xff00, 'ELF symbol section index')
                symbols.append(dict(table=section['index'], ordinal=ordinal, name=label, value=value,
                                    bytes=size, bind=info >> 4, type=info & 15,
                                    visibility=other & 3, other=other, section=target))
        elif section['type'] in (4, 9):
            stride = 12 if section['type'] == 4 else 8
            require(section['entry_bytes'] == stride and section['bytes'] % stride == 0 and
                 section['link'] < len(sections) and section['info'] < len(sections), 'ELF relocation table bounds')
            require(sections[section['link']]['type'] in (2, 11), 'Relocation symbol-table link')
            relocations.append(dict(section=section['index'], target_section=section['info'],
                                    symbol_table=section['link'], count=section['bytes'] // stride,
                                    type='RELA' if stride == 12 else 'REL',
                                    sha256=sha(data[section['offset']:section['offset'] + section['bytes']])))
    return dict(bytes=len(data), sha256=sha(data), elf_class=32, byte_order='little', e_machine=8,
                e_type=kind, entry=entry, flags=flags, sections=sections, segments=segments,
                symbols=symbols, relocation_tables=relocations)

DISABLED_NV_INIT='NDIS_STATUS rtmp_nv_init(RTMP_ADAPTER*p){(void)p;return NDIS_STATUS_SUCCESS;}'

def validate_contract():
    require(FUNCTION_SOURCES and CASES and EXPECTED and MODEL_FRAGMENTS_SHA256,'WiFi Factory contract not frozen')
    require(set(BASELINE_FUNCTION_HASHES)==set(FUNCTION_SOURCES) and
            set(EXPECTED)=={name for name,_ in CASES},'WiFi Factory fixed contract incomplete')

def function(text,name):
    tokens=r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*'
    masked=re.sub(tokens,lambda m:' '*len(m.group()),text)
    pattern=r'^(?:static\s+)?(?:void|VOID|int|INT|INT32|BOOLEAN|NDIS_STATUS)\s+'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{'
    matches=list(re.finditer(pattern,masked,re.M));require(len(matches)==1,'Missing/ambiguous WiFi function '+name)
    start=matches[0].start();opening=text.index('{',start);depth=0
    for token in re.finditer(tokens+r'|[{}]',text[opening:]):
        if token.group()=='{':depth+=1
        elif token.group()=='}':
            depth-=1
            if not depth:return text[start:opening+token.end()]
    raise ValueError('Unterminated WiFi function '+name)

def actual_functions(inputs):
    return {name:function(inputs[key],'pci_ate_leave'if name in ('ate_pci_ate_leave','testmode_pci_ate_leave')else name)
            for name,key in FUNCTION_SOURCES.items()}

def literal_harness(inputs):
    """Evaluate only literal data, aliases, string concatenation and tuple(dict)."""
    values={}
    def value(node):
        if isinstance(node,ast.Name):
            require(node.id in values,'Forward/unknown WiFi literal alias');return values[node.id]
        if isinstance(node,ast.BinOp)and isinstance(node.op,ast.Add):
            left,right=value(node.left),value(node.right)
            require(type(left)is str and type(right)is str,'WiFi data concatenation must be strings');return left+right
        if isinstance(node,ast.Dict):return {value(k):value(v)for k,v in zip(node.keys,node.values)}
        if isinstance(node,(ast.Tuple,ast.List)):
            result=[value(v)for v in node.elts];return tuple(result)if isinstance(node,ast.Tuple)else result
        if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='tuple'and len(node.args)==1 and not node.keywords:
            item=value(node.args[0]);require(type(item)in(dict,list,tuple),'WiFi tuple literal input');return tuple(item)
        return ast.literal_eval(node)
    for node in ast.parse(inputs['harness']).body:
        require(isinstance(node,(ast.Import,ast.Assign,ast.FunctionDef))or isinstance(node,ast.Expr)and
                isinstance(node.value,ast.Constant)and type(node.value.value)is str,'Unsupported WiFi generator top-level execution')
        if isinstance(node,ast.Import):require(all(a.name in('hashlib','re')for a in node.names),'Unexpected WiFi generator import')
        if isinstance(node,ast.Assign):
            require(len(node.targets)==1,'Unsupported WiFi data multi-assignment');target=node.targets[0];item=value(node.value)
            if isinstance(target,ast.Name):values[target.id]=item
            else:
                require(isinstance(target,ast.Subscript)and isinstance(target.value,ast.Name)and
                        target.value.id in values and type(values[target.value.id])is dict,'Unsupported WiFi data subscript assignment')
                key=value(target.slice);require(type(key)is str and key not in values[target.value.id],'Duplicate WiFi literal dictionary key')
                values[target.value.id][key]=item
    return values

def fragment_hash(values):
    require(type(values.get('PREFIX'))is str and type(values.get('MAIN'))is str,'WiFi model must use literal fragments')
    return sha((values['PREFIX']+values['MAIN']+json.dumps({'order':values['BODY_ORDER'],'projections':values['PROJECTIONS']},sort_keys=True,separators=(',',':'))).encode())

def generate_source(inputs,fixture_root,owner_uid,profile='current',old_bodies=None):
    validate_contract()
    require(set(inputs)==set(SOURCE_PATHS),'WiFi exact source set required')
    require(profile in('current','baseline','disabled')and type(owner_uid)is int and 0<=owner_uid<2**32,'Typed WiFi profile/owner required')
    require(type(fixture_root)is str and re.fullmatch('/tmp/k2p-wifi-factory-source-[A-Za-z0-9_-]+/'+profile+'-fixture',fixture_root),
            'Unexpected WiFi inert fixture metadata')
    values=literal_harness(inputs)
    for name,expected in (('SOURCE_PATHS',HARNESS_SOURCE_PATHS),('FUNCTION_SOURCES',FUNCTION_SOURCES),
                          ('BASELINE_COMMIT',BASELINE_COMMIT),('BASELINE_FUNCTIONS_SHA256',BASELINE_FUNCTION_HASHES),
                          ('BODY_ORDER',BODY_ORDER),('PROJECTIONS',PROJECTIONS)):
        exact(values.get(name),expected,'Locked WiFi source model differs: '+name)
    require(fragment_hash(values)==MODEL_FRAGMENTS_SHA256,'WiFi inert model fragments changed')
    for selected,key in (('current','CASE_NAMES'),('baseline','BASELINE_CASES'),('disabled','DISABLED_CASES')):
        exact(list(values.get(key,())),[o['selector']for _,o in CASES if o['profile']==selected],
              'Locked WiFi selector set differs: '+selected)
    embedded=values['BASELINE_FUNCTIONS']
    exact({name:sha(body.encode())for name,body in embedded.items()},BASELINE_FUNCTION_HASHES,'WiFi old source bytes changed')
    if old_bodies is not None:exact(embedded,old_bodies,'WiFi old bodies differ from independent public Git')
    bodies=embedded if profile=='baseline'else actual_functions(inputs)
    fragments={};manifest={}
    for name,body in bodies.items():
        execution='early-section'if name in PROJECTIONS else'whole-function'
        if name in PROJECTIONS:
            spec=PROJECTIONS[name]
            require(spec['start']in body and body.count(spec['end'])==1,'Missing/ambiguous WiFi section anchors: '+name)
            start=body.index(spec['start']);end=body.index(spec['end'],start)+(len(spec['end'])if spec['include_end']else 0)
            require(end>start,'Empty WiFi execution section');fragment=spec['prefix']+body[start:end]+spec['suffix']
        else:fragment=body
        if profile=='disabled'and name=='rtmp_nv_init':execution='disabled-control';fragment=DISABLED_NV_INIT
        fragments[name]=fragment;manifest[name]={'execution':execution,'full_body_sha256':sha(body.encode()),'executed_fragment_sha256':sha(fragment.encode())}
    admission='\n'.join('if(!strcmp(case_name,"'+name+'"))known=1;'for name in values['CASE_NAMES'])
    generated=values['PREFIX']+'\n'+'\n'.join(fragments[name]for name in BODY_ORDER)+'\n'+values['MAIN'].replace('CASE_ADMISSION',admission)
    require(0<len(generated.encode())<=MAX_SOURCE,'WiFi source budget')
    for name,fragment in fragments.items():require(generated.count(fragment)==1,'WiFi actual fragment missing/duplicated: '+name)
    return generated,manifest

def validate_records(rows):
    validate_contract();require(type(rows)is list and len(rows)==len(CASES),'WiFi required cases missing/extra')
    for row,(name,options)in zip(rows,CASES):
        require(type(row)is dict and set(row)=={'case','inputs','observed'}and row['case']==name,'WiFi case schema/order differs')
        exact(row['inputs'],options,'WiFi exact typed inputs differ: '+name)
        exact(row['observed'],EXPECTED[name],'WiFi fixed typed startup/Factory/cleanup outcome differs: '+name)
def source_selection(inputs):
    makefile,config=inputs['wifi_makefile'],inputs['wifi_config']
    for name,value in (('DRV_NAME','mt_7615e'),('SRC_DIR','../mt7615'),('SRC_EMBEDDED_DIR','../mt7615/embedded')):
        require(len(re.findall(r'^'+name+r'\s*=\s*'+re.escape(value)+r'\s*$',makefile,re.M))==1,
                'Configured WiFi Makefile selection differs: '+name)
    for line in ('CONFIG_RTMP_FLASH_SUPPORT=y','CONFIG_ATE_SUPPORT=y','CONFIG_MT_AP_SUPPORT=m'):
        require(len(re.findall('^'+re.escape(line)+'$',config,re.M))==1,'Configured WiFi mode differs: '+line)
    require('-DCONFIG_WIFI_MTD' in makefile and '$(SRC_DIR)/ate/mt_mac/mt_testmode.o' in makefile,
            'Configured WiFi MTD/ATE objects absent')
    require('$(SRC_DIR)/ate/mt_mac/mt_ate.o' not in makefile,'Unexpected alternate ATE object selected')
    for relative,key,symbol in OBJECTS.values():
        leaf=relative.split('/mt7615/',1)[1]
        require(('$(SRC_EMBEDDED_DIR)/'+leaf.removeprefix('embedded/') if leaf.startswith('embedded/') else
                 '$(SRC_DIR)/'+leaf) in makefile,'Configured startup object absent: '+relative)
    return {'module':SHIPPED_MODULE,'driver_name':'mt_7615e','mtd_backend':'CONFIG_WIFI_MTD',
            'ate_implementation':'mt_testmode.o','source_sha256':{key:sha(inputs[key].encode())for key in ('wifi_makefile','wifi_config')}}

def module_runtime(data,parse):
    """No code/data masking: compare exact allocated bytes plus semantic relocations."""
    parsed=parse(data,1);sections=parsed['sections']
    require(not parsed['segments'],'Relocatable WiFi module has program segments')
    alloc={}
    for row in sections:
        if not row['flags']&2:continue
        require(row['type'] not in (2,3,4,6,9,11),'Allocated WiFi metadata type unsupported')
        alloc[row['name']]={key:row[key]for key in ('type','flags','address','bytes','alignment')}
        alloc[row['name']]['sha256']=None if row['type']==8 else sha(data[row['offset']:row['offset']+row['bytes']])
    require(alloc and any(row['flags']&4 and row['bytes'] for row in alloc.values()),'WiFi module has no allocated code')
    lookup={(row['table'],row['ordinal']):row for row in parsed['symbols']}
    relocations={}
    for table in sections:
        if table['type']not in(4,9):continue
        target=sections[table['info']]
        if not target['flags']&2:continue
        stride=12 if table['type']==4 else 8;entries=[]
        require(table['bytes']//stride<=1048576,'WiFi runtime relocation budget')
        for at in range(table['offset'],table['offset']+table['bytes'],stride):
            offset,info=struct.unpack_from('<II',data,at);ordinal=info>>8
            require((table['link'],ordinal)in lookup and offset<max(1,target['bytes']),'WiFi runtime relocation target/symbol bounds')
            symbol=lookup[(table['link'],ordinal)]
            section=symbol['section'];section_name=sections[section]['name']if 0<section<len(sections)else section
            identity={key:symbol[key]for key in ('name','value','bytes','bind','type','visibility','other')}
            identity['section']=section_name
            entries.append({'offset':offset,'type':info&255,'symbol':identity,
                            'addend':struct.unpack_from('<i',data,at+8)[0]if stride==12 else None})
        relocations[target['name']+':'+str(table['type'])]=entries
    return {'allocated_sections':alloc,'runtime_relocations':relocations,'flags':parsed['flags']}

def module_artifact_names():
    names={'target-wifi-built.ko','target-wifi-module.cmd','target-wifi-link.cmd','target-wifi-shipped.ko'}
    for label in OBJECTS:names.update(('target-wifi-'+label+'.o','target-wifi-'+label+'.cmd'))
    return names

def canonical_command(data):
    require(type(data)is bytes and 0<len(data)<=2*1024*1024 and b'\0'not in data,'Invalid WiFi build command')
    text=data.decode('utf-8')
    return text.replace('mt7615_ap/../mt7615/','mt7615/')

def module_binding_from_bytes(inputs,artifacts,metadata,parse):
    require(set(artifacts)==module_artifact_names(),'WiFi compiled/module artifact set differs')
    selection=source_selection(inputs)
    built=artifacts['target-wifi-built.ko'];shipped=artifacts['target-wifi-shipped.ko']
    built_meta=metadata(built,1);shipped_meta=metadata(shipped,1)
    runtime_built=module_runtime(built,parse);runtime_shipped=module_runtime(shipped,parse)
    exact(runtime_built,runtime_shipped,'Built and shipped WiFi runtime code/data/relocations differ after stripping')
    modulecmd=canonical_command(artifacts['target-wifi-module.cmd'])
    linkcmd=canonical_command(artifacts['target-wifi-link.cmd'])
    require(BUILT_MODULE in modulecmd and BUILT_MODULE.removesuffix('.ko')+'.o' in modulecmd,
            'Final WiFi module command does not name configured module')
    require(BUILT_MODULE.removesuffix('.ko')+'.o' in linkcmd,'WiFi aggregate command names wrong module')
    selected={}
    for label,(relative,key,symbol)in OBJECTS.items():
        stem='target-wifi-'+label;command=canonical_command(artifacts[stem+'.cmd'])
        require(relative in command and relative.removesuffix('.o')+'.c' in command,
                'WiFi object command/source binding differs: '+label)
        require(relative in linkcmd,'WiFi object absent from aggregate command: '+label)
        if label=='ee-flash':require('-DCONFIG_WIFI_MTD' in command,'Configured Factory MTD branch is not compiled')
        obj=metadata(artifacts[stem+'.o'],1)
        require(len(obj['function_symbols'].get(symbol,[]))==1 and len(built_meta['function_symbols'].get(symbol,[]))==1 and
                obj['function_symbols'][symbol][0]['bytes']>0 and built_meta['function_symbols'][symbol][0]['bytes']>0,
                'Configured WiFi startup implementation absent/ambiguous: '+symbol)
        selected[label]={'object_file':stem+'.o','ELF':obj,'command_file':stem+'.cmd','command_sha256':sha(artifacts[stem+'.cmd']),
                         'source_key':key,'source_sha256':sha(inputs[key].encode()),'required_symbol':symbol,
                         'object_symbol':obj['function_symbols'][symbol][0],'module_symbol':built_meta['function_symbols'][symbol][0]}
    imports={}
    for data,tag in ((built,'built'),(shipped,'shipped')):
        symbols=parse(data,1)['symbols'];imports[tag]=[]
        for name in ('mt_mtd_read_nm_wifi','mt_mtd_write_nm_wifi'):
            matches=[row for row in symbols if row['name']==name and row['section']==0 and row['bind']in(1,2)]
            require(len(matches)==1,'Configured WiFi module lacks unique Factory backend import: '+name)
            imports[tag].append(name)
    return {'status':'PASS','source_selection':selection,'objects':selected,
            'built_module':{'file':'target-wifi-built.ko','ELF':built_meta,'command_file':'target-wifi-module.cmd',
                            'command_sha256':sha(artifacts['target-wifi-module.cmd']),
                            'aggregate_command_file':'target-wifi-link.cmd','aggregate_command_sha256':sha(artifacts['target-wifi-link.cmd'])},
            'shipped_module':{'file':'target-wifi-shipped.ko','path':SHIPPED_MODULE,'ELF':shipped_meta},
            'backend_imports':imports,'runtime_strip_equivalence':{'all_allocated_bytes_equal':True,
                'semantic_runtime_relocations_equal':True,'allocated_sections':runtime_built['allocated_sections'],
                'runtime_relocation_sha256':sha(json.dumps(runtime_built['runtime_relocations'],sort_keys=True,separators=(',',':')).encode()),
                'comparison_scope':'Exact SHF_ALLOC payloads/NOBITS metadata and semantic runtime relocations; only symbol/section indices may change during stripping.'},
            'exports':{name:sha(data)for name,data in artifacts.items()},
            'source_to_compiled_scope':'Clean locked full-build attestation; compilation and object-to-module relocation are not independently replayed.'}
def collect_module(trunk,rootfs):
    kernel=trunk/'linux-4.4.x';module=kernel/BUILT_MODULE
    paths={'target-wifi-built.ko':module,'target-wifi-module.cmd':module.with_name('.'+module.name+'.cmd'),
           'target-wifi-link.cmd':module.with_name('.'+module.stem+'.o.cmd'),
           'target-wifi-shipped.ko':rootfs/SHIPPED_MODULE}
    for label,(relative,_,_)in OBJECTS.items():
        obj=kernel/relative;paths['target-wifi-'+label+'.o']=obj
        paths['target-wifi-'+label+'.cmd']=obj.with_name('.'+obj.name+'.cmd')
    return {name:read_regular(path,2*1024*1024 if name.endswith('.cmd')else MAX_ELF)for name,path in paths.items()}

def check(trunk,compiler,output,preflight=False,rootfs=None,spi_report=None):
    validate_contract()
    require(type(preflight)is bool and ((preflight and rootfs is None and spi_report is None)or
            (not preflight and rootfs is not None and spi_report is not None)),'WiFi gate requires preflight alone or rootfs plus final SPI proof')
    config=(trunk/'.config').read_text()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$',config,re.M)and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$',config,re.M),'WiFi gate requires configured K2P4.4')
    qemu=shutil.which('qemu-mipsel');require(qemu is not None,'qemu-mipsel required')
    inputs={key:read_regular(trunk.parent/relative,MAX_SOURCE).decode('utf-8')for key,relative in SOURCE_PATHS.items()}
    source_selection(inputs)
    rows,probes,exports,manifests=[],{},{},{}
    with tempfile.TemporaryDirectory(prefix='k2p-wifi-factory-source-',dir='/tmp')as temporary:
        base=Path(temporary).resolve()
        for profile in('current','baseline','disabled'):
            fixture=str(base/(profile+'-fixture'));generated,manifest=generate_source(inputs,fixture,os.geteuid(),profile)
            source,binary=base/(profile+'.c'),base/profile;source.write_text(generated)
            run=subprocess.run([str(compiler),*FLAGS,str(source),'-o',str(binary)],capture_output=True,text=True,timeout=90)
            require(run.returncode==0,'WiFi MIPS actual-source compile failed: '+run.stdout+run.stderr)
            data=binary.read_bytes();elf=resident.validate_static_helper(data)
            for name,options in CASES:
                if options['profile']!=profile:continue
                run=subprocess.run([qemu,str(binary),options['selector']],capture_output=True,text=True,timeout=MAX_COMMAND_SECONDS)
                require(run.returncode==0 and not run.stderr,'WiFi inert case failed '+name+': '+run.stdout+run.stderr)
                rows.append({'case':name,'inputs':options,'observed':json.loads(run.stdout)})
            stem='target-wifi-factory'+(''if profile=='current'else'-'+profile)
            exports[stem+'.c'],exports[stem]=generated.encode(),data;manifests[profile]=manifest
            probes[profile]={'source_file':stem+'.c','source_sha256':sha(generated.encode()),'binary_file':stem,
                             'binary_sha256':sha(data),'ELF':elf,'compile_flags':list(FLAGS),
                             'fixture_root':fixture,'owner_uid':os.geteuid()}
    validate_records(rows)
    reference=kernel_reference(inputs,spi_report)if not preflight else None
    binding=None
    if not preflight:
        artifacts=collect_module(trunk,rootfs)
        binding=module_binding_from_bytes(inputs,artifacts,spi.inspect_elf,parse_module_elf);exports.update(artifacts)
    output.parent.mkdir(parents=True,exist_ok=True)
    for name,data in exports.items():
        path=output.parent/name;path.write_bytes(data)
        if name in('target-wifi-factory','target-wifi-factory-baseline','target-wifi-factory-disabled'):path.chmod(0o755)
    report={'schema_version':1,'status':'PASS','profile':'k2p-4.4',
            'phase':'early-source-only'if preflight else'final-module-image-reference-bound',
            'execution_role':ROLE,'required_cases':[name for name,_ in CASES],'checks':rows,
            'source_files':SOURCE_PATHS,'source_sha256':{key:sha(text.encode())for key,text in inputs.items()},
            'baseline_source_commit':BASELINE_COMMIT,'model_fragments_sha256':MODEL_FRAGMENTS_SHA256,
            'function_manifest':manifests,'probes':probes,'kernel_reference':reference,'module_binding':binding,
            'compiler':str(compiler),'limits':list(LIMITS)}
    output.write_text(json.dumps(report,indent=2)+'\n')
    print('WiFi Factory: '+str(len(rows))+' inert actual-source MIPS cases PASS')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('trunk','compiler','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--preflight',action='store_true');parser.add_argument('--rootfs',type=Path);parser.add_argument('--spi-report',type=Path)
    args=parser.parse_args()
    try:check(args.trunk.resolve(),args.compiler.resolve(),args.output.resolve(),args.preflight,
              args.rootfs.resolve()if args.rootfs else None,args.spi_report.resolve()if args.spi_report else None)
    except(OSError,ValueError,subprocess.SubprocessError)as error:parser.exit(1,'WiFi Factory validation failed: '+str(error)+'\n')
