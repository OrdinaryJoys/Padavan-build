#!/usr/bin/env python3
"""Current initialization/DMA error-chain source adapters and same-image objects."""
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
import tempfile
import check_target_resident_upgrade as resident
import check_target_spi_nor as spi

SOURCE_PATHS = {'init_tr': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/cmm_data.c',
 'init_basic': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl_basic.c',
 'init_sys': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.c',
 'init_mgmt': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_rbus_pci_drv.c',
 'init_ba': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/ba_action.c',
 'init_spectrum': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/spectrum.c',
 'init_qm': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/qm.c',
 'init_tm': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/tm.c',
 'init_adapter': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.c',
 'init_free': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_profile.c',
 'init_tr_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/tr.h',
 'init_hw_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/hw_ctrl.h',
 'init_rtmp_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp.h',
 'init_task_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_os.h',
 'init_os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h',
 'init_chip_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/hw_ctrl/cmm_chip.h',
 'init_qm_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/qm.h',
 'init_harness': 'tests/init_transaction_harness.py',
 'dma_dma': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/cmm_mac_pci.c',
 'dma_asic': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_asic.c',
 'dma_andes': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/mcu/andes_mt.c',
 'dma_chip': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_chip.c',
 'dma_init': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.c',
 'dma_ready': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.c',
 'dma_hw': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.c',
 'dma_fwdl': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/mcu/fwdl.c',
 'dma_flags': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_def.h',
 'dma_os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h',
 'dma_chip_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/hw_ctrl/cmm_chip.h',
 'dma_dma_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_chip.h',
 'dma_asic_mt': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_asic_mt_dmac.c',
 'dma_chip_hw': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/chips/mt7615.c',
 'dma_chip_cr': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/chip/mt7615_cr.h',
 'dma_hif_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/hif/mt_hif_pci.h',
 'dma_mcu': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/mcu/mcu.c',
 'dma_chip_mt': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_chip_mt.c',
 'dma_harness': 'tests/dma_lifecycle_harness.py',
 'unwind_inf': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.c',
 'unwind_hw': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.c',
 'unwind_ap': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/ap/ap.c',
 'unwind_flags': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_def.h',
 'unwind_os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h',
 'unwind_open': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_main_dev.c',
 'unwind_harness': 'tests/first_arm_unwind_harness.py',
 'wifi_config': 'trunk/configs/boards/K2P/kernel-4.4.x.config',
 'flags': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/Makefile.mt_wifi_ap',
 'wifi_makefile': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615_ap/Makefile',
 'kernel_makefile': 'trunk/linux-4.4.x/Makefile',
 'driver_config': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/config.mk',
 'chip': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/chips/mt7615.c',
 'os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h'}

COMPONENTS = {'init': {'paths': {'tr': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/cmm_data.c',
                    'basic': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl_basic.c',
                    'sys': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.c',
                    'mgmt': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_rbus_pci_drv.c',
                    'ba': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/ba_action.c',
                    'spectrum': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/spectrum.c',
                    'qm': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/qm.c',
                    'tm': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/tm.c',
                    'adapter': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.c',
                    'free': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_profile.c',
                    'tr_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/tr.h',
                    'hw_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/hw_ctrl.h',
                    'rtmp_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp.h',
                    'task_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_os.h',
                    'os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h',
                    'chip_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/hw_ctrl/cmm_chip.h',
                    'qm_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/qm.h'},
          'source_keys': {'tr': 'init_tr',
                          'basic': 'init_basic',
                          'sys': 'init_sys',
                          'mgmt': 'init_mgmt',
                          'ba': 'init_ba',
                          'spectrum': 'init_spectrum',
                          'qm': 'init_qm',
                          'tm': 'init_tm',
                          'adapter': 'init_adapter',
                          'free': 'init_free',
                          'tr_header': 'init_tr_header',
                          'hw_header': 'init_hw_header',
                          'rtmp_header': 'init_rtmp_header',
                          'task_header': 'init_task_header',
                          'os_header': 'init_os_header',
                          'chip_header': 'init_chip_header',
                          'qm_header': 'init_qm_header'},
          'functions': {'tr_ctl_init': 'tr',
                        'tr_ctl_exit': 'tr',
                        'ser_init': 'basic',
                        'HwCtrlSerExit': 'basic',
                        'ser_exit': 'basic',
                        'HwCtrlInit': 'basic',
                        'HwCtrlExit': 'basic',
                        'RtmpMgmtTaskInit': 'mgmt',
                        'RtmpMgmtTaskExit': 'mgmt',
                        'ba_reordering_resource_init': 'ba',
                        'ba_reordering_resource_release': 'ba',
                        'MeasureReqTabInit': 'spectrum',
                        'MeasureReqTabExit': 'spectrum',
                        'TpcReqTabInit': 'spectrum',
                        'TpcReqTabExit': 'spectrum',
                        'qm_init': 'qm',
                        'qm_exit': 'qm',
                        'tm_init': 'tm',
                        'tm_exit': 'tm',
                        'rtmp_sys_task_exit': 'sys',
                        'rtmp_sys_init': 'sys',
                        'rtmp_sys_exit': 'sys'},
          'source_only_functions': {'RTMPAllocAdapterBlock': 'adapter', 'RTMPFreeAdapter': 'free'},
          'harness_key': 'init_harness',
          'model_data_sha256': '0de97dad40cc013209270a22df92c22cc9a82fd706870c0296732a46cf15cf67',
          'variants': ('current',)},
 'dma': {'paths': {'dma': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/cmm_mac_pci.c',
                   'asic': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_asic.c',
                   'andes': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/mcu/andes_mt.c',
                   'chip': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_chip.c',
                   'init': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.c',
                   'ready': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.c',
                   'hw': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.c',
                   'fwdl': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/mcu/fwdl.c',
                   'flags': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_def.h',
                   'os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h',
                   'chip_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/hw_ctrl/cmm_chip.h',
                   'dma_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_chip.h',
                   'asic_mt': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_asic_mt_dmac.c',
                   'chip_hw': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/chips/mt7615.c',
                   'chip_cr': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/chip/mt7615_cr.h',
                   'hif_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/hif/mt_hif_pci.h',
                   'mcu': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/mcu/mcu.c',
                   'chip_mt': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_chip_mt.c'},
         'source_keys': {'dma': 'dma_dma',
                         'asic': 'dma_asic',
                         'andes': 'dma_andes',
                         'chip': 'dma_chip',
                         'init': 'dma_init',
                         'ready': 'dma_ready',
                         'hw': 'dma_hw',
                         'fwdl': 'dma_fwdl',
                         'flags': 'dma_flags',
                         'os_header': 'dma_os_header',
                         'chip_header': 'dma_chip_header',
                         'dma_header': 'dma_dma_header',
                         'asic_mt': 'dma_asic_mt',
                         'chip_hw': 'dma_chip_hw',
                         'chip_cr': 'dma_chip_cr',
                         'hif_header': 'dma_hif_header',
                         'mcu': 'dma_mcu',
                         'chip_mt': 'dma_chip_mt'},
         'functions': {'hif_wait_WPDMA_idle': 'chip_hw',
                       'MtAsicWaitPDMAIdle': 'asic_mt',
                       'AsicWaitPDMAIdle': 'asic',
                       'AsicResetWPDMA': 'asic',
                       'RT28XXDMAEnable': 'dma',
                       'RT28XXDMAStop': 'dma',
                       'RT28XXDMAReset': 'dma',
                       'AndesMTPciFwInit': 'andes',
                       'chip_fw_init': 'chip',
                       'WfMcuSysInit': 'init',
                       'RTMPEnableRxTx': 'init',
                       'mt_sys_ready': 'ready',
                       'NICRestartFirmware': 'fwdl',
                       'WfHifSysExit': 'init',
                       'WfSysPosExit': 'hw'},
         'source_only_functions': {'MCUSysPrepare': 'mcu',
                                   'MCUSysInit': 'mcu',
                                   'ChipOpsMCUHook': 'mcu',
                                   'PDMAResetAndRecovery': 'chip_mt',
                                   'MtAsicResetWPDMA': 'asic_mt',
                                   'hif_reset_WPDMA': 'chip_hw',
                                   'hif_set_WPDMA': 'chip_hw',
                                   'RTMPResetTxRxRingMemory': 'dma'},
         'harness_key': 'dma_harness',
         'model_data_sha256': 'b069744f4fded8d2fc192551a6031a34f85b8c04951d3d2aaabe8d522c53769d',
         'variants': ('current',)},
 'unwind': {'paths': {'inf': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.c',
                      'hw': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.c',
                      'ap': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/ap/ap.c',
                      'flags': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_def.h',
                      'os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h',
                      'open': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_main_dev.c'},
            'source_keys': {'inf': 'unwind_inf',
                            'hw': 'unwind_hw',
                            'ap': 'unwind_ap',
                            'flags': 'unwind_flags',
                            'os_header': 'unwind_os_header',
                            'open': 'unwind_open'},
            'functions': {'WfMcuInit': 'hw',
                          'WfInit': 'hw',
                          'rtmp_ap_init': 'ap',
                          'mt_sys_ready': 'inf',
                          'WfSysPosExit': 'hw',
                          'mt_wifi_init': 'inf',
                          'mt_wifi_open': 'open'},
            'source_only_functions': {'ApAutoChannelAtBootUp': 'ap',
                                      'APOverlappingBSSScan': 'ap',
                                      'RTMPDrvClose': 'inf',
                                      'RtmpOSIRQRequest': 'open',
                                      'rtmp_sys_task_exit': 'inf'},
            'harness_key': 'unwind_harness',
            'model_data_sha256': 'd5a3c8f05d15eaebdd5e4790fddd920225156a9e242d88431c37ff5bcdaf517d',
            'variants': ('current',)}}

CASES = (('init:current:tr-oom1', {'component': 'init', 'variant': 'current', 'selector': 'tr-oom1'}),
 ('init:current:tr-oom2', {'component': 'init', 'variant': 'current', 'selector': 'tr-oom2'}),
 ('init:current:tr-oom3', {'component': 'init', 'variant': 'current', 'selector': 'tr-oom3'}),
 ('init:current:tr-normal', {'component': 'init', 'variant': 'current', 'selector': 'tr-normal'}),
 ('init:current:tr-owner', {'component': 'init', 'variant': 'current', 'selector': 'tr-owner'}),
 ('init:current:tr-partial', {'component': 'init', 'variant': 'current', 'selector': 'tr-partial'}),
 ('init:current:tr-reopen', {'component': 'init', 'variant': 'current', 'selector': 'tr-reopen'}),
 ('init:current:ser-init-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'ser-init-failure'}),
 ('init:current:ser-attach-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'ser-attach-failure'}),
 ('init:current:ser-normal', {'component': 'init', 'variant': 'current', 'selector': 'ser-normal'}),
 ('init:current:ser-owner', {'component': 'init', 'variant': 'current', 'selector': 'ser-owner'}),
 ('init:current:ser-joined', {'component': 'init', 'variant': 'current', 'selector': 'ser-joined'}),
 ('init:current:ser-natural-exit',
  {'component': 'init', 'variant': 'current', 'selector': 'ser-natural-exit'}),
 ('init:current:ser-reopen', {'component': 'init', 'variant': 'current', 'selector': 'ser-reopen'}),
 ('init:current:hw-init-failure', {'component': 'init', 'variant': 'current', 'selector': 'hw-init-failure'}),
 ('init:current:hw-attach-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'hw-attach-failure'}),
 ('init:current:hw-ser-init-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'hw-ser-init-failure'}),
 ('init:current:hw-ser-attach-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'hw-ser-attach-failure'}),
 ('init:current:hw-normal', {'component': 'init', 'variant': 'current', 'selector': 'hw-normal'}),
 ('init:current:hw-owner', {'component': 'init', 'variant': 'current', 'selector': 'hw-owner'}),
 ('init:current:hw-reopen', {'component': 'init', 'variant': 'current', 'selector': 'hw-reopen'}),
 ('init:current:mgmt-init-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'mgmt-init-failure'}),
 ('init:current:mgmt-attach-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'mgmt-attach-failure'}),
 ('init:current:mgmt-normal', {'component': 'init', 'variant': 'current', 'selector': 'mgmt-normal'}),
 ('init:current:ba-oom', {'component': 'init', 'variant': 'current', 'selector': 'ba-oom'}),
 ('init:current:ba-owner', {'component': 'init', 'variant': 'current', 'selector': 'ba-owner'}),
 ('init:current:ba-reopen', {'component': 'init', 'variant': 'current', 'selector': 'ba-reopen'}),
 ('init:current:qm-init-failure', {'component': 'init', 'variant': 'current', 'selector': 'qm-init-failure'}),
 ('init:current:qm-notify-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'qm-notify-failure'}),
 ('init:current:qm-normal', {'component': 'init', 'variant': 'current', 'selector': 'qm-normal'}),
 ('init:current:qm-owner', {'component': 'init', 'variant': 'current', 'selector': 'qm-owner'}),
 ('init:current:tm-qm-failure', {'component': 'init', 'variant': 'current', 'selector': 'tm-qm-failure'}),
 ('init:current:tm-hif-failure', {'component': 'init', 'variant': 'current', 'selector': 'tm-hif-failure'}),
 ('init:current:tm-invalid-method',
  {'component': 'init', 'variant': 'current', 'selector': 'tm-invalid-method'}),
 ('init:current:tm-normal', {'component': 'init', 'variant': 'current', 'selector': 'tm-normal'}),
 ('init:current:tm-owner', {'component': 'init', 'variant': 'current', 'selector': 'tm-owner'}),
 ('init:current:sys-mgmt-init-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'sys-mgmt-init-failure'}),
 ('init:current:sys-mgmt-attach-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'sys-mgmt-attach-failure'}),
 ('init:current:sys-hw-init-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'sys-hw-init-failure'}),
 ('init:current:sys-hw-attach-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'sys-hw-attach-failure'}),
 ('init:current:sys-ser-init-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'sys-ser-init-failure'}),
 ('init:current:sys-ser-attach-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'sys-ser-attach-failure'}),
 ('init:current:sys-config-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'sys-config-failure'}),
 ('init:current:sys-ba-oom', {'component': 'init', 'variant': 'current', 'selector': 'sys-ba-oom'}),
 ('init:current:sys-measure-oom', {'component': 'init', 'variant': 'current', 'selector': 'sys-measure-oom'}),
 ('init:current:sys-tpc-oom', {'component': 'init', 'variant': 'current', 'selector': 'sys-tpc-oom'}),
 ('init:current:sys-tr-oom1', {'component': 'init', 'variant': 'current', 'selector': 'sys-tr-oom1'}),
 ('init:current:sys-tr-oom2', {'component': 'init', 'variant': 'current', 'selector': 'sys-tr-oom2'}),
 ('init:current:sys-tr-oom3', {'component': 'init', 'variant': 'current', 'selector': 'sys-tr-oom3'}),
 ('init:current:sys-qm-failure', {'component': 'init', 'variant': 'current', 'selector': 'sys-qm-failure'}),
 ('init:current:sys-tm-qm-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'sys-tm-qm-failure'}),
 ('init:current:sys-tm-hif-failure',
  {'component': 'init', 'variant': 'current', 'selector': 'sys-tm-hif-failure'}),
 ('init:current:sys-normal', {'component': 'init', 'variant': 'current', 'selector': 'sys-normal'}),
 ('init:current:sys-owner', {'component': 'init', 'variant': 'current', 'selector': 'sys-owner'}),
 ('init:current:sys-reopen', {'component': 'init', 'variant': 'current', 'selector': 'sys-reopen'}),
 ('init:current:sys-old-ser', {'component': 'init', 'variant': 'current', 'selector': 'sys-old-ser'}),
 ('init:current:sys-old-ba', {'component': 'init', 'variant': 'current', 'selector': 'sys-old-ba'}),
 ('init:current:sys-old-measure', {'component': 'init', 'variant': 'current', 'selector': 'sys-old-measure'}),
 ('init:current:sys-old-tpc', {'component': 'init', 'variant': 'current', 'selector': 'sys-old-tpc'}),
 ('init:current:sys-old-tr', {'component': 'init', 'variant': 'current', 'selector': 'sys-old-tr'}),
 ('init:current:sys-retired', {'component': 'init', 'variant': 'current', 'selector': 'sys-retired'}),
 ('dma:current:enable-idle', {'component': 'dma', 'variant': 'current', 'selector': 'enable-idle'}),
 ('dma:current:enable-busy', {'component': 'dma', 'variant': 'current', 'selector': 'enable-busy'}),
 ('dma:current:enable-nic-missing',
  {'component': 'dma', 'variant': 'current', 'selector': 'enable-nic-missing'}),
 ('dma:current:enable-set-failure',
  {'component': 'dma', 'variant': 'current', 'selector': 'enable-set-failure'}),
 ('dma:current:stop-idle', {'component': 'dma', 'variant': 'current', 'selector': 'stop-idle'}),
 ('dma:current:stop-busy', {'component': 'dma', 'variant': 'current', 'selector': 'stop-busy'}),
 ('dma:current:stop-set-failure', {'component': 'dma', 'variant': 'current', 'selector': 'stop-set-failure'}),
 ('dma:current:reset-idle', {'component': 'dma', 'variant': 'current', 'selector': 'reset-idle'}),
 ('dma:current:reset-busy', {'component': 'dma', 'variant': 'current', 'selector': 'reset-busy'}),
 ('dma:current:reset-set-failure',
  {'component': 'dma', 'variant': 'current', 'selector': 'reset-set-failure'}),
 ('dma:current:reset-callback-failure',
  {'component': 'dma', 'variant': 'current', 'selector': 'reset-callback-failure'}),
 ('dma:current:asic-non-mt', {'component': 'dma', 'variant': 'current', 'selector': 'asic-non-mt'}),
 ('dma:current:fw-init-idle', {'component': 'dma', 'variant': 'current', 'selector': 'fw-init-idle'}),
 ('dma:current:fw-init-busy', {'component': 'dma', 'variant': 'current', 'selector': 'fw-init-busy'}),
 ('dma:current:fw-init-set-failure',
  {'component': 'dma', 'variant': 'current', 'selector': 'fw-init-set-failure'}),
 ('dma:current:fw-init-no-callback',
  {'component': 'dma', 'variant': 'current', 'selector': 'fw-init-no-callback'}),
 ('dma:current:fw-init-non-mt', {'component': 'dma', 'variant': 'current', 'selector': 'fw-init-non-mt'}),
 ('dma:current:ready-idle', {'component': 'dma', 'variant': 'current', 'selector': 'ready-idle'}),
 ('dma:current:ready-busy', {'component': 'dma', 'variant': 'current', 'selector': 'ready-busy'}),
 ('dma:current:ready-set-failure',
  {'component': 'dma', 'variant': 'current', 'selector': 'ready-set-failure'}),
 ('dma:current:rx-filter-idle', {'component': 'dma', 'variant': 'current', 'selector': 'rx-filter-idle'}),
 ('dma:current:rx-filter-busy', {'component': 'dma', 'variant': 'current', 'selector': 'rx-filter-busy'}),
 ('dma:current:restart-success', {'component': 'dma', 'variant': 'current', 'selector': 'restart-success'}),
 ('dma:current:restart-failure', {'component': 'dma', 'variant': 'current', 'selector': 'restart-failure'}),
 ('dma:current:teardown-idle', {'component': 'dma', 'variant': 'current', 'selector': 'teardown-idle'}),
 ('dma:current:teardown-busy-residual',
  {'component': 'dma', 'variant': 'current', 'selector': 'teardown-busy-residual'}),
 ('dma:current:teardown-reset-failure-residual',
  {'component': 'dma', 'variant': 'current', 'selector': 'teardown-reset-failure-residual'}),
 ('dma:current:enable-busy-to-idle',
  {'component': 'dma', 'variant': 'current', 'selector': 'enable-busy-to-idle'}),
 ('dma:current:enable-nic-vanishes',
  {'component': 'dma', 'variant': 'current', 'selector': 'enable-nic-vanishes'}),
 ('unwind:current:sys-failure', {'component': 'unwind', 'variant': 'current', 'selector': 'sys-failure'}),
 ('unwind:current:top-failure', {'component': 'unwind', 'variant': 'current', 'selector': 'top-failure'}),
 ('unwind:current:hif-failure', {'component': 'unwind', 'variant': 'current', 'selector': 'hif-failure'}),
 ('unwind:current:mcu-sys-failure',
  {'component': 'unwind', 'variant': 'current', 'selector': 'mcu-sys-failure'}),
 ('unwind:current:mcu-hw-failure',
  {'component': 'unwind', 'variant': 'current', 'selector': 'mcu-hw-failure'}),
 ('unwind:current:eeprom-failure',
  {'component': 'unwind', 'variant': 'current', 'selector': 'eeprom-failure'}),
 ('unwind:current:mac-failure', {'component': 'unwind', 'variant': 'current', 'selector': 'mac-failure'}),
 ('unwind:current:phy-failure', {'component': 'unwind', 'variant': 'current', 'selector': 'phy-failure'}),
 ('unwind:current:mlme-failure', {'component': 'unwind', 'variant': 'current', 'selector': 'mlme-failure'}),
 ('unwind:current:ap-arm-failure',
  {'component': 'unwind', 'variant': 'current', 'selector': 'ap-arm-failure'}),
 ('unwind:current:ready-arm-failure',
  {'component': 'unwind', 'variant': 'current', 'selector': 'ready-arm-failure'}),
 ('unwind:current:success', {'component': 'unwind', 'variant': 'current', 'selector': 'success'}),
 ('unwind:current:unwind-busy-residual',
  {'component': 'unwind', 'variant': 'current', 'selector': 'unwind-busy-residual'}),
 ('unwind:current:open-irq-failure',
  {'component': 'unwind', 'variant': 'current', 'selector': 'open-irq-failure'}),
 ('unwind:current:open-mlme-failure',
  {'component': 'unwind', 'variant': 'current', 'selector': 'open-mlme-failure'}),
 ('unwind:current:open-success', {'component': 'unwind', 'variant': 'current', 'selector': 'open-success'}))

EXPECTED = {'init:current:tr-oom1': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:tr-oom2': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:tr-oom3': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:tr-normal': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:tr-owner': [1, 1, -1, 1, 1, 0, 0, 0],
 'init:current:tr-partial': [1, 1, -1, 1, 1, 0, 0, 0],
 'init:current:tr-reopen': [0, 1, 0, 1, 1, 0, 0, 0],
 'init:current:ser-init-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:ser-attach-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:ser-normal': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:ser-owner': [1, 1, -1, 1, 1, 0, 0, 0],
 'init:current:ser-joined': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:ser-natural-exit': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:ser-reopen': [0, 1, 0, 1, 1, 0, 0, 0],
 'init:current:hw-init-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:hw-attach-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:hw-ser-init-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:hw-ser-attach-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:hw-normal': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:hw-owner': [1, 1, -1, 1, 1, 0, 0, 0],
 'init:current:hw-reopen': [0, 1, 0, 1, 1, 0, 0, 0],
 'init:current:mgmt-init-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:mgmt-attach-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:mgmt-normal': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:ba-oom': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:ba-owner': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:ba-reopen': [1, 1, 1, 1, 1, 0, 0, 0],
 'init:current:qm-init-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:qm-notify-failure': [1, 1, 0, 1, 1, 0, 0, 0],
 'init:current:qm-normal': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:qm-owner': [1, 1, -1, 1, 1, 0, 0, 0],
 'init:current:tm-qm-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:tm-hif-failure': [3, 1, 0, 1, 1, 0, 0, 0],
 'init:current:tm-invalid-method': [1, 1, 0, 1, 1, 0, 0, 0],
 'init:current:tm-normal': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:tm-owner': [1, 1, -1, 1, 1, 0, 0, 0],
 'init:current:sys-mgmt-init-failure': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-mgmt-attach-failure': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-hw-init-failure': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-hw-attach-failure': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-ser-init-failure': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-ser-attach-failure': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-config-failure': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-ba-oom': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-measure-oom': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-tpc-oom': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-tr-oom1': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-tr-oom2': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-tr-oom3': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-qm-failure': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-tm-qm-failure': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-tm-hif-failure': [0, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-normal': [1, 1, -1, 1, 1, 0, 0, 0],
 'init:current:sys-owner': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:sys-reopen': [1, 1, 1, 1, 1, 0, 0, 0],
 'init:current:sys-old-ser': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:sys-old-ba': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:sys-old-measure': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:sys-old-tpc': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:sys-old-tr': [0, 1, -1, 1, 1, 0, 0, 0],
 'init:current:sys-retired': [1, 1, -1, 1, 1, 0, 0, 0],
 'dma:current:enable-idle': [1, 0, 0, 0, 1, 1, 0, 0, 2, 1, 2, 1, 0],
 'dma:current:enable-busy': [0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 201, 201],
 'dma:current:enable-nic-missing': [0, 256, 0, 0, 1, 1, 0, 0, 0, 0, 0],
 'dma:current:enable-set-failure': [0, 0, 0, 0, 1, 1, 0, 0, 2, 1, 2, 1, 0],
 'dma:current:stop-idle': [1, 0, 0, 0, 1, 1, 0, 0, 2, 3, 1, 1, 0],
 'dma:current:stop-busy': [0, 0, 0, 0, 1, 1, 0, 0, 2, 3, 1, 201, 201],
 'dma:current:stop-set-failure': [0, 0, 0, 0, 1, 1, 0, 0, 1, 3, 0, 0],
 'dma:current:reset-idle': [1, 0, 0, 0, 1, 1, 0, 0, 3, 3, 1, 4, 1, 0],
 'dma:current:reset-busy': [0, 0, 0, 0, 1, 1, 0, 0, 2, 3, 1, 201, 201],
 'dma:current:reset-set-failure': [0, 0, 0, 0, 1, 1, 0, 0, 1, 3, 0, 0],
 'dma:current:reset-callback-failure': [0, 0, 0, 0, 1, 1, 0, 0, 3, 3, 1, 4, 1, 0],
 'dma:current:asic-non-mt': [0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0],
 'dma:current:fw-init-idle': [0, 285212672, 1, 1, 1, 1, 0, 0, 4, 7, 5, 1, 2, 1, 0],
 'dma:current:fw-init-busy': [1, 0, 0, 1, 1, 1, 0, 0, 4, 7, 5, 1, 6, 201, 201],
 'dma:current:fw-init-set-failure': [1, 0, 0, 1, 1, 1, 0, 0, 5, 7, 5, 1, 2, 6, 1, 0],
 'dma:current:fw-init-no-callback': [1, 0, 0, 1, 1, 1, 0, 0, 1, 7, 0, 0],
 'dma:current:fw-init-non-mt': [1, 0, 0, 1, 1, 1, 0, 0, 1, 7, 0, 0],
 'dma:current:ready-idle': [1, 268435456, 1, 0, 1, 1, 0, 0, 5, 5, 1, 2, 8, 9, 1, 0],
 'dma:current:ready-busy': [0, 0, 0, 0, 1, 1, 0, 0, 3, 5, 1, 6, 201, 201],
 'dma:current:ready-set-failure': [0, 0, 0, 0, 1, 1, 0, 0, 4, 5, 1, 2, 6, 1, 0],
 'dma:current:rx-filter-idle': [1, 0, 0, 0, 1, 1, 0, 0, 4, 1, 2, 8, 9, 1, 0],
 'dma:current:rx-filter-busy': [0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 201, 201],
 'dma:current:restart-success': [0, 0, 0, 0, 1, 1, 0, 0, 1, 10, 0, 0],
 'dma:current:restart-failure': [7, 0, 0, 0, 1, 1, 0, 0, 1, 10, 0, 0],
 'dma:current:teardown-idle': [0, 0, 0, 0, 0, 0, 0, 0, 8, 14, 15, 3, 1, 4, 11, 12, 13, 1, 0],
 'dma:current:teardown-busy-residual': [1, 0, 0, 0, 0, 0, 2, 0, 7, 14, 15, 3, 1, 11, 12, 13, 201, 201],
 'dma:current:teardown-reset-failure-residual': [1,
                                                 0,
                                                 0,
                                                 0,
                                                 0,
                                                 0,
                                                 0,
                                                 0,
                                                 8,
                                                 14,
                                                 15,
                                                 3,
                                                 1,
                                                 4,
                                                 11,
                                                 12,
                                                 13,
                                                 1,
                                                 0],
 'dma:current:enable-busy-to-idle': [1, 0, 0, 0, 1, 1, 0, 0, 2, 1, 2, 3, 2],
 'dma:current:enable-nic-vanishes': [0, 256, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0],
 'unwind:current:sys-failure': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
 'unwind:current:top-failure': [0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                1,
                                8,
                                1,
                                2,
                                20,
                                25,
                                26,
                                17,
                                21,
                                20,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0],
 'unwind:current:hif-failure': [0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                1,
                                9,
                                1,
                                2,
                                3,
                                20,
                                25,
                                26,
                                17,
                                21,
                                20,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0],
 'unwind:current:mcu-sys-failure': [0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    1,
                                    13,
                                    1,
                                    2,
                                    3,
                                    4,
                                    20,
                                    25,
                                    26,
                                    17,
                                    6,
                                    20,
                                    7,
                                    21,
                                    20,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0],
 'unwind:current:mcu-hw-failure': [0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   1,
                                   14,
                                   1,
                                   2,
                                   3,
                                   4,
                                   5,
                                   20,
                                   25,
                                   26,
                                   17,
                                   6,
                                   20,
                                   7,
                                   21,
                                   20,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0],
 'unwind:current:eeprom-failure': [0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   1,
                                   14,
                                   1,
                                   2,
                                   3,
                                   4,
                                   5,
                                   8,
                                   20,
                                   25,
                                   26,
                                   17,
                                   6,
                                   7,
                                   21,
                                   20,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0],
 'unwind:current:mac-failure': [0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                1,
                                16,
                                1,
                                2,
                                3,
                                4,
                                5,
                                8,
                                10,
                                20,
                                25,
                                26,
                                17,
                                9,
                                6,
                                7,
                                21,
                                20,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0],
 'unwind:current:phy-failure': [0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                1,
                                17,
                                1,
                                2,
                                3,
                                4,
                                5,
                                8,
                                10,
                                11,
                                20,
                                25,
                                26,
                                17,
                                9,
                                6,
                                7,
                                21,
                                20,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0],
 'unwind:current:mlme-failure': [0,
                                 64,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 1,
                                 19,
                                 1,
                                 2,
                                 3,
                                 4,
                                 5,
                                 8,
                                 10,
                                 11,
                                 12,
                                 13,
                                 20,
                                 25,
                                 26,
                                 17,
                                 9,
                                 6,
                                 7,
                                 21,
                                 20,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0],
 'unwind:current:ap-arm-failure': [0,
                                   64,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   1,
                                   22,
                                   1,
                                   2,
                                   3,
                                   4,
                                   5,
                                   8,
                                   10,
                                   11,
                                   12,
                                   14,
                                   15,
                                   16,
                                   13,
                                   20,
                                   25,
                                   26,
                                   17,
                                   9,
                                   6,
                                   7,
                                   21,
                                   20,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0,
                                   0],
 'unwind:current:ready-arm-failure': [0,
                                      64,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      1,
                                      23,
                                      1,
                                      2,
                                      3,
                                      4,
                                      5,
                                      8,
                                      10,
                                      11,
                                      12,
                                      14,
                                      15,
                                      15,
                                      16,
                                      13,
                                      20,
                                      25,
                                      26,
                                      17,
                                      9,
                                      6,
                                      7,
                                      21,
                                      20,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0],
 'unwind:current:success': [1,
                            285212674,
                            1,
                            1,
                            1,
                            1,
                            1,
                            1,
                            1,
                            1,
                            1,
                            1,
                            1,
                            0,
                            0,
                            0,
                            12,
                            1,
                            2,
                            3,
                            4,
                            5,
                            8,
                            10,
                            11,
                            12,
                            14,
                            15,
                            15,
                            0,
                            0,
                            0,
                            1,
                            1,
                            1],
 'unwind:current:unwind-busy-residual': [0,
                                         64,
                                         0,
                                         0,
                                         0,
                                         0,
                                         0,
                                         0,
                                         0,
                                         0,
                                         0,
                                         0,
                                         1,
                                         0,
                                         1,
                                         1,
                                         19,
                                         1,
                                         2,
                                         3,
                                         4,
                                         5,
                                         8,
                                         10,
                                         11,
                                         12,
                                         13,
                                         20,
                                         25,
                                         26,
                                         17,
                                         9,
                                         6,
                                         7,
                                         21,
                                         20,
                                         0,
                                         0,
                                         0,
                                         0,
                                         0,
                                         0],
 'unwind:current:open-irq-failure': [-16,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     1,
                                     22,
                                     1,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0],
 'unwind:current:open-mlme-failure': [-1,
                                      64,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      1,
                                      21,
                                      22,
                                      1,
                                      2,
                                      3,
                                      4,
                                      5,
                                      8,
                                      10,
                                      11,
                                      12,
                                      13,
                                      20,
                                      25,
                                      26,
                                      17,
                                      9,
                                      6,
                                      7,
                                      21,
                                      20,
                                      23,
                                      1,
                                      1,
                                      0,
                                      0,
                                      0,
                                      0],
 'unwind:current:open-success': [0,
                                 285212674,
                                 1,
                                 1,
                                 1,
                                 1,
                                 1,
                                 1,
                                 1,
                                 1,
                                 1,
                                 1,
                                 1,
                                 0,
                                 0,
                                 0,
                                 14,
                                 22,
                                 1,
                                 2,
                                 3,
                                 4,
                                 5,
                                 8,
                                 10,
                                 11,
                                 12,
                                 14,
                                 15,
                                 15,
                                 24,
                                 1,
                                 0,
                                 1,
                                 1,
                                 1,
                                 1]}

COMPILED_OBJECTS = {'data': ('drivers/net/wireless/mediatek/mt7615/embedded/common/cmm_data.o',
          'init_tr',
          ('tr_ctl_init', 'tr_ctl_exit')),
 'basic': ('drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl_basic.o',
           'init_basic',
           ('ser_init', 'ser_exit', 'HwCtrlSerExit', 'HwCtrlInit', 'HwCtrlExit')),
 'mgmt': ('drivers/net/wireless/mediatek/mt7615/os/linux/rt_rbus_pci_drv.o',
          'init_mgmt',
          ('RtmpMgmtTaskInit', 'RtmpMgmtTaskExit')),
 'ba': ('drivers/net/wireless/mediatek/mt7615/embedded/common/ba_action.o',
        'init_ba',
        ('ba_reordering_resource_init', 'ba_reordering_resource_release')),
 'spectrum': ('drivers/net/wireless/mediatek/mt7615/embedded/common/spectrum.o',
              'init_spectrum',
              ('MeasureReqTabInit', 'MeasureReqTabExit', 'TpcReqTabInit', 'TpcReqTabExit')),
 'qm': ('drivers/net/wireless/mediatek/mt7615/embedded/common/qm.o', 'init_qm', ('qm_init', 'qm_exit')),
 'tm': ('drivers/net/wireless/mediatek/mt7615/os/linux/tm.o', 'init_tm', ('tm_init', 'tm_exit')),
 'init': ('drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.o',
          'init_adapter',
          ('RTMPAllocAdapterBlock', 'WfHifSysExit', 'WfMcuSysInit', 'RTMPEnableRxTx')),
 'profile': ('drivers/net/wireless/mediatek/mt7615/os/linux/rt_profile.o', 'init_free', ('RTMPFreeAdapter',)),
 'dma': ('drivers/net/wireless/mediatek/mt7615/embedded/common/cmm_mac_pci.o',
         'dma_dma',
         ('RT28XXDMAEnable', 'RT28XXDMAStop', 'RT28XXDMAReset', 'RTMPResetTxRxRingMemory')),
 'asic': ('drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_asic.o',
          'dma_asic',
          ('AsicWaitPDMAIdle', 'AsicResetWPDMA')),
 'asic_mt': ('drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_asic_mt_dmac.o',
             'dma_asic_mt',
             ('MtAsicWaitPDMAIdle', 'MtAsicResetWPDMA')),
 'chip_hw': ('drivers/net/wireless/mediatek/mt7615/chips/mt7615.o',
             'dma_chip_hw',
             ('hif_wait_WPDMA_idle', 'hif_reset_WPDMA', 'hif_set_WPDMA')),
 'andes': ('drivers/net/wireless/mediatek/mt7615/embedded/mcu/andes_mt.o',
           'dma_andes',
           ('AndesMTPciFwInit',)),
 'chip': ('drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_chip.o', 'dma_chip', ('chip_fw_init',)),
 'ready': ('drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.o',
           'init_sys',
           ('mt_wifi_init', 'RTMPDrvClose', 'rtmp_sys_task_exit')),
 'open': ('drivers/net/wireless/mediatek/mt7615/os/linux/rt_main_dev.o',
          'unwind_open',
          ('mt_wifi_open', 'RtmpOSIRQRequest')),
 'hardware': ('drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.o',
              'dma_hw',
              ('WfInit', 'WfMcuInit', 'WfSysPosExit')),
 'fwdl': ('drivers/net/wireless/mediatek/mt7615/mcu/fwdl.o', 'dma_fwdl', ('NICRestartFirmware',)),
 'ap': ('drivers/net/wireless/mediatek/mt7615/embedded/ap/ap.o',
        'unwind_ap',
        ('rtmp_ap_init', 'ApAutoChannelAtBootUp', 'APOverlappingBSSScan')),
 'chip_mt': ('drivers/net/wireless/mediatek/mt7615/hw_ctrl/cmm_chip_mt.o',
             'dma_chip_mt',
             ('PDMAResetAndRecovery',)),
 'mcu': ('drivers/net/wireless/mediatek/mt7615/embedded/mcu/mcu.o',
         'dma_mcu',
         ('MCUSysPrepare', 'MCUSysInit', 'ChipOpsMCUHook'))}

PARENT_EXPORTS = ('target-wifi-built.ko', 'target-wifi-shipped.ko', 'target-wifi-module.cmd', 'target-wifi-link.cmd')

BUILT_MODULE = 'drivers/net/wireless/mediatek/mt7615_ap/mt_7615e.ko'

SHIPPED_MODULE = 'lib/modules/4.4.198/kernel/drivers/net/wireless/mediatek/mt7615_ap/mt_7615e.ko'

FLAGS = ('-std=gnu99',
 '-Os',
 '-static',
 '-s',
 '-Wall',
 '-Wextra',
 '-Werror',
 '-fno-strict-aliasing',
 '-pthread',
 '-Wno-unused-parameter',
 '-Wno-unused-variable',
 '-Wno-unused-but-set-variable')

REQUIRED_OBJECT_FLAGS = ('-DMT7615',
 '-DRTMP_MAC_PCI',
 '-DRTMP_PCI_SUPPORT',
 '-DCUT_THROUGH',
 '-DERR_RECOVERY',
 '-DRESOURCE_PRE_ALLOC',
 '-fno-strict-aliasing',
 '-DMT_MAC',
 '-DCONFIG_AP_SUPPORT',
 '-DDOT11_N_SUPPORT',
 '-DCONFIG_TX_DELAY')

FORBIDDEN_OBJECT_FLAGS = ('-DWHNAT_SUPPORT',
 '-DRX_CUT_THROUGH',
 '-DCUT_THROUGH_DBG',
 '-DOS_ABL_FUNC_SUPPORT',
 '-UKTHREAD_SUPPORT',
 '-fstrict-aliasing',
 '-DCONFIG_PROPRIETARY_DRIVER',
 '-DWSC_INCLUDED',
 '-DWSC_AP_SUPPORT',
 '-DWSC_STA_SUPPORT',
 '-DWSC_V2_SUPPORT',
 '-DRT_BIG_ENDIAN')

SOURCE_ABI = {'enabled_config': ('CONFIG_RALINK_MT7621=y',
                    'CONFIG_CHIP_MT7615E=y',
                    'CONFIG_MT7615_AP=m',
                    'CONFIG_CPU_LITTLE_ENDIAN=y'),
 'disabled_config': ('# CONFIG_WHNAT_SUPPORT is not set',
                     '# CONFIG_WSC_INCLUDED is not set',
                     '# CONFIG_WSC_V2_SUPPORT is not set')}

ROLE = 'Current initialization/DMA checked-error and known-residual inert source adapters'

LIMITS = ('These fixed inert control-flow observations include an explicitly known unsafe legacy busy-teardown case; '
 'PASS does not close that risk.',
 'The ordinary close/remove failed-idle ownership quarantine remains unresolved: the model observes two '
 'legacy unsafe frees on perpetual busy.',
 'Stop/idle/arm, callback statuses and staged software unwind are modeled with private memory, '
 'pthread/reference seams and inert IO; no kernel task or DMA executes.',
 'Busy bits and PCI clear-master alone do not prove in-flight bus transactions drained; hardware reset/drain '
 'and all concurrent teardown owners remain unproved.',
 'Actual module configuration is locked to K2P4.4 MT7615 KTHREAD/tasklet/FAST_PATH_QM, little-endian and '
 'WSC-disabled.',
 'Complete functions are copied, but inert preprocessor seams project ownership/error branches; optional '
 'production ATE/UAPSD/MAT and other branches are not all executed.',
 'Whole source-only caller manifests are labeled source-only-not-run, not counted as executed C functions.',
 'Source/object/module/image identities bind a clean full build without independent compiler or relocation '
 'replay.',
 'No device, network, MTD, flash, reboot, historical unsafe source or private backup is executed.')

MAX_SOURCE = 4194304

MAX_REPORT = 16777216

MAX_ELF = 33554432

MAX_COMMAND = 2097152

MAX_STDOUT = 65536

MAX_CASE_SECONDS = 20

def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact(left, right, message):
    require(json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) ==
            json.dumps(right, sort_keys=True, separators=(',', ':'), allow_nan=False), message)


def decode_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'Duplicate Init/DMA JSON key')
            out[key] = value
        return out

    def nonfinite(value):
        raise ValueError('Non-finite Init/DMA JSON value: ' + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
                'Ordinary bounded single-link Init/DMA input required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
                'Init/DMA input changed during read')
        return data
    finally:
        os.close(fd)


def literal_data(source):
    """Parse source data declarations only; never import/execute its generator."""
    values = {}

    def value(node):
        if isinstance(node, ast.Name):
            require(node.id in values, 'Unknown Init/DMA literal alias')
            return values[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = value(node.left), value(node.right)
            require(type(left) is str and type(right) is str, 'Only Init/DMA literal strings concatenate')
            return left + right
        if isinstance(node, ast.Dict):
            require(all(k is not None for k in node.keys), 'Init/DMA dictionary expansion is not literal')
            items = [(value(k), value(v)) for k, v in zip(node.keys, node.values)]
            require(len(dict(items)) == len(items), 'Duplicate Init/DMA literal dictionary key')
            return dict(items)
        if isinstance(node, (ast.Tuple, ast.List)):
            items = [value(n) for n in node.elts]
            return tuple(items) if isinstance(node, ast.Tuple) else items
        return ast.literal_eval(node)

    for node in ast.parse(source).body:
        require(isinstance(node, (ast.Import, ast.Assign, ast.FunctionDef)) or
                isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and
                type(node.value.value) is str, 'Unsupported Init/DMA source top-level execution')
        if isinstance(node, ast.Import):
            require(all(n.name in ('hashlib', 're') for n in node.names), 'Unexpected Init/DMA source import')
        if isinstance(node, ast.Assign):
            require(len(node.targets) == 1 and isinstance(node.targets[0], ast.Name), 'Init/DMA literal assignment required')
            name = node.targets[0].id
            require(name not in values, 'Duplicate Init/DMA literal assignment')
            values[name] = value(node.value)
    return values


def model_data_hash(values):
    return sha(json.dumps(values, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())


def command_member(text, path):
    return re.search(r'(?<![A-Za-z0-9_./+-])' + re.escape(path) + r'(?![A-Za-z0-9_./+-])', text) is not None


def canonical_command(data):
    require(type(data) is bytes and 0 < len(data) <= MAX_COMMAND and b'\0' not in data,
            'Bounded ordinary Init/DMA command required')
    return data.decode().replace('mt7615_ap/../mt7615/', 'mt7615/')


def compiled_export_names():
    return {'target-init-dma-lifecycle-'+label+suffix
            for label in COMPILED_OBJECTS for suffix in ('.o', '.cmd')}


def compiled_binding_from_bytes(inputs, parent_raw, artifacts, metadata):
    require(set(artifacts) == set(PARENT_EXPORTS) | compiled_export_names(), 'Init/DMA exact compiled export inventory differs')
    parent = decode_json(parent_raw)
    require(type(parent) is dict and type(parent.get('schema_version')) is int and parent['schema_version'] == 1 and
            parent.get('status') == 'PASS' and parent.get('profile') == 'k2p-4.4' and
            parent.get('phase') == 'final-module-image-reference-bound', 'Init/DMA requires completed Factory49 parent')
    binding = parent.get('module_binding', {})
    require(type(binding) is dict and binding.get('status') == 'PASS', 'Init/DMA parent module binding absent')
    for name in PARENT_EXPORTS:
        require(binding.get('exports', {}).get(name) == sha(artifacts[name]), 'Init/DMA actual Factory export differs: ' + name)
    built, shipped = metadata(artifacts['target-wifi-built.ko'], 1), metadata(artifacts['target-wifi-shipped.ko'], 1)
    require(binding.get('built_module', {}).get('ELF', {}).get('sha256') == built['sha256'] and
            binding.get('shipped_module', {}).get('ELF', {}).get('sha256') == shipped['sha256'] and
            binding.get('shipped_module', {}).get('path') == SHIPPED_MODULE, 'Init/DMA parent actual module identity differs')
    image = parent.get('kernel_reference', {}).get('image_sha256')
    require(type(image) is str and re.fullmatch('[0-9a-f]{64}', image), 'Init/DMA parent image identity absent')
    for key in ('wifi_makefile', 'wifi_config'):
        require(parent.get('source_sha256', {}).get(key) == sha(inputs[key].encode()), 'Init/DMA parent configured source differs')
    require(type(parent.get('required_cases')) is list and len(parent['required_cases']) == 49 and
            len(set(parent['required_cases'])) == 49 and type(parent.get('checks')) is list and len(parent['checks']) == 49,
            'Init/DMA completed parent49 cases absent')
    module_cmd = canonical_command(artifacts['target-wifi-module.cmd'])
    aggregate = canonical_command(artifacts['target-wifi-link.cmd'])
    aggpath = BUILT_MODULE.removesuffix('.ko') + '.o'
    require(command_member(module_cmd, BUILT_MODULE) and command_member(module_cmd, aggpath) and
            command_member(aggregate, aggpath), 'Init/DMA module/aggregate command differs')
    objects = {}
    for label, (relative, source_key, names) in COMPILED_OBJECTS.items():
        stem = 'target-init-dma-lifecycle-' + label
        data, cmd = artifacts[stem + '.o'], artifacts[stem + '.cmd']
        text = canonical_command(cmd)
        require(command_member(text, relative) and command_member(text, relative.removesuffix('.o') + '.c') and
                command_member(aggregate, relative), 'Init/DMA object/source/module command membership differs')
        require(all(command_member(text, flag) for flag in REQUIRED_OBJECT_FLAGS) and
                all(not command_member(text, '-U' + flag[2:]) for flag in REQUIRED_OBJECT_FLAGS if flag.startswith('-D')) and
                not any(command_member(text, flag) for flag in FORBIDDEN_OBJECT_FLAGS),
                'Init/DMA configured object preprocessor/aliasing selection differs')
        obj = metadata(data, 1)
        symbols = {}
        for name in names:
            a, b = obj['function_symbols'].get(name, []), built['function_symbols'].get(name, [])
            require(len(a) == len(b) == 1 and a[0]['bytes'] > 0 and b[0]['bytes'] > 0,
                    'Init/DMA implementation symbol absent/ambiguous: ' + name)
            symbols[name] = {'object_symbol': a[0], 'module_symbol': b[0]}
        objects[label] = {'object_file': stem + '.o', 'command_file': stem + '.cmd', 'source_key': source_key,
                          'source_sha256': sha(inputs[source_key].encode()), 'command_sha256': sha(cmd),
                          'ELF': obj, 'required_symbols': list(names), 'symbol_bindings': symbols}
    return {'status': 'PASS', 'factory_report_file': 'target-wifi-factory.json', 'factory_report_sha256': sha(parent_raw),
            'factory_cases': 49, 'image_sha256': image, 'built_module_sha256': built['sha256'],
            'shipped_module_sha256': shipped['sha256'],
            'parent_exports_sha256': {n: sha(artifacts[n]) for n in PARENT_EXPORTS},
            'compiled_exports_sha256': {n: sha(artifacts[n]) for n in sorted(compiled_export_names())}, 'objects': objects,
            'source_to_compiled_scope': 'Clean locked full-build compilation and object-to-module relocation attestations; no independent replay.'}


def collect_compiled(trunk, wifi_report):
    artifacts = {n: read_regular(wifi_report.parent / n, MAX_COMMAND if n.endswith('.cmd') else MAX_ELF) for n in PARENT_EXPORTS}
    for label, (relative, _, _) in COMPILED_OBJECTS.items():
        obj = trunk / 'linux-4.4.x' / relative
        artifacts['target-init-dma-lifecycle-' + label + '.o'] = read_regular(obj, MAX_ELF)
        artifacts['target-init-dma-lifecycle-' + label + '.cmd'] = read_regular(obj.with_name('.' + obj.name + '.cmd'), MAX_COMMAND)
    return artifacts


def function(source, name):
    token = r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\[\s\S]|[^"\\])*"'
    masked = re.sub(token, lambda m: ' '*len(m.group()), source)
    pattern = r'^(?:static\s+)?(?:inline\s+)?(?:VOID|INT|INT32|UINT32|UCHAR|BOOLEAN|NTSTATUS|NDIS_STATUS|int|void)\s+'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{'
    found = list(re.finditer(pattern, masked, re.M))
    require(len(found) == 1, 'Missing/ambiguous current init/DMA function: '+name)
    start = found[0].start(); opening = masked.index('{', start); depth = 0
    for match in re.finditer(token+r'|[{}]', source[opening:]):
        if match.group() == '{': depth += 1
        elif match.group() == '}':
            depth -= 1
            if not depth: return source[start:opening+match.end()]
    raise ValueError('Unterminated current function: '+name)


def validate_contract():
    require(set(COMPONENTS)=={'init','dma','unwind'} and len(CASES)==106 and len(COMPILED_OBJECTS)==22,
            'Exact current init61/DMA29/unwind16 with22objects required')
    require({key:sum(options['component']==key for _,options in CASES)for key in COMPONENTS}==
            {'init':61,'dma':29,'unwind':16},'Exact current init/DMA component counts differ')
    require(len(set(name for name,_ in CASES)) == len(CASES) and set(EXPECTED) == {name for name,_ in CASES},
            'Init/DMA exact case inventory differs')
    for name,options in CASES:
        require(type(options) is dict and set(options) == {'component','variant','selector'} and
                options['component'] in COMPONENTS and options['variant'] == 'current' and
                type(options['selector']) is str and re.fullmatch('[a-z0-9-]{1,100}',options['selector']) and
                name == options['component']+':current:'+options['selector'], 'Init/DMA typed selector differs')
    for spec in COMPONENTS.values():
        require(spec['variants'] == ('current',) and
                all(SOURCE_PATHS[spec['source_keys'][k]] == v for k,v in spec['paths'].items()) and
                spec['harness_key'] in SOURCE_PATHS, 'Init/DMA source mapping differs')


def validate_records(rows):
    require(type(rows) is list and len(rows) == len(CASES), 'Exact init/DMA observations required')
    exact(rows,[{'case':name,'inputs':options,'observed':EXPECTED[name]}for name,options in CASES],
          'Init/DMA exact typed/order observation differs')


def status_contract(text, names):
    values = {'SUCCESS': 0, 'FAILURE': 1, 'INVALID_DATA': 2, 'RESOURCES': 3}
    for name in names:
        found = re.findall(r'^#define NDIS_STATUS_'+name+r'\s+(0x[0-9a-fA-F]+)\s*$', text, re.M)
        require(len(found) == 1 and int(found[0], 16) == values[name], 'Real NDIS status differs: '+name)








def source_selection(inputs):
    require(set(inputs) == set(SOURCE_PATHS), 'Exact init/DMA source inventory required')
    for line in SOURCE_ABI['enabled_config']+SOURCE_ABI['disabled_config']:
        require(len(re.findall('^'+re.escape(line)+'$',inputs['wifi_config'],re.M)) == 1,
                'Actual K2P init/DMA configured profile differs')
    require('DRV_NAME = mt_7615e' in inputs['wifi_makefile'] and
            command_member(inputs['kernel_makefile'],'-fno-strict-aliasing'),
            'Actual init/DMA module/compiler profile differs')
    for key in ('flags','wifi_makefile'):
        selected=re.findall(r'ifeq \(\$\(CONFIG_CHIP_MT7615E\),y\)\n([\s\S]*?)\nendif',inputs[key])
        require(len(selected)==1 and all(command_member(selected[0],f)for f in
                ('-DMT7615','-DRTMP_MAC_PCI','-DRTMP_PCI_SUPPORT')),
                'Actual init/DMA selected compiler branch differs')
    config=inputs['driver_config']
    require(all(line in config for line in ('HAS_RESOURCE_PRE_ALLOC=y','HAS_RX_CUT_THROUGH=n',
            'HAS_CUT_THROUGH_DBG=n','WFLAGS += -DERR_RECOVERY')),
            'Actual init/DMA allocator/SER configuration differs')
    require('MT7615_ChipCap.qm_tm = TASKLET_METHOD;' in inputs['chip'] and
            'MT7615_ChipCap.hif_tm = TASKLET_METHOD;' in inputs['chip'],
            'Actual init/DMA tasklet method differs')
    require('MT7615_ChipCap.qm = FAST_PATH_QM;' in inputs['chip'] and
            '#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)\n#define KTHREAD_SUPPORT 1' in inputs['os_header'],
            'Actual init/DMA FAST_PATH_QM/KTHREAD selection differs')
    require(re.search(r'^VERSION\s*=\s*4$',inputs['kernel_makefile'],re.M) and
            re.search(r'^PATCHLEVEL\s*=\s*4$',inputs['kernel_makefile'],re.M),
            'Actual init/DMA kernel version differs')
    status_contract(inputs['os_header'],('SUCCESS','FAILURE','RESOURCES','INVALID_DATA'))
    callback=re.findall(r'NDIS_STATUS\s+\(\*FwInit\)\(struct _RTMP_ADAPTER \*pAd\);',
                        inputs[COMPONENTS['dma']['source_keys']['chip_header']])
    require(len(callback)==1,'Actual checked firmware init callback declaration differs')
    wait_callback=re.findall(r'BOOLEAN\s+\(\*hif_wait_dma_idle\)\(struct _RTMP_ADAPTER \*pAd,\s*INT round,\s*INT wait_us\);',
                             inputs[COMPONENTS['dma']['source_keys']['chip_header']])
    require(len(wait_callback)==1,'Actual checked DMA wait callback declaration differs')
    outer={}
    for component,spec in COMPONENTS.items():
        data=literal_data(inputs[spec['harness_key']])
        require(model_data_hash(data)==spec['model_data_sha256'],'Init/DMA source-only model pin differs')
        mapping=spec.get('source_only_functions',{})
        exact(data.get('SOURCE_ONLY_FUNCTION_SOURCES',{}),mapping,'Init/DMA source-only function mapping differs')
        outer[component]={name:{'source':spec['paths'][key],'execution':'source-only-not-run',
              'full_body_sha256':sha(function(inputs[spec['source_keys'][key]],name).encode())}
              for name,key in mapping.items()}
    return {'status':'PASS','current_K2P_profile':True,'source_only_error_chain':True,
            'hardware_DMA_or_reset_executed':False,'model_preprocessor_is_reduced_control_flow':True,'outer_function_manifest':outer,
            'fw_init_callback_declaration_sha256':sha(callback[0].encode()),
            'hif_wait_callback_declaration_sha256':sha(wait_callback[0].encode()),
            'known_busy_teardown_release_gap':True}


def source_definitions(inputs,spec,data,prefix):
    declarations=data.get('SOURCE_DECLARATIONS',{})
    require(type(declarations)is dict,'Init/DMA declarations must be literal mapping')
    if not declarations:
        require('SOURCE_DEFINITIONS'not in prefix,'Unbound init/DMA declaration marker')
        return prefix
    require(prefix.count('SOURCE_DEFINITIONS')==1,'Exactly one init/DMA declaration marker required')
    fragments=[]
    for pattern,key in declarations.items():
        require(type(pattern)is type(key)is str and key in spec['source_keys'],'Init/DMA declaration source key differs')
        rows=re.findall(pattern,inputs[spec['source_keys'][key]],re.M)
        require(len(rows)==1 and type(rows[0])is str and rows[0],'Unique complete init/DMA source declaration required')
        fragments.append(rows[0])
    return prefix.replace('SOURCE_DEFINITIONS','\n'.join(fragments))


def generate_component(inputs,component):
    spec=COMPONENTS[component];data=literal_data(inputs[spec['harness_key']])
    require(model_data_hash(data)==spec['model_data_sha256'],'Reviewed init/DMA literal model differs')
    exact(data['SOURCE_PATHS'],spec['paths'],'Init/DMA model source paths differ')
    exact(data['FUNCTION_SOURCES'],spec['functions'],'Init/DMA whole-function mapping differs')
    selectors=tuple(o['selector']for _,o in CASES if o['component']==component)
    exact(data['CASE_NAMES'],selectors,'Init/DMA exact selectors differ')
    exact(data['EXPECTED_ROWS'],{o['selector']:EXPECTED[n]for n,o in CASES if o['component']==component},
          'Init/DMA exact typed expected rows differ')
    exact(data['BODY_ORDER'],tuple(spec['functions']),'Init/DMA body order differs')
    prefix,suffix=data['PREFIX'],data['SUFFIX']
    require(type(prefix)is type(suffix)is str and suffix.count('CASE_ADMISSION')==1,
            'Init/DMA exact literal/admission marker differs')
    prefix=source_definitions(inputs,spec,data,prefix)
    bodies={name:function(inputs[spec['source_keys'][key]],name)for name,key in spec['functions'].items()}
    admission='if(!('+'||'.join('!strcmp(name,"'+name+'")'for name in selectors)+'))return 91;'
    code=prefix+'\n'.join(bodies.values())+suffix.replace('CASE_ADMISSION',admission)
    require(0<len(code.encode())<=MAX_SOURCE and all(code.count(body)==1 for body in bodies.values()),
            'Init/DMA whole-function inclusion differs')
    return code,{name:{'source':spec['paths'][spec['functions'][name]],'execution':'whole-function',
                       'full_body_sha256':sha(body.encode())}for name,body in bodies.items()}


def check(trunk, compiler, output, preflight=False, wifi_report=None):
    validate_contract()
    require(type(preflight) is bool and ((preflight and wifi_report is None) or (not preflight and wifi_report is not None)),
            'Init/DMA requires preflight alone or final Factory49 report')
    config = read_regular(trunk/'.config', MAX_SOURCE).decode()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M), 'Init/DMA requires configured K2P4.4')
    inputs = {k: read_regular(trunk.parent/p, MAX_SOURCE).decode() for k, p in SOURCE_PATHS.items()}
    selection = source_selection(inputs)
    qemu = shutil.which('qemu-mipsel'); require(qemu is not None, 'qemu-mipsel required')
    rows, probes, manifests, exports = [], {}, {}, {}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='k2p-init-dma-lifecycle-', dir=output.parent) as temporary:
        base = Path(temporary)
        for component in COMPONENTS:
            generated, manifest = generate_component(inputs, component)
            stem = 'target-init-dma-lifecycle-'+component+'-current'
            source, binary = base/(stem+'.c'), base/stem; source.write_text(generated)
            run = subprocess.run([str(compiler), *FLAGS, str(source), '-o', str(binary)], capture_output=True, text=True, timeout=90)
            require(run.returncode == 0, 'Init/DMA static MIPS compile failed: '+run.stdout+run.stderr)
            data = read_regular(binary, MAX_ELF); elf = resident.validate_static_helper(data); stdout_rows = []
            for name, options in CASES:
                if options['component'] != component: continue
                run = subprocess.run([qemu, str(binary), options['selector']], capture_output=True, text=True, timeout=MAX_CASE_SECONDS)
                require(run.returncode == 0 and not run.stderr and 0 < len(run.stdout.encode()) <= MAX_STDOUT,
                        'Init/DMA inert MIPS case failed '+name+': '+run.stdout+run.stderr)
                rows.append({'case': name, 'inputs': options, 'observed': decode_json(run.stdout)})
                stdout_rows.append({'selector': options['selector'], 'stdout': run.stdout})
            raw_stdout = (json.dumps(stdout_rows, indent=2)+'\n').encode()
            exports.update({stem+'.c': generated.encode(), stem: data, stem+'.stdout.json': raw_stdout})
            probes[component] = {'current': {'source_file': stem+'.c', 'source_sha256': sha(generated.encode()),
                'binary_file': stem, 'binary_sha256': sha(data), 'ELF': elf, 'compile_flags': list(FLAGS),
                'stdout_file': stem+'.stdout.json', 'stdout_sha256': sha(raw_stdout)}}
            manifests[component] = {'current': manifest}
    validate_records(rows); binding = None
    if not preflight:
        artifacts = collect_compiled(trunk, wifi_report)
        binding = compiled_binding_from_bytes(inputs, read_regular(wifi_report, MAX_REPORT), artifacts, spi.inspect_elf)
        exports.update({n: d for n, d in artifacts.items() if n in compiled_export_names()})
    output.parent.mkdir(parents=True, exist_ok=True)
    for name, payload in exports.items():
        target = output.parent/name; target.write_bytes(payload)
        if name in {p['current']['binary_file'] for p in probes.values()}: target.chmod(0o755)
    report = {'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4',
        'phase': 'early-source-only' if preflight else 'final-module-reference-bound', 'execution_role': ROLE,
        'required_cases': [n for n, _ in CASES], 'checks': rows, 'source_files': SOURCE_PATHS,
        'source_sha256': {k: sha(v.encode()) for k, v in inputs.items()}, 'component_models': COMPONENTS,
        'source_contract': selection, 'function_manifest': manifests, 'probes': probes,
        'compiled_binding': binding, 'compiler': str(compiler), 'limits': list(LIMITS)}
    output.write_text(json.dumps(report, indent=2)+'\n')
    print('Init/DMA lifecycle: '+str(len(rows))+' inert source/MIPS cases PASS')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'compiler', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--preflight', action='store_true'); parser.add_argument('--wifi-report', type=Path)
    args = parser.parse_args()
    try:
        check(args.trunk.resolve(), args.compiler.resolve(), args.output.resolve(), args.preflight,
              args.wifi_report.resolve() if args.wifi_report else None)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Init/DMA lifecycle validation failed: '+str(error)+'\n')
