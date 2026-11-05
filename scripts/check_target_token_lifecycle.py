#!/usr/bin/env python3
"""Current token/SER/task ownership source adapters and same-image objects."""
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

SOURCE_PATHS = {'token_token': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/cut_through.c',
 'token_hif': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.c',
 'token_hardware': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.c',
 'token_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/cut_through.h',
 'token_os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h',
 'token_harness': 'tests/token_init_harness.py',
 'ser_basic': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl_basic.c',
 'ser_recovery': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl.c',
 'ser_command': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl_cmd.c',
 'ser_os': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_linux.c',
 'ser_close': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.c',
 'ser_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/hw_ctrl.h',
 'ser_task_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_os.h',
 'ser_wire_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/hif/mt_hif_pci.h',
 'ser_flag_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_def.h',
 'ser_harness': 'tests/ser_lifecycle_harness.py',
 'task_harness': 'tests/kthread_owner_harness.py',
 'wifi_config': 'trunk/configs/boards/K2P/kernel-4.4.x.config',
 'flags': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/Makefile.mt_wifi_ap',
 'wifi_makefile': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615_ap/Makefile',
 'kernel_makefile': 'trunk/linux-4.4.x/Makefile',
 'driver_config': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/config.mk',
 'chip': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/chips/mt7615.c',
 'kernel_kthread': 'trunk/linux-4.4.x/kernel/kthread.c'}

COMPONENTS = {'token': {'paths': {'token': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/cut_through.c',
                     'hif': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.c',
                     'hardware': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.c',
                     'header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/cut_through.h',
                     'os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h'},
           'source_keys': {'token': 'token_token',
                           'hif': 'token_hif',
                           'hardware': 'token_hardware',
                           'header': 'token_header',
                           'os_header': 'token_os_header'},
           'functions': {'cut_through_token_list_destroy': 'token',
                         'cut_through_token_list_init': 'token',
                         'cut_through_deinit': 'token',
                         'cut_through_init': 'token',
                         'WfHifSysInit': 'hif',
                         'WfHifInit': 'hardware'},
           'harness_key': 'token_harness',
           'model_data_sha256': '0534395867ebdd22df8da5ef3a24cf1cc294aef0509657c92c5aca34462079bf',
           'variants': ('current',)},
 'ser': {'paths': {'basic': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl_basic.c',
                   'recovery': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl.c',
                   'command': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl_cmd.c',
                   'os': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_linux.c',
                   'close': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.c',
                   'header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/hw_ctrl.h',
                   'task_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_os.h',
                   'wire_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/hif/mt_hif_pci.h',
                   'flag_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_def.h',
                   'os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h'},
         'source_keys': {'basic': 'ser_basic',
                         'recovery': 'ser_recovery',
                         'command': 'ser_command',
                         'os': 'ser_os',
                         'close': 'ser_close',
                         'header': 'ser_header',
                         'task_header': 'ser_task_header',
                         'wire_header': 'ser_wire_header',
                         'flag_header': 'ser_flag_header',
                         'os_header': 'token_os_header'},
         'functions': {'__RtmpOSTaskKill': 'os',
                       'HwRecoveryFromErrorOwned': 'recovery',
                       'HwRecoveryFromError': 'recovery',
                       'ser_ctrl_task': 'basic',
                       'ser_init': 'basic',
                       'HwCtrlSerExit': 'basic',
                       'ser_exit': 'basic',
                       'RTMP_MAC_RECOVERY': 'command'},
         'harness_key': 'ser_harness',
         'model_data_sha256': '93e02e20f176ec51464a8d504d8928f26060af3bfb578b077366043a150ce355',
         'variants': ('current',)},
 'task': {'paths': {'os': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_linux.c',
                    'os_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h',
                    'task_header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/include/rtmp_os.h'},
          'source_keys': {'os': 'ser_os', 'os_header': 'token_os_header', 'task_header': 'ser_task_header'},
          'functions': {'__RtmpOSTaskInit': 'os', '__RtmpOSTaskAttach': 'os', '__RtmpOSTaskKill': 'os'},
          'harness_key': 'task_harness',
          'model_data_sha256': 'ad676332c4a063f113719791b0c96e9fc4e30e64cfa965996f2640f4cac2b000',
          'variants': ('current',)}}

CASES = (('token:current:token-cb-oom', {'component': 'token', 'variant': 'current', 'selector': 'token-cb-oom'}),
 ('token:current:token-tx-list-oom',
  {'component': 'token', 'variant': 'current', 'selector': 'token-tx-list-oom'}),
 ('token:current:token-tx-id-oom',
  {'component': 'token', 'variant': 'current', 'selector': 'token-tx-id-oom'}),
 ('token:current:token-tx-entry-oom',
  {'component': 'token', 'variant': 'current', 'selector': 'token-tx-entry-oom'}),
 ('token:current:token-rx-list-oom',
  {'component': 'token', 'variant': 'current', 'selector': 'token-rx-list-oom'}),
 ('token:current:token-rx-id-oom',
  {'component': 'token', 'variant': 'current', 'selector': 'token-rx-id-oom'}),
 ('token:current:token-rx-entry-oom',
  {'component': 'token', 'variant': 'current', 'selector': 'token-rx-entry-oom'}),
 ('token:current:token-normal', {'component': 'token', 'variant': 'current', 'selector': 'token-normal'}),
 ('token:current:token-repeat-owner',
  {'component': 'token', 'variant': 'current', 'selector': 'token-repeat-owner'}),
 ('token:current:queue-repeat', {'component': 'token', 'variant': 'current', 'selector': 'queue-repeat'}),
 ('token:current:queue-unpublished-owner',
  {'component': 'token', 'variant': 'current', 'selector': 'queue-unpublished-owner'}),
 ('token:current:hif-ring-failure',
  {'component': 'token', 'variant': 'current', 'selector': 'hif-ring-failure'}),
 ('token:current:hif-token-oom', {'component': 'token', 'variant': 'current', 'selector': 'hif-token-oom'}),
 ('token:current:hif-normal', {'component': 'token', 'variant': 'current', 'selector': 'hif-normal'}),
 ('token:current:hif-existing-owner',
  {'component': 'token', 'variant': 'current', 'selector': 'hif-existing-owner'}),
 ('token:current:hif-direct-existing-owner',
  {'component': 'token', 'variant': 'current', 'selector': 'hif-direct-existing-owner'}),
 ('token:current:null-output', {'component': 'token', 'variant': 'current', 'selector': 'null-output'}),
 ('token:current:null-adapter', {'component': 'token', 'variant': 'current', 'selector': 'null-adapter'}),
 ('ser:current:hif-failure', {'component': 'ser', 'variant': 'current', 'selector': 'hif-failure'}),
 ('ser:current:hif-failure-repeat',
  {'component': 'ser', 'variant': 'current', 'selector': 'hif-failure-repeat'}),
 ('ser:current:hif-success', {'component': 'ser', 'variant': 'current', 'selector': 'hif-success'}),
 ('ser:current:recovery-halted', {'component': 'ser', 'variant': 'current', 'selector': 'recovery-halted'}),
 ('ser:current:recovery-failed-entry',
  {'component': 'ser', 'variant': 'current', 'selector': 'recovery-failed-entry'}),
 ('ser:current:producer-running', {'component': 'ser', 'variant': 'current', 'selector': 'producer-running'}),
 ('ser:current:producer-halted', {'component': 'ser', 'variant': 'current', 'selector': 'producer-halted'}),
 ('ser:current:producer-failed', {'component': 'ser', 'variant': 'current', 'selector': 'producer-failed'}),
 ('ser:current:producer-stopped', {'component': 'ser', 'variant': 'current', 'selector': 'producer-stopped'}),
 ('ser:current:stop-normal', {'component': 'ser', 'variant': 'current', 'selector': 'stop-normal'}),
 ('ser:current:stop-repeat', {'component': 'ser', 'variant': 'current', 'selector': 'stop-repeat'}),
 ('ser:current:stop-nonzero-exit',
  {'component': 'ser', 'variant': 'current', 'selector': 'stop-nonzero-exit'}),
 ('ser:current:stop-before-owner-release',
  {'component': 'ser', 'variant': 'current', 'selector': 'stop-before-owner-release'}),
 ('ser:current:ser-reopen-reset', {'component': 'ser', 'variant': 'current', 'selector': 'ser-reopen-reset'}),
 ('ser:current:stop-during-recovery',
  {'component': 'ser', 'variant': 'current', 'selector': 'stop-during-recovery'}),
 ('ser:current:ser-stop-failure', {'component': 'ser', 'variant': 'current', 'selector': 'ser-stop-failure'}),
 ('ser:current:ser-stop-failure-repeat',
  {'component': 'ser', 'variant': 'current', 'selector': 'ser-stop-failure-repeat'}),
 ('ser:current:ser-idle-failure', {'component': 'ser', 'variant': 'current', 'selector': 'ser-idle-failure'}),
 ('ser:current:ser-arm-failure', {'component': 'ser', 'variant': 'current', 'selector': 'ser-arm-failure'}),
 ('ser:current:ser-arm-failure-repeat',
  {'component': 'ser', 'variant': 'current', 'selector': 'ser-arm-failure-repeat'}),
 ('ser:current:ser-qm-failure', {'component': 'ser', 'variant': 'current', 'selector': 'ser-qm-failure'}),
 ('ser:current:ser-tm-failure', {'component': 'ser', 'variant': 'current', 'selector': 'ser-tm-failure'}),
 ('ser:current:recovery-owner-busy',
  {'component': 'ser', 'variant': 'current', 'selector': 'recovery-owner-busy'}),
 ('ser:current:recovery-stopping',
  {'component': 'ser', 'variant': 'current', 'selector': 'recovery-stopping'}),
 ('ser:current:recovery-unpinned',
  {'component': 'ser', 'variant': 'current', 'selector': 'recovery-unpinned'}),
 ('task:current:create-failure', {'component': 'task', 'variant': 'current', 'selector': 'create-failure'}),
 ('task:current:create-order', {'component': 'task', 'variant': 'current', 'selector': 'create-order'}),
 ('task:current:natural-early-exit',
  {'component': 'task', 'variant': 'current', 'selector': 'natural-early-exit'}),
 ('task:current:nonzero-exit', {'component': 'task', 'variant': 'current', 'selector': 'nonzero-exit'}),
 ('task:current:repeat-kill', {'component': 'task', 'variant': 'current', 'selector': 'repeat-kill'}),
 ('task:current:existing-owner', {'component': 'task', 'variant': 'current', 'selector': 'existing-owner'}),
 ('task:current:kill-no-owner', {'component': 'task', 'variant': 'current', 'selector': 'kill-no-owner'}))

EXPECTED = {'token:current:token-cb-oom': [0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:token-tx-list-oom': [0, 2, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:token-tx-id-oom': [0, 3, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:token-tx-entry-oom': [0, 4, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:token-rx-list-oom': [0, 5, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:token-rx-id-oom': [0, 6, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:token-rx-entry-oom': [0, 7, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:token-normal': [1, 7, 7, 3, 1, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:token-repeat-owner': [0, 7, 7, 3, 1, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:queue-repeat': [1, 3, 3, 1, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:queue-unpublished-owner': [0, 1, 1, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:hif-ring-failure': [2, 0, 0, 0, 0, 1, -1, 0, 0, 0, 1, 1, 1, 0, 0, 0],
 'token:current:hif-token-oom': [3, 1, 0, 0, 0, 1, -1, 0, 0, 0, 1, 1, 1, 0, 0, 0],
 'token:current:hif-normal': [0, 7, 7, 3, 1, 1, -1, 0, 0, 0, 1, 1, 0, 1, 1, 0],
 'token:current:hif-existing-owner': [1, 7, 7, 3, 1, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:hif-direct-existing-owner': [1, 7, 7, 3, 1, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:null-output': [0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
 'token:current:null-adapter': [0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
 'ser:current:hif-failure': [1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:hif-failure-repeat': [1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:hif-success': [0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:recovery-halted': [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:recovery-failed-entry': [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:producer-running': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 2, 1, 0, 0],
 'ser:current:producer-halted': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0],
 'ser:current:producer-failed': [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 1, 0, 0],
 'ser:current:producer-stopped': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 0, 0],
 'ser:current:stop-normal': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
 'ser:current:stop-repeat': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
 'ser:current:stop-nonzero-exit': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
 'ser:current:stop-before-owner-release': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0],
 'ser:current:ser-reopen-reset': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0],
 'ser:current:stop-during-recovery': [0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0],
 'ser:current:ser-stop-failure': [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:ser-stop-failure-repeat': [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:ser-idle-failure': [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:ser-arm-failure': [1, 2, 2, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:ser-arm-failure-repeat': [1, 2, 2, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:ser-qm-failure': [1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:ser-tm-failure': [1, 1, 2, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:recovery-owner-busy': [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:recovery-stopping': [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
 'ser:current:recovery-unpinned': [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
 'task:current:create-failure': [1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1],
 'task:current:create-order': [0, 1, 1, 1, 1, 1, 1, 2, 0, 1, 1, 0, 6, 1, 2, 3, 4, 5, 6],
 'task:current:natural-early-exit': [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 7, 1, 2, 3, 7, 4, 5, 6],
 'task:current:nonzero-exit': [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 7, 1, 2, 3, 7, 4, 5, 6],
 'task:current:repeat-kill': [1, 1, 1, 1, 1, 1, 1, 2, 0, 1, 1, 0, 6, 1, 2, 3, 4, 5, 6],
 'task:current:existing-owner': [1, 1, 1, 1, 1, 1, 1, 2, 0, 1, 1, 0, 6, 1, 2, 3, 4, 5, 6],
 'task:current:kill-no-owner': [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0]}

COMPILED_OBJECTS = {'token': ('drivers/net/wireless/mediatek/mt7615/embedded/common/cut_through.o',
           'token_token',
           ('cut_through_init', 'cut_through_deinit')),
 'hif': ('drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init.o', 'token_hif', ('WfHifSysInit',)),
 'hardware': ('drivers/net/wireless/mediatek/mt7615/hw_ctrl/hw_init.o', 'token_hardware', ('WfHifInit',)),
 'recovery': ('drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl.o',
              'ser_recovery',
              ('HwRecoveryFromError',)),
 'basic': ('drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl_basic.o',
           'ser_basic',
           ('HwCtrlSerExit', 'ser_init', 'ser_exit', 'HwCtrlExit', 'ser_ctrl_task')),
 'command': ('drivers/net/wireless/mediatek/mt7615/embedded/hw_ctrl/hw_ctrl_cmd.o',
             'ser_command',
             ('RTMP_MAC_RECOVERY',)),
 'os': ('drivers/net/wireless/mediatek/mt7615/os/linux/rt_linux.o',
        'ser_os',
        ('RtmpOSTaskInit', 'RtmpOSTaskAttach', 'RtmpOSTaskKill')),
 'close': ('drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.o',
           'ser_close',
           ('RTMPDrvClose',))}

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

REQUIRED_OBJECT_FLAGS = ('-DLINUX',
 '-DMT7615',
 '-DRTMP_MAC_PCI',
 '-DRTMP_PCI_SUPPORT',
 '-DCUT_THROUGH',
 '-DERR_RECOVERY',
 '-DRESOURCE_PRE_ALLOC',
 '-fno-strict-aliasing')

FORBIDDEN_OBJECT_FLAGS = ('-DWHNAT_SUPPORT',
 '-DRX_CUT_THROUGH',
 '-DCUT_THROUGH_DBG',
 '-DOS_ABL_FUNC_SUPPORT',
 '-UKTHREAD_SUPPORT',
 '-fstrict-aliasing')

SOURCE_ABI = {'enabled_config': ('CONFIG_RALINK_MT7621=y', 'CONFIG_CHIP_MT7615E=y', 'CONFIG_MT7615_AP=m'),
 'disabled_config': ('# CONFIG_WHNAT_SUPPORT is not set',)}

ROLE = 'Complete current token18, SER25 and task-owner7 inert static MIPS adapters'

LIMITS = ('One serialized lifecycle teardown owner may race SER and its event producer; multiple concurrent teardown '
 'owners are not covered.',
 'Private malloc/pthread/reference/lock and inert queue/register operations are models, not kernel tasks, '
 'PCI, cache or DMA.',
 'The task model uses a uniform ULONG callback ABI; target kernel callback ABI is not executed.',
 'Only current KTHREAD/non-OS_ABL/tasklet profile is covered; other QM algorithms and non-KTHREAD are not '
 'covered.',
 'This gate stubs checked DMA/queue APIs; separate init/DMA probes bind those implementations. '
 'Permanent-busy ordinary close/remove quarantine, hardware reset/drain, whole-system memory and efd2 remain unproved.',
 'Actual source/object/module/parent evidence is bound without independent compiler or relocation replay.',
 'No module, device, network, MTD, flash, reset or historical unsafe source is executed.')

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
            require(key not in out, 'Duplicate Token JSON key')
            out[key] = value
        return out

    def nonfinite(value):
        raise ValueError('Non-finite Token JSON value: ' + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
                'Ordinary bounded single-link Token input required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
                'Token input changed during read')
        return data
    finally:
        os.close(fd)


def literal_data(source):
    """Parse source data declarations only; never import/execute its generator."""
    values = {}

    def value(node):
        if isinstance(node, ast.Name):
            require(node.id in values, 'Unknown Token literal alias')
            return values[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = value(node.left), value(node.right)
            require(type(left) is str and type(right) is str, 'Only Token literal strings concatenate')
            return left + right
        if isinstance(node, ast.Dict):
            require(all(k is not None for k in node.keys), 'Token dictionary expansion is not literal')
            items = [(value(k), value(v)) for k, v in zip(node.keys, node.values)]
            require(len(dict(items)) == len(items), 'Duplicate Token literal dictionary key')
            return dict(items)
        if isinstance(node, (ast.Tuple, ast.List)):
            items = [value(n) for n in node.elts]
            return tuple(items) if isinstance(node, ast.Tuple) else items
        return ast.literal_eval(node)

    for node in ast.parse(source).body:
        require(isinstance(node, (ast.Import, ast.Assign, ast.FunctionDef)) or
                isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and
                type(node.value.value) is str, 'Unsupported Token source top-level execution')
        if isinstance(node, ast.Import):
            require(all(n.name in ('hashlib', 're') for n in node.names), 'Unexpected Token source import')
        if isinstance(node, ast.Assign):
            require(len(node.targets) == 1 and isinstance(node.targets[0], ast.Name), 'Token literal assignment required')
            name = node.targets[0].id
            require(name not in values, 'Duplicate Token literal assignment')
            values[name] = value(node.value)
    return values


def model_data_hash(values):
    return sha(json.dumps(values, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())


def command_member(text, path):
    return re.search(r'(?<![A-Za-z0-9_./+-])' + re.escape(path) + r'(?![A-Za-z0-9_./+-])', text) is not None


def canonical_command(data):
    require(type(data) is bytes and 0 < len(data) <= MAX_COMMAND and b'\0' not in data,
            'Bounded ordinary Token command required')
    return data.decode().replace('mt7615_ap/../mt7615/', 'mt7615/')


def compiled_export_names():
    return {'target-token-lifecycle-'+label+suffix
            for label in COMPILED_OBJECTS for suffix in ('.o', '.cmd')}


def compiled_binding_from_bytes(inputs, parent_raw, artifacts, metadata):
    require(set(artifacts) == set(PARENT_EXPORTS) | compiled_export_names(), 'Token exact compiled export inventory differs')
    parent = decode_json(parent_raw)
    require(type(parent) is dict and type(parent.get('schema_version')) is int and parent['schema_version'] == 1 and
            parent.get('status') == 'PASS' and parent.get('profile') == 'k2p-4.4' and
            parent.get('phase') == 'final-module-image-reference-bound', 'Token requires completed Factory49 parent')
    binding = parent.get('module_binding', {})
    require(type(binding) is dict and binding.get('status') == 'PASS', 'Token parent module binding absent')
    for name in PARENT_EXPORTS:
        require(binding.get('exports', {}).get(name) == sha(artifacts[name]), 'Token actual Factory export differs: ' + name)
    built, shipped = metadata(artifacts['target-wifi-built.ko'], 1), metadata(artifacts['target-wifi-shipped.ko'], 1)
    require(binding.get('built_module', {}).get('ELF', {}).get('sha256') == built['sha256'] and
            binding.get('shipped_module', {}).get('ELF', {}).get('sha256') == shipped['sha256'] and
            binding.get('shipped_module', {}).get('path') == SHIPPED_MODULE, 'Token parent actual module identity differs')
    image = parent.get('kernel_reference', {}).get('image_sha256')
    require(type(image) is str and re.fullmatch('[0-9a-f]{64}', image), 'Token parent image identity absent')
    for key in ('wifi_makefile', 'wifi_config'):
        require(parent.get('source_sha256', {}).get(key) == sha(inputs[key].encode()), 'Token parent configured source differs')
    require(type(parent.get('required_cases')) is list and len(parent['required_cases']) == 49 and
            len(set(parent['required_cases'])) == 49 and type(parent.get('checks')) is list and len(parent['checks']) == 49,
            'Token completed parent49 cases absent')
    module_cmd = canonical_command(artifacts['target-wifi-module.cmd'])
    aggregate = canonical_command(artifacts['target-wifi-link.cmd'])
    aggpath = BUILT_MODULE.removesuffix('.ko') + '.o'
    require(command_member(module_cmd, BUILT_MODULE) and command_member(module_cmd, aggpath) and
            command_member(aggregate, aggpath), 'Token module/aggregate command differs')
    objects = {}
    for label, (relative, source_key, names) in COMPILED_OBJECTS.items():
        stem = 'target-token-lifecycle-' + label
        data, cmd = artifacts[stem + '.o'], artifacts[stem + '.cmd']
        text = canonical_command(cmd)
        require(command_member(text, relative) and command_member(text, relative.removesuffix('.o') + '.c') and
                command_member(aggregate, relative), 'Token object/source/module command membership differs')
        require(all(command_member(text, flag) for flag in REQUIRED_OBJECT_FLAGS) and
                all(not command_member(text, '-U' + flag[2:]) for flag in REQUIRED_OBJECT_FLAGS if flag.startswith('-D')) and
                not any(command_member(text, flag) for flag in FORBIDDEN_OBJECT_FLAGS),
                'Token configured object preprocessor/aliasing selection differs')
        obj = metadata(data, 1)
        symbols = {}
        for name in names:
            a, b = obj['function_symbols'].get(name, []), built['function_symbols'].get(name, [])
            require(len(a) == len(b) == 1 and a[0]['bytes'] > 0 and b[0]['bytes'] > 0,
                    'Token implementation symbol absent/ambiguous: ' + name)
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
        artifacts['target-token-lifecycle-' + label + '.o'] = read_regular(obj, MAX_ELF)
        artifacts['target-token-lifecycle-' + label + '.cmd'] = read_regular(obj.with_name('.' + obj.name + '.cmd'), MAX_COMMAND)
    return artifacts


def function(source, name):
    token = r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\[\s\S]|[^"\\])*"'
    masked = re.sub(token, lambda m: ' '*len(m.group()), source)
    pattern = r'^(?:static\s+)?(?:inline\s+)?(?:VOID|INT|INT32|NTSTATUS|NDIS_STATUS|int)\s+'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{'
    found = list(re.finditer(pattern, masked, re.M))
    require(len(found) == 1, 'Missing/ambiguous current token/SER function: '+name)
    start = found[0].start(); opening = masked.index('{', start); depth = 0
    for match in re.finditer(token+r'|[{}]', source[opening:]):
        if match.group() == '{': depth += 1
        elif match.group() == '}':
            depth -= 1
            if not depth: return source[start:opening+match.end()]
    raise ValueError('Unterminated current function: '+name)


def validate_contract():
    require(set(COMPONENTS) == {'token', 'ser', 'task'} and len(CASES) == 50 and len(COMPILED_OBJECTS) == 8,
            'Fixed token18/SER25/task7 object contract required')
    require(len({name for name, _ in CASES}) == 50 and set(EXPECTED) == {name for name, _ in CASES},
            'Fixed50 case names differ')
    counts = {key: 0 for key in COMPONENTS}
    for name, options in CASES:
        require(type(options) is dict and set(options) == {'component', 'variant', 'selector'} and
                options['component'] in COMPONENTS and options['variant'] == 'current' and
                type(options['selector']) is str and re.fullmatch('[a-z0-9-]{1,100}', options['selector']) and
                name == options['component']+':current:'+options['selector'], 'Fixed token typed selector differs')
        counts[options['component']] += 1
    require(counts == {'token': 18, 'ser': 25, 'task': 7}, 'Fixed component counts differ')
    for spec in COMPONENTS.values():
        require(spec['variants'] == ('current',) and
                all(SOURCE_PATHS[spec['source_keys'][k]] == v for k, v in spec['paths'].items()) and
                spec['harness_key'] in SOURCE_PATHS, 'Fixed token component/source mapping differs')


def validate_records(rows):
    require(type(rows) is list and len(rows) == len(CASES), 'Exactly50 token lifecycle observations required')
    for row, (name, options) in zip(rows, CASES):
        exact(row, {'case': name, 'inputs': options, 'observed': EXPECTED[name]},
              'Token complete typed/order observation differs: '+name)


def status_contract(text, names):
    values = {'SUCCESS': 0, 'FAILURE': 1, 'INVALID_DATA': 2, 'RESOURCES': 3}
    for name in names:
        found = re.findall(r'^#define NDIS_STATUS_'+name+r'\s+(0x[0-9a-fA-F]+)\s*$', text, re.M)
        require(len(found) == 1 and int(found[0], 16) == values[name], 'Real NDIS status differs: '+name)


def token_declarations(text):
    rows = []
    for name in ('ENTRY', 'LIST', 'QUEUE', 'CB'):
        found = re.findall(r'typedef struct _PKT_TOKEN_'+name+r'\s*\{[\s\S]*?\}\s*PKT_TOKEN_'+name+r'(?:\s+____cacheline_aligned)?;', text)
        require(len(found) == 1, 'Real token structure differs: '+name)
        rows.append(found[0])
    require('#define DEFAUT_PKT_TX_TOKEN_ID_MAX 4095' in text, 'Actual token capacity differs')
    return '\n'.join(rows)


def ser_declarations(text):
    rows = []
    for name in ('ERR_RECOVERY_STATE', 'ERR_RECOVERY_CTRL_T'):
        found = re.findall(r'typedef (?:enum|struct) _'+name+r'\s*\{[\s\S]*?\}\s*'+name+r'(?:,\s*\*P_ERR_RECOVERY_STATE)?;', text)
        require(len(found) == 1, 'Real SER state/owner declaration differs: '+name)
        rows.append(found[0])
    return '\n'.join(rows)


def ser_prefix(prefix, sources):
    names = ('ERROR_DETECT_STOP_PDMA_WITH_FW_RELOAD', 'ERROR_DETECT_STOP_PDMA', 'ERROR_DETECT_RESET_DONE',
             'ERROR_DETECT_RECOVERY_DONE', 'ERROR_DETECT_N9_NORMAL_STATE', 'ERROR_DETECT_LMAC_ERROR',
             'ERROR_DETECT_PSE_ERROR', 'ERROR_DETECT_PLE_ERROR', 'ERROR_DETECT_PDMA_ERROR', 'ERROR_DETECT_PCIE_ERROR',
             'ERROR_DETECT_MASK', 'MCU_INT_PDMA0_STOP_DONE', 'MCU_INT_PDMA0_INIT_DONE', 'MCU_INT_PDMA0_RECOVERY_DONE')
    definitions = ['#define BIT(n) (1U<<(n))']; lines = sources['wire_header'].splitlines(keepends=True)
    for name in names:
        found = []
        for index, line in enumerate(lines):
            if re.match(r'^#define '+name+r'\b', line):
                block = line
                while block.rstrip().endswith('\\'):
                    index += 1
                    require(index < len(lines), 'Unterminated real SER macro')
                    block += lines[index]
                found.append(block)
        require(found and len(set(found)) == 1, 'Real SER wire macro differs: '+name)
        definitions.append(found[0])
    states = re.findall(r'typedef enum _RTMP_TASK_STATUS_ \{[\s\S]*?\} RTMP_TASK_STATUS;', sources['task_header'])
    halt = re.findall(r'^#define fRTMP_ADAPTER_HALT_IN_PROGRESS\s+0x[0-9a-fA-F]+\s*$', sources['flag_header'], re.M)
    require(len(states) == len(halt) == 1, 'Real SER task-state/flag ABI absent')
    definitions += states+halt
    status_contract(sources['os_header'], ('SUCCESS', 'FAILURE', 'INVALID_DATA'))
    for name in (*names, 'RTMP_TASK_STAT_UNKNOWN', 'RTMP_TASK_STAT_INITED', 'RTMP_TASK_STAT_RUNNING',
                 'RTMP_TASK_STAT_STOPED', 'fRTMP_ADAPTER_HALT_IN_PROGRESS'):
        prefix = re.sub(r'^#define '+name+r'\b[^\n]*\n', '', prefix, flags=re.M)
    prefix = prefix.replace('struct lock {', '\n'.join(definitions)+'\n'+ser_declarations(sources['header'])+'\nstruct lock {')
    return prefix.replace('static int __RtmpOSTaskKill(OS_TASK *p);', 'static inline int __RtmpOSTaskKill(OS_TASK *p);')


def source_selection(inputs):
    require(set(inputs) == set(SOURCE_PATHS), 'Exact token source inventory required')
    for line in SOURCE_ABI['enabled_config']+SOURCE_ABI['disabled_config']:
        require(len(re.findall('^'+re.escape(line)+'$', inputs['wifi_config'], re.M)) == 1, 'Real K2P token profile differs')
    require('DRV_NAME = mt_7615e' in inputs['wifi_makefile'] and command_member(inputs['kernel_makefile'], '-fno-strict-aliasing') and
            re.search(r'^VERSION\s*=\s*4$', inputs['kernel_makefile'], re.M) and
            re.search(r'^PATCHLEVEL\s*=\s*4$', inputs['kernel_makefile'], re.M), 'Real K2P4.4 compiler/module profile differs')
    for key in ('flags', 'wifi_makefile'):
        selected = re.findall(r'ifeq \(\$\(CONFIG_CHIP_MT7615E\),y\)\n([\s\S]*?)\nendif', inputs[key])
        require(len(selected) == 1 and all(command_member(selected[0], f) for f in ('-DMT7615', '-DRTMP_MAC_PCI', '-DRTMP_PCI_SUPPORT')),
                'Actual compiler chipset selection absent')
    config = inputs['driver_config']
    require(all(line in config for line in ('HAS_RESOURCE_PRE_ALLOC=y', 'HAS_RX_CUT_THROUGH=n',
            'HAS_CUT_THROUGH_DBG=n', 'WFLAGS += -DERR_RECOVERY')), 'Actual allocator/SER configuration differs')
    require('MT7615_ChipCap.qm_tm = TASKLET_METHOD;' in inputs['chip'] and
            'MT7615_ChipCap.hif_tm = TASKLET_METHOD;' in inputs['chip'], 'Actual MT7615 tasklet method differs')
    os_header = inputs[COMPONENTS['token']['source_keys']['os_header']]
    require('#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)\n#define KTHREAD_SUPPORT 1' in os_header,
            'Linux4.4 real KTHREAD selection differs')
    close = function(inputs[COMPONENTS['ser']['source_keys']['close']], 'RTMPDrvClose')
    tm_pos=close.index('tm_exit(pAd)');qm_pos=close.index('qm_exit(pAd);')
    tr_pos=close.index('tr_ctl_exit(pAd)');hw_pos=close.index('WfSysPosExit(pAd)')
    require(close.index('RTMP_OS_IRQ_RELEASE') < close.index('HwCtrlSerExit(pAd);') <
            tm_pos < qm_pos < close.index('queues_retired = TRUE;') < tr_pos < hw_pos and
            re.search(r'if \(!pAd->ErrRecoveryCtl.queues_retired\) \{[\s\S]*?tm_exit\(pAd\)[\s\S]*?qm_exit\(pAd\);[\s\S]*?queues_retired = TRUE;\s*\}', close),
            'Actual serialized close retirement/owner guard differs')
    for name,boundary in (('tm_exit',qm_pos),('tr_ctl_exit',hw_pos)):
        failures=list(re.finditer(r'if\s*\(\s*'+name+r'\(pAd\)\s*!=\s*NDIS_STATUS_SUCCESS\s*\)\s*\{\s*RtmpDmaQuarantine\(pAd\);\s*return;\s*\}',close))
        require(len(failures)==1 and failures[0].end()<boundary,
                'Actual checked close cleanup failure must quarantine and return before dependent release: '+name)
    basic = inputs[COMPONENTS['ser']['source_keys']['basic']]
    hwexit = function(basic, 'HwCtrlExit')
    require(hwexit.index('HwCtrlSerExit(pAd);') < hwexit.index('HwCtrlCmdHandler(pAd);') and 'ser_exit(pAd);' in hwexit,
            'Actual final teardown does not retire SER before HW cleanup')
    sysinit = function(inputs[COMPONENTS['ser']['source_keys']['close']], 'rtmp_sys_init')
    require(sysinit.index('HwCtrlInit(pAd)') < sysinit.index('qm_init(pAd)') < sysinit.index('tm_init(pAd)'),
            'Actual reopen initializes SER ownership after queue creation')
    core = function(inputs['kernel_kthread'], 'kthread_stop')
    require(core.index('get_task_struct(k);') < core.index('wait_for_completion(&kthread->exited);') <
            core.index('ret = k->exit_code;') < core.index('put_task_struct(k);'), 'Linux4.4 real stop ownership/exit-code semantics differ')
    return {'status': 'PASS', 'KTHREAD_current_profile': True, 'single_serialized_teardown_owner_required': True,
            'RTMPDrvClose_sha256': sha(close.encode()), 'HwCtrlExit_sha256': sha(hwexit.encode()),
            'rtmp_sys_init_sha256': sha(sysinit.encode()), 'kernel_kthread_stop_sha256': sha(core.encode()),
            'software_retirement_does_not_prove_DMA_idle': True,
            'checked_TM_and_TR_failures_quarantine_before_dependent_release':True}


def generate_component(inputs, component):
    spec = COMPONENTS[component]; data = literal_data(inputs[spec['harness_key']])
    require(model_data_hash(data) == spec['model_data_sha256'], 'Fixed current token/SER/task model pin differs')
    exact(data['SOURCE_PATHS'], spec['paths'], 'Model source paths differ')
    exact(data['FUNCTION_SOURCES'], spec['functions'], 'Model actual whole function inventory differs')
    selectors = tuple(o['selector'] for _, o in CASES if o['component'] == component)
    exact(data['CASE_NAMES'], selectors, 'Model fixed selector order differs')
    exact(data['EXPECTED_ROWS'], {o['selector']: EXPECTED[n] for n, o in CASES if o['component'] == component}, 'Model fixed typed rows differ')
    exact(data['BODY_ORDER'], tuple(spec['functions']), 'Whole function ordering differs')
    sources = {k: inputs[v] for k, v in spec['source_keys'].items()}
    prefix, suffix = data['PREFIX'], data['SUFFIX']
    require(type(prefix) is str and type(suffix) is str and suffix.count('CASE_ADMISSION') == 1 and
            'CASE_ADMISSION' not in prefix, 'Exactly one inert case admission marker required')
    if component == 'token':
        status_contract(sources['os_header'], ('SUCCESS', 'FAILURE', 'RESOURCES'))
        prefix += token_declarations(sources['header'])+'\n'
        prefix += 'static const char *oom_names[7]={'+','.join('"'+n+'"' for n in selectors[:7])+'};\n'
    elif component == 'ser':
        prefix = ser_prefix(prefix, sources)
    else:
        status_contract(sources['os_header'], ('SUCCESS', 'FAILURE'))
        require(re.search(r'^#define RTMP_OS_TASK_NAME_LEN\s+16$', sources['task_header'], re.M), 'Real task-name capacity differs')
        prefix = re.sub(r'\bputs\b', 'put_count', prefix)
        prefix = re.sub(r'\bgets\b', 'get_count', prefix)
        suffix = re.sub(r'\bgets\b', 'get_count', suffix)
        suffix = suffix.replace('get_count==puts', 'get_count==put_count').replace('stops,puts,destroyed', 'stops,put_count,destroyed')
    bodies = {n: function(sources[k], n) for n, k in spec['functions'].items()}
    admission = 'if(!('+'||'.join('!strcmp(name,"'+n+'")' for n in selectors)+'))return 91;'
    manifest = {n: {'source': spec['paths'][spec['functions'][n]], 'execution': 'whole-function',
                    'full_body_sha256': sha(body.encode())} for n, body in bodies.items()}
    return prefix+'\n'.join(bodies.values())+suffix.replace('CASE_ADMISSION', admission), manifest


def check(trunk, compiler, output, preflight=False, wifi_report=None):
    validate_contract()
    require(type(preflight) is bool and ((preflight and wifi_report is None) or (not preflight and wifi_report is not None)),
            'Token requires preflight alone or final Factory49 report')
    config = read_regular(trunk/'.config', MAX_SOURCE).decode()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M), 'Token requires configured K2P4.4')
    inputs = {k: read_regular(trunk.parent/p, MAX_SOURCE).decode() for k, p in SOURCE_PATHS.items()}
    selection = source_selection(inputs)
    qemu = shutil.which('qemu-mipsel'); require(qemu is not None, 'qemu-mipsel required')
    rows, probes, manifests, exports = [], {}, {}, {}
    with tempfile.TemporaryDirectory(prefix='k2p-token-lifecycle-', dir='/tmp') as temporary:
        base = Path(temporary)
        for component in COMPONENTS:
            generated, manifest = generate_component(inputs, component)
            stem = 'target-token-lifecycle-'+component+'-current'
            source, binary = base/(stem+'.c'), base/stem; source.write_text(generated)
            run = subprocess.run([str(compiler), *FLAGS, str(source), '-o', str(binary)], capture_output=True, text=True, timeout=90)
            require(run.returncode == 0, 'Token static MIPS compile failed: '+run.stdout+run.stderr)
            data = read_regular(binary, MAX_ELF); elf = resident.validate_static_helper(data); stdout_rows = []
            for name, options in CASES:
                if options['component'] != component: continue
                run = subprocess.run([qemu, str(binary), options['selector']], capture_output=True, text=True, timeout=MAX_CASE_SECONDS)
                require(run.returncode == 0 and not run.stderr and 0 < len(run.stdout.encode()) <= MAX_STDOUT,
                        'Token inert MIPS case failed '+name+': '+run.stdout+run.stderr)
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
    print('Token lifecycle: '+str(len(rows))+' inert source/MIPS cases PASS')
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
        parser.exit(1, 'Token lifecycle validation failed: '+str(error)+'\n')
