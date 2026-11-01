#!/usr/bin/env python3
"""Static MIPS resident-upgrade contracts with inert destructive backends.

Actual shipped invocations are refusal-only and run without reboot capability.
No real firmware write, watchdog access, reboot or router connection occurs.
"""
import argparse
import ast
import hashlib
import json
import os
import platform
import ctypes
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import types

PROFILE = 'k2p-4.4'
# Filled from independently reviewed source fixtures before target execution.
# An incomplete contract deliberately cannot produce a passing report.
ADAPTERS = {'helper': {'harness': 'helper_harness',
            'source_paths': {'admission': 'trunk/user/mtd_write/resident_admission.h',
                             'resident': 'trunk/user/mtd_write/resident_upgrade.h',
                             'main': 'trunk/user/mtd_write/fw_upgrade.c',
                             'writer': 'trunk/user/mtd_write/upgrade_write.h',
                             'makefile': 'trunk/user/mtd_write/Makefile',
                             'crc': 'trunk/user/mtd_write/crc32.c',
                             'crc_header': 'trunk/user/mtd_write/crc32.h'},
            'source_keys': {'admission': 'helper_admission',
                            'resident': 'helper_resident',
                            'main': 'helper_main',
                            'writer': 'helper_writer',
                            'makefile': 'helper_makefile',
                            'crc': 'helper_crc',
                            'crc_header': 'helper_crc_header'},
            'functions': {'fwup_resident_tmpfs': 'helper_admission',
                          'fwup_resident_same': 'helper_admission',
                          'fwup_resident_regular': 'helper_admission',
                          'fwup_resident_directory': 'helper_admission',
                          'fwup_resident_split': 'helper_admission',
                          'fwup_resident_admission': 'helper_admission',
                          'fwup_resident_run': 'helper_resident',
                          'main': 'helper_main'},
            'owner_model': 'compiled owner/PID/TMPFS substitutions; real file identity/flock',
            'renames': {'main': 'production_main'},
            'embedded_headers': ['helper_admission', 'helper_resident']},
 'legacy': {'harness': 'legacy_harness',
            'source_paths': {'mtd': 'trunk/user/mtd_write/mtd.c',
                             'legacy_guard': 'trunk/user/mtd_write/legacy_guard.h'},
            'source_keys': {'mtd': 'legacy_mtd', 'legacy_guard': 'legacy_legacy_guard'},
            'functions': {'image_check': 'legacy_mtd',
                          'mtd_write': 'legacy_mtd',
                          'do_reboot': 'legacy_mtd',
                          'main': 'legacy_mtd'},
            'owner_model': 'compiled owner and read-only synthetic device stat aliases; real ordinary '
                           'files',
            'enabled': True,
            'case_args': {'old-stage-protocol': ['--upgrade-write', '@IMAGE', 'firmware', '@STATUS'],
                          'malformed-stage-protocol': ['--upgrade-write'],
                          'firmware-write': ['write', '@IMAGE', 'firmware'],
                          'firmware-write-reboot': ['-r', 'write', '@IMAGE', 'firmware'],
                          'firmware-char-alias': ['write', '@IMAGE', '/dev/mtd3'],
                          'firmware-ro-alias': ['erase', '/dev/mtd3ro'],
                          'firmware-directory-alias': ['unlock', '/dev/mtd/3'],
                          'firmware-block-alias': ['write', '@IMAGE', '/dev/mtdblock3'],
                          'firmware-block-directory-alias': ['erase', '/dev/mtdblock/3'],
                          'firmware-short-alias': ['write', '@IMAGE', 'mtd3'],
                          'firmware-symlink-alias': ['write', '@IMAGE', '/fixture/firmware-link'],
                          'firmware-renumbered-alias': ['write', '@IMAGE', '/dev/mtd11'],
                          'kernel-overlap': ['write', '@IMAGE', 'kernel'],
                          'rootfs-overlap': ['write', '@IMAGE', 'rootfs'],
                          'all-label': ['erase', 'ALL'],
                          'all-device': ['unlock', '/dev/mtd7'],
                          'firmware-fixtrx': ['fixtrx', 'firmware'],
                          'firmware-fixseama': ['fixseama', 'firmware'],
                          'firmware-fixwrgg': ['fixwrgg', 'firmware'],
                          'firmware-resetbc': ['resetbc', 'firmware'],
                          'firmware-jffs2write': ['jffs2write', '@IMAGE', 'firmware'],
                          'preerase-firmware': ['-e', 'firmware', 'write', '@IMAGE', 'Storage'],
                          'preerase-firmware-read': ['-e', '/dev/mtdblock3', 'dump', 'Storage'],
                          'colon-firmware': ['write', '@IMAGE', 'Storage:firmware'],
                          'colon-preerase': ['-e', 'Storage:ALL', 'write', '@IMAGE', 'Config'],
                          'reboot-storage-read': ['-r', 'dump', 'Storage'],
                          'reboot-storage-write': ['-r', 'write', '@IMAGE', 'Storage'],
                          'unknown-target': ['write', '@IMAGE', '/fixture/unknown'],
                          'regular-file-target': ['write', '@IMAGE', '@IMAGE'],
                          'bad-partition-table': ['write', '@IMAGE', 'Storage'],
                          'duplicate-index-table': ['write', '@IMAGE', 'Storage'],
                          'duplicate-name-table': ['write', '@IMAGE', 'Storage'],
                          'overflow-table': ['write', '@IMAGE', 'Storage'],
                          'truncated-table': ['write', '@IMAGE', 'Storage'],
                          'unknown-partition-table': ['write', '@IMAGE', 'Storage'],
                          'safe-storage-write': ['write', '@IMAGE', 'Storage'],
                          'safe-config-erase': ['erase', 'Config'],
                          'safe-nvram-write': ['write', '@IMAGE', 'Nvram'],
                          'safe-storage-device': ['write', '@IMAGE', '/dev/mtd6'],
                          'readonly-firmware-dump': ['dump', 'firmware'],
                          'readonly-bad-table': ['dump', 'firmware'],
                          'disabled-guard-silent-corruption': ['-r', 'write', '@IMAGE', 'firmware'],
                          'too-many-preerase': ['-e',
                                                'Storage',
                                                '-e',
                                                'Storage',
                                                '-e',
                                                'Storage',
                                                '-e',
                                                'Storage',
                                                '-e',
                                                'Storage',
                                                '-e',
                                                'Storage',
                                                '-e',
                                                'Storage',
                                                '-e',
                                                'Storage',
                                                'write',
                                                '@IMAGE',
                                                'Storage'],
                          'missing-partition-table': ['write', '@IMAGE', 'Storage'],
                          'oversized-partition-line': ['write', '@IMAGE', 'Storage']},
            'embedded_headers': ['legacy_legacy_guard']},
 'legacy-disabled': {'harness': 'legacy_harness',
                     'source_paths': {'mtd': 'trunk/user/mtd_write/mtd.c',
                                      'legacy_guard': 'trunk/user/mtd_write/legacy_guard.h'},
                     'source_keys': {'mtd': 'legacy_mtd', 'legacy_guard': 'legacy_legacy_guard'},
                     'functions': {'image_check': 'legacy_mtd',
                                   'mtd_write': 'legacy_mtd',
                                   'do_reboot': 'legacy_mtd',
                                   'main': 'legacy_mtd'},
                     'owner_model': 'compiled owner and read-only synthetic device stat aliases; real '
                                    'ordinary files',
                     'enabled': False,
                     'case_args': {'old-stage-protocol': ['--upgrade-write',
                                                          '@IMAGE',
                                                          'firmware',
                                                          '@STATUS'],
                                   'malformed-stage-protocol': ['--upgrade-write'],
                                   'firmware-write': ['write', '@IMAGE', 'firmware'],
                                   'firmware-write-reboot': ['-r', 'write', '@IMAGE', 'firmware'],
                                   'firmware-char-alias': ['write', '@IMAGE', '/dev/mtd3'],
                                   'firmware-ro-alias': ['erase', '/dev/mtd3ro'],
                                   'firmware-directory-alias': ['unlock', '/dev/mtd/3'],
                                   'firmware-block-alias': ['write', '@IMAGE', '/dev/mtdblock3'],
                                   'firmware-block-directory-alias': ['erase', '/dev/mtdblock/3'],
                                   'firmware-short-alias': ['write', '@IMAGE', 'mtd3'],
                                   'firmware-symlink-alias': ['write', '@IMAGE', '/fixture/firmware-link'],
                                   'firmware-renumbered-alias': ['write', '@IMAGE', '/dev/mtd11'],
                                   'kernel-overlap': ['write', '@IMAGE', 'kernel'],
                                   'rootfs-overlap': ['write', '@IMAGE', 'rootfs'],
                                   'all-label': ['erase', 'ALL'],
                                   'all-device': ['unlock', '/dev/mtd7'],
                                   'firmware-fixtrx': ['fixtrx', 'firmware'],
                                   'firmware-fixseama': ['fixseama', 'firmware'],
                                   'firmware-fixwrgg': ['fixwrgg', 'firmware'],
                                   'firmware-resetbc': ['resetbc', 'firmware'],
                                   'firmware-jffs2write': ['jffs2write', '@IMAGE', 'firmware'],
                                   'preerase-firmware': ['-e', 'firmware', 'write', '@IMAGE', 'Storage'],
                                   'preerase-firmware-read': ['-e', '/dev/mtdblock3', 'dump', 'Storage'],
                                   'colon-firmware': ['write', '@IMAGE', 'Storage:firmware'],
                                   'colon-preerase': ['-e', 'Storage:ALL', 'write', '@IMAGE', 'Config'],
                                   'reboot-storage-read': ['-r', 'dump', 'Storage'],
                                   'reboot-storage-write': ['-r', 'write', '@IMAGE', 'Storage'],
                                   'unknown-target': ['write', '@IMAGE', '/fixture/unknown'],
                                   'regular-file-target': ['write', '@IMAGE', '@IMAGE'],
                                   'bad-partition-table': ['write', '@IMAGE', 'Storage'],
                                   'duplicate-index-table': ['write', '@IMAGE', 'Storage'],
                                   'duplicate-name-table': ['write', '@IMAGE', 'Storage'],
                                   'overflow-table': ['write', '@IMAGE', 'Storage'],
                                   'truncated-table': ['write', '@IMAGE', 'Storage'],
                                   'unknown-partition-table': ['write', '@IMAGE', 'Storage'],
                                   'safe-storage-write': ['write', '@IMAGE', 'Storage'],
                                   'safe-config-erase': ['erase', 'Config'],
                                   'safe-nvram-write': ['write', '@IMAGE', 'Nvram'],
                                   'safe-storage-device': ['write', '@IMAGE', '/dev/mtd6'],
                                   'readonly-firmware-dump': ['dump', 'firmware'],
                                   'readonly-bad-table': ['dump', 'firmware'],
                                   'disabled-guard-silent-corruption': ['-r',
                                                                        'write',
                                                                        '@IMAGE',
                                                                        'firmware'],
                                   'too-many-preerase': ['-e',
                                                         'Storage',
                                                         '-e',
                                                         'Storage',
                                                         '-e',
                                                         'Storage',
                                                         '-e',
                                                         'Storage',
                                                         '-e',
                                                         'Storage',
                                                         '-e',
                                                         'Storage',
                                                         '-e',
                                                         'Storage',
                                                         '-e',
                                                         'Storage',
                                                         'write',
                                                         '@IMAGE',
                                                         'Storage'],
                                   'missing-partition-table': ['write', '@IMAGE', 'Storage'],
                                   'oversized-partition-line': ['write', '@IMAGE', 'Storage']},
                     'embedded_headers': ['legacy_legacy_guard']},
 'parent': {'harness': 'parent_harness',
            'source_paths': {'rc': 'trunk/user/rc/rc.c'},
            'source_keys': {'rc': 'parent_rc'},
            'functions': {'firmware_upgrade_spawn': 'parent_rc', 'firmware_upgrade_run': 'parent_rc'},
            'owner_model': 'real fork/file/FD/flock/signal-mask/wait; inert child exec recorder'},
 'consumer': {'harness': 'consumer_harness',
              'source_paths': {'rc': 'trunk/user/rc/rc.c',
                               'watchdog': 'trunk/user/rc/watchdog.c',
                               'guard': 'trunk/user/shared/upgrade_guard.h',
                               'notify': 'trunk/user/shared/notify_rc.c',
                               'notify_header': 'trunk/user/shared/notify_rc.h',
                               'upgrade_fixture': 'tests/upgrade_gate_harness.py',
                               'old_consumer': 'tests/fixtures/resident-consumer/d67-handle-notifications.c'},
              'source_keys': {'rc': 'consumer_rc',
                              'watchdog': 'consumer_watchdog',
                              'guard': 'consumer_guard',
                              'notify': 'consumer_notify',
                              'notify_header': 'consumer_notify_header',
                              'upgrade_fixture': 'consumer_upgrade_fixture',
                              'old_consumer': 'consumer_old_consumer'},
              'functions': {'handle_notifications': 'consumer_rc',
                            'flash_firmware': 'consumer_rc',
                            'firmware_upgrade_run': 'consumer_rc',
                            'firmware_upgrade_signal_inhibited': 'consumer_rc',
                            'valid_event_name': 'consumer_notify',
                            'rc_notification_open_dir': 'consumer_notify',
                            'rc_notification_valid_marker': 'consumer_notify'},
              'owner_model': 'compiled owner and inert writer/MTD/reset effects; actual flash and '
                             'notification consumer bodies'}}
SOURCE_PATHS = {'helper_admission': 'trunk/user/mtd_write/resident_admission.h',
 'helper_resident': 'trunk/user/mtd_write/resident_upgrade.h',
 'helper_main': 'trunk/user/mtd_write/fw_upgrade.c',
 'helper_writer': 'trunk/user/mtd_write/upgrade_write.h',
 'helper_makefile': 'trunk/user/mtd_write/Makefile',
 'helper_crc': 'trunk/user/mtd_write/crc32.c',
 'helper_crc_header': 'trunk/user/mtd_write/crc32.h',
 'helper_harness': 'tests/resident_upgrade_harness.py',
 'legacy_mtd': 'trunk/user/mtd_write/mtd.c',
 'legacy_legacy_guard': 'trunk/user/mtd_write/legacy_guard.h',
 'legacy_harness': 'tests/legacy_firmware_harness.py',
 'parent_rc': 'trunk/user/rc/rc.c',
 'parent_harness': 'tests/resident_parent_harness.py',
 'consumer_rc': 'trunk/user/rc/rc.c',
 'consumer_watchdog': 'trunk/user/rc/watchdog.c',
 'consumer_guard': 'trunk/user/shared/upgrade_guard.h',
 'consumer_notify': 'trunk/user/shared/notify_rc.c',
 'consumer_notify_header': 'trunk/user/shared/notify_rc.h',
 'consumer_upgrade_fixture': 'tests/upgrade_gate_harness.py',
 'consumer_old_consumer': 'tests/fixtures/resident-consumer/d67-handle-notifications.c',
 'consumer_harness': 'tests/resident_consumer_harness.py',
 'romfs_install': 'trunk/tools/romfs-inst.sh',
 'sstrip_source': 'trunk/tools/ELFkickers-3.1/sstrip/sstrip.c',
 'trunk_makefile': 'trunk/Makefile'}
CASES = (('helper:safe-prewrite', {'adapter': 'helper', 'selector': 'safe-prewrite'}),
 ('helper:verified-reset-error', {'adapter': 'helper', 'selector': 'verified-reset-error'}),
 ('helper:verified-reset-zero', {'adapter': 'helper', 'selector': 'verified-reset-zero'}),
 ('helper:unknown', {'adapter': 'helper', 'selector': 'unknown'}),
 ('helper:bad-argc', {'adapter': 'helper', 'selector': 'bad-argc'}),
 ('helper:bad-command', {'adapter': 'helper', 'selector': 'bad-command'}),
 ('helper:bad-target', {'adapter': 'helper', 'selector': 'bad-target'}),
 ('helper:bad-fd-argument', {'adapter': 'helper', 'selector': 'bad-fd-argument'}),
 ('helper:nonempty-environment', {'adapter': 'helper', 'selector': 'nonempty-environment'}),
 ('helper:wrong-parent', {'adapter': 'helper', 'selector': 'wrong-parent'}),
 ('helper:lease-unlocked', {'adapter': 'helper', 'selector': 'lease-unlocked'}),
 ('helper:lease-shared', {'adapter': 'helper', 'selector': 'lease-shared'}),
 ('helper:lease-other-inode', {'adapter': 'helper', 'selector': 'lease-other-inode'}),
 ('helper:lease-hardlink', {'adapter': 'helper', 'selector': 'lease-hardlink'}),
 ('helper:lease-mode', {'adapter': 'helper', 'selector': 'lease-mode'}),
 ('helper:foreign-exclusive', {'adapter': 'helper', 'selector': 'foreign-exclusive'}),
 ('helper:marker-absent', {'adapter': 'helper', 'selector': 'marker-absent'}),
 ('helper:marker-symlink', {'adapter': 'helper', 'selector': 'marker-symlink'}),
 ('helper:marker-nonempty', {'adapter': 'helper', 'selector': 'marker-nonempty'}),
 ('helper:private-mode', {'adapter': 'helper', 'selector': 'private-mode'}),
 ('helper:attempt-symlink', {'adapter': 'helper', 'selector': 'attempt-symlink'}),
 ('helper:status-other-parent', {'adapter': 'helper', 'selector': 'status-other-parent'}),
 ('helper:status-other-leaf', {'adapter': 'helper', 'selector': 'status-other-leaf'}),
 ('helper:exe-symlink', {'adapter': 'helper', 'selector': 'exe-symlink'}),
 ('helper:exe-other-inode', {'adapter': 'helper', 'selector': 'exe-other-inode'}),
 ('helper:exe-mode', {'adapter': 'helper', 'selector': 'exe-mode'}),
 ('helper:lease-not-tmpfs', {'adapter': 'helper', 'selector': 'lease-not-tmpfs'}),
 ('helper:status-not-tmpfs', {'adapter': 'helper', 'selector': 'status-not-tmpfs'}),
 ('helper:exe-not-tmpfs', {'adapter': 'helper', 'selector': 'exe-not-tmpfs'}),
 ('helper:statfs-error', {'adapter': 'helper', 'selector': 'statfs-error'}),
 ('helper:owner-mismatch', {'adapter': 'helper', 'selector': 'owner-mismatch'}),
 ('helper:marker-hardlink', {'adapter': 'helper', 'selector': 'marker-hardlink'}),
 ('helper:exe-hardlink', {'adapter': 'helper', 'selector': 'exe-hardlink'}),
 ('helper:exe-open-error', {'adapter': 'helper', 'selector': 'exe-open-error'}),
 ('legacy:old-stage-protocol', {'adapter': 'legacy', 'selector': 'old-stage-protocol'}),
 ('legacy:malformed-stage-protocol', {'adapter': 'legacy', 'selector': 'malformed-stage-protocol'}),
 ('legacy:firmware-write', {'adapter': 'legacy', 'selector': 'firmware-write'}),
 ('legacy:firmware-write-reboot', {'adapter': 'legacy', 'selector': 'firmware-write-reboot'}),
 ('legacy:firmware-char-alias', {'adapter': 'legacy', 'selector': 'firmware-char-alias'}),
 ('legacy:firmware-ro-alias', {'adapter': 'legacy', 'selector': 'firmware-ro-alias'}),
 ('legacy:firmware-directory-alias', {'adapter': 'legacy', 'selector': 'firmware-directory-alias'}),
 ('legacy:firmware-block-alias', {'adapter': 'legacy', 'selector': 'firmware-block-alias'}),
 ('legacy:firmware-block-directory-alias',
  {'adapter': 'legacy', 'selector': 'firmware-block-directory-alias'}),
 ('legacy:firmware-short-alias', {'adapter': 'legacy', 'selector': 'firmware-short-alias'}),
 ('legacy:firmware-symlink-alias', {'adapter': 'legacy', 'selector': 'firmware-symlink-alias'}),
 ('legacy:firmware-renumbered-alias', {'adapter': 'legacy', 'selector': 'firmware-renumbered-alias'}),
 ('legacy:kernel-overlap', {'adapter': 'legacy', 'selector': 'kernel-overlap'}),
 ('legacy:rootfs-overlap', {'adapter': 'legacy', 'selector': 'rootfs-overlap'}),
 ('legacy:all-label', {'adapter': 'legacy', 'selector': 'all-label'}),
 ('legacy:all-device', {'adapter': 'legacy', 'selector': 'all-device'}),
 ('legacy:firmware-fixtrx', {'adapter': 'legacy', 'selector': 'firmware-fixtrx'}),
 ('legacy:firmware-fixseama', {'adapter': 'legacy', 'selector': 'firmware-fixseama'}),
 ('legacy:firmware-fixwrgg', {'adapter': 'legacy', 'selector': 'firmware-fixwrgg'}),
 ('legacy:firmware-resetbc', {'adapter': 'legacy', 'selector': 'firmware-resetbc'}),
 ('legacy:firmware-jffs2write', {'adapter': 'legacy', 'selector': 'firmware-jffs2write'}),
 ('legacy:preerase-firmware', {'adapter': 'legacy', 'selector': 'preerase-firmware'}),
 ('legacy:preerase-firmware-read', {'adapter': 'legacy', 'selector': 'preerase-firmware-read'}),
 ('legacy:colon-firmware', {'adapter': 'legacy', 'selector': 'colon-firmware'}),
 ('legacy:colon-preerase', {'adapter': 'legacy', 'selector': 'colon-preerase'}),
 ('legacy:reboot-storage-read', {'adapter': 'legacy', 'selector': 'reboot-storage-read'}),
 ('legacy:reboot-storage-write', {'adapter': 'legacy', 'selector': 'reboot-storage-write'}),
 ('legacy:unknown-target', {'adapter': 'legacy', 'selector': 'unknown-target'}),
 ('legacy:regular-file-target', {'adapter': 'legacy', 'selector': 'regular-file-target'}),
 ('legacy:bad-partition-table', {'adapter': 'legacy', 'selector': 'bad-partition-table'}),
 ('legacy:duplicate-index-table', {'adapter': 'legacy', 'selector': 'duplicate-index-table'}),
 ('legacy:duplicate-name-table', {'adapter': 'legacy', 'selector': 'duplicate-name-table'}),
 ('legacy:overflow-table', {'adapter': 'legacy', 'selector': 'overflow-table'}),
 ('legacy:truncated-table', {'adapter': 'legacy', 'selector': 'truncated-table'}),
 ('legacy:unknown-partition-table', {'adapter': 'legacy', 'selector': 'unknown-partition-table'}),
 ('legacy:safe-storage-write', {'adapter': 'legacy', 'selector': 'safe-storage-write'}),
 ('legacy:safe-config-erase', {'adapter': 'legacy', 'selector': 'safe-config-erase'}),
 ('legacy:safe-nvram-write', {'adapter': 'legacy', 'selector': 'safe-nvram-write'}),
 ('legacy:safe-storage-device', {'adapter': 'legacy', 'selector': 'safe-storage-device'}),
 ('legacy:readonly-firmware-dump', {'adapter': 'legacy', 'selector': 'readonly-firmware-dump'}),
 ('legacy:readonly-bad-table', {'adapter': 'legacy', 'selector': 'readonly-bad-table'}),
 ('legacy:too-many-preerase', {'adapter': 'legacy', 'selector': 'too-many-preerase'}),
 ('legacy:missing-partition-table', {'adapter': 'legacy', 'selector': 'missing-partition-table'}),
 ('legacy:oversized-partition-line', {'adapter': 'legacy', 'selector': 'oversized-partition-line'}),
 ('legacy-disabled:disabled-guard-silent-corruption',
  {'adapter': 'legacy-disabled', 'selector': 'disabled-guard-silent-corruption'}),
 ('parent:fd3', {'adapter': 'parent', 'selector': 'fd3'}),
 ('parent:fd-high', {'adapter': 'parent', 'selector': 'fd-high'}),
 ('parent:child-safe20', {'adapter': 'parent', 'selector': 'child-safe20'}),
 ('parent:unexpected-zero', {'adapter': 'parent', 'selector': 'unexpected-zero'}),
 ('parent:exec-failure', {'adapter': 'parent', 'selector': 'exec-failure'}),
 ('parent:wait-eintr', {'adapter': 'parent', 'selector': 'wait-eintr'}),
 ('parent:fork-failure', {'adapter': 'parent', 'selector': 'fork-failure'}),
 ('parent:invalid-lease', {'adapter': 'parent', 'selector': 'invalid-lease'}),
 ('parent:parent-mask-failure', {'adapter': 'parent', 'selector': 'parent-mask-failure'}),
 ('parent:parent-restore-failure', {'adapter': 'parent', 'selector': 'parent-restore-failure'}),
 ('parent:child-mask-failure', {'adapter': 'parent', 'selector': 'child-mask-failure'}),
 ('parent:dup-failure', {'adapter': 'parent', 'selector': 'dup-failure'}),
 ('parent:cloexec-failure', {'adapter': 'parent', 'selector': 'cloexec-failure'}),
 ('parent:setsid-failure', {'adapter': 'parent', 'selector': 'setsid-failure'}),
 ('parent:opendir-failure', {'adapter': 'parent', 'selector': 'opendir-failure'}),
 ('parent:readdir-failure', {'adapter': 'parent', 'selector': 'readdir-failure'}),
 ('parent:closedir-failure', {'adapter': 'parent', 'selector': 'closedir-failure'}),
 ('parent:close-failure', {'adapter': 'parent', 'selector': 'close-failure'}),
 ('consumer:consumer-unknown', {'adapter': 'consumer', 'selector': 'consumer-unknown'}),
 ('consumer:consumer-verified-return', {'adapter': 'consumer', 'selector': 'consumer-verified-return'}),
 ('consumer:consumer-signal', {'adapter': 'consumer', 'selector': 'consumer-signal'}),
 ('consumer:consumer-exec-failure', {'adapter': 'consumer', 'selector': 'consumer-exec-failure'}),
 ('consumer:consumer-untrusted20', {'adapter': 'consumer', 'selector': 'consumer-untrusted20'}),
 ('consumer:consumer-mismatched20', {'adapter': 'consumer', 'selector': 'consumer-mismatched20'}),
 ('consumer:consumer-safe20', {'adapter': 'consumer', 'selector': 'consumer-safe20'}),
 ('consumer:consumer-first-save-abort', {'adapter': 'consumer', 'selector': 'consumer-first-save-abort'}),
 ('consumer:consumer-hook-abort', {'adapter': 'consumer', 'selector': 'consumer-hook-abort'}),
 ('consumer:old-consumer-negative', {'adapter': 'consumer', 'selector': 'old-consumer-negative'}))
EXPECTED = {'helper:safe-prewrite': {'case': 'safe-prewrite',
                          'trace': ['writer-calls:1',
                                    'writer-result:20',
                                    'reboot-calls:0',
                                    'exit:20',
                                    'fd-balance:1',
                                    'canonical-exclusion:1']},
 'helper:verified-reset-error': {'case': 'verified-reset-error',
                                 'trace': ['writer-calls:1',
                                           'writer-result:0',
                                           'reboot-calls:1',
                                           'exit:21',
                                           'fd-balance:1',
                                           'canonical-exclusion:1']},
 'helper:verified-reset-zero': {'case': 'verified-reset-zero',
                                'trace': ['writer-calls:1',
                                          'writer-result:0',
                                          'reboot-calls:1',
                                          'exit:21',
                                          'fd-balance:1',
                                          'canonical-exclusion:1']},
 'helper:unknown': {'case': 'unknown',
                    'trace': ['writer-calls:1',
                              'writer-result:21',
                              'reboot-calls:0',
                              'exit:21',
                              'fd-balance:1',
                              'canonical-exclusion:1']},
 'helper:bad-argc': {'case': 'bad-argc',
                     'trace': ['writer-calls:0',
                               'writer-result:-1',
                               'reboot-calls:0',
                               'exit:21',
                               'fd-balance:1',
                               'canonical-exclusion:1']},
 'helper:bad-command': {'case': 'bad-command',
                        'trace': ['writer-calls:0',
                                  'writer-result:-1',
                                  'reboot-calls:0',
                                  'exit:21',
                                  'fd-balance:1',
                                  'canonical-exclusion:1']},
 'helper:bad-target': {'case': 'bad-target',
                       'trace': ['writer-calls:0',
                                 'writer-result:-1',
                                 'reboot-calls:0',
                                 'exit:21',
                                 'fd-balance:1',
                                 'canonical-exclusion:1']},
 'helper:bad-fd-argument': {'case': 'bad-fd-argument',
                            'trace': ['writer-calls:0',
                                      'writer-result:-1',
                                      'reboot-calls:0',
                                      'exit:21',
                                      'fd-balance:1',
                                      'canonical-exclusion:1']},
 'helper:nonempty-environment': {'case': 'nonempty-environment',
                                 'trace': ['writer-calls:0',
                                           'writer-result:-1',
                                           'reboot-calls:0',
                                           'exit:21',
                                           'fd-balance:1',
                                           'canonical-exclusion:1']},
 'helper:wrong-parent': {'case': 'wrong-parent',
                         'trace': ['writer-calls:0',
                                   'writer-result:-1',
                                   'reboot-calls:0',
                                   'exit:21',
                                   'fd-balance:1',
                                   'canonical-exclusion:1']},
 'helper:lease-unlocked': {'case': 'lease-unlocked',
                           'trace': ['writer-calls:0',
                                     'writer-result:-1',
                                     'reboot-calls:0',
                                     'exit:21',
                                     'fd-balance:1',
                                     'canonical-exclusion:0']},
 'helper:lease-shared': {'case': 'lease-shared',
                         'trace': ['writer-calls:0',
                                   'writer-result:-1',
                                   'reboot-calls:0',
                                   'exit:21',
                                   'fd-balance:1',
                                   'canonical-exclusion:0']},
 'helper:lease-other-inode': {'case': 'lease-other-inode',
                              'trace': ['writer-calls:0',
                                        'writer-result:-1',
                                        'reboot-calls:0',
                                        'exit:21',
                                        'fd-balance:1',
                                        'canonical-exclusion:0']},
 'helper:lease-hardlink': {'case': 'lease-hardlink',
                           'trace': ['writer-calls:0',
                                     'writer-result:-1',
                                     'reboot-calls:0',
                                     'exit:21',
                                     'fd-balance:1',
                                     'canonical-exclusion:1']},
 'helper:lease-mode': {'case': 'lease-mode',
                       'trace': ['writer-calls:0',
                                 'writer-result:-1',
                                 'reboot-calls:0',
                                 'exit:21',
                                 'fd-balance:1',
                                 'canonical-exclusion:1']},
 'helper:foreign-exclusive': {'case': 'foreign-exclusive',
                              'trace': ['writer-calls:0',
                                        'writer-result:-1',
                                        'reboot-calls:0',
                                        'exit:21',
                                        'fd-balance:1',
                                        'canonical-exclusion:1']},
 'helper:marker-absent': {'case': 'marker-absent',
                          'trace': ['writer-calls:0',
                                    'writer-result:-1',
                                    'reboot-calls:0',
                                    'exit:21',
                                    'fd-balance:1',
                                    'canonical-exclusion:1']},
 'helper:marker-symlink': {'case': 'marker-symlink',
                           'trace': ['writer-calls:0',
                                     'writer-result:-1',
                                     'reboot-calls:0',
                                     'exit:21',
                                     'fd-balance:1',
                                     'canonical-exclusion:1']},
 'helper:marker-nonempty': {'case': 'marker-nonempty',
                            'trace': ['writer-calls:0',
                                      'writer-result:-1',
                                      'reboot-calls:0',
                                      'exit:21',
                                      'fd-balance:1',
                                      'canonical-exclusion:1']},
 'helper:private-mode': {'case': 'private-mode',
                         'trace': ['writer-calls:0',
                                   'writer-result:-1',
                                   'reboot-calls:0',
                                   'exit:21',
                                   'fd-balance:1',
                                   'canonical-exclusion:1']},
 'helper:attempt-symlink': {'case': 'attempt-symlink',
                            'trace': ['writer-calls:0',
                                      'writer-result:-1',
                                      'reboot-calls:0',
                                      'exit:21',
                                      'fd-balance:1',
                                      'canonical-exclusion:1']},
 'helper:status-other-parent': {'case': 'status-other-parent',
                                'trace': ['writer-calls:0',
                                          'writer-result:-1',
                                          'reboot-calls:0',
                                          'exit:21',
                                          'fd-balance:1',
                                          'canonical-exclusion:1']},
 'helper:status-other-leaf': {'case': 'status-other-leaf',
                              'trace': ['writer-calls:0',
                                        'writer-result:-1',
                                        'reboot-calls:0',
                                        'exit:21',
                                        'fd-balance:1',
                                        'canonical-exclusion:1']},
 'helper:exe-symlink': {'case': 'exe-symlink',
                        'trace': ['writer-calls:0',
                                  'writer-result:-1',
                                  'reboot-calls:0',
                                  'exit:21',
                                  'fd-balance:1',
                                  'canonical-exclusion:1']},
 'helper:exe-other-inode': {'case': 'exe-other-inode',
                            'trace': ['writer-calls:0',
                                      'writer-result:-1',
                                      'reboot-calls:0',
                                      'exit:21',
                                      'fd-balance:1',
                                      'canonical-exclusion:1']},
 'helper:exe-mode': {'case': 'exe-mode',
                     'trace': ['writer-calls:0',
                               'writer-result:-1',
                               'reboot-calls:0',
                               'exit:21',
                               'fd-balance:1',
                               'canonical-exclusion:1']},
 'helper:lease-not-tmpfs': {'case': 'lease-not-tmpfs',
                            'trace': ['writer-calls:0',
                                      'writer-result:-1',
                                      'reboot-calls:0',
                                      'exit:21',
                                      'fd-balance:1',
                                      'canonical-exclusion:1']},
 'helper:status-not-tmpfs': {'case': 'status-not-tmpfs',
                             'trace': ['writer-calls:0',
                                       'writer-result:-1',
                                       'reboot-calls:0',
                                       'exit:21',
                                       'fd-balance:1',
                                       'canonical-exclusion:1']},
 'helper:exe-not-tmpfs': {'case': 'exe-not-tmpfs',
                          'trace': ['writer-calls:0',
                                    'writer-result:-1',
                                    'reboot-calls:0',
                                    'exit:21',
                                    'fd-balance:1',
                                    'canonical-exclusion:1']},
 'helper:statfs-error': {'case': 'statfs-error',
                         'trace': ['writer-calls:0',
                                   'writer-result:-1',
                                   'reboot-calls:0',
                                   'exit:21',
                                   'fd-balance:1',
                                   'canonical-exclusion:1']},
 'helper:owner-mismatch': {'case': 'owner-mismatch',
                           'trace': ['writer-calls:0',
                                     'writer-result:-1',
                                     'reboot-calls:0',
                                     'exit:21',
                                     'fd-balance:1',
                                     'canonical-exclusion:1']},
 'helper:marker-hardlink': {'case': 'marker-hardlink',
                            'trace': ['writer-calls:0',
                                      'writer-result:-1',
                                      'reboot-calls:0',
                                      'exit:21',
                                      'fd-balance:1',
                                      'canonical-exclusion:1']},
 'helper:exe-hardlink': {'case': 'exe-hardlink',
                         'trace': ['writer-calls:0',
                                   'writer-result:-1',
                                   'reboot-calls:0',
                                   'exit:21',
                                   'fd-balance:1',
                                   'canonical-exclusion:1']},
 'helper:exe-open-error': {'case': 'exe-open-error',
                           'trace': ['writer-calls:0',
                                     'writer-result:-1',
                                     'reboot-calls:0',
                                     'exit:21',
                                     'fd-balance:1',
                                     'canonical-exclusion:1']},
 'legacy:old-stage-protocol': {'case': 'old-stage-protocol',
                               'returncode': 21,
                               'trace': '',
                               'device_reads': 0,
                               'corrupted': 0},
 'legacy:malformed-stage-protocol': {'case': 'malformed-stage-protocol',
                                     'returncode': 21,
                                     'trace': '',
                                     'device_reads': 0,
                                     'corrupted': 0},
 'legacy:firmware-write': {'case': 'firmware-write',
                           'returncode': 21,
                           'trace': '',
                           'device_reads': 0,
                           'corrupted': 0},
 'legacy:firmware-write-reboot': {'case': 'firmware-write-reboot',
                                  'returncode': 21,
                                  'trace': '',
                                  'device_reads': 0,
                                  'corrupted': 0},
 'legacy:firmware-char-alias': {'case': 'firmware-char-alias',
                                'returncode': 21,
                                'trace': '',
                                'device_reads': 0,
                                'corrupted': 0},
 'legacy:firmware-ro-alias': {'case': 'firmware-ro-alias',
                              'returncode': 21,
                              'trace': '',
                              'device_reads': 0,
                              'corrupted': 0},
 'legacy:firmware-directory-alias': {'case': 'firmware-directory-alias',
                                     'returncode': 21,
                                     'trace': '',
                                     'device_reads': 0,
                                     'corrupted': 0},
 'legacy:firmware-block-alias': {'case': 'firmware-block-alias',
                                 'returncode': 21,
                                 'trace': '',
                                 'device_reads': 0,
                                 'corrupted': 0},
 'legacy:firmware-block-directory-alias': {'case': 'firmware-block-directory-alias',
                                           'returncode': 21,
                                           'trace': '',
                                           'device_reads': 0,
                                           'corrupted': 0},
 'legacy:firmware-short-alias': {'case': 'firmware-short-alias',
                                 'returncode': 21,
                                 'trace': '',
                                 'device_reads': 0,
                                 'corrupted': 0},
 'legacy:firmware-symlink-alias': {'case': 'firmware-symlink-alias',
                                   'returncode': 21,
                                   'trace': '',
                                   'device_reads': 0,
                                   'corrupted': 0},
 'legacy:firmware-renumbered-alias': {'case': 'firmware-renumbered-alias',
                                      'returncode': 21,
                                      'trace': '',
                                      'device_reads': 0,
                                      'corrupted': 0},
 'legacy:kernel-overlap': {'case': 'kernel-overlap',
                           'returncode': 21,
                           'trace': '',
                           'device_reads': 0,
                           'corrupted': 0},
 'legacy:rootfs-overlap': {'case': 'rootfs-overlap',
                           'returncode': 21,
                           'trace': '',
                           'device_reads': 0,
                           'corrupted': 0},
 'legacy:all-label': {'case': 'all-label',
                      'returncode': 21,
                      'trace': '',
                      'device_reads': 0,
                      'corrupted': 0},
 'legacy:all-device': {'case': 'all-device',
                       'returncode': 21,
                       'trace': '',
                       'device_reads': 0,
                       'corrupted': 0},
 'legacy:firmware-fixtrx': {'case': 'firmware-fixtrx',
                            'returncode': 21,
                            'trace': '',
                            'device_reads': 0,
                            'corrupted': 0},
 'legacy:firmware-fixseama': {'case': 'firmware-fixseama',
                              'returncode': 21,
                              'trace': '',
                              'device_reads': 0,
                              'corrupted': 0},
 'legacy:firmware-fixwrgg': {'case': 'firmware-fixwrgg',
                             'returncode': 21,
                             'trace': '',
                             'device_reads': 0,
                             'corrupted': 0},
 'legacy:firmware-resetbc': {'case': 'firmware-resetbc',
                             'returncode': 21,
                             'trace': '',
                             'device_reads': 0,
                             'corrupted': 0},
 'legacy:firmware-jffs2write': {'case': 'firmware-jffs2write',
                                'returncode': 21,
                                'trace': '',
                                'device_reads': 0,
                                'corrupted': 0},
 'legacy:preerase-firmware': {'case': 'preerase-firmware',
                              'returncode': 21,
                              'trace': '',
                              'device_reads': 0,
                              'corrupted': 0},
 'legacy:preerase-firmware-read': {'case': 'preerase-firmware-read',
                                   'returncode': 21,
                                   'trace': '',
                                   'device_reads': 0,
                                   'corrupted': 0},
 'legacy:colon-firmware': {'case': 'colon-firmware',
                           'returncode': 21,
                           'trace': '',
                           'device_reads': 0,
                           'corrupted': 0},
 'legacy:colon-preerase': {'case': 'colon-preerase',
                           'returncode': 21,
                           'trace': '',
                           'device_reads': 0,
                           'corrupted': 0},
 'legacy:reboot-storage-read': {'case': 'reboot-storage-read',
                                'returncode': 21,
                                'trace': '',
                                'device_reads': 0,
                                'corrupted': 0},
 'legacy:reboot-storage-write': {'case': 'reboot-storage-write',
                                 'returncode': 21,
                                 'trace': '',
                                 'device_reads': 0,
                                 'corrupted': 0},
 'legacy:unknown-target': {'case': 'unknown-target',
                           'returncode': 21,
                           'trace': '',
                           'device_reads': 0,
                           'corrupted': 0},
 'legacy:regular-file-target': {'case': 'regular-file-target',
                                'returncode': 21,
                                'trace': '',
                                'device_reads': 0,
                                'corrupted': 0},
 'legacy:bad-partition-table': {'case': 'bad-partition-table',
                                'returncode': 21,
                                'trace': '',
                                'device_reads': 0,
                                'corrupted': 0},
 'legacy:duplicate-index-table': {'case': 'duplicate-index-table',
                                  'returncode': 21,
                                  'trace': '',
                                  'device_reads': 0,
                                  'corrupted': 0},
 'legacy:duplicate-name-table': {'case': 'duplicate-name-table',
                                 'returncode': 21,
                                 'trace': '',
                                 'device_reads': 0,
                                 'corrupted': 0},
 'legacy:overflow-table': {'case': 'overflow-table',
                           'returncode': 21,
                           'trace': '',
                           'device_reads': 0,
                           'corrupted': 0},
 'legacy:truncated-table': {'case': 'truncated-table',
                            'returncode': 21,
                            'trace': '',
                            'device_reads': 0,
                            'corrupted': 0},
 'legacy:unknown-partition-table': {'case': 'unknown-partition-table',
                                    'returncode': 21,
                                    'trace': '',
                                    'device_reads': 0,
                                    'corrupted': 0},
 'legacy:safe-storage-write': {'case': 'safe-storage-write',
                               'returncode': 0,
                               'trace': 'mtd-check,sync,unlock,writable-open,erase,write,erase,write,erase,write,erase,write,sync',
                               'device_reads': 0,
                               'corrupted': 0},
 'legacy:safe-config-erase': {'case': 'safe-config-erase',
                              'returncode': 0,
                              'trace': 'sync,unlock,erase,sync',
                              'device_reads': 0,
                              'corrupted': 0},
 'legacy:safe-nvram-write': {'case': 'safe-nvram-write',
                             'returncode': 0,
                             'trace': 'mtd-check,sync,unlock,writable-open,erase,write,erase,write,erase,write,erase,write,sync',
                             'device_reads': 0,
                             'corrupted': 0},
 'legacy:safe-storage-device': {'case': 'safe-storage-device',
                                'returncode': 0,
                                'trace': 'mtd-check,sync,unlock,writable-open,erase,write,erase,write,erase,write,erase,write,sync',
                                'device_reads': 0,
                                'corrupted': 0},
 'legacy:readonly-firmware-dump': {'case': 'readonly-firmware-dump',
                                   'returncode': 0,
                                   'trace': 'sync,dump,sync',
                                   'device_reads': 0,
                                   'corrupted': 0},
 'legacy:readonly-bad-table': {'case': 'readonly-bad-table',
                               'returncode': 0,
                               'trace': 'sync,dump,sync',
                               'device_reads': 0,
                               'corrupted': 0},
 'legacy:too-many-preerase': {'case': 'too-many-preerase',
                              'returncode': 21,
                              'trace': '',
                              'device_reads': 0,
                              'corrupted': 0},
 'legacy:missing-partition-table': {'case': 'missing-partition-table',
                                    'returncode': 21,
                                    'trace': '',
                                    'device_reads': 0,
                                    'corrupted': 0},
 'legacy:oversized-partition-line': {'case': 'oversized-partition-line',
                                     'returncode': 21,
                                     'trace': '',
                                     'device_reads': 0,
                                     'corrupted': 0},
 'legacy-disabled:disabled-guard-silent-corruption': {'case': 'disabled-guard-silent-corruption',
                                                      'returncode': 0,
                                                      'trace': 'mtd-check,sync,unlock,writable-open,erase,write,erase,write,erase,write,erase,write,sync,system-reboot,sleep2,raw-reboot',
                                                      'device_reads': 0,
                                                      'corrupted': 1},
 'parent:fd3': {'case': 'fd3',
                'status': 5376,
                'child_created': 1,
                'parent_mask_restored': 1,
                'exec_record': 1,
                'observations': [1, 1, 1, 1, 1, 1, 1, 1]},
 'parent:fd-high': {'case': 'fd-high',
                    'status': 5376,
                    'child_created': 1,
                    'parent_mask_restored': 1,
                    'exec_record': 1,
                    'observations': [1, 1, 1, 1, 1, 1, 1, 1]},
 'parent:child-safe20': {'case': 'child-safe20',
                         'status': 5120,
                         'child_created': 1,
                         'parent_mask_restored': 1,
                         'exec_record': 1,
                         'observations': [1, 1, 1, 1, 1, 1, 1, 1]},
 'parent:unexpected-zero': {'case': 'unexpected-zero',
                            'status': 0,
                            'child_created': 1,
                            'parent_mask_restored': 1,
                            'exec_record': 1,
                            'observations': [1, 1, 1, 1, 1, 1, 1, 1]},
 'parent:exec-failure': {'case': 'exec-failure',
                         'status': 5376,
                         'child_created': 1,
                         'parent_mask_restored': 1,
                         'exec_record': 1,
                         'observations': [1, 1, 1, 1, 1, 1, 1, 1]},
 'parent:wait-eintr': {'case': 'wait-eintr',
                       'status': 5376,
                       'child_created': 1,
                       'parent_mask_restored': 1,
                       'exec_record': 1,
                       'observations': [1, 1, 1, 1, 1, 1, 1, 1]},
 'parent:fork-failure': {'case': 'fork-failure',
                         'status': -1,
                         'child_created': 0,
                         'parent_mask_restored': 1,
                         'exec_record': 0,
                         'observations': []},
 'parent:invalid-lease': {'case': 'invalid-lease',
                          'status': -1,
                          'child_created': 0,
                          'parent_mask_restored': 1,
                          'exec_record': 0,
                          'observations': []},
 'parent:parent-mask-failure': {'case': 'parent-mask-failure',
                                'status': -1,
                                'child_created': 0,
                                'parent_mask_restored': 1,
                                'exec_record': 0,
                                'observations': []},
 'parent:parent-restore-failure': {'case': 'parent-restore-failure',
                                   'status': -1,
                                   'child_created': 1,
                                   'parent_mask_restored': 0,
                                   'exec_record': 1,
                                   'observations': [1, 1, 1, 1, 1, 1, 1, 1]},
 'parent:child-mask-failure': {'case': 'child-mask-failure',
                               'status': 5376,
                               'child_created': 1,
                               'parent_mask_restored': 1,
                               'exec_record': 0,
                               'observations': []},
 'parent:dup-failure': {'case': 'dup-failure',
                        'status': 5376,
                        'child_created': 1,
                        'parent_mask_restored': 1,
                        'exec_record': 0,
                        'observations': []},
 'parent:cloexec-failure': {'case': 'cloexec-failure',
                            'status': 5376,
                            'child_created': 1,
                            'parent_mask_restored': 1,
                            'exec_record': 0,
                            'observations': []},
 'parent:setsid-failure': {'case': 'setsid-failure',
                           'status': 5376,
                           'child_created': 1,
                           'parent_mask_restored': 1,
                           'exec_record': 0,
                           'observations': []},
 'parent:opendir-failure': {'case': 'opendir-failure',
                            'status': 5376,
                            'child_created': 1,
                            'parent_mask_restored': 1,
                            'exec_record': 0,
                            'observations': []},
 'parent:readdir-failure': {'case': 'readdir-failure',
                            'status': 5376,
                            'child_created': 1,
                            'parent_mask_restored': 1,
                            'exec_record': 0,
                            'observations': []},
 'parent:closedir-failure': {'case': 'closedir-failure',
                             'status': 5376,
                             'child_created': 1,
                             'parent_mask_restored': 1,
                             'exec_record': 0,
                             'observations': []},
 'parent:close-failure': {'case': 'close-failure',
                          'status': 5376,
                          'child_created': 1,
                          'parent_mask_restored': 1,
                          'exec_record': 0,
                          'observations': []},
 'consumer:consumer-unknown': {'case': 'consumer-unknown',
                               'active': 1,
                               'events': 1,
                               'signals': 0,
                               'actions': 0,
                               'remaining': 12,
                               'pending_flash': 1,
                               'writer_calls': 1,
                               'reboots': 0,
                               'watchdog_running': 0,
                               'memory_queries': 2,
                               'post': [0, 0, 0, 0, 0, 0],
                               'second': [0, 0, 0, 0, 0, 0]},
 'consumer:consumer-verified-return': {'case': 'consumer-verified-return',
                                       'active': 1,
                                       'events': 1,
                                       'signals': 0,
                                       'actions': 0,
                                       'remaining': 12,
                                       'pending_flash': 1,
                                       'writer_calls': 1,
                                       'reboots': 0,
                                       'watchdog_running': 0,
                                       'memory_queries': 2,
                                       'post': [0, 0, 0, 0, 0, 0],
                                       'second': [0, 0, 0, 0, 0, 0]},
 'consumer:consumer-signal': {'case': 'consumer-signal',
                              'active': 1,
                              'events': 1,
                              'signals': 0,
                              'actions': 0,
                              'remaining': 12,
                              'pending_flash': 1,
                              'writer_calls': 1,
                              'reboots': 0,
                              'watchdog_running': 0,
                              'memory_queries': 2,
                              'post': [0, 0, 0, 0, 0, 0],
                              'second': [0, 0, 0, 0, 0, 0]},
 'consumer:consumer-exec-failure': {'case': 'consumer-exec-failure',
                                    'active': 1,
                                    'events': 1,
                                    'signals': 0,
                                    'actions': 0,
                                    'remaining': 12,
                                    'pending_flash': 1,
                                    'writer_calls': 1,
                                    'reboots': 0,
                                    'watchdog_running': 0,
                                    'memory_queries': 2,
                                    'post': [0, 0, 0, 0, 0, 0],
                                    'second': [0, 0, 0, 0, 0, 0]},
 'consumer:consumer-untrusted20': {'case': 'consumer-untrusted20',
                                   'active': 1,
                                   'events': 1,
                                   'signals': 0,
                                   'actions': 0,
                                   'remaining': 12,
                                   'pending_flash': 1,
                                   'writer_calls': 1,
                                   'reboots': 0,
                                   'watchdog_running': 0,
                                   'memory_queries': 2,
                                   'post': [0, 0, 0, 0, 0, 0],
                                   'second': [0, 0, 0, 0, 0, 0]},
 'consumer:consumer-mismatched20': {'case': 'consumer-mismatched20',
                                    'active': 1,
                                    'events': 1,
                                    'signals': 0,
                                    'actions': 0,
                                    'remaining': 12,
                                    'pending_flash': 1,
                                    'writer_calls': 1,
                                    'reboots': 0,
                                    'watchdog_running': 0,
                                    'memory_queries': 2,
                                    'post': [0, 0, 0, 0, 0, 0],
                                    'second': [0, 0, 0, 0, 0, 0]},
 'consumer:consumer-safe20': {'case': 'consumer-safe20',
                              'active': 0,
                              'events': 13,
                              'signals': 1,
                              'actions': 1,
                              'remaining': 0,
                              'pending_flash': 0,
                              'writer_calls': 1,
                              'reboots': 0,
                              'watchdog_running': 1,
                              'memory_queries': 2,
                              'post': [13, 25, 25, 2, 1, 1],
                              'second': [3, 6, 6, 1, 0, 1]},
 'consumer:consumer-first-save-abort': {'case': 'consumer-first-save-abort',
                                        'active': 0,
                                        'events': 13,
                                        'signals': 1,
                                        'actions': 1,
                                        'remaining': 0,
                                        'pending_flash': 0,
                                        'writer_calls': 0,
                                        'reboots': 0,
                                        'watchdog_running': 1,
                                        'memory_queries': 2,
                                        'post': [13, 25, 25, 2, 0, 1],
                                        'second': [3, 6, 6, 1, 0, 1]},
 'consumer:consumer-hook-abort': {'case': 'consumer-hook-abort',
                                  'active': 0,
                                  'events': 13,
                                  'signals': 1,
                                  'actions': 1,
                                  'remaining': 0,
                                  'pending_flash': 0,
                                  'writer_calls': 0,
                                  'reboots': 0,
                                  'watchdog_running': 1,
                                  'memory_queries': 2,
                                  'post': [13, 25, 25, 2, 0, 1],
                                  'second': [3, 6, 6, 1, 0, 1]},
 'consumer:old-consumer-negative': {'case': 'old-consumer-negative',
                                    'active': 1,
                                    'events': 1,
                                    'signals': 0,
                                    'actions': 0,
                                    'remaining': 12,
                                    'pending_flash': 0,
                                    'writer_calls': 1,
                                    'reboots': 0,
                                    'watchdog_running': 0,
                                    'memory_queries': 0,
                                    'post': [1, 1, 1, 1, 0, 1],
                                    'second': [0, 0, 0, 0, 0, 1]}}
SHIPPED_CASES = ({'case': 'helper-bad-argc', 'program': 'bin/fw_upgrade', 'argv': [], 'exit_code': 21, 'stderr': ''},
 {'case': 'helper-old-parent-no-lease',
  'program': 'bin/fw_upgrade',
  'argv': ['--resident-upgrade', '/no-public-image', 'firmware', '@STATUS@', '3'],
  'exit_code': 21,
  'stderr': ''},
 {'case': 'legacy-protocol-refused',
  'program': 'bin/mtd_write',
  'argv': ['--upgrade-write', '/no-public-image', 'firmware', '@STATUS@'],
  'exit_code': 21,
  'stderr': 'mtd_write: firmware protocol moved to the controlled resident upgrade helper\n'},
 {'case': 'legacy-reboot-read-refused',
  'program': 'bin/mtd_write',
  'argv': ['-r', 'dump', 'Storage'],
  'exit_code': 21,
  'stderr': 'mtd_write: legacy firmware/whole-flash mutation and -r are disabled; use the controlled upgrade '
            'transaction\n'})
ROLE = ('Locked production-source static MIPS adapters with ordinary private files and '
        'real file-descriptor/lease operations; MTD, watchdog, reset and parent PID1 '
        'identity effects are explicit inert substitutes. Shipped programs run only refusal controls.')
LIMITS = (
    'No real MTD, flash write, erase, hardware watchdog, router PID1 signal or reboot is executed.',
    'The source adapters do not execute full shipped RC as PID1 or establish its complete memory residency.',
    'A static ELF removes interpreter/shared-library dependencies; this is not proof against OOM, kernel I/O stalls, hardware reset failure or power loss.',
    'Fixture identity/filesystem-type substitutions are not actual root ownership or hardware admission transitions.',
    'The new protocol does not retrofit the currently running efd2 controller or authorize its first migration.',
)
MAX_ELF = 4*1024*1024
MAX_SOURCE = 2*1024*1024


def refusal_preexec():
    """Deny host reboot/IOCTL before QEMU; refuse unsupported host ABIs."""
    require(sys.platform.startswith('linux') and platform.machine()=='x86_64' and
            ctypes.sizeof(ctypes.c_void_p)==8, 'Refusal sandbox requires Linux x86_64')
    class Instruction(ctypes.Structure):
        _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[('length',ctypes.c_ushort),('instructions',ctypes.POINTER(Instruction))]
    rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x00050001),(0x20,0,0,0)]
    for number in (169,16,0x40000000+169,0x40000000+16):
        rows += [(0x15,0,1,number),(0x06,0,0,0x00050001)]
    rows += [(0x06,0,0,0x7fff0000)]
    instructions=(Instruction*len(rows))(*(Instruction(*row) for row in rows))
    program=Program(len(rows),instructions)
    libc=ctypes.CDLL(None,use_errno=True)
    def install():
        if libc.prctl(38,1,0,0,0)!=0 or libc.prctl(22,2,ctypes.byref(program),0,0)!=0:
            os._exit(126)
    return install


def refusal_environment():
    require(sys.platform.startswith('linux') and platform.machine()=='x86_64',
            'Actual refusals require Linux x86_64')
    require(not Path('/proc/mtd').exists() and not list(Path('/dev').glob('mtd*')),
            'Actual refusals require a build host with no MTD interfaces')
    status=Path('/proc/self/status').read_text()
    caps={}
    for key in ('CapEff','CapPrm','CapAmb'):
        match=re.search(r'^'+key+r':\s*([0-9a-fA-F]+)$',status,re.M)
        require(match is not None,'Missing refusal-host capability observation: '+key)
        caps[key]=match.group(1)
    return {'uid':os.getuid(),'euid':os.geteuid(),'capabilities':caps,
            'no_proc_mtd':True,'no_dev_mtd':True,'no_new_privileges':True,
            'seccomp_denied_host_syscalls':['reboot','ioctl','x32-reboot','x32-ioctl']}


def validate_refusal(spec, run, status):
    require(run.returncode==spec['exit_code'] and run.stdout=='',
            'Shipped early refusal exit/output differs: '+spec['case'])
    # The guard-specific bytes prove that legacy -r was rejected by the
    # compiled K2P gate, rather than merely failing later on a host without MTD.
    require(run.stderr==spec['stderr'], 'Shipped refusal diagnostic differs: '+spec['case'])
    require(not status.exists() and not status.is_symlink(), 'Shipped refusal created writer status')
    return {'case':spec['case'],'program':spec['program'],'argv':spec['argv'],
            'exit_code':run.returncode,'stdout':run.stdout,'stderr':run.stderr,
            'status_file_created':False}


def validate_refusal_trace(spec, run, status):
    """Inspect target syscall attempts, separately from host seccomp defense."""
    require(run.returncode==spec['exit_code'] and run.stdout=='' and
            0<len(run.stderr.encode())<=128*1024,'Invalid traced refusal result: '+spec['case'])
    require(not status.exists() and not status.is_symlink(),'Traced refusal created a status')
    raw=run.stderr;diagnostic=spec['stderr']
    if diagnostic:
        require(raw.count(diagnostic)==1,'Traced guard-specific diagnostic differs: '+spec['case'])
    clean=raw.replace(diagnostic,'',1) if diagnostic else raw
    require('Unknown syscall' not in clean and re.search(r'\bexit(?:_group)?\(21\)',clean),
            'Traced refusal lacks a known normal exit21')
    calls=re.findall(r'(?m)^\s*[0-9]+\s+([a-zA-Z_][a-zA-Z_0-9]*)\(([^\n]*)',clean)
    require(calls,'No target syscalls were captured')
    require(not re.search(r'/proc/mtd|/dev/(?:mtd|watchdog)',clean),'Refusal attempted an MTD/watchdog interface')
    forbidden={'sync','syncfs','fsync','fdatasync','reboot','creat','pwrite64','pwrite','writev',
               'truncate','ftruncate','rename','renameat','renameat2','unlink','unlinkat',
               'mkdir','mkdirat','mknod','mknodat','link','linkat','symlink','symlinkat',
               'chmod','fchmod','fchmodat','chown','fchown','fchownat','utime','utimes',
               'socket','connect','send','sendto','sendmsg','mount','umount','umount2'}
    opens=[];writes=[];terminal_queries=[]
    for name,args in calls:
        require(name not in forbidden,'Refusal attempted forbidden syscall: '+name)
        if name in ('open','openat'):
            match=re.search(r'"(?:\\.|[^"\\])*"\s*,\s*([^,)]+)',args)
            require(match is not None,'Cannot inspect refusal open flags')
            flags=match.group(1).strip()
            if flags.startswith('O_'):
                require(all(flag in ('O_RDONLY','O_CLOEXEC','O_LARGEFILE','O_NOFOLLOW','O_DIRECTORY','O_NONBLOCK')
                            for flag in flags.split('|')) and 'O_RDONLY' in flags.split('|'),
                        'Refusal attempted a writable open')
            else:
                try:numeric=int(flags,0)
                except ValueError as error:raise ValueError('Cannot inspect numeric MIPS open flags') from error
                # Linux MIPS o32: access mask3, APPEND8, CREAT0x100, TRUNC0x200.
                require(numeric>=0 and numeric & 0x30b==0,'Refusal attempted a writable numeric open')
            opens.append({'syscall':name,'arguments':args,'flags':flags})
        if name=='write':
            require(diagnostic and re.match(r'^\s*2\s*,',args),'Refusal attempted a non-diagnostic write')
            writes.append(args)
        if name=='ioctl':
            # libc may ask whether inherited stdio is a terminal. No MTD/WDT
            # descriptor or arbitrary IOCTL is accepted as a benign query.
            require(re.match(r'^\s*[012]\s*,\s*(?:TCGETS|0x540d|21517)\s*,',args),
                    'Refusal attempted a non-terminal IOCTL')
            terminal_queries.append(args)
    return {'stderr':raw,'sha256':sha(raw.encode()),'syscalls_observed':[name for name,_ in calls],
            'read_only_open_calls':opens,'diagnostic_write_calls':writes,'stdio_terminal_queries':terminal_queries,
            'forbidden_attempts':[],'target_trace_is_not_host_seccomp_evidence':True}


def run_refusals(programs, qemu, specs, rootfs=None):
    environment=refusal_environment();records=[]
    with tempfile.TemporaryDirectory(prefix='k2p-resident-refusal-',dir='/tmp') as temporary:
        status=Path(temporary)/'must-not-be-created'
        for spec in specs:
            args=[str(status) if value=='@STATUS@' else value for value in spec['argv']]
            command=[qemu]
            if spec['program']!='bin/fw_upgrade':
                require(rootfs is not None,'Legacy dynamic refusal requires shipped loader root')
                command += ['-L',str(rootfs)]
            command += [str(programs[spec['program']]),*args]
            run=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                               text=True,timeout=10,close_fds=True,env={},preexec_fn=refusal_preexec())
            row=validate_refusal(spec,run,status)
            traced=subprocess.run([qemu,'-strace',*command[1:]],stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10,
                                  close_fds=True,env={},preexec_fn=refusal_preexec())
            row['target_syscall_trace']=validate_refusal_trace(spec,traced,status)
            records.append(row)
    return {'isolation':environment,'runs_per_case':2,'checks':records}


def shipped_refusals(rootfs, qemu):
    require(SHIPPED_CASES,'Shipped refusal contract has not been frozen')
    return run_refusals({spec['program']:rootfs/spec['program'] for spec in SHIPPED_CASES},
                        qemu,SHIPPED_CASES,rootfs)


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact(left, right, message):
    require(json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True), message)


def validate_static_helper(data, source_weak_symbols=False):
    """Independently inspect ELF32LE/MIPS load/entry and any symbol tables.

    Stripped binaries can omit SYMTAB. No dynamic segment/interpreter/dynsym
    imports are permitted; the report states which tables were observable.
    """
    require(type(source_weak_symbols) is bool,'Invalid source-only weak-symbol policy')
    require(type(data) in (bytes, bytearray) and 52 <= len(data) <= MAX_ELF and
            data[:7] == b'\x7fELF\x01\x01\x01', 'Helper must be bounded ELF32 little-endian MIPS')
    fields = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
    etype, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, _ = fields
    require((etype,machine,version,ehsize)==(2,8,1,52), 'Helper must be MIPS ET_EXEC')
    require(phsize==32 and 0 < phnum <= 128 and phoff >= 52 and phoff+phnum*32 <= len(data),
            'Invalid helper program-header bounds')
    loads=[]
    for index in range(phnum):
        kind,offset,vaddr,_,filesz,memsz,pflags,align=struct.unpack_from('<8I',data,phoff+index*32)
        require(offset <= len(data) and filesz <= len(data)-offset and filesz <= memsz and
                vaddr+memsz <= 2**32, 'Invalid helper segment bounds')
        require(kind not in (2,3), 'Resident helper must have no PT_DYNAMIC or PT_INTERP')
        if kind==1:
            require(align in (0,1) or align & (align-1)==0, 'Invalid helper LOAD alignment')
            loads.append({'offset':offset,'vaddr':vaddr,'file_bytes':filesz,'memory_bytes':memsz,'flags':pflags})
    require(loads and any(row['flags'] & 1 and row['vaddr'] <= entry < row['vaddr']+row['file_bytes']
                          for row in loads), 'Helper entry is outside file-backed executable LOAD')
    tables=[]
    undefined=[];weak_undefined=[]
    if shnum:
        require(shsize==40 and 0 < shnum <= 4096 and shoff >= 52 and shoff+shnum*40 <= len(data),
                'Invalid helper section-header bounds')
        sections=[struct.unpack_from('<10I',data,shoff+i*40) for i in range(shnum)]
        for index,section in enumerate(sections):
            _,kind,_,_,offset,size,link,_,_,entsize=section
            if kind != 8:
                require(offset <= len(data) and size <= len(data)-offset, 'Invalid helper section bounds')
            require(kind != 6, 'Resident helper must have no dynamic section')
            if kind not in (2,11):
                continue
            require(entsize==16 and size % 16==0 and link < shnum, 'Invalid helper symbol table')
            strings=sections[link]
            require(strings[1]==3 and strings[4] <= len(data) and strings[5] <= len(data)-strings[4],
                    'Invalid helper symbol-name table')
            pool=data[strings[4]:strings[4]+strings[5]]
            tables.append({'section':index,'kind':'DYNSYM' if kind==11 else 'SYMTAB','symbols':size//16})
            for at in range(offset,offset+size,16):
                name,value,symbol_size,info,other,shndx=struct.unpack_from('<IIIBBH',data,at)
                require(name < len(pool), 'Symbol name outside helper string table')
                end=pool.find(b'\0',name)
                require(end >= name, 'Unterminated helper symbol name')
                label=pool[name:end]
                if label and shndx==0 and info>>4 in (1,2):
                    if source_weak_symbols and info>>4==2:
                        weak_undefined.append(label.decode('ascii'))
                    else:
                        undefined.append(label.decode('ascii'))
    else:
        require(shoff==0 or shoff<=len(data), 'Invalid absent helper section table')
    require(not undefined, 'Resident helper has named undefined imports: '+','.join(undefined))
    return {'bytes':len(data),'sha256':sha(data),'ELF_class':32,'byte_order':'little','machine':8,
            'type':'ET_EXEC','entry':entry,'flags':flags,'LOAD':loads,'PT_INTERP':None,'PT_DYNAMIC':False,
            'symbol_tables':tables,'named_undefined_imports':undefined,
            'source_only_weak_undefined_symbols':weak_undefined,
            'static_no_runtime_loader':True,'executed_as_router_PID1':False}


def mask_c(text):
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*',
                  lambda match:' '*len(match.group()),text)


def function(text, name):
    pattern=r'(?:static\s+)?(?:inline\s+)?(?:void|int|ssize_t|pid_t|char\s*\*|FILE\s*\*)\s+\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{'
    found=list(re.finditer(pattern,mask_c(text)))
    require(len(found)==1,'Missing/ambiguous resident function: '+name)
    start=found[0].start();opening=text.index('{',start);depth=0
    for token in re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|[{}]',text[opening:]):
        if token.group()=='{':depth+=1
        elif token.group()=='}':
            depth-=1
            if not depth:return text[start:opening+token.end()]
    raise ValueError('Unterminated resident function: '+name)


def checked_module(text, label):
    ast.parse(text)
    module=types.ModuleType('_locked_resident_'+label)
    module.__file__='<locked-resident-'+label+'>'
    # Never import by path or accept a timestamp-valid stale .pyc.
    previous=sys.modules.get(module.__name__);sys.modules[module.__name__]=module
    try:exec(compile(text,module.__file__,'exec'),module.__dict__)
    finally:
        if previous is None:del sys.modules[module.__name__]
        else:sys.modules[module.__name__]=previous
    require(callable(getattr(module,'generate_source',None)), 'Missing pure resident generator')
    return module


def validate_contract():
    require(ADAPTERS and SOURCE_PATHS and CASES and EXPECTED,
            'Resident upgrade contract has not been frozen')
    require(len({name for name,_ in CASES})==len(CASES) and set(EXPECTED)=={name for name,_ in CASES},
            'Resident case identity is incomplete')


def validate_records(records):
    validate_contract()
    require(type(records) is list and len(records)==len(CASES), 'Resident cases missing/extra')
    for row,(name,options) in zip(records,CASES):
        require(type(row) is dict and set(row)=={'case','inputs','observed'} and row['case']==name,
                'Resident case schema/order differs')
        exact(row['inputs'],options,'Resident input mismatch: '+name)
        exact(row['observed'],EXPECTED[name],'Resident trace/state/effect mismatch: '+name)


def read_source_inputs(trunk):
    return {key:(trunk.parent/relative).read_text() for key,relative in SOURCE_PATHS.items()}


def generate_source(inputs, fixture_root, owner_uid, adapter):
    validate_contract()
    require(set(inputs)==set(SOURCE_PATHS) and adapter in ADAPTERS, 'Resident source/adapter mapping differs')
    require(type(owner_uid) is int and 0<=owner_uid<2**32, 'Invalid resident fixture owner')
    spec=ADAPTERS[adapter]
    module=checked_module(inputs[spec['harness']],adapter)
    exact(module.SOURCE_PATHS,spec['source_paths'],'Resident fixture source contract changed')
    expected=tuple((options['selector'],EXPECTED[name]) for name,options in CASES if options['adapter']==adapter)
    if 'case_args' in spec:
        exact(module.CASE_ARGS,spec['case_args'],'Legacy fixture argv contract changed')
    else:
        exact(module.CASES,expected,'Resident fixture case contract changed')
    texts={key:inputs[value] for key,value in spec['source_keys'].items()}
    options={'owner_uid':owner_uid}
    if 'enabled' in spec:
        require(type(spec['enabled']) is bool,'Legacy compile profile must be boolean')
        options['enabled']=spec['enabled']
    generated=module.generate_source(texts,str(fixture_root),**options)
    require(type(generated) is str and 0<len(generated.encode())<=MAX_SOURCE,'Invalid generated resident C')
    actual={name:function(inputs[key],name) for name,key in spec['functions'].items()}
    for name,body in actual.items():
        if name in spec.get('renames',{}):
            body=body.replace('int '+name+'(', 'int '+spec['renames'][name]+'(',1)
        require(generated.count(body)==1,'Resident adapter omitted/duplicated actual function: '+name)
    for key in spec.get('embedded_headers',[]):
        require(generated.count(inputs[key])==1,'Resident adapter did not embed exact header: '+key)
    return generated,actual


def export_probe(output, adapter, source, binary):
    require(adapter in ADAPTERS, 'Unknown resident export adapter')
    base='target-resident-upgrade-'+adapter
    (output.parent/(base+'.c')).write_bytes(source)
    target=output.parent/base;target.write_bytes(binary);target.chmod(0o755)


def execute_adapter(command, fixture, adapter):
    records=[]
    for name,options in CASES:
        if options['adapter']!=adapter:continue
        if fixture.exists():
            require(fixture.is_dir() and not fixture.is_symlink(),'Unsafe replaced resident fixture')
            shutil.rmtree(fixture)
        fixture.mkdir(mode=0o700)
        run=subprocess.run([*command,options['selector']],capture_output=True,text=True,timeout=20)
        diagnostic_ok=(len(run.stderr.encode())<=8192 and 'AddressSanitizer' not in run.stderr and
                       'runtime error:' not in run.stderr) if adapter.startswith('legacy') else not run.stderr
        require(run.returncode==0 and diagnostic_ok,
                'Resident probe failed '+name+': '+run.stdout+run.stderr)
        try:observed=json.loads(run.stdout)
        except json.JSONDecodeError as error:raise ValueError('Invalid resident JSON: '+name) from error
        records.append({'case':name,'inputs':options.copy(),'observed':observed})
    return records


def compile_full_helper(inputs, compiler, base, qemu):
    """Compile the complete unmodified helper, not a fixture entry/ABI shim."""
    main=function(inputs['helper_main'],'main')
    require(re.sub(r'\s+','',mask_c(main))==
            'intmain(intargc,char**argv,char**environment){_exit(fwup_resident_run(argc,argv,environment));}',
            'Actual helper main must terminate through _exit without CRT cleanup')
    makefile=inputs['helper_makefile']
    require(re.search(r'^fw_upgrade:[^\n]*\n\t\$\(CC\)[^\n]* -static [^\n]*fw_upgrade\.c crc32\.c',
                      makefile,re.M) is not None,'Shipped helper link rule must be static and use actual sources')
    directory=base/'full-helper-source';directory.mkdir(mode=0o700)
    filenames={'main':'fw_upgrade.c','writer':'upgrade_write.h','admission':'resident_admission.h',
               'resident':'resident_upgrade.h','crc':'crc32.c','crc_header':'crc32.h','makefile':'Makefile'}
    sources={filename:inputs['helper_'+key].encode() for key,filename in filenames.items()}
    for filename,data in sources.items():(directory/filename).write_bytes(data)
    binary=base/'full-helper'
    flags=['-std=gnu99','-Os','-static','-s','-D__BYTE_ORDER=__LITTLE_ENDIAN',
           '-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-Wl,-z,now']
    command=[str(compiler),*flags,'-o',str(binary),str(directory/'fw_upgrade.c'),str(directory/'crc32.c')]
    run=subprocess.run(command,text=True,capture_output=True,timeout=90)
    require(run.returncode==0,'Complete actual resident helper compile failed: '+run.stdout+run.stderr)
    data=binary.read_bytes();elf=validate_static_helper(data)
    refusals=run_refusals({'bin/fw_upgrade':binary},qemu,SHIPPED_CASES[:2])
    return {'role':'Complete current-source helper, independent of shipped rootfs; refusal-only execution',
            'binary_file':'target-resident-upgrade-full-helper','source_directory':'target-resident-upgrade-full-helper-source',
            'compile_flags':flags,'source_sha256':{name:sha(value) for name,value in sources.items()},
            'binary_sha256':sha(data),'ELF':elf,'refusals':refusals},sources,data


def bind_shipped_helper(trunk, rootfs, compiler, inputs):
    """Reproduce the inspected ROMFS install transforms on a private copy.

    Whole-file equality avoids broad masks of executable LOAD bytes. The raw
    source-built executable is not executed; observable static weak symbols
    may exist before strip, and are explicitly listed only for that input.
    """
    install=inputs['romfs_install']
    expected=('${STRIPTOOL} ${dstfile} 2>/dev/null',
              '${STRIPTOOL} -R .comment -R .note --strip-debug --strip-unneeded ${dstfile} 2>/dev/null',
              '${SSTRIP_TOOL} ${dstfile}')
    positions=[install.find(line) for line in expected]
    require(all(at>=0 and install.count(line)==1 for at,line in zip(positions,expected)) and
            positions==sorted(positions),'ROMFS helper strip rules changed; review required')
    require('SSTRIP_TOOL    = $(if $(CONFIG_FIRMWARE_PERFORM_SSTRIP),$(ROOTDIR)/tools/sstrip/sstrip)'
            in inputs['trunk_makefile'],'ROMFS sstrip selection changed; review required')
    require(compiler.name.endswith('gcc'),'Cannot determine exact toolchain strip program')
    strip=compiler.with_name(compiler.name[:-3]+'strip')
    require(strip.is_file() and os.access(strip,os.X_OK),'Missing helper install strip tool')
    built=trunk/'user/mtd_write/fw_upgrade';shipped=rootfs/'bin/fw_upgrade'
    require(built.is_file() and not built.is_symlink() and os.access(built,os.X_OK),
            'Missing source-built resident helper provenance input')
    original=built.read_bytes();original_elf=validate_static_helper(original,source_weak_symbols=True)
    config=(trunk/'.config').read_text()
    use_sstrip=re.search(r'^CONFIG_FIRMWARE_PERFORM_SSTRIP=y$',config,re.M) is not None
    sstrip=trunk/'tools/sstrip/sstrip'
    if use_sstrip:
        require(sstrip.is_file() and os.access(sstrip,os.X_OK),'Configured ROMFS sstrip tool is missing')
    commands=[]
    with tempfile.TemporaryDirectory(prefix='k2p-resident-install-',dir='/tmp') as temporary:
        transformed=Path(temporary)/'fw_upgrade';transformed.write_bytes(original)
        transforms=[(strip,[]),(strip,['-R','.comment','-R','.note','--strip-debug','--strip-unneeded'])]
        if use_sstrip:transforms.append((sstrip,[]))
        for tool,options in transforms:
            run=subprocess.run([str(tool),*options,str(transformed)],capture_output=True,text=True,timeout=30)
            require(run.returncode==0,'Resident install transform failed: '+run.stdout+run.stderr)
            commands.append({'program':tool.name,'options':options,'tool_sha256':sha(tool.read_bytes()),
                             'stdout':run.stdout,'stderr':run.stderr})
        installed=transformed.read_bytes()
    installed_elf=validate_static_helper(installed);shipped_data=shipped.read_bytes()
    require(installed==shipped_data,'Shipped resident helper differs from the source-built ROMFS transformation')
    return {'role':'Source-built full helper transformed by exact ROMFS strip rules; byte-identical to shipped helper',
            'source_built_file':'target-resident-upgrade-source-built-helper',
            'installed_file':'target-resident-upgrade-installed-helper',
            'source_built_sha256':sha(original),'source_built_ELF':original_elf,
            'installed_sha256':sha(installed),'installed_ELF':installed_elf,
            'shipped_sha256':sha(shipped_data),'whole_file_equal':True,'configured_sstrip':use_sstrip,
            'rule_sha256':{key:sha(inputs[key].encode()) for key in ('romfs_install','sstrip_source','trunk_makefile')},
            'transforms':commands},original,installed


def check(trunk,compiler,output,preflight=False,rootfs=None):
    validate_contract()
    config=(trunk/'.config').read_text()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$',config,re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$',config,re.M), 'Resident gate requires configured K2P4.4')
    require(preflight or rootfs is not None,'Final resident gate requires shipped rootfs')
    qemu=shutil.which('qemu-mipsel');require(qemu is not None,'qemu-mipsel is required')
    inputs=read_source_inputs(trunk)
    probes={};records=[];exports={};function_hashes={}
    with tempfile.TemporaryDirectory(prefix='k2p-resident-upgrade-',dir='/tmp') as temporary:
        base=Path(temporary).resolve()
        full_helper,full_sources,full_binary=compile_full_helper(inputs,compiler,base,qemu)
        for adapter in ADAPTERS:
            fixture=base/(adapter+'-fixture')
            generated,actual=generate_source(inputs,fixture,os.geteuid(),adapter)
            source=base/(adapter+'.c');binary=base/adapter;source.write_text(generated)
            optional=['-Wno-sign-compare'] if adapter.startswith('legacy') else []
            compile_flags=['-std=gnu99','-Os','-static','-s','-Wall','-Wextra','-Werror',
                           '-Wno-unused-function','-Wno-unused-parameter',*optional]
            compiled=subprocess.run([str(compiler),*compile_flags,str(source),'-o',str(binary)],
                                    text=True,capture_output=True,timeout=90)
            require(compiled.returncode==0,'Resident MIPS compile failed: '+compiled.stdout+compiled.stderr)
            data=binary.read_bytes();elf=validate_static_helper(data)
            records+=execute_adapter([qemu,str(binary)],fixture,adapter)
            encoded=generated.encode();exports[adapter]=(encoded,data)
            function_hashes[adapter]={name:sha(body.encode()) for name,body in actual.items()}
            probes[adapter]={'fixture_root':str(fixture),'owner_uid':os.geteuid(),
                             'owner_model':ADAPTERS[adapter]['owner_model'],
                             'compile_flags':compile_flags,
                             'source_file':'target-resident-upgrade-'+adapter+'.c',
                             'binary_file':'target-resident-upgrade-'+adapter,
                             'source_sha256':sha(encoded),'binary_sha256':sha(data),'ELF':elf}
    validate_records(records)
    output.parent.mkdir(parents=True,exist_ok=True)
    for adapter,(source,binary) in exports.items():export_probe(output,adapter,source,binary)
    full_source_dir=output.parent/full_helper['source_directory'];full_source_dir.mkdir(exist_ok=True)
    require(not full_source_dir.is_symlink(),'Invalid full helper source export directory')
    for filename,data in full_sources.items():(full_source_dir/filename).write_bytes(data)
    full_target=output.parent/full_helper['binary_file'];full_target.write_bytes(full_binary);full_target.chmod(0o755)
    shipped=None
    if rootfs is not None:
        shipped=validate_static_helper((rootfs/'bin/fw_upgrade').read_bytes())
        binding,source_built,installed=bind_shipped_helper(trunk,rootfs,compiler,inputs)
        for key,data in (('source_built_file',source_built),('installed_file',installed)):
            path=output.parent/binding[key];path.write_bytes(data);path.chmod(0o755)
        refusals=shipped_refusals(rootfs,qemu)
    else:
        refusals=None;binding=None
    report={'schema_version':1,'status':'PASS','profile':PROFILE,'phase':'early-source-only' if preflight else 'final-with-shipped-static',
            'execution_role':ROLE,'required_cases':[name for name,_ in CASES],'checks':records,
            'source_files':SOURCE_PATHS,'source_sha256':{key:sha(value.encode()) for key,value in inputs.items()},
            'source_functions_sha256':function_hashes,'probes':probes,'shipped_helper':shipped,
            'shipped_source_binding':binding,
            'shipped_refusals':refusals,'full_source_helper':full_helper,
            'compiler':str(compiler),'limits':list(LIMITS)}
    output.write_text(json.dumps(report,indent=2)+'\n')
    print('Resident upgrade: '+str(len(records))+' inert static MIPS cases PASS')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for option in ('trunk','compiler','output'):parser.add_argument('--'+option,type=Path,required=True)
    parser.add_argument('--preflight',action='store_true')
    parser.add_argument('--rootfs',type=Path)
    parser.add_argument('--sysroot',type=Path) # Interface parity; static probes do not use a loader prefix.
    args=parser.parse_args()
    try:check(args.trunk.resolve(),args.compiler.resolve(),args.output,args.preflight,args.rootfs.resolve() if args.rootfs else None)
    except (OSError,ValueError,subprocess.SubprocessError) as error:parser.exit(1,'Resident target validation failed: '+str(error)+'\n')
