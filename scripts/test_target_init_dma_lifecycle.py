import hashlib
"""Inert initialization/DMA gate interfaces; no target, clone or device."""
import contextlib
import copy
import io
import json
import os
import re
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import check_target_init_dma_lifecycle as g
from test_target_resident_upgrade import elf as static_elf


def module_elf(names):
    """Data-only ET_REL with disjoint dynamic sections and complete name offsets."""
    names=tuple(names)
    labels=b'\0.text\0.shstrtab\0.strtab\0.symtab\0'
    strings=b'\0';offsets={}
    for name in names:
        offsets[name]=len(strings);strings+=name.encode()+b'\0'
    text=b''.join(struct.pack('<I',0x24020000|i)for i in range(len(names)))
    symbols=bytes(16)+b''.join(struct.pack('<IIIBBH',offsets[name],i*4,4,0x12,0,1)
                              for i,name in enumerate(names))
    raw=bytearray(0x100);parts=[]
    for payload in(text,labels,strings,symbols):
        raw.extend(bytes((-len(raw))%16));parts.append((len(raw),len(payload)));raw.extend(payload)
    raw.extend(bytes((-len(raw))%16));shoff=len(raw)
    rows=[(0,0,0,0,0,0,0,0,0,0),
          (labels.index(b'.text'),1,6,0,*parts[0],0,0,4,0),
          (labels.index(b'.shstrtab'),3,0,0,*parts[1],0,0,1,0),
          (labels.index(b'.strtab'),3,0,0,*parts[2],0,0,1,0),
          (labels.index(b'.symtab'),2,0,0,*parts[3],3,1,4,16)]
    for row in rows:raw.extend(struct.pack('<10I',*row))
    raw[:16]=b'\x7fELF\x01\x01\x01'+bytes(9)
    struct.pack_into('<HHIIIIIHHHHHH',raw,16,1,8,1,0,0,shoff,0x50001001,52,0,0,40,len(rows),2)
    return bytes(raw)


KERNEL_REFERENCE_BODIES = {'try_module_get': 'bool try_module_get(struct module *module)\n'
                   '{\n'
                   '\tbool ret = true;\n'
                   '\n'
                   '\tif (module) {\n'
                   '\t\tpreempt_disable();\n'
                   '\t\t/* Note: here, we can fail to get a reference */\n'
                   '\t\tif (likely(module_is_live(module) &&\n'
                   '\t\t\t   atomic_inc_not_zero(&module->refcnt) != 0))\n'
                   '\t\t\ttrace_module_get(module, _RET_IP_);\n'
                   '\t\telse\n'
                   '\t\t\tret = false;\n'
                   '\n'
                   '\t\tpreempt_enable();\n'
                   '\t}\n'
                   '\treturn ret;\n'
                   '}',
 'module_put': 'void module_put(struct module *module)\n'
               '{\n'
               '\tint ret;\n'
               '\n'
               '\tif (module) {\n'
               '\t\tpreempt_disable();\n'
               '\t\tret = atomic_dec_if_positive(&module->refcnt);\n'
               '\t\tWARN_ON(ret < 0);\t/* Failed to put refcount */\n'
               '\t\ttrace_module_put(module, _RET_IP_);\n'
               '\t\tpreempt_enable();\n'
               '\t}\n'
               '}',
 'try_release_module_ref': 'static int try_release_module_ref(struct module *mod)\n'
                           '{\n'
                           '\tint ret;\n'
                           '\n'
                           '\t/* Try to decrement refcnt which we set at loading */\n'
                           '\tret = atomic_sub_return(MODULE_REF_BASE, &mod->refcnt);\n'
                           '\tBUG_ON(ret < 0);\n'
                           '\tif (ret)\n'
                           '\t\t/* Someone can put this right now, recover with checking */\n'
                           '\t\tret = atomic_add_unless(&mod->refcnt, MODULE_REF_BASE, 0);\n'
                           '\n'
                           '\treturn ret;\n'
                           '}',
 'try_stop_module': 'static int try_stop_module(struct module *mod, int flags, int *forced)\n'
                    '{\n'
                    "\t/* If it's not unused, quit unless we're forcing. */\n"
                    '\tif (try_release_module_ref(mod) != 0) {\n'
                    '\t\t*forced = try_force_unload(flags);\n'
                    '\t\tif (!(*forced))\n'
                    '\t\t\treturn -EWOULDBLOCK;\n'
                    '\t}\n'
                    '\n'
                    '\t/* Mark it as dying. */\n'
                    '\tmod->state = MODULE_STATE_GOING;\n'
                    '\n'
                    '\treturn 0;\n'
                    '}',
 'module_is_live': 'static inline int module_is_live(struct module *mod)\n'
                   '{\n'
                   '\treturn mod->state != MODULE_STATE_GOING;\n'
                   '}'}


HWCMD_DECLARATION_FIXTURES = {'enum \\{\\n\\tHWCMD_TYPE_FIRST[\\s\\S]*?\\n\\};': 'enum {\n'
                                                    '\tHWCMD_TYPE_FIRST = 0,\n'
                                                    '\tHWCMD_TYPE_RADIO = '
                                                    'HWCMD_TYPE_FIRST,\n'
                                                    '\tHWCMD_TYPE_SECURITY,\n'
                                                    '\tHWCMD_TYPE_PERIPHERAL,\n'
                                                    '\tHWCMD_TYPE_HT_CAP,\n'
                                                    '\tHWCMD_TYPE_PS,\n'
                                                    '\tHWCMD_TYPE_WIFISYS,\n'
                                                    '\tHWCMD_TYPE_WMM,\n'
                                                    '\tHWCMD_TYPE_PROTECT,\n'
                                                    '\tHWCMD_TYPE_END\n'
                                                    '};',
 'typedef struct _HwCmdQElmt \\{[\\s\\S]*?\\} HwCmdQElmt, \\*PHwCmdQElmt;': 'typedef '
                                                                            'struct '
                                                                            '_HwCmdQElmt '
                                                                            '{\n'
                                                                            '\t'
                                                                            'UINT32 '
                                                                            'type;\n'
                                                                            '\t'
                                                                            'UINT32 '
                                                                            'command;\n'
                                                                            '\t'
                                                                            'VOID '
                                                                            '*buffer;\n'
                                                                            '\t'
                                                                            'UINT32 '
                                                                            'bufferlength;\n'
                                                                            '\t'
                                                                            'BOOLEAN '
                                                                            'NeedWait;\n'
                                                                            '\t'
                                                                            'RTMP_OS_COMPLETION '
                                                                            'ack_done;\n'
                                                                            '\t'
                                                                            'VOID '
                                                                            '*RspBuffer;\n'
                                                                            '\t'
                                                                            'UINT32 '
                                                                            'RspBufferLen;\n'
                                                                            '\t'
                                                                            'HwCmdCb '
                                                                            'CallbackFun;\n'
                                                                            '\t'
                                                                            'VOID '
                                                                            '*CallbackArgs;\n'
                                                                            '\t'
                                                                            'NDIS_SPIN_LOCK '
                                                                            'lock;\n'
                                                                            '\t'
                                                                            'os_kref '
                                                                            'refcnt;\n'
                                                                            '\t'
                                                                            'NDIS_STATUS '
                                                                            'result;\n'
                                                                            '#ifdef '
                                                                            'DBG_STARVATION\n'
                                                                            '\t'
                                                                            'struct '
                                                                            'starv_dbg '
                                                                            'starv;\n'
                                                                            '#endif '
                                                                            '/*DBG_STARVATION*/\n'
                                                                            '\t'
                                                                            'struct '
                                                                            '_HwCmdQElmt '
                                                                            '*next;\n'
                                                                            '} '
                                                                            'HwCmdQElmt, '
                                                                            '*PHwCmdQElmt;',
 'typedef struct _HwCmdQ \\{[\\s\\S]*?\\} HwCmdQ, \\*PHwCmdQ;': 'typedef '
                                                                'struct '
                                                                '_HwCmdQ {\n'
                                                                '\tUINT32 '
                                                                'size;\n'
                                                                '\tHwCmdQElmt '
                                                                '*head;\n'
                                                                '\tHwCmdQElmt '
                                                                '*tail;\n'
                                                                '\tUINT32 '
                                                                'CmdQState;\n'
                                                                '} HwCmdQ, '
                                                                '*PHwCmdQ;',
 'typedef struct _HwFlagCtrl \\{[\\s\\S]*?\\} HwFlagCtrl, \\*PHwFlagCtrl;': 'typedef '
                                                                            'struct '
                                                                            '_HwFlagCtrl '
                                                                            '{\n'
                                                                            '\t'
                                                                            'BOOLEAN\t'
                                                                            'IsFlagSet;\n'
                                                                            '\t'
                                                                            'UINT32\t\t'
                                                                            'FlagId;\n'
                                                                            '} '
                                                                            'HwFlagCtrl, '
                                                                            '*PHwFlagCtrl;',
 'typedef struct _HW_CTRL_TXD \\{[\\s\\S]*?\\} HW_CTRL_TXD;': 'typedef struct '
                                                              '_HW_CTRL_TXD {\n'
                                                              '\tUINT32\t\t\t'
                                                              'CmdType;\n'
                                                              '\tUINT32\t\t\t'
                                                              'CmdId;\n'
                                                              '\tBOOLEAN\t\t\t'
                                                              'NeedWait;\n'
                                                              '\tUINT32\t\t\t'
                                                              'wait_time;\n'
                                                              '\tVOID\t\t\t'
                                                              '*pInformationBuffer;\n'
                                                              '\tUINT32\t\t\t'
                                                              'InformationBufferLength;\n'
                                                              '\tVOID\t\t\t'
                                                              '*pRespBuffer;\n'
                                                              '\tUINT32\t\t\t'
                                                              'RespBufferLength;\n'
                                                              '\tHwCmdCb\t\t'
                                                              'CallbackFun;\n'
                                                              '\tVOID\t\t\t'
                                                              '*CallbackArgs;\n'
                                                              '} HW_CTRL_TXD;',
 'typedef struct _HWCTRL_OP \\{[\\s\\S]*?\\} HWCTRL_OP;': 'typedef struct '
                                                          '_HWCTRL_OP {\n'
                                                          '\tNTSTATUS '
                                                          '(*wifi_sys_open)(struct '
                                                          'WIFI_SYS_CTRL '
                                                          '*wsys);\n'
                                                          '\tNTSTATUS '
                                                          '(*wifi_sys_close)(struct '
                                                          'WIFI_SYS_CTRL '
                                                          '*wsys);\n'
                                                          '\tNTSTATUS '
                                                          '(*wifi_sys_link_up)(struct '
                                                          'WIFI_SYS_CTRL '
                                                          '*wsys);\n'
                                                          '\tNTSTATUS '
                                                          '(*wifi_sys_link_down)(struct '
                                                          'WIFI_SYS_CTRL '
                                                          '*wsys);\n'
                                                          '\tNTSTATUS '
                                                          '(*wifi_sys_connt_act)(struct '
                                                          'WIFI_SYS_CTRL '
                                                          '*wsys);\n'
                                                          '\tNTSTATUS '
                                                          '(*wifi_sys_disconnt_act)(struct '
                                                          'WIFI_SYS_CTRL '
                                                          '*wsys);\n'
                                                          '\tNTSTATUS '
                                                          '(*wifi_sys_peer_update)(struct '
                                                          'WIFI_SYS_CTRL '
                                                          '*wsys);\n'
                                                          '} HWCTRL_OP;',
 'typedef struct _HW_CTRL_T \\{[\\s\\S]*?\\} HW_CTRL_T;': 'typedef struct '
                                                          '_HW_CTRL_T {\n'
                                                          '\tHwCmdQ HwCtrlQ;\n'
                                                          '\tHwFlagCtrl\t'
                                                          'HwCtrlFlag;\n'
                                                          '\tNDIS_SPIN_LOCK '
                                                          'HwCtrlQLock;\t/* '
                                                          'CmdQLock spinlock '
                                                          '*/\n'
                                                          '\tRTMP_OS_TASK '
                                                          'HwCtrlTask;\n'
                                                          '\tUINT32 TotalCnt;\n'
                                                          '\tHWCTRL_OP '
                                                          'hwctrl_ops;\n'
                                                          '#ifdef '
                                                          'ERR_RECOVERY\n'
                                                          '\tRTMP_OS_TASK '
                                                          'ser_task;\n'
                                                          '\tINT '
                                                          'ser_func_state;\n'
                                                          '\tUINT32 '
                                                          'ser_status;\n'
                                                          '\tNDIS_SPIN_LOCK '
                                                          'ser_lock;\n'
                                                          '\tBOOLEAN '
                                                          'ser_initialized;\n'
                                                          '\tUINT32 '
                                                          'ser_times[SER_TIME_ID_END];\n'
                                                          '#endif /* '
                                                          'ERR_RECOVERY */\n'
                                                          '#ifdef '
                                                          'DBG_STARVATION\n'
                                                          '\tstruct '
                                                          'starv_dbg_block '
                                                          'block;\n'
                                                          '#endif '
                                                          '/*DBG_STARVATION*/\n'
                                                          '} HW_CTRL_T;',
 'typedef enum _RTMP_TASK_STATUS_ \\{[\\s\\S]*?\\} RTMP_TASK_STATUS;': 'typedef '
                                                                       'enum '
                                                                       '_RTMP_TASK_STATUS_ '
                                                                       '{\n'
                                                                       '\t'
                                                                       'RTMP_TASK_STAT_UNKNOWN '
                                                                       '= 0,\n'
                                                                       '\t'
                                                                       'RTMP_TASK_STAT_INITED '
                                                                       '= 1,\n'
                                                                       '\t'
                                                                       'RTMP_TASK_STAT_RUNNING '
                                                                       '= 2,\n'
                                                                       '\t'
                                                                       'RTMP_TASK_STAT_STOPED '
                                                                       '= 4,\n'
                                                                       '} '
                                                                       'RTMP_TASK_STATUS;',
 '^#define RTMP_TASK_CAN_DO_INSERT[^\\n]*': '#define '
                                            'RTMP_TASK_CAN_DO_INSERT\t\t'
                                            '(RTMP_TASK_STAT_INITED | '
                                            'RTMP_TASK_STAT_RUNNING)',
 '^#define HWCTRL_CMD_TIMEOUT[^\\n]*': '#define HWCTRL_CMD_TIMEOUT 100',
 '^INT32 MtCmdGetThermalSensorResult\\(struct _RTMP_ADAPTER \\*pAd, UINT8 ActionIdx, UINT32 \\*SensorResult\\);': 'INT32 '
                                                                                                                  'MtCmdGetThermalSensorResult(struct '
                                                                                                                  '_RTMP_ADAPTER '
                                                                                                                  '*pAd, '
                                                                                                                  'UINT8 '
                                                                                                                  'ActionIdx, '
                                                                                                                  'UINT32 '
                                                                                                                  '*SensorResult);',
 'enum \\{\\n\\tHWCMD_ID_FIRST[\\s\\S]*?\\n\\};': 'enum {\n'
                                                  '\tHWCMD_ID_FIRST = 0,\n'
                                                  '\t/*Peripheral*/\n'
                                                  '\tHWCMD_ID_GPIO_CHECK\t\t\t'
                                                  '= HWCMD_ID_FIRST,\n'
                                                  '\t/*USB related*/\n'
                                                  '\t'
                                                  'HWCMD_ID_RESET_BULK_OUT\t\t\t'
                                                  '= 1,\n'
                                                  '\t'
                                                  'HWCMD_ID_RESET_BULK_IN\t\t\t'
                                                  '= 2,\n'
                                                  '\t/*WSC & LED related*/\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_LED_STATUS\t\t\t'
                                                  '= 3,\n'
                                                  '\t'
                                                  'HWCMD_ID_LED_WPS_MODE10\t\t\t'
                                                  '= 4,\n'
                                                  '\t/*Security related*/\n'
                                                  '\t'
                                                  'HWCMD_ID_DEL_ASIC_WCID\t\t\t'
                                                  '= 7,\n'
                                                  '#ifdef HTC_DECRYPT_IOT\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_ASIC_AAD_OM\t\t'
                                                  '= 8,\n'
                                                  '#endif /* HTC_DECRYPT_IOT '
                                                  '*/\n'
                                                  '\t'
                                                  'HWCMD_ID_ADDREMOVE_ASIC_KEY\t\t'
                                                  '= 9,\n'
                                                  '\t/*MT_MAC */\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_CLIENT_MAC_ENTRY\t'
                                                  '= 10,\n'
                                                  '\tHWCMD_ID_PS_CLEAR\t\t\t\t'
                                                  '= 11,\n'
                                                  '\t'
                                                  'HWCMD_ID_PS_RETRIEVE_START\t\t'
                                                  '= 12,\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_TR_ENTRY\t\t\t'
                                                  '= 13,\n'
                                                  '\t'
                                                  'HWCMD_ID_UPDATE_DAW_COUNTER\t\t'
                                                  '= 14,\n'
                                                  '\t'
                                                  'HWCMD_ID_UPDATE_BEACON\t\t\t'
                                                  '= 15,\n'
                                                  '\t'
                                                  'HWCMD_ID_GET_TEMPERATURE\t\t'
                                                  '= 16,\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_SLOTTIME\t\t\t'
                                                  '= 17,\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_TX_BURST\t\t\t'
                                                  '= 18,\n'
                                                  '#ifdef TXBF_SUPPORT\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_APCLI_BF_CAP\t\t'
                                                  '= 19,\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_APCLI_BF_REPEATER\t'
                                                  '= 20,\n'
                                                  '\t'
                                                  'HWCMD_ID_ADJUST_STA_BF_SOUNDING\t'
                                                  '= 21,\n'
                                                  '\t'
                                                  'HWCMD_ID_TXBF_TX_APPLY_CTRL\t\t'
                                                  '= 22,\n'
                                                  '#endif /* TXBF_SUPPORT */\n'
                                                  '#ifdef ERR_RECOVERY\n'
                                                  '\t'
                                                  'HWCMD_ID_MAC_ERROR_DETECT\t\t'
                                                  '= 23,\n'
                                                  '#endif /* ERR_RECOVERY */\n'
                                                  '\t/*AP realted*/\n'
                                                  '\t'
                                                  'HWCMD_ID_AP_ADJUST_EXP_ACK_TIME\t'
                                                  '= 24,\n'
                                                  '\t'
                                                  'HWCMD_ID_AP_RECOVER_EXP_ACK_TIME '
                                                  '= 25,\n'
                                                  '\t'
                                                  'HWCMD_ID_UPDATE_BSSINFO\t\t\t'
                                                  '= 26,\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_BA_REC\t\t\t\t'
                                                  '= 27,\n'
                                                  '\t/*STA related*/\n'
                                                  '\t'
                                                  'HWCMD_ID_PWR_MGT_BIT_WIFI\t\t'
                                                  '= 28,\n'
                                                  '\t'
                                                  'HWCMD_ID_FORCE_WAKE_UP\t\t\t'
                                                  '= 29,\n'
                                                  '\t'
                                                  'HWCMD_ID_FORCE_SLEEP_AUTO_WAKEUP '
                                                  '= 30,\n'
                                                  '\tHWCMD_ID_MAKE_FW_OWN\t\t\t'
                                                  '= 31,\n'
                                                  '\t'
                                                  'HWCMD_ID_ENTER_PS_NULL\t\t\t'
                                                  '= 32,\n'
                                                  '#ifdef VOW_SUPPORT\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_STA_DWRR\t\t\t'
                                                  '= 33,\n'
                                                  '#endif /* VOW_SUPPORT */\n'
                                                  '\tHWCMD_ID_UPDATE_RSSI\t\t\t'
                                                  '= 34,\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_STA_DWRR_QUANTUM\t'
                                                  '= 35,\n'
                                                  '\t'
                                                  'HWCMD_ID_PERODIC_CR_ACCESS_NIC_UPDATE_RAW_COUNTERS\t\t\t'
                                                  '= 37,\n'
                                                  '\t'
                                                  'HWCMD_ID_SET_BCN_OFFLOAD\t\t'
                                                  '= 38,\n'
                                                  '\t'
                                                  'HWCMD_ID_ADD_REPT_ENTRY\t\t\t'
                                                  '= 39,\n'
                                                  '\t'
                                                  'HWCMD_ID_REMOVE_REPT_ENTRY\t\t'
                                                  '= 40,\n'
                                                  '\t'
                                                  'HWCMD_ID_WIFISYS_LINKDOWN\t\t'
                                                  '= 41,\n'
                                                  '\t'
                                                  'HWCMD_ID_WIFISYS_LINKUP\t\t\t'
                                                  '= 42,\n'
                                                  '\t'
                                                  'HWCMD_ID_WIFISYS_OPEN\t\t\t'
                                                  '= 43,\n'
                                                  '\t'
                                                  'HWCMD_ID_WIFISYS_CLOSE\t\t\t'
                                                  '= 44,\n'
                                                  '\t'
                                                  'HWCMD_ID_WIFISYS_PEER_LINKUP\t'
                                                  '= 45,\n'
                                                  '\t'
                                                  'HWCMD_ID_WIFISYS_PEER_LINKDOWN\t'
                                                  '= 46,\n'
                                                  '\t'
                                                  'HWCMD_ID_WIFISYS_PEER_UPDATE\t'
                                                  '= 47,\n'
                                                  '#ifdef '
                                                  'THERMAL_PROTECT_SUPPORT\n'
                                                  '\t'
                                                  'HWCMD_ID_THERMAL_PROTECTION_RADIOOFF '
                                                  '= 48,\n'
                                                  '#endif /* '
                                                  'THERMAL_PROTECT_SUPPORT */\n'
                                                  '\t'
                                                  'HWCMD_ID_GET_TX_STATISTIC\t\t'
                                                  '= 49,\n'
                                                  '\t'
                                                  'HWCMD_ID_RADIO_ON_OFF\t\t\t'
                                                  '= 50,\n'
                                                  '\tHWCMD_ID_PBC_CTRL\t\t\t\t'
                                                  '= 51,\n'
                                                  '#ifdef GREENAP_SUPPORT\n'
                                                  '\t'
                                                  'HWCMD_ID_GREENAP_ON_OFF\t\t\t'
                                                  '= 52,\n'
                                                  '#endif /* GREENAP_SUPPORT '
                                                  '*/\n'
                                                  '\t'
                                                  'HWCMD_ID_HT_PROTECT\t\t\t\t'
                                                  '= 54,\n'
                                                  '\tHWCMD_ID_RTS_THLD\t\t\t\t'
                                                  '= 55,\n'
                                                  '#ifdef '
                                                  'HOST_RESUME_DONE_ACK_SUPPORT\n'
                                                  '\t'
                                                  'HWCMD_ID_HOST_RESUME_DONE_ACK\t'
                                                  '= 56,\n'
                                                  '#endif /* '
                                                  'HOST_RESUME_DONE_ACK_SUPPORT '
                                                  '*/\n'
                                                  '#ifdef '
                                                  'ETSI_RX_BLOCKER_SUPPORT\n'
                                                  '\t'
                                                  'HWCMD_RX_CHECK_RSSI        '
                                                  '= 57,\n'
                                                  '#endif /* end of '
                                                  'ETSI_RX_BLOCKER_SUPPORT */\n'
                                                  '#ifdef '
                                                  'PCIE_ASPM_DYM_CTRL_SUPPORT\n'
                                                  '\t'
                                                  'HWCMD_ID_PCIE_ASPM_DYM_CTRL\t\t'
                                                  '= 58,\n'
                                                  '#endif /* '
                                                  'PCIE_ASPM_DYM_CTRL_SUPPORT '
                                                  '*/\n'
                                                  '#ifdef MBO_SUPPORT\n'
                                                  '\t'
                                                  'HWCMD_ID_BSS_TERMINATION        '
                                                  '= 59,\n'
                                                  '#endif /* MBO_SUPPORT */\n'
                                                  '\tHWCMD_ID_SET_EDCA = 60,\n'
                                                  '#ifdef '
                                                  'MBSS_AS_WDS_AP_SUPPORT\n'
                                                  '    '
                                                  'HWCMD_ID_UPDATE_4ADDR_HDR_TRANS,\n'
                                                  '#endif\n'
                                                  '\n'
                                                  '\tHWCMD_ID_END,\n'
                                                  '};'}

NATIVE_BOUNDARY_FIXTURE = {'pci_bind_pci': 'static struct pci_driver rt_pci_driver = {\n'
                 '    /* A failed DMA stop retains owners, but the driver core still unbinds.\n'
                 '     * Keep manual bind/unbind unavailable until that transition is supported.\n'
                 '     * Normal module exit and PCI shutdown callbacks remain registered.\n'
                 '     */\n'
                 '    .driver = {\n'
                 '        .suppress_bind_attrs = true,\n'
                 '    },\n'
                 'name:\n'
                 '\tRTMP_DRV_NAME,\n'
                 'id_table :\n'
                 '\trt_pci_tbl,\n'
                 'probe :\n'
                 '\trt_pci_probe,\n'
                 'shutdown :\n'
                 '\trt_pci_shutdown,\n'
                 '#if LINUX_VERSION_CODE >= 0x20412\n'
                 'remove :\n'
                 '\tDEVEXIT_P(rt_pci_remove),\n'
                 '#else\n'
                 'remove :\n'
                 '\t__devexit(rt_pci_remove),\n'
                 '#endif\n'
                 '\n'
                 '#if (KERNEL_VERSION(2, 5, 0) <= LINUX_VERSION_CODE)\n'
                 '#ifdef CONFIG_PM\n'
                 'suspend :\n'
                 '\trt_pci_suspend,\n'
                 'resume :\n'
                 '\trt_pci_resume,\n'
                 '#endif\n'
                 '#endif\n'
                 '};\n'
                 'static VOID rt_pci_shutdown(struct pci_dev *pci_dev)\n'
                 '{\n'
                 '\t/* Ordinary reboot does not clear bus mastering in the PCI core.  Keep\n'
                 '\t * all DMA ownership intact here: disabling new transactions is not an\n'
                 '\t * acknowledgement that the device has completed in-flight DMA.\n'
                 '\t */\n'
                 '\tpci_clear_master(pci_dev);\n'
                 '}\n'
                 'int __init rt_pci_init_module(void)\n'
                 '{\n'
                 '\tMTWF_LOG(DBG_CAT_HIF, CATHIF_PCI, DBG_LVL_ERROR, ("register %s\\n", RTMP_DRV_NAME));\n'
                 '#ifdef MEM_ALLOC_INFO_SUPPORT\n'
                 '\tMemInfoListInital();\n'
                 '#endif /* MEM_ALLOC_INFO_SUPPORT */\n'
                 '\t/*\n'
                 '\t *\tMTWF_LOG(DBG_CAT_HIF, CATHIF_PCI, DBG_LVL_ERROR, ("DriverVersion: '
                 '2.7.0.2-Beta-121007\\n"\n'
                 '\t *\t\t\t\t\t\t\t\t"\\tBBP:120824\\n"\n'
                 '\t *\t\t\t\t\t\t\t\t"\\tRF :120813\\n"));\n'
                 '\t */\n'
                 '#if (KERNEL_VERSION(2, 5, 0) <= LINUX_VERSION_CODE)\n'
                 '\treturn pci_register_driver(&rt_pci_driver);\n'
                 '#else\n'
                 '\treturn pci_module_init(&rt_pci_driver);\n'
                 '#endif\n'
                 '}\n'
                 'void __exit rt_pci_cleanup_module(void)\n'
                 '{\n'
                 '\tpci_unregister_driver(&rt_pci_driver);\n'
                 '}',
 'pci_bind_core': 'int __pci_register_driver(struct pci_driver *drv, struct module *owner,\n'
                  '\t\t\t  const char *mod_name)\n'
                  '{\n'
                  '\t/* initialize common driver fields */\n'
                  '\tdrv->driver.name = drv->name;\n'
                  '\tdrv->driver.bus = &pci_bus_type;\n'
                  '\tdrv->driver.owner = owner;\n'
                  '\tdrv->driver.mod_name = mod_name;\n'
                  '\n'
                  '\tspin_lock_init(&drv->dynids.lock);\n'
                  '\tINIT_LIST_HEAD(&drv->dynids.list);\n'
                  '\n'
                  '\t/* register with core */\n'
                  '\treturn driver_register(&drv->driver);\n'
                  '}\n'
                  'void pci_unregister_driver(struct pci_driver *drv)\n'
                  '{\n'
                  '\tdriver_unregister(&drv->driver);\n'
                  '\tpci_free_dynids(drv);\n'
                  '}',
 'pci_bind_bus': 'int bus_add_driver(struct device_driver *drv)\n'
                 '{\n'
                 '\tstruct bus_type *bus;\n'
                 '\tstruct driver_private *priv;\n'
                 '\tint error = 0;\n'
                 '\n'
                 '\tbus = bus_get(drv->bus);\n'
                 '\tif (!bus)\n'
                 '\t\treturn -EINVAL;\n'
                 '\n'
                 '\tpr_debug("bus: \'%s\': add driver %s\\n", bus->name, drv->name);\n'
                 '\n'
                 '\tpriv = kzalloc(sizeof(*priv), GFP_KERNEL);\n'
                 '\tif (!priv) {\n'
                 '\t\terror = -ENOMEM;\n'
                 '\t\tgoto out_put_bus;\n'
                 '\t}\n'
                 '\tklist_init(&priv->klist_devices, NULL, NULL);\n'
                 '\tpriv->driver = drv;\n'
                 '\tdrv->p = priv;\n'
                 '\tpriv->kobj.kset = bus->p->drivers_kset;\n'
                 '\terror = kobject_init_and_add(&priv->kobj, &driver_ktype, NULL,\n'
                 '\t\t\t\t     "%s", drv->name);\n'
                 '\tif (error)\n'
                 '\t\tgoto out_unregister;\n'
                 '\n'
                 '\tklist_add_tail(&priv->knode_bus, &bus->p->klist_drivers);\n'
                 '\tif (drv->bus->p->drivers_autoprobe) {\n'
                 '\t\tif (driver_allows_async_probing(drv)) {\n'
                 '\t\t\tpr_debug("bus: \'%s\': probing driver %s asynchronously\\n",\n'
                 '\t\t\t\tdrv->bus->name, drv->name);\n'
                 '\t\t\tasync_schedule(driver_attach_async, drv);\n'
                 '\t\t} else {\n'
                 '\t\t\terror = driver_attach(drv);\n'
                 '\t\t\tif (error)\n'
                 '\t\t\t\tgoto out_unregister;\n'
                 '\t\t}\n'
                 '\t}\n'
                 '\tmodule_add_driver(drv->owner, drv);\n'
                 '\n'
                 '\terror = driver_create_file(drv, &driver_attr_uevent);\n'
                 '\tif (error) {\n'
                 '\t\tprintk(KERN_ERR "%s: uevent attr (%s) failed\\n",\n'
                 '\t\t\t__func__, drv->name);\n'
                 '\t}\n'
                 '\terror = driver_add_groups(drv, bus->drv_groups);\n'
                 '\tif (error) {\n'
                 '\t\t/* How the hell do we get out of this pickle? Give up */\n'
                 '\t\tprintk(KERN_ERR "%s: driver_create_groups(%s) failed\\n",\n'
                 '\t\t\t__func__, drv->name);\n'
                 '\t}\n'
                 '\n'
                 '\tif (!drv->suppress_bind_attrs) {\n'
                 '\t\terror = add_bind_files(drv);\n'
                 '\t\tif (error) {\n'
                 '\t\t\t/* Ditto */\n'
                 '\t\t\tprintk(KERN_ERR "%s: add_bind_files(%s) failed\\n",\n'
                 '\t\t\t\t__func__, drv->name);\n'
                 '\t\t}\n'
                 '\t}\n'
                 '\n'
                 '\treturn 0;\n'
                 '\n'
                 'out_unregister:\n'
                 '\tkobject_put(&priv->kobj);\n'
                 '\t/* drv->p is freed in driver_release()  */\n'
                 '\tdrv->p = NULL;\n'
                 'out_put_bus:\n'
                 '\tbus_put(bus);\n'
                 '\treturn error;\n'
                 '}',
 'pci_bind_config': 'CONFIG_SYSFS=y\n'
                    'CONFIG_MODULE_UNLOAD=y\n'
                    'CONFIG_MT7615_AP=m\n'
                    '# CONFIG_MODULE_FORCE_UNLOAD is not set\n'
                    '# CONFIG_PM is not set\n',
 'pci_bind_harness': '"""PCI manual-bind policy using real initializer/core regions and inert APIs.\n'
                     '\n'
                     'This is not a PCI unbind, module unload, device removal or hardware execution.\n'
                     "The driver's init/exit/shutdown and PCI registration functions are complete;\n"
                     'bus_add_driver contributes only its final bind-file decision block.\n'
                     '"""\n'
                     'import hashlib\n'
                     'import re\n'
                     '\n'
                     'SOURCE_PATHS = {\n'
                     "    'pci': "
                     "'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/pci_main_dev.c',\n"
                     "    'core': 'trunk/linux-4.4.x/drivers/pci/pci-driver.c',\n"
                     "    'bus': 'trunk/linux-4.4.x/drivers/base/bus.c',\n"
                     "    'config': 'trunk/configs/boards/K2P/kernel-4.4.x.config',\n"
                     '}\n'
                     "BASELINE_COMMIT = '60ae6bf98bd46b68c648620c599f1aa78073131e'\n"
                     'BASELINE_INITIALIZER_SHA256 = '
                     "'c7ea843f0c96d7dc63b6e563b42cef96605c282852c22cd6be8bb5a77e09433c'\n"
                     'FUNCTION_SOURCES = {\n'
                     "    '__pci_register_driver': 'core', 'pci_unregister_driver': 'core',\n"
                     "    'rt_pci_shutdown': 'pci', 'rt_pci_init_module': 'pci',\n"
                     "    'rt_pci_cleanup_module': 'pci',\n"
                     '}\n'
                     "CASE_NAMES = ('register', 'core-add-error', 'shutdown', 'cleanup', 'register-error')\n"
                     "FIELDS = ('result', 'registered', 'bind_calls', 'nodes', 'errors', 'shutdowns',\n"
                     "          'removes', 'unregisters', 'dynid_frees', 'core_fields',\n"
                     "          'callback_fields', 'master')\n"
                     'EXPECTED_ROWS = {\n'
                     "    'register': [0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1],\n"
                     "    'core-add-error': [0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1],\n"
                     "    'shutdown': [0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0],\n"
                     "    'cleanup': [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1],\n"
                     "    'register-error': [-12, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1],\n"
                     '}\n'
                     'BASELINE_ROWS = {\n'
                     "    'register': [0, 1, 1, 2, 0, 0, 0, 0, 0, 1, 1, 1],\n"
                     "    'core-add-error': [0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1],\n"
                     "    'shutdown': [0, 1, 1, 2, 0, 1, 0, 0, 0, 1, 1, 0],\n"
                     "    'cleanup': [0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1],\n"
                     "    'register-error': [-12, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1],\n"
                     '}\n'
                     'TOKEN = '
                     'r\'/\\*[\\s\\S]*?\\*/|//[^\\n]*|"(?:\\\\[\\s\\S]|[^"\\\\])*"|\\\'(?:\\\\[\\s\\S]|[^\\\'\\\\])*\\\'\'\n'
                     '\n'
                     '\n'
                     'def masked(text):\n'
                     "    return re.sub(TOKEN, lambda m: ' ' * len(m.group()), text)\n"
                     '\n'
                     '\n'
                     'def block_end(text, opening):\n'
                     '    clean = masked(text)\n'
                     '    depth = 0\n'
                     '    for i in range(opening, len(clean)):\n'
                     "        if clean[i] == '{':\n"
                     '            depth += 1\n'
                     "        elif clean[i] == '}':\n"
                     '            depth -= 1\n'
                     '            if not depth:\n'
                     '                return i + 1\n'
                     "    raise ValueError('Unterminated C region')\n"
                     '\n'
                     '\n'
                     'def function(text, name):\n'
                     '    clean = masked(text)\n'
                     "    pattern = r'^(?:static\\s+)?(?:int|void|VOID)\\s+(?:(?:__init|__exit)\\s+)?' + "
                     "re.escape(name) + r'\\s*\\([^;{}]*\\)\\s*\\{'\n"
                     '    found = list(re.finditer(pattern, clean, re.M))\n'
                     '    if len(found) != 1:\n'
                     "        raise ValueError('Missing/ambiguous PCI policy function: ' + name)\n"
                     '    start = found[0].start()\n'
                     "    opening = clean.index('{', start)\n"
                     '    return text[start:block_end(text, opening)]\n'
                     '\n'
                     '\n'
                     'def initializer(text):\n'
                     '    clean = masked(text)\n'
                     '    found = '
                     "list(re.finditer(r'^static\\s+struct\\s+pci_driver\\s+rt_pci_driver\\s*=\\s*\\{', "
                     'clean, re.M))\n'
                     '    if len(found) != 1:\n'
                     "        raise ValueError('One real PCI driver initializer required')\n"
                     '    start = found[0].start()\n'
                     "    end = block_end(text, clean.index('{', start))\n"
                     "    if not re.match(r'\\s*;', clean[end:]):\n"
                     "        raise ValueError('PCI driver initializer terminator absent')\n"
                     "    return text[start:end] + ';'\n"
                     '\n'
                     '\n'
                     'def bind_guard(text):\n'
                     "    body = function(text, 'bus_add_driver')\n"
                     '    clean = masked(body)\n'
                     '    found = '
                     "list(re.finditer(r'if\\s*\\(\\s*!\\s*drv->suppress_bind_attrs\\s*\\)\\s*\\{', clean))\n"
                     '    if len(found) != 1:\n'
                     "        raise ValueError('One final bus bind-file policy block required')\n"
                     '    start = found[0].start()\n'
                     "    end = block_end(body, clean.index('{', start))\n"
                     "    tail = re.match(r'\\s*return\\s+0\\s*;', clean[end:])\n"
                     "    if not tail or 'add_bind_files(drv)' not in clean[start:end]:\n"
                     "        raise ValueError('Final bind guard/ordinary success continuation differs')\n"
                     '    return body[start:end + tail.end()]\n'
                     '\n'
                     '\n'
                     'def actual_parts(texts):\n'
                     '    if set(texts) != set(SOURCE_PATHS):\n'
                     "        raise ValueError('Exact PCI policy input set required')\n"
                     "    config = texts['config']\n"
                     "    for flag in ('CONFIG_SYSFS=y', 'CONFIG_MODULE_UNLOAD=y', 'CONFIG_MT7615_AP=m',\n"
                     "                 '# CONFIG_MODULE_FORCE_UNLOAD is not set', '# CONFIG_PM is not "
                     "set'):\n"
                     '        if flag not in config.splitlines():\n'
                     "            raise ValueError('Configured K2P policy selection absent: ' + flag)\n"
                     '    return {\n'
                     "        'initializer': initializer(texts['pci']),\n"
                     "        'bus_guard': bind_guard(texts['bus']),\n"
                     "        'functions': {n: function(texts[k], n) for n, k in FUNCTION_SOURCES.items()},\n"
                     '    }\n'
                     '\n'
                     '\n'
                     "PREFIX = r'''\n"
                     '#include <assert.h>\n'
                     '#include <stdbool.h>\n'
                     '#include <stdio.h>\n'
                     '#include <string.h>\n'
                     '#define VOID void\n'
                     '#define __init\n'
                     '#define __exit\n'
                     '#define DEVEXIT_P(x) x\n'
                     '#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))\n'
                     '#define LINUX_VERSION_CODE KERNEL_VERSION(4,4,198)\n'
                     '#define RTMP_DRV_NAME "fixture-mt7615"\n'
                     '#define MTWF_LOG(...) ((void)0)\n'
                     '#define KERN_ERR ""\n'
                     'struct module { int unused; } fixture_owner;\n'
                     '#define THIS_MODULE (&fixture_owner)\n'
                     'struct pci_dev { int master; } fixture_device;\n'
                     'struct pci_device_id { int unused; };\n'
                     'static struct pci_device_id rt_pci_tbl[1];\n'
                     'struct dynids { int lock, list; };\n'
                     'struct device_driver {\n'
                     ' const char *name, *mod_name; void *bus; struct module *owner;\n'
                     ' bool suppress_bind_attrs;\n'
                     '};\n'
                     'struct pci_driver {\n'
                     ' const char *name; struct pci_device_id *id_table;\n'
                     ' int (*probe)(struct pci_dev *,const struct pci_device_id *);\n'
                     ' void (*shutdown)(struct pci_dev *),(*remove)(struct pci_dev *);\n'
                     ' struct device_driver driver; struct dynids dynids;\n'
                     '};\n'
                     'static int pci_bus_type;\n'
                     'static int registered, bind_calls, nodes, errors, shutdowns, removes, unregisters, '
                     'dynid_frees;\n'
                     'static int registration_error, add_error;\n'
                     'static int rt_pci_probe(struct pci_dev *p,const struct pci_device_id *id)\n'
                     '{ assert(p==&fixture_device&&id==rt_pci_tbl);return 0; }\n'
                     'static void rt_pci_remove(struct pci_dev *p)\n'
                     '{ assert(p==&fixture_device);removes++; }\n'
                     'static void pci_clear_master(struct pci_dev *p)\n'
                     '{ assert(p==&fixture_device);p->master=0;shutdowns++; }\n'
                     'static void spin_lock_init(int *p) { *p=7; }\n'
                     '#define INIT_LIST_HEAD(p) (*(p)=9)\n'
                     'static int add_bind_files(struct device_driver *drv)\n'
                     '{ assert(drv);bind_calls++;if(add_error)return -12;nodes=2;return 0; }\n'
                     '#define printk(...) (errors++)\n'
                     'static int driver_register(struct device_driver *drv);\n'
                     'static void driver_unregister(struct device_driver *drv);\n'
                     'static void pci_free_dynids(struct pci_driver *drv)\n'
                     '{ assert(drv);dynid_frees++; }\n'
                     'int __pci_register_driver(struct pci_driver *,struct module *,const char *);\n'
                     'void pci_unregister_driver(struct pci_driver *);\n'
                     '#define pci_register_driver(p) '
                     '__pci_register_driver((p),THIS_MODULE,"fixture-module")\n'
                     "'''\n"
                     '\n'
                     "SUFFIX = r'''\n"
                     'static int driver_register(struct device_driver *drv)\n'
                     '{\n'
                     ' int error;\n'
                     ' assert(drv==&rt_pci_driver.driver);\n'
                     ' if(registration_error)return -12;\n'
                     ' registered=1;\n'
                     ' BUS_GUARD\n'
                     '}\n'
                     'static void driver_unregister(struct device_driver *drv)\n'
                     '{\n'
                     ' assert(drv==&rt_pci_driver.driver&&registered);\n'
                     ' unregisters++;\n'
                     ' rt_pci_driver.remove(&fixture_device);\n'
                     ' nodes=0;registered=0;\n'
                     '}\n'
                     'int main(int argc,char **argv)\n'
                     '{\n'
                     ' const char *name;int result,core_fields,callback_fields;\n'
                     ' assert(argc==2);name=argv[1];CASE_ADMISSION\n'
                     ' fixture_device.master=1;\n'
                     ' '
                     'registration_error=!strcmp(name,"register-error");add_error=!strcmp(name,"core-add-error");\n'
                     ' result=rt_pci_init_module();\n'
                     ' '
                     'core_fields=rt_pci_driver.driver.owner==THIS_MODULE&&rt_pci_driver.driver.bus==&pci_bus_type&&\n'
                     '  '
                     '!strcmp(rt_pci_driver.driver.name,RTMP_DRV_NAME)&&!strcmp(rt_pci_driver.driver.mod_name,"fixture-module")&&\n'
                     '  rt_pci_driver.dynids.lock==7&&rt_pci_driver.dynids.list==9;\n'
                     ' '
                     'callback_fields=rt_pci_driver.id_table==rt_pci_tbl&&rt_pci_driver.probe==rt_pci_probe&&\n'
                     '  rt_pci_driver.remove==rt_pci_remove&&rt_pci_driver.shutdown==rt_pci_shutdown;\n'
                     ' if(!result&&!strcmp(name,"shutdown"))rt_pci_driver.shutdown(&fixture_device);\n'
                     ' if(!result&&!strcmp(name,"cleanup"))rt_pci_cleanup_module();\n'
                     ' '
                     'printf("[%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d]\\n",result,registered,bind_calls,nodes,errors,\n'
                     '  '
                     'shutdowns,removes,unregisters,dynid_frees,core_fields,callback_fields,fixture_device.master);\n'
                     ' return 0;\n'
                     '}\n'
                     "'''\n"
                     '\n'
                     '\n'
                     'def generate_source(texts, historical_initializer=None):\n'
                     '    parts = actual_parts(texts)\n'
                     "    selected = parts['initializer']\n"
                     '    if historical_initializer is not None:\n'
                     '        selected = initializer(historical_initializer)\n'
                     "    bodies = parts['functions']\n"
                     '    admission = \'if(!(\' + \'||\'.join(\'!strcmp(name,"\' + n + \'")\' for n in '
                     "CASE_NAMES) + '))return 91;'\n"
                     "    return (PREFIX + '\\n' + bodies['__pci_register_driver'] + '\\n' +\n"
                     "            bodies['pci_unregister_driver'] + '\\n' + bodies['rt_pci_shutdown'] + "
                     "'\\n' +\n"
                     "            selected + '\\n' + bodies['rt_pci_init_module'] + '\\n' +\n"
                     "            bodies['rt_pci_cleanup_module'] + '\\n' +\n"
                     "            SUFFIX.replace('BUS_GUARD', parts['bus_guard']).replace('CASE_ADMISSION', "
                     'admission))\n'
                     '\n'
                     '\n'
                     'def manifest(texts):\n'
                     '    parts = actual_parts(texts)\n'
                     '    return {\n'
                     "        'whole_functions': {n: {'source': FUNCTION_SOURCES[n], 'sha256': "
                     'hashlib.sha256(b.encode()).hexdigest()}\n'
                     "                            for n, b in parts['functions'].items()},\n"
                     "        'initializer': {'source': 'pci', 'sha256': "
                     "hashlib.sha256(parts['initializer'].encode()).hexdigest()},\n"
                     "        'bus_guard': {'source': 'bus', 'execution': 'function-fragment',\n"
                     "                      'sha256': "
                     "hashlib.sha256(parts['bus_guard'].encode()).hexdigest()},\n"
                     "        'hardware_execution': False, 'complete_module_unload_execution': False,\n"
                     "        'full_bus_add_driver_execution': False,\n"
                     '    }\n',
 'pci_bind_tests': '"""Manual bind-file admission, real PCI registration bodies, inert callbacks."""\n'
                   'import hashlib\n'
                   'import json\n'
                   'import os\n'
                   'from pathlib import Path\n'
                   'import shutil\n'
                   'import subprocess\n'
                   'import tempfile\n'
                   'import unittest\n'
                   '\n'
                   'import pci_bind_guard_harness as h\n'
                   '\n'
                   'ROOT = Path(__file__).resolve().parents[1]\n'
                   "FLAGS = ['-std=gnu99', '-O2', '-Wall', '-Wextra', '-Werror']\n"
                   '\n'
                   '\n'
                   'class PciBindGuardTests(unittest.TestCase):\n'
                   '    @classmethod\n'
                   '    def setUpClass(cls):\n'
                   "        cls.temp = tempfile.TemporaryDirectory(prefix='k2p-pci-bind-')\n"
                   '        cls.directory = Path(cls.temp.name)\n'
                   '        cls.texts = {k: (ROOT / p).read_text() for k, p in h.SOURCE_PATHS.items()}\n'
                   '        cls.current = h.generate_source(cls.texts)\n'
                   "        gcc = shutil.which('gcc-16') or shutil.which('gcc')\n"
                   "        clang = shutil.which('clang')\n"
                   '        if not gcc or not clang:\n'
                   "            raise AssertionError('Genuine GNU compiler and Clang required')\n"
                   "        version = subprocess.check_output([gcc, '--version'], text=True, timeout=10)\n"
                   "        if 'Free Software Foundation' not in version or 'clang' in version.lower():\n"
                   "            raise AssertionError('Genuine GNU compiler required')\n"
                   "        cls.compilers = {'gcc': gcc, 'clang': clang}\n"
                   "        cls.binaries = {label: cls.build(cls.current, 'current-' + label, label)\n"
                   '                        for label in cls.compilers}\n'
                   '\n'
                   '    @classmethod\n'
                   '    def tearDownClass(cls):\n'
                   '        cls.temp.cleanup()\n'
                   '\n'
                   '    @classmethod\n'
                   '    def build(cls, code, name, label):\n'
                   "        source = cls.directory / (name + '.c')\n"
                   '        source.write_text(code)\n'
                   "        binary = source.with_suffix('')\n"
                   '        # Retain the historical GNU "name:" initializer byte-for-byte.\n'
                   '        # This narrow Clang compatibility flag does not suppress C bounds,\n'
                   '        # lifetime, type, return-value or sanitizer diagnostics.\n'
                   "        flags = FLAGS + (['-Wno-gnu-designator', '-fsanitize=address,undefined',\n"
                   "                          '-fno-sanitize-recover=all'] if label == 'clang' else [])\n"
                   "        run = subprocess.run([cls.compilers[label], *flags, str(source), '-o', "
                   'str(binary)],\n'
                   '                             capture_output=True, text=True, timeout=60)\n'
                   '        if run.returncode or run.stderr:\n'
                   "            raise AssertionError('Strict actual-region compile failed:\\n' + "
                   'run.stderr)\n'
                   '        return binary\n'
                   '\n'
                   '    def run_case(self, binary, name):\n'
                   '        run = subprocess.run([str(binary), name], capture_output=True, text=True, '
                   'timeout=10,\n'
                   "                             env=dict(os.environ, ASAN_OPTIONS='halt_on_error=1',\n"
                   '                                      '
                   "UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))\n"
                   "        self.assertEqual((run.returncode, run.stderr), (0, ''), run.stderr)\n"
                   '        row = json.loads(run.stdout)\n'
                   '        self.assertEqual(len(row), len(h.FIELDS))\n'
                   '        self.assertTrue(all(type(value) is int for value in row))\n'
                   '        return row\n'
                   '\n'
                   '    def '
                   'test_exact_whole_functions_initializer_and_final_core_fragment_are_source_bound(self):\n'
                   '        parts = h.actual_parts(self.texts)\n'
                   "        self.assertEqual(set(parts['functions']), {'__pci_register_driver', "
                   "'pci_unregister_driver',\n"
                   "                                                 'rt_pci_init_module', "
                   "'rt_pci_cleanup_module', 'rt_pci_shutdown'})\n"
                   "        for body in (*parts['functions'].values(), parts['initializer'], "
                   "parts['bus_guard']):\n"
                   '            self.assertEqual(self.current.count(body), 1)\n'
                   '        manifest = h.manifest(self.texts)\n'
                   "        self.assertEqual(len(manifest['whole_functions']), 5)\n"
                   "        self.assertEqual(manifest['bus_guard']['execution'], 'function-fragment')\n"
                   "        self.assertFalse(manifest['hardware_execution'])\n"
                   "        self.assertFalse(manifest['complete_module_unload_execution'])\n"
                   "        self.assertFalse(manifest['full_bus_add_driver_execution'])\n"
                   "        self.assertIn('.suppress_bind_attrs = true', parts['initializer'])\n"
                   "        self.assertIn('if (!drv->suppress_bind_attrs)', parts['bus_guard'])\n"
                   '\n'
                   '    def '
                   'test_current_registration_excludes_manual_nodes_and_keeps_initialized_core_fields(self):\n'
                   '        for label, binary in self.binaries.items():\n'
                   "            for name in ('register', 'core-add-error', 'register-error'):\n"
                   '                with self.subTest(compiler=label, case=name):\n'
                   '                    self.assertEqual(self.run_case(binary, name), '
                   'h.EXPECTED_ROWS[name])\n'
                   '\n'
                   '    def test_registered_shutdown_and_normal_cleanup_dispatch_remain_available(self):\n'
                   '        for label, binary in self.binaries.items():\n'
                   "            for name in ('shutdown', 'cleanup'):\n"
                   '                with self.subTest(compiler=label, case=name):\n'
                   '                    self.assertEqual(self.run_case(binary, name), '
                   'h.EXPECTED_ROWS[name])\n'
                   '\n'
                   '    def '
                   'test_fixed_60_initializer_reproduces_manual_bind_exposure_and_preserves_callbacks(self):\n'
                   "        fixture = ROOT / 'tests/fixtures/pci-bind-guard'\n"
                   "        raw = (fixture / 'rt_pci_driver.c').read_bytes()\n"
                   "        metadata = json.loads((fixture / 'manifest.json').read_text())\n"
                   "        self.assertEqual(set(metadata), {'rt_pci_driver.c'})\n"
                   '        self.assertEqual(hashlib.sha256(raw).hexdigest(), '
                   'h.BASELINE_INITIALIZER_SHA256)\n'
                   "        self.assertEqual(metadata['rt_pci_driver.c']['sha256'], "
                   'h.BASELINE_INITIALIZER_SHA256)\n'
                   "        self.assertEqual(metadata['rt_pci_driver.c']['source_commit'], "
                   'h.BASELINE_COMMIT)\n'
                   "        self.assertEqual(metadata['rt_pci_driver.c']['source_path'], "
                   "h.SOURCE_PATHS['pci'])\n"
                   "        self.assertEqual(h.initializer(raw.decode()) + '\\n', raw.decode())\n"
                   '        for label in self.compilers:\n'
                   '            binary = self.build(h.generate_source(self.texts, raw.decode()), '
                   "'historical-' + label, label)\n"
                   '            for name in h.CASE_NAMES:\n'
                   '                with self.subTest(compiler=label, case=name):\n'
                   '                    self.assertEqual(self.run_case(binary, name), '
                   'h.BASELINE_ROWS[name])\n'
                   "            self.assertNotEqual(self.run_case(binary, 'register'), "
                   "h.EXPECTED_ROWS['register'])\n"
                   '\n'
                   '    def test_executable_guard_registration_and_callback_mutants_break_semantics(self):\n'
                   '        mutants = {\n'
                   "            'allow-bind': self.current.replace('.suppress_bind_attrs = true', "
                   "'.suppress_bind_attrs = false'),\n"
                   "            'core-overwrite': self.current.replace('drv->driver.name = drv->name;',\n"
                   "                                                 'drv->driver.suppress_bind_attrs = "
                   "false; drv->driver.name = drv->name;'),\n"
                   "            'inverted-core': self.current.replace('if (!drv->suppress_bind_attrs)', 'if "
                   "(drv->suppress_bind_attrs)'),\n"
                   "            'drop-shutdown': self.current.replace('shutdown :\\n\\trt_pci_shutdown,', "
                   "'shutdown :\\n\\tNULL,'),\n"
                   "            'drop-remove': self.current.replace('DEVEXIT_P(rt_pci_remove)', 'NULL'),\n"
                   "            'drop-owner': self.current.replace('drv->driver.owner = owner;', "
                   "'drv->driver.owner = NULL; (void)owner;'),\n"
                   '        }\n'
                   '        for label in self.compilers:\n'
                   '            for name, source in mutants.items():\n'
                   '                self.assertNotEqual(source, self.current, name)\n'
                   '                # Avoid dispatching intentionally NULL callbacks: the register\n'
                   '                # observation independently checks the actual pointer slots.\n'
                   "                binary = self.build(source, 'mutant-' + name + '-' + label, label)\n"
                   '                with self.subTest(compiler=label, mutant=name):\n'
                   "                    self.assertNotEqual(self.run_case(binary, 'register'), "
                   "h.EXPECTED_ROWS['register'])\n"
                   '\n'
                   '    def '
                   'test_source_parser_rejects_missing_duplicate_wrong_guard_and_config_inputs(self):\n'
                   '        for name, key in h.FUNCTION_SOURCES.items():\n'
                   '            body = h.function(self.texts[key], name)\n'
                   "            for text in (self.texts[key].replace(body, ''), self.texts[key] + '\\n' + "
                   'body):\n'
                   '                bad = dict(self.texts);bad[key] = text\n'
                   '                with self.subTest(function=name), self.assertRaises(ValueError):\n'
                   '                    h.generate_source(bad)\n'
                   "        actual = h.initializer(self.texts['pci'])\n"
                   "        for text in (self.texts['pci'].replace(actual, ''), self.texts['pci'] + '\\n' + "
                   'actual):\n'
                   "            bad = dict(self.texts);bad['pci'] = text\n"
                   '            with self.assertRaises(ValueError):h.generate_source(bad)\n'
                   "        for old, new in (('if (!drv->suppress_bind_attrs)', 'if "
                   "(drv->suppress_bind_attrs)'),\n"
                   "                         ('add_bind_files(drv)', 'unrelated(drv)')):\n"
                   "            bad = dict(self.texts);bad['bus'] = bad['bus'].replace(old, new)\n"
                   '            with self.assertRaises(ValueError):h.generate_source(bad)\n'
                   "        for flag in ('CONFIG_SYSFS=y', 'CONFIG_MODULE_UNLOAD=y', 'CONFIG_MT7615_AP=m',\n"
                   "                     '# CONFIG_MODULE_FORCE_UNLOAD is not set', '# CONFIG_PM is not "
                   "set'):\n"
                   "            bad = dict(self.texts);bad['config'] = bad['config'].replace(flag, '')\n"
                   '            with self.assertRaises(ValueError):h.generate_source(bad)\n'
                   '        with self.assertRaises(ValueError):h.generate_source({})\n'
                   '\n'
                   '    def test_unadmitted_cases_do_not_execute_registration(self):\n'
                   '        self.assertEqual(set(h.EXPECTED_ROWS), set(h.BASELINE_ROWS))\n'
                   '        self.assertEqual(tuple(h.EXPECTED_ROWS), h.CASE_NAMES)\n'
                   '        self.assertEqual(len(h.FIELDS), 12)\n'
                   '        for binary in self.binaries.values():\n'
                   "            run = subprocess.run([str(binary), 'unadmitted'], capture_output=True, "
                   'text=True, timeout=10)\n'
                   '            self.assertEqual(run.returncode, 91)\n'
                   "            self.assertEqual((run.stdout, run.stderr), ('', ''))\n"
                   '\n'
                   '\n'
                   "if __name__ == '__main__':\n"
                   '    unittest.main()\n',
 'pci_bind_baseline': 'static struct pci_driver rt_pci_driver = {\n'
                      'name:\n'
                      '\tRTMP_DRV_NAME,\n'
                      'id_table :\n'
                      '\trt_pci_tbl,\n'
                      'probe :\n'
                      '\trt_pci_probe,\n'
                      'shutdown :\n'
                      '\trt_pci_shutdown,\n'
                      '#if LINUX_VERSION_CODE >= 0x20412\n'
                      'remove :\n'
                      '\tDEVEXIT_P(rt_pci_remove),\n'
                      '#else\n'
                      'remove :\n'
                      '\t__devexit(rt_pci_remove),\n'
                      '#endif\n'
                      '\n'
                      '#if (KERNEL_VERSION(2, 5, 0) <= LINUX_VERSION_CODE)\n'
                      '#ifdef CONFIG_PM\n'
                      'suspend :\n'
                      '\trt_pci_suspend,\n'
                      'resume :\n'
                      '\trt_pci_resume,\n'
                      '#endif\n'
                      '#endif\n'
                      '};\n',
 'pci_bind_manifest': '{\n'
                      '  "rt_pci_driver.c": {\n'
                      '    "source_commit": "60ae6bf98bd46b68c648620c599f1aa78073131e",\n'
                      '    "source_path": '
                      '"trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/pci_main_dev.c",\n'
                      '    "source_region": "complete rt_pci_driver initializer",\n'
                      '    "sha256": "c7ea843f0c96d7dc63b6e563b42cef96605c282852c22cd6be8bb5a77e09433c"\n'
                      '  }\n'
                      '}\n',
 'fwd_native_0': 'int ApCliLinkCoverRxPolicy(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int RTMPSendPackets(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int announce_802_3_packet(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'struct wifi_fwd_read_guard wifi_fwd_read_begin(void)\n'
                 '{\n'
                 '\tstruct wifi_fwd_read_guard guard = { &wifi_fwd_empty, 0, 0 };\n'
                 '\tconst struct wifi_fwd_func_table *table;\n'
                 '\n'
                 '\t/* Compare only: do not dereference an unprotected published pointer. */\n'
                 '\tif (!READ_ONCE(wifi_fwd_published))\n'
                 '\t\treturn guard;\n'
                 '\tif (in_atomic() || in_interrupt() || irqs_disabled()) {\n'
                 '\t\trcu_read_lock();\n'
                 '\t\tguard.domain = 1;\n'
                 '\t\ttable = rcu_dereference(wifi_fwd_published);\n'
                 '\t} else {\n'
                 '\t\tguard.srcu_index = srcu_read_lock(&wifi_fwd_srcu);\n'
                 '\t\tguard.domain = 2;\n'
                 '\t\ttable = srcu_dereference(wifi_fwd_published, &wifi_fwd_srcu);\n'
                 '\t}\n'
                 '\tif (table)\n'
                 '\t\tguard.table = table;\n'
                 '\treturn guard;\n'
                 '}\n'
                 'void wifi_fwd_read_end(struct wifi_fwd_read_guard *guard)\n'
                 '{\n'
                 '\tif (guard->domain == 1)\n'
                 '\t\trcu_read_unlock();\n'
                 '\telse if (guard->domain == 2)\n'
                 '\t\tsrcu_read_unlock(&wifi_fwd_srcu, guard->srcu_index);\n'
                 '\tguard->domain = 0;\n'
                 '\tguard->table = &wifi_fwd_empty;\n'
                 '}\n'
                 'static void wifi_fwd_drain(void)\n'
                 '{\n'
                 '\trcu_assign_pointer(wifi_fwd_published, NULL);\n'
                 '\tsynchronize_rcu();\n'
                 '\tsynchronize_srcu(&wifi_fwd_srcu);\n'
                 '\tflush_delayed_work(&wifi_fwd_srcu.work);\n'
                 '}\n'
                 'VOID wifi_fwd_register(struct wifi_fwd_func_table *table)\n'
                 '{\n'
                 '\tif (WARN_ON_ONCE(in_atomic() || in_interrupt() || irqs_disabled()))\n'
                 '\t\treturn;\n'
                 '\tmutex_lock(&wifi_fwd_writer_lock);\n'
                 '\twifi_fwd_drain();\n'
                 '\tif (table) {\n'
                 '\t\t/* Publish every ABI member as one immutable snapshot. */\n'
                 '\t\twifi_fwd_slot = *table;\n'
                 '\t\trcu_assign_pointer(wifi_fwd_published, &wifi_fwd_slot);\n'
                 '\t}\n'
                 '\tmutex_unlock(&wifi_fwd_writer_lock);\n'
                 '}\n'
                 'VOID wifi_fwd_unregister(VOID)\n'
                 '{\n'
                 '\tif (WARN_ON_ONCE(in_atomic() || in_interrupt() || irqs_disabled()))\n'
                 '\t\treturn;\n'
                 '\tmutex_lock(&wifi_fwd_writer_lock);\n'
                 '\twifi_fwd_drain();\n'
                 '\tmutex_unlock(&wifi_fwd_writer_lock);\n'
                 '}',
 'fwd_native_1': 'int APStartUpForMbss(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int APStopByBss(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}',
 'fwd_native_2': 'int ApCliIfDown(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int ApCliLinkDown(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int ApCliLinkUp(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int IsApCliLinkUp(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int apcli_inf_open(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}',
 'fwd_native_3': 'int IAPP_L2_Update_Frame_Send(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}',
 'fwd_native_4': 'int ap_fp_tx_pkt_allowed(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int ap_rx_pkt_foward(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int ap_tx_pkt_allowed(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}',
 'fwd_native_5': 'int ReptTxPktCheckHandler(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}',
 'fwd_native_6': 'int announce_or_forward_802_3_pkt(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int indicate_802_11_pkt(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}',
 'fwd_native_7': 'int Set_PacketSourceDeleteEntry(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int Set_PacketSourceShowEntry(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int Set_WifiFwdAccessSchedule_Proc(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int Set_WifiFwdBpdu_Proc(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int Set_WifiFwdBridge_Proc(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int Set_WifiFwdDeleteEntry(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int Set_WifiFwdHijack_Proc(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int Set_WifiFwdRepDevice(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int Set_WifiFwdShowEntry(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int Set_WifiFwd_Proc(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int WifiFwdSet(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}',
 'fwd_native_8': 'int UserCfgInit(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}',
 'fwd_native_9': 'int MacTableDeleteEntry(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}\n'
                 'int MacTableInsertEntry(void) {\n'
                 '#if defined(CONFIG_WIFI_PKT_FWD) || defined(CONFIG_WIFI_PKT_FWD_MODULE)\n'
                 'WIFI_FWD_GUARD(wf_fwd_snapshot);\n'
                 '#endif\n'
                 'wf_fwd_snapshot->callback();\n'
                 'return 0;\n'
                 '}',
 'fwd_native_10': 'struct wifi_fwd_func_table{\n'
                  '\tint (*wf_fwd_rx_hook) (struct sk_buff *skb);\n'
                  '\tint (*wf_fwd_tx_hook) (struct sk_buff *skb);\n'
                  '\tunsigned char (*wf_fwd_entry_insert_hook) (struct net_device *src, struct net_device '
                  '*dest, void *adapter);\n'
                  '\tunsigned char (*wf_fwd_entry_delete_hook) (struct net_device *src, struct net_device '
                  '*dest, unsigned char link_down);\n'
                  '\tvoid (*wf_fwd_set_cb_num) (unsigned int band_cb_num, unsigned int receive_cb_num);\n'
                  '\tvoid (*wf_fwd_set_debug_level_hook) (unsigned char level);\n'
                  '\tbool (*wf_fwd_check_active_hook) (void);\n'
                  '\tvoid (*wf_fwd_get_rep_hook) (unsigned char idx);\n'
                  '\tvoid (*wf_fwd_pro_active_hook) (void);\n'
                  '\tvoid (*wf_fwd_pro_halt_hook) (void);\n'
                  '\tvoid (*wf_fwd_pro_enabled_hook) (void);\n'
                  '\tvoid (*wf_fwd_pro_disabled_hook) (void);\n'
                  '\tvoid (*wf_fwd_access_schedule_active_hook) (void);\n'
                  '\tvoid (*wf_fwd_access_schedule_halt_hook) (void);\n'
                  '\tvoid (*wf_fwd_hijack_active_hook) (void);\n'
                  '\tvoid (*wf_fwd_hijack_halt_hook) (void);\n'
                  '\tvoid (*wf_fwd_bpdu_active_hook) (void);\n'
                  '\tvoid (*wf_fwd_bpdu_halt_hook) (void);\n'
                  '\tvoid (*wf_fwd_show_entry_hook) (void);\n'
                  '\tbool (*wf_fwd_needed_hook) (void);\n'
                  '\tvoid (*wf_fwd_delete_entry_hook) (unsigned char idx);\n'
                  '\tvoid (*packet_source_show_entry_hook) (void);\n'
                  '\tvoid (*packet_source_delete_entry_hook) (unsigned char idx);\n'
                  '\tvoid (*wf_fwd_feedback_map_table) (void *adapter, void **peer, void **opp_peer, void '
                  '**oth_peer);\n'
                  '\tvoid (*wf_fwd_probe_adapter) (void *adapter);\n'
                  '\tvoid (*wf_fwd_remove_adapter)(void *adapter);\n'
                  '\tvoid (*wf_fwd_insert_repeater_mapping_hook)(void *adapter, void *lock, void '
                  '*cli_mapping, void *map_mapping, void *ifAddr_mapping);\n'
                  '\tvoid (*wf_fwd_delete_repeater_mapping) (void *apcli_device);\n'
                  '\tvoid (*wf_fwd_insert_bridge_mapping_hook) (struct sk_buff *skb);\n'
                  '\tint (*wf_fwd_search_mapping_table_hook) (struct sk_buff *skb, struct '
                  'APCLI_BRIDGE_LEARNING_MAPPING_STRUCT **tbl_entry);\n'
                  '\tvoid (*wf_fwd_delete_entry_inform_hook) (unsigned char *addr);\n'
                  '\tvoid (*wf_fwd_check_device_hook) (struct net_device *net_dev, signed int type, signed '
                  'int mbss_idx, unsigned char channel, unsigned char link);\n'
                  '\tvoid (*wf_fwd_add_entry_inform_hook) (unsigned char *addr);\n'
                  '\tvoid (*wf_fwd_debug_level_hook) (unsigned char level);\n'
                  '\tvoid (*wf_fwd_set_easy_setup_mode) (unsigned int easy_setup_mode);\n'
                  '\tvoid (*wf_fwd_set_bridge_hook) (unsigned char* bridge_intf_name,unsigned int len);\n'
                  '};\n'
                  'struct wifi_fwd_read_guard {\n'
                  '\tconst struct wifi_fwd_func_table *table;\n'
                  '\tint domain;\n'
                  '\tint srcu_index;\n'
                  '};\n'
                  '#define WIFI_FWD_GUARD(name) \\\n'
                  '\tstruct wifi_fwd_read_guard name##_guard \\\n'
                  '\t\t__attribute__((cleanup(wifi_fwd_read_end))) = wifi_fwd_read_begin(); \\\n'
                  '\tconst struct wifi_fwd_func_table *name __attribute__((unused)) = name##_guard.table\n'
                  '\n',
 'fwd_native_11': 'static void __synchronize_srcu(struct srcu_struct *sp, int trycount)\n'
                  '{\n'
                  '\tstruct rcu_synchronize rcu;\n'
                  '\tstruct rcu_head *head = &rcu.head;\n'
                  '\tbool done = false;\n'
                  '\n'
                  '\tRCU_LOCKDEP_WARN(lock_is_held(&sp->dep_map) ||\n'
                  '\t\t\t lock_is_held(&rcu_bh_lock_map) ||\n'
                  '\t\t\t lock_is_held(&rcu_lock_map) ||\n'
                  '\t\t\t lock_is_held(&rcu_sched_lock_map),\n'
                  '\t\t\t "Illegal synchronize_srcu() in same-type SRCU (or in RCU) read-side critical '
                  'section");\n'
                  '\n'
                  '\tmight_sleep();\n'
                  '\tinit_completion(&rcu.completion);\n'
                  '\n'
                  '\thead->next = NULL;\n'
                  '\thead->func = wakeme_after_rcu;\n'
                  '\tspin_lock_irq(&sp->queue_lock);\n'
                  '\tif (!sp->running) {\n'
                  '\t\t/* steal the processing owner */\n'
                  '\t\tsp->running = true;\n'
                  '\t\trcu_batch_queue(&sp->batch_check0, head);\n'
                  '\t\tspin_unlock_irq(&sp->queue_lock);\n'
                  '\n'
                  '\t\tsrcu_advance_batches(sp, trycount);\n'
                  '\t\tif (!rcu_batch_empty(&sp->batch_done)) {\n'
                  '\t\t\tBUG_ON(sp->batch_done.head != head);\n'
                  '\t\t\trcu_batch_dequeue(&sp->batch_done);\n'
                  '\t\t\tdone = true;\n'
                  '\t\t}\n'
                  '\t\t/* give the processing owner to work_struct */\n'
                  '\t\tsrcu_reschedule(sp);\n'
                  '\t} else {\n'
                  '\t\trcu_batch_queue(&sp->batch_queue, head);\n'
                  '\t\tspin_unlock_irq(&sp->queue_lock);\n'
                  '\t}\n'
                  '\n'
                  '\tif (!done)\n'
                  '\t\twait_for_completion(&rcu.completion);\n'
                  '}\n'
                  'static void srcu_reschedule(struct srcu_struct *sp)\n'
                  '{\n'
                  '\tbool pending = true;\n'
                  '\n'
                  '\tif (rcu_batch_empty(&sp->batch_done) &&\n'
                  '\t    rcu_batch_empty(&sp->batch_check1) &&\n'
                  '\t    rcu_batch_empty(&sp->batch_check0) &&\n'
                  '\t    rcu_batch_empty(&sp->batch_queue)) {\n'
                  '\t\tspin_lock_irq(&sp->queue_lock);\n'
                  '\t\tif (rcu_batch_empty(&sp->batch_done) &&\n'
                  '\t\t    rcu_batch_empty(&sp->batch_check1) &&\n'
                  '\t\t    rcu_batch_empty(&sp->batch_check0) &&\n'
                  '\t\t    rcu_batch_empty(&sp->batch_queue)) {\n'
                  '\t\t\tsp->running = false;\n'
                  '\t\t\tpending = false;\n'
                  '\t\t}\n'
                  '\t\tspin_unlock_irq(&sp->queue_lock);\n'
                  '\t}\n'
                  '\n'
                  '\tif (pending)\n'
                  '\t\tqueue_delayed_work(system_power_efficient_wq,\n'
                  '\t\t\t\t   &sp->work, SRCU_INTERVAL);\n'
                  '}\n'
                  'void process_srcu(struct work_struct *work)\n'
                  '{\n'
                  '\tstruct srcu_struct *sp;\n'
                  '\n'
                  '\tsp = container_of(work, struct srcu_struct, work.work);\n'
                  '\n'
                  '\tsrcu_collect_new(sp);\n'
                  '\tsrcu_advance_batches(sp, 1);\n'
                  '\tsrcu_invoke_callbacks(sp);\n'
                  '\tsrcu_reschedule(sp);\n'
                  '}',
 'fwd_native_12': '/* source-only unexecuted Linux SRCU header fixture */\n',
 'fwd_native_13': 'CONFIG_SRCU=y\nCONFIG_CHIP_MT7615E=y\nCONFIG_MT7615_AP=m\n',
 'fwd_native_14': 'EXTRA_CFLAGS += -DCONFIG_WIFI_PKT_FWD\n',
 'fwd_native_15': '"""Real forwarding publication/guard bodies with inert RCU/SRCU backends.\n'
                  '\n'
                  'All 31 callers are source-bound; only the named control reader executes whole.\n'
                  'The map user and grace-period implementation are explicit native models, not\n'
                  'kernel scheduler, packet path, provider module, or hardware execution.\n'
                  '"""\n'
                  'import hashlib\n'
                  'import re\n'
                  'from pci_bind_guard_harness import masked, block_end\n'
                  '\n'
                  "BASE = 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/'\n"
                  'CALLERS = {\n'
                  "    'os/linux/rt_profile.c': ('ApCliLinkCoverRxPolicy', 'RTMPSendPackets', "
                  "'announce_802_3_packet'),\n"
                  "    'embedded/ap/ap.c': ('APStartUpForMbss', 'APStopByBss'),\n"
                  "    'embedded/ap/ap_apcli.c': ('ApCliIfDown', 'ApCliLinkDown', 'ApCliLinkUp', "
                  "'IsApCliLinkUp', 'apcli_inf_open'),\n"
                  "    'embedded/ap/ap_assoc.c': ('IAPP_L2_Update_Frame_Send',),\n"
                  "    'embedded/ap/ap_data.c': ('ap_fp_tx_pkt_allowed', 'ap_rx_pkt_foward', "
                  "'ap_tx_pkt_allowed'),\n"
                  "    'embedded/ap/ap_repeater.c': ('ReptTxPktCheckHandler',),\n"
                  "    'embedded/common/cmm_data.c': ('announce_or_forward_802_3_pkt', "
                  "'indicate_802_11_pkt'),\n"
                  "    'embedded/common/cmm_info.c': ('Set_PacketSourceDeleteEntry', "
                  "'Set_PacketSourceShowEntry',\n"
                  "        'Set_WifiFwdAccessSchedule_Proc', 'Set_WifiFwdBpdu_Proc', "
                  "'Set_WifiFwdBridge_Proc',\n"
                  "        'Set_WifiFwdDeleteEntry', 'Set_WifiFwdHijack_Proc', 'Set_WifiFwdRepDevice',\n"
                  "        'Set_WifiFwdShowEntry', 'Set_WifiFwd_Proc', 'WifiFwdSet'),\n"
                  "    'embedded/common/rtmp_init.c': ('UserCfgInit',),\n"
                  "    'embedded/mgmt/mgmt_entrytb.c': ('MacTableDeleteEntry', 'MacTableInsertEntry'),\n"
                  '}\n'
                  'SOURCE_PATHS = {p: BASE + p for p in CALLERS}\n'
                  'SOURCE_PATHS.update({\n'
                  "    'header': BASE + 'include/os/rt_linux.h',\n"
                  "    'core_srcu': 'trunk/linux-4.4.x/kernel/rcu/srcu.c',\n"
                  "    'srcu_header': 'trunk/linux-4.4.x/include/linux/srcu.h',\n"
                  "    'config': 'trunk/configs/boards/K2P/kernel-4.4.x.config',\n"
                  '})\n'
                  "FUNCTION_NAMES = ('wifi_fwd_read_begin', 'wifi_fwd_read_end', 'wifi_fwd_drain',\n"
                  "                  'wifi_fwd_register', 'wifi_fwd_unregister')\n"
                  "BASELINE_COMMIT = '60ae6bf98bd46b68c648620c599f1aa78073131e'\n"
                  'BASELINE_SHA256 = {\n'
                  "    'wifi_fwd_register.c': "
                  "'6d8ec3c3063bb030f27a4bf9f2de2eeaf4d38c8abbaf77c739428eeff2dd4f4f',\n"
                  "    'wifi_fwd_unregister.c': "
                  "'07d8a495c878ec81db3fd3c3c5ff7c1cf02ccff8e99323da17ec639f3f497ed5',\n"
                  "    'Set_WifiFwdShowEntry.c': "
                  "'069401939065dcc183a7e847d291ac571f6f1468eaf7b04526363fcfb85f0029',\n"
                  '}\n'
                  '\n'
                  '\n'
                  'def function(text, name):\n'
                  '    clean = masked(text)\n'
                  "    pattern = r'^(?:(?:static|inline)\\s+)?(?:[A-Za-z_]\\w*\\s+|\\*\\s*)+?' + "
                  "re.escape(name) + r'\\s*\\([^;{}]*\\)\\s*\\{'\n"
                  '    matches = list(re.finditer(pattern, clean, re.M))\n'
                  '    if len(matches) != 1:\n'
                  "        raise ValueError('Missing/ambiguous forwarding function: ' + name)\n"
                  '    start = matches[0].start()\n'
                  "    return text[start:block_end(text, clean.index('{', start))]\n"
                  '\n'
                  '\n'
                  'def declaration(text, name):\n'
                  '    clean = masked(text)\n'
                  "    matches = list(re.finditer(r'(?m)^struct\\s+' + name + r'\\s*\\{', clean))\n"
                  '    if len(matches) != 1:\n'
                  "        raise ValueError('One forwarding declaration required: ' + name)\n"
                  "    start = matches[0].start();end = block_end(text, clean.index('{', start))\n"
                  "    if not re.match(r'\\s*;', clean[end:]):\n"
                  "        raise ValueError('Declaration terminator absent')\n"
                  "    return text[start:end] + ';'\n"
                  '\n'
                  '\n'
                  'def parts(texts):\n'
                  '    if set(texts) != set(SOURCE_PATHS):\n'
                  "        raise ValueError('Exact forwarding input set required')\n"
                  "    profile = texts['os/linux/rt_profile.c'];header = texts['header']\n"
                  "    for flag in ('CONFIG_SRCU=y', 'CONFIG_CHIP_MT7615E=y', 'CONFIG_MT7615_AP=m'):\n"
                  "        if flag not in texts['config'].splitlines():\n"
                  "            raise ValueError('Configured forwarding/SRCU profile differs')\n"
                  "    if 'wf_drv_tbl' in ''.join(masked(texts[p]) for p in CALLERS):\n"
                  "        raise ValueError('Unowned mutable forwarding table remains')\n"
                  "    bodies = {p + ':' + n: function(texts[p], n) for p, names in CALLERS.items() for n in "
                  'names}\n'
                  '    for name, body in bodies.items():\n'
                  "        clean = masked(body);opening = clean.index('{') + 1\n"
                  "        if clean.count('WIFI_FWD_GUARD(wf_fwd_snapshot);') != 1:\n"
                  "            raise ValueError('Exactly one whole-caller guard required: ' + name)\n"
                  "        if not re.match(r'\\s*#if defined\\(CONFIG_WIFI_PKT_FWD\\) \\|\\| "
                  "defined\\(CONFIG_WIFI_PKT_FWD_MODULE\\)\\s*WIFI_FWD_GUARD\\(wf_fwd_snapshot\\);\\s*#endif', "
                  'clean[opening:]):\n'
                  "            raise ValueError('Guard must precede every original caller statement: ' + "
                  'name)\n'
                  "    calls = sum(len(re.findall(r'\\bwf_fwd_snapshot->\\w+\\s*\\(', masked(b))) for b in "
                  'bodies.values())\n'
                  '    if calls != 47 or len(bodies) != 31:\n'
                  "        raise ValueError('All 47 direct calls and 31 full caller scopes required')\n"
                  "    macro_match = re.search(r'(?m)^#define WIFI_FWD_GUARD\\(name\\)[\\s\\S]*?(?=\\n\\n)', "
                  'header)\n'
                  "    if not macro_match or 'cleanup(wifi_fwd_read_end)' not in macro_match[0]:\n"
                  "        raise ValueError('Automatic cleanup declaration required')\n"
                  "    start = profile.index('static DEFINE_MUTEX(wifi_fwd_writer_lock);')\n"
                  "    end = profile.index('static const struct wifi_fwd_func_table __rcu "
                  "*wifi_fwd_published;', start)\n"
                  "    globals_ = profile[start:end] + 'static const struct wifi_fwd_func_table __rcu "
                  "*wifi_fwd_published;'\n"
                  "    check_start = profile.index('#if !defined(CONFIG_SRCU)')\n"
                  "    checks = profile[check_start:profile.index('#include <linux/srcu.h>', check_start)]\n"
                  "    return dict(table=declaration(header, 'wifi_fwd_func_table'),\n"
                  "                guard=declaration(header, 'wifi_fwd_read_guard'), macro=macro_match[0],\n"
                  '                globals=globals_, checks=checks, callers=bodies,\n'
                  '                functions={n: function(profile, n) for n in FUNCTION_NAMES})\n'
                  '\n'
                  '\n'
                  "PREFIX = r'''\n"
                  '#include <assert.h>\n'
                  '#include <stdbool.h>\n'
                  '#include <stdint.h>\n'
                  '#include <stdio.h>\n'
                  '#include <string.h>\n'
                  '#include <pthread.h>\n'
                  '#define VOID void\n'
                  '#define INT int\n'
                  '#define TRUE 1\n'
                  '#define IN\n'
                  'typedef char RTMP_STRING;\n'
                  'typedef void RTMP_ADAPTER;\n'
                  'typedef void *PRTMP_ADAPTER;\n'
                  '#define CONFIG_SRCU 1\n'
                  '#define CONFIG_WIFI_PKT_FWD 1\n'
                  '#define __rcu\n'
                  'struct sk_buff; struct net_device; struct APCLI_BRIDGE_LEARNING_MAPPING_STRUCT;\n'
                  'struct delayed_work { int running,pending; };\n'
                  'struct srcu_struct { struct delayed_work work; };\n'
                  '#define DEFINE_STATIC_SRCU(n) static struct srcu_struct n = {{0,0}}\n'
                  '#define DEFINE_MUTEX(n) pthread_mutex_t n=PTHREAD_MUTEX_INITIALIZER\n'
                  'static pthread_mutex_t state=PTHREAD_MUTEX_INITIALIZER;\n'
                  'static pthread_cond_t cv=PTHREAD_COND_INITIALIZER;\n'
                  'static __thread int context,thread_id;\n'
                  'static int '
                  'readers[2],locks[2],unlocks[2],syncs[2],flushes,warnings,unsafe_code,unsafe_data;\n'
                  'static int '
                  'entered,release_reader,writer_done,provider_live=1,map_ready,map_value=73,is_map;\n'
                  'static int '
                  'pause_writer,release_writer,writer_attempts,writer_acquisitions,max_writers,active_writers;\n'
                  'static int pause_fast,fast_entered,release_fast,fast_reads;\n'
                  'static void lock_state(void){assert(!pthread_mutex_lock(&state));}\n'
                  'static void unlock_state(void){assert(!pthread_mutex_unlock(&state));}\n'
                  'static void wake(void){assert(!pthread_cond_broadcast(&cv));}\n'
                  'static void wait_state(void){assert(!pthread_cond_wait(&cv,&state));}\n'
                  'static void wait_value(int *p,int '
                  'n){lock_state();while(*p<n)wait_state();unlock_state();}\n'
                  'static void '
                  'after_pointer_read(void){if(thread_id!=7||!pause_fast||fast_reads++)return;lock_state();fast_entered=1;wake();while(!release_fast)wait_state();unlock_state();}\n'
                  '#define READ_ONCE(p) ({ __typeof__(p) '
                  'value=__atomic_load_n(&(p),__ATOMIC_ACQUIRE);after_pointer_read();value; })\n'
                  '#define rcu_assign_pointer(p,v) __atomic_store_n(&(p),(v),__ATOMIC_RELEASE)\n'
                  '#define rcu_dereference(p) READ_ONCE(p)\n'
                  '#define srcu_dereference(p,s) ((void)(s),READ_ONCE(p))\n'
                  'static int in_atomic(void){return context==1;}\n'
                  'static int in_interrupt(void){return context==2||context==3;}\n'
                  'static int irqs_disabled(void){return context==4;}\n'
                  'static int warn_once(int bad){if(bad)warnings++;return bad;}\n'
                  '#define WARN_ON_ONCE(v) warn_once(!!(v))\n'
                  'static void rcu_read_lock(void){lock_state();readers[0]++;locks[0]++;unlock_state();}\n'
                  'static void '
                  'rcu_read_unlock(void){lock_state();assert(readers[0]>0);readers[0]--;unlocks[0]++;wake();unlock_state();}\n'
                  'static int srcu_read_lock(struct srcu_struct '
                  '*s){assert(!context);(void)s;lock_state();readers[1]++;locks[1]++;unlock_state();return '
                  '0;}\n'
                  'static void srcu_read_unlock(struct srcu_struct *s,int '
                  'idx){assert(!context&&!idx);(void)s;lock_state();assert(readers[1]>0);readers[1]--;unlocks[1]++;wake();unlock_state();}\n'
                  'static void '
                  'synchronize_rcu(void){lock_state();syncs[0]++;wake();while(readers[0])wait_state();if(thread_id==1&&pause_writer){entered=1;wake();while(!release_writer)wait_state();}unlock_state();}\n'
                  'static void synchronize_srcu(struct srcu_struct '
                  '*s){lock_state();syncs[1]++;s->work.running=s->work.pending=1;wake();while(readers[1])wait_state();unlock_state();}\n'
                  'static void flush_delayed_work(struct delayed_work '
                  '*w){lock_state();flushes++;w->running=w->pending=0;unlock_state();}\n'
                  'static void mutex_lock(pthread_mutex_t '
                  '*m){lock_state();writer_attempts++;wake();unlock_state();assert(!pthread_mutex_lock(m));lock_state();writer_acquisitions++;active_writers++;if(active_writers>max_writers)max_writers=active_writers;unlock_state();}\n'
                  'static void mutex_unlock(pthread_mutex_t '
                  '*m){lock_state();assert(active_writers==1);active_writers--;unlock_state();assert(!pthread_mutex_unlock(m));}\n'
                  "'''\n"
                  '\n'
                  "SUFFIX = r'''\n"
                  'static void callback(void)\n'
                  '{\n'
                  ' lock_state();entered=1;wake();while(!release_reader)wait_state();\n'
                  ' if(!provider_live){unsafe_code++;}unlock_state();\n'
                  '}\n'
                  'static void feedback(void *ad,void **a,void **b,void **c)\n'
                  '{(void)ad;*a=&map_value;*b=NULL;*c=NULL;}\n'
                  'static void read_map(void)\n'
                  '{\n'
                  '#if BASELINE\n'
                  ' const struct wifi_fwd_func_table *snapshot=&wf_drv_tbl;\n'
                  '#else\n'
                  ' WIFI_FWD_GUARD(snapshot);\n'
                  '#endif\n'
                  ' void *a=NULL,*b=NULL,*c=NULL;\n'
                  ' '
                  'if(snapshot->wf_fwd_feedback_map_table)snapshot->wf_fwd_feedback_map_table(NULL,&a,&b,&c);\n'
                  ' lock_state();map_ready=1;wake();while(!release_reader)wait_state();\n'
                  ' if(a){if(!provider_live)unsafe_data++;assert(*(int*)a==73);}unlock_state();\n'
                  '}\n'
                  'static int early(int value)\n'
                  '{\n'
                  ' WIFI_FWD_GUARD(snapshot);\n'
                  ' (void)snapshot;\n'
                  ' if(value==0)return 7;\n'
                  ' if(value==1)goto out;\n'
                  ' return 9;\n'
                  'out:return 8;\n'
                  '}\n'
                  'static void *reader_thread(void *arg)\n'
                  '{thread_id=7;context=(int)(intptr_t)arg;if(is_map)read_map();else '
                  'Set_WifiFwdShowEntry(NULL,NULL);return NULL;}\n'
                  'static struct wifi_fwd_func_table table_a,table_b;\n'
                  'static void *unregister_thread(void *arg)\n'
                  '{(void)arg;wifi_fwd_unregister();lock_state();provider_live=0;writer_done=1;wake();unlock_state();return '
                  'NULL;}\n'
                  'static void *register_thread(void *arg)\n'
                  '{thread_id=(int)(intptr_t)arg;wifi_fwd_register(thread_id==1?&table_a:&table_b);return '
                  'NULL;}\n'
                  'int main(int argc,char **argv)\n'
                  '{\n'
                  ' pthread_t reader,writer,second;int i,ctx=0,all_fields=1;\n'
                  ' const char *name;struct wifi_fwd_read_guard g;\n'
                  ' assert(argc==2);name=argv[1];CASE_ADMISSION\n'
                  ' (void)&wifi_fwd_slot;(void)&wifi_fwd_writer_lock;\n'
                  ' (void)wifi_fwd_drain;(void)mutex_lock;(void)mutex_unlock;(void)warn_once;\n'
                  ' memset(&table_a,0,sizeof(table_a));memset(&table_b,0,sizeof(table_b));\n'
                  ' FILL_TABLE\n'
                  ' table_b=table_a;\n'
                  ' table_a.wf_fwd_show_entry_hook=callback;table_a.wf_fwd_feedback_map_table=feedback;\n'
                  ' table_b.wf_fwd_show_entry_hook=NULL;\n'
                  ' if(!strcmp(name,"empty")){\n'
                  '  '
                  'for(i=0;i<5;i++){context=i;g=wifi_fwd_read_begin();assert(g.table==&wifi_fwd_empty);wifi_fwd_read_end(&g);}\n'
                  ' }else if(!strcmp(name,"all-fields")){\n'
                  '  '
                  'wifi_fwd_register(&table_b);g=wifi_fwd_read_begin();all_fields=!memcmp(g.table,&table_b,sizeof(table_b));wifi_fwd_read_end(&g);wifi_fwd_unregister();\n'
                  ' }else if(!strcmp(name,"repeat")){\n'
                  '  '
                  'for(i=0;i<3;i++){wifi_fwd_register(&table_b);wifi_fwd_unregister();assert(!wifi_fwd_srcu.work.running&&!wifi_fwd_srcu.work.pending);}\n'
                  ' }else if(!strcmp(name,"early")){\n'
                  '  '
                  'wifi_fwd_register(&table_b);for(context=0;context<5;context++)for(i=0;i<3;i++)assert(early(i)==i+7);context=0;assert(!readers[0]&&!readers[1]);wifi_fwd_unregister();\n'
                  ' }else if(!strcmp(name,"writers")){\n'
                  '  '
                  'pause_writer=1;assert(!pthread_create(&writer,NULL,register_thread,(void*)1));wait_value(&entered,1);\n'
                  '  '
                  'assert(!pthread_create(&second,NULL,register_thread,(void*)2));wait_value(&writer_attempts,2);\n'
                  '  '
                  'lock_state();release_writer=1;wake();unlock_state();assert(!pthread_join(writer,NULL));assert(!pthread_join(second,NULL));\n'
                  '  '
                  'g=wifi_fwd_read_begin();all_fields=!memcmp(g.table,&table_b,sizeof(table_b));wifi_fwd_read_end(&g);wifi_fwd_unregister();\n'
                  ' }else if(!strcmp(name,"atomic-writers")){\n'
                  '  for(context=1;context<5;context++){wifi_fwd_register(&table_b);wifi_fwd_unregister();}\n'
                  '  context=0;assert(!wifi_fwd_published);\n'
                  ' }else if(!strcmp(name,"late-reader")){\n'
                  '  wifi_fwd_register(&table_a);pause_fast=1;release_reader=1;\n'
                  '  assert(!pthread_create(&reader,NULL,reader_thread,NULL));wait_value(&fast_entered,1);\n'
                  '  '
                  'wifi_fwd_unregister();provider_live=0;lock_state();release_fast=1;wake();unlock_state();\n'
                  '  assert(!pthread_join(reader,NULL));assert(!entered&&!unsafe_code);\n'
                  ' }else{\n'
                  '  if(!strcmp(name,"atomic"))ctx=1;else if(!strcmp(name,"irq"))ctx=2;else '
                  'if(!strcmp(name,"bh"))ctx=3;else if(!strcmp(name,"irq-off"))ctx=4;\n'
                  '  if(!strcmp(name,"map"))is_map=1;\n'
                  '  wifi_fwd_register(&table_a);syncs[0]=syncs[1]=0;\n'
                  '  assert(!pthread_create(&reader,NULL,reader_thread,(void*)(intptr_t)ctx));\n'
                  '  '
                  'wait_value(is_map?&map_ready:&entered,1);assert(!pthread_create(&writer,NULL,unregister_thread,NULL));\n'
                  '#if BASELINE\n'
                  '  wait_value(&writer_done,1);\n'
                  '#else\n'
                  '  '
                  'lock_state();while(!syncs[ctx?0:1]&&!writer_done)wait_state();assert(!writer_done);unlock_state();\n'
                  '#endif\n'
                  '  '
                  'lock_state();release_reader=1;wake();unlock_state();assert(!pthread_join(reader,NULL));assert(!pthread_join(writer,NULL));\n'
                  ' }\n'
                  ' assert(!readers[0]&&!readers[1]);\n'
                  ' assert(!wifi_fwd_published);\n'
                  ' '
                  'printf("{\\"unsafe_code\\":%d,\\"unsafe_data\\":%d,\\"all_fields\\":%d,\\"rcu_locks\\":%d,\\"srcu_locks\\":%d,\\"rcu_unlocks\\":%d,\\"srcu_unlocks\\":%d,\\"flushes\\":%d,\\"warnings\\":%d,\\"max_writers\\":%d,\\"running\\":%d,\\"pending\\":%d}\\n",unsafe_code,unsafe_data,all_fields,locks[0],locks[1],unlocks[0],unlocks[1],flushes,warnings,max_writers,wifi_fwd_srcu.work.running,wifi_fwd_srcu.work.pending);\n'
                  ' return 0;\n'
                  '}\n'
                  "'''\n"
                  "CASES = ('empty', 'all-fields', 'repeat', 'early', 'writers', 'atomic-writers', "
                  "'late-reader',\n"
                  "         'process', 'atomic', 'irq', 'bh', 'irq-off', 'map')\n"
                  '\n'
                  '\n'
                  'def generate_source(texts, baseline=None):\n'
                  '    p = parts(texts)\n'
                  '    # Real typed, noncalled stubs let the full 36-member copy be observed.\n'
                  '    callbacks = []\n'
                  '    fill = []\n'
                  '    for index, m in '
                  "enumerate(re.finditer(r'(?m)^\\s*(\\w+(?:\\s+\\w+)*)\\s*\\(\\*(\\w+)\\)\\s*\\(([^;]*)\\);', "
                  "p['table'])):\n"
                  '        ret, name, args = m.groups()\n'
                  '        params = []\n'
                  "        if args.strip() != 'void':\n"
                  "            for arg in args.split(','):\n"
                  "                n = re.search(r'(\\w+)\\s*$', arg).group(1)\n"
                  "                params.append('(void)' + n + ';')\n"
                  "        callbacks.append('static ' + ret + ' cb_' + name + '(' + args + '){' + "
                  "''.join(params) +\n"
                  "                         ('' if ret.strip() == 'void' else 'return 0;') + '}')\n"
                  "        fill.append('table_a.' + name + '=cb_' + name + ';')\n"
                  '    if len(fill) != 36:\n'
                  "        raise ValueError('All 36 real typed callback members required')\n"
                  "    f = dict(p['functions'])\n"
                  "    reader = function(texts['embedded/common/cmm_info.c'], 'Set_WifiFwdShowEntry')\n"
                  "    extra = ''\n"
                  '    if baseline:\n'
                  "        f['wifi_fwd_register'] = baseline['wifi_fwd_register.c'].rstrip()\n"
                  "        f['wifi_fwd_unregister'] = baseline['wifi_fwd_unregister.c'].rstrip()\n"
                  "        reader = baseline['Set_WifiFwdShowEntry.c'].rstrip()\n"
                  "        extra = 'static struct wifi_fwd_func_table wf_drv_tbl;\\n'\n"
                  '    admission = \'if(!(\' + \'||\'.join(\'!strcmp(name,"\' + n + \'")\' for n in CASES) + '
                  "'))return 91;'\n"
                  "    return (PREFIX + '\\n' + p['checks'] + '\\n' + p['table'] + '\\n' + p['guard'] + "
                  "'\\n' +\n"
                  "            p['macro'] + '\\n' + p['globals'] + '\\n' + extra + '\\n' +\n"
                  "            '\\n'.join(f[n] for n in FUNCTION_NAMES) + '\\n' + reader + '\\n' +\n"
                  "            '\\n'.join(callbacks) + '\\n' +\n"
                  "            SUFFIX.replace('FILL_TABLE', '\\n'.join(fill)).replace('CASE_ADMISSION', "
                  'admission))\n'
                  '\n'
                  '\n'
                  'def manifest(texts):\n'
                  '    p = parts(texts)\n'
                  '    digest = lambda b: hashlib.sha256(b.encode()).hexdigest()\n'
                  "    return {'native_whole_functions': {n: digest(b) for n, b in p['functions'].items()},\n"
                  "            'native_control_reader': digest(function(texts['embedded/common/cmm_info.c'], "
                  "'Set_WifiFwdShowEntry')),\n"
                  "            'source_bound_callers': {n: digest(b) for n, b in p['callers'].items()},\n"
                  "            'source_only_kernel_srcu': {n: digest(function(texts['core_srcu'], n))\n"
                  "                                      for n in ('__synchronize_srcu', 'srcu_reschedule', "
                  "'process_srcu')},\n"
                  "            'table_declaration': digest(p['table']), 'guard_declaration': "
                  "digest(p['guard']),\n"
                  "            'cleanup_macro': digest(p['macro']),\n"
                  "            'caller_count': 31, 'direct_calls': 47, 'abi_members': 36,\n"
                  "            'all_31_callers_executed': False, 'kernel_rcu_srcu_execution': False,\n"
                  "            'provider_module_or_hardware_execution': False}\n",
 'fwd_native_16': '"""Optional FWD lifetime contract; real guards/writers, inert grace periods."""\n'
                  'import hashlib\n'
                  'import json\n'
                  'import os\n'
                  'from pathlib import Path\n'
                  'import shutil\n'
                  'import subprocess\n'
                  'import tempfile\n'
                  'import unittest\n'
                  '\n'
                  'import fwd_lifecycle_harness as h\n'
                  '\n'
                  'ROOT = Path(__file__).resolve().parents[1]\n'
                  "FLAGS = ['-std=gnu99', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', "
                  "'-pthread']\n"
                  '\n'
                  '\n'
                  'class FwdLifecycleTests(unittest.TestCase):\n'
                  '    @classmethod\n'
                  '    def setUpClass(cls):\n'
                  "        cls.temp = tempfile.TemporaryDirectory(prefix='k2p-fwd-native-')\n"
                  '        cls.directory = Path(cls.temp.name)\n'
                  '        cls.texts = {k: (ROOT / p).read_text() for k, p in h.SOURCE_PATHS.items()}\n'
                  '        cls.code = h.generate_source(cls.texts)\n'
                  "        gcc = shutil.which('gcc-16') or shutil.which('gcc')\n"
                  "        clang = shutil.which('clang')\n"
                  '        if not gcc or not clang:\n'
                  "            raise AssertionError('Genuine GNU compiler and Clang required')\n"
                  "        version = subprocess.check_output([gcc, '--version'], text=True, timeout=10)\n"
                  "        if 'Free Software Foundation' not in version or 'clang' in version.lower():\n"
                  "            raise AssertionError('Genuine GNU compiler required')\n"
                  "        cls.compilers = {'gcc': gcc, 'clang': clang}\n"
                  "        cls.binaries = {n: cls.compile(cls.code, 'current-' + n, n) for n in "
                  'cls.compilers}\n'
                  '\n'
                  '    @classmethod\n'
                  '    def tearDownClass(cls):\n'
                  '        cls.temp.cleanup()\n'
                  '\n'
                  '    @classmethod\n'
                  '    def compile(cls, code, name, compiler, baseline=False):\n'
                  "        p = cls.directory / (name + '.c');p.write_text(code)\n"
                  "        out = p.with_suffix('')\n"
                  "        flags = FLAGS + ['-DBASELINE=' + str(int(baseline))]\n"
                  "        if compiler == 'clang':\n"
                  "            flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']\n"
                  "        r = subprocess.run([cls.compilers[compiler], *flags, str(p), '-o', str(out)],\n"
                  '                           capture_output=True, text=True, timeout=60)\n'
                  '        if r.returncode or r.stderr:\n'
                  '            raise AssertionError(r.stderr)\n'
                  '        return out\n'
                  '\n'
                  '    @staticmethod\n'
                  '    def run_binary(binary, case):\n'
                  '        return subprocess.run([str(binary), case], capture_output=True, text=True, '
                  'timeout=10,\n'
                  "                              env=dict(os.environ, ASAN_OPTIONS='halt_on_error=1',\n"
                  '                                       '
                  "UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))\n"
                  '\n'
                  '    def row(self, binary, case):\n'
                  '        r = self.run_binary(binary, case)\n'
                  "        self.assertEqual((r.returncode, r.stderr), (0, ''), r.stderr)\n"
                  '        row = json.loads(r.stdout)\n'
                  "        self.assertEqual(set(row), {'unsafe_code', 'unsafe_data', 'all_fields', "
                  "'rcu_locks', 'srcu_locks',\n"
                  "                                   'rcu_unlocks', 'srcu_unlocks', 'flushes', 'warnings', "
                  "'max_writers', 'running', 'pending'})\n"
                  '        self.assertTrue(all(type(v) is int for v in row.values()))\n'
                  '        return row\n'
                  '\n'
                  '    def safe_case(self, case):\n'
                  '        result = []\n'
                  '        for compiler, binary in self.binaries.items():\n'
                  '            with self.subTest(compiler=compiler, case=case):\n'
                  '                row = self.row(binary, case)\n'
                  "                self.assertEqual((row['unsafe_code'], row['unsafe_data'], "
                  "row['all_fields'],\n"
                  "                                  row['running'], row['pending']), (0, 0, 1, 0, 0))\n"
                  "                self.assertEqual(row['rcu_locks'], row['rcu_unlocks'])\n"
                  "                self.assertEqual(row['srcu_locks'], row['srcu_unlocks'])\n"
                  '                result.append(row)\n'
                  '        return result\n'
                  '\n'
                  '    def test_empty_fast_path_never_takes_either_reader_or_writer_domain(self):\n'
                  "        for row in self.safe_case('empty'):\n"
                  "            self.assertEqual((row['rcu_locks'], row['srcu_locks'], row['flushes'], "
                  "row['max_writers']), (0, 0, 0, 0))\n"
                  '\n'
                  '    def test_complete_36_member_snapshot_and_repeated_register_retire_work(self):\n'
                  "        for case, flushes in (('all-fields', 2), ('repeat', 6)):\n"
                  '            for row in self.safe_case(case):\n'
                  "                self.assertEqual((row['flushes'], row['max_writers']), (flushes, 1))\n"
                  '\n'
                  '    def test_each_ordinary_return_and_goto_releases_process_and_atomic_guards(self):\n'
                  "        for row in self.safe_case('early'):\n"
                  "            self.assertEqual((row['rcu_locks'], row['srcu_locks']), (12, 3))\n"
                  '\n'
                  '    def '
                  'test_controlled_process_atomic_irq_bh_and_irq_disabled_readers_block_retirement(self):\n'
                  "        for case in ('process', 'atomic', 'irq', 'bh', 'irq-off'):\n"
                  '            for row in self.safe_case(case):\n'
                  "                self.assertEqual((row['rcu_locks'], row['srcu_locks']), (0, 1) if case == "
                  "'process' else (1, 0))\n"
                  "                self.assertEqual(row['flushes'], 2)\n"
                  '\n'
                  '    def test_returned_map_remains_owned_after_callback_until_consumer_scope_exits(self):\n'
                  "        for row in self.safe_case('map'):\n"
                  "            self.assertEqual((row['srcu_locks'], row['flushes']), (1, 2))\n"
                  '\n'
                  '    def test_pointer_seen_before_retirement_is_reread_after_domain_acquisition(self):\n'
                  "        for row in self.safe_case('late-reader'):\n"
                  "            self.assertEqual((row['srcu_locks'], row['flushes']), (1, 2))\n"
                  '\n'
                  '    def '
                  'test_concurrent_writers_publish_complete_last_snapshot_and_atomic_writers_refuse(self):\n'
                  "        for row in self.safe_case('writers'):\n"
                  "            self.assertEqual((row['max_writers'], row['flushes']), (1, 3))\n"
                  "        for row in self.safe_case('atomic-writers'):\n"
                  "            self.assertEqual((row['warnings'], row['max_writers'], row['flushes']), (8, "
                  '0, 0))\n'
                  '\n'
                  '    def '
                  'test_genuine_fixed60_writers_and_reader_return_before_callback_code_and_map_users(self):\n'
                  "        d = ROOT / 'tests/fixtures/fwd-lifecycle';metadata = json.loads((d / "
                  "'manifest.json').read_text())\n"
                  '        self.assertEqual(set(metadata), set(h.BASELINE_SHA256))\n'
                  '        bodies = {}\n'
                  '        for name, digest in h.BASELINE_SHA256.items():\n'
                  '            raw = (d / name).read_bytes()\n'
                  '            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)\n'
                  "            self.assertEqual(metadata[name]['source_commit'], h.BASELINE_COMMIT)\n"
                  "            self.assertEqual(metadata[name]['sha256'], digest)\n"
                  '            bodies[name] = raw.decode()\n'
                  '        for compiler in self.compilers:\n'
                  "            binary = self.compile(h.generate_source(self.texts, bodies), 'historical-' + "
                  'compiler, compiler, True)\n'
                  "            self.assertEqual(self.row(binary, 'process')['unsafe_code'], 1)\n"
                  "            self.assertEqual(self.row(binary, 'atomic')['unsafe_code'], 1)\n"
                  "            self.assertEqual(self.row(binary, 'map')['unsafe_data'], 1)\n"
                  '\n'
                  '    def test_real_guard_writer_and_pointer_lifetime_mutants_are_rejected(self):\n'
                  '        mutants = {\n'
                  "            'no-process-drain': (self.code.replace('synchronize_srcu(&wifi_fwd_srcu);', "
                  "'(void)synchronize_srcu;'), 'process'),\n"
                  "            'no-atomic-drain': (self.code.replace('synchronize_rcu();', "
                  "'(void)synchronize_rcu;'), 'irq'),\n"
                  "            'no-work-tail-flush': "
                  "(self.code.replace('flush_delayed_work(&wifi_fwd_srcu.work);', "
                  "'(void)flush_delayed_work;'), 'repeat'),\n"
                  "            'no-caller-cleanup': "
                  "(self.code.replace('__attribute__((cleanup(wifi_fwd_read_end)))', ''), 'early'),\n"
                  "            'atomic-uses-srcu': (self.code.replace('if (in_atomic() || in_interrupt() || "
                  "irqs_disabled()) {', 'if (0) {'), 'irq'),\n"
                  "            'incomplete-table': (self.code.replace('wifi_fwd_slot = *table;', "
                  "'wifi_fwd_slot.wf_fwd_show_entry_hook = table->wf_fwd_show_entry_hook;'), 'all-fields'),\n"
                  "            'no-null-publish': (self.code.replace('rcu_assign_pointer(wifi_fwd_published, "
                  "NULL);', '(void)wifi_fwd_published;'), 'all-fields'),\n"
                  "            'stale-after-acquire': (self.code.replace('table = "
                  "srcu_dereference(wifi_fwd_published, &wifi_fwd_srcu);', 'table = &wifi_fwd_slot;'), "
                  "'late-reader'),\n"
                  "            'no-writer-lock': (self.code.replace('mutex_lock(&wifi_fwd_writer_lock);', "
                  "'(void)mutex_lock;').replace('mutex_unlock(&wifi_fwd_writer_lock);', "
                  "'(void)mutex_unlock;'), 'all-fields'),\n"
                  '        }\n'
                  '        for compiler in self.compilers:\n'
                  '            for name, (code, case) in mutants.items():\n'
                  '                self.assertNotEqual(code, self.code, name)\n'
                  "                binary = self.compile(code, name + '-' + compiler, compiler)\n"
                  '                r = self.run_binary(binary, case)\n'
                  '                with self.subTest(compiler=compiler, mutant=name):\n'
                  '                    if r.returncode == 0:\n'
                  '                        row = json.loads(r.stdout)\n'
                  "                        self.assertTrue(row['all_fields'] != 1 or row['max_writers'] != "
                  '1,\n'
                  "                                        'Mutant preserved the fixed semantics: ' + "
                  'r.stdout)\n'
                  '\n'
                  '    def '
                  'test_all_callers_and_map_scopes_are_bound_without_claiming_full_kernel_execution(self):\n'
                  '        m = h.manifest(self.texts)\n'
                  "        self.assertEqual((m['caller_count'], m['direct_calls'], m['abi_members']), (31, "
                  '47, 36))\n'
                  "        self.assertEqual(len(m['source_bound_callers']), 31)\n"
                  "        self.assertFalse(m['all_31_callers_executed'])\n"
                  "        self.assertFalse(m['kernel_rcu_srcu_execution'])\n"
                  "        self.assertFalse(m['provider_module_or_hardware_execution'])\n"
                  '        p = h.parts(self.texts)\n'
                  '        for file, names in h.CALLERS.items():\n'
                  '            name = names[0];body = h.function(self.texts[file], name)\n'
                  '            bad = dict(self.texts);bad[file] = bad[file].replace(body, '
                  "body.replace('WIFI_FWD_GUARD(wf_fwd_snapshot);', ''))\n"
                  '            with self.assertRaises(ValueError):h.generate_source(bad)\n'
                  "        for file in ('os/linux/rt_profile.c', 'embedded/common/cmm_data.c'):\n"
                  "            self.assertIn('wf_fwd_snapshot->wf_fwd_feedback_map_table', "
                  'self.texts[file])\n'
                  "        self.assertIn('dont\\'t call init_srcu_struct() nor cleanup_srcu_struct()', "
                  "self.texts['srcu_header'])\n"
                  "        for name in ('__synchronize_srcu', 'process_srcu', 'srcu_reschedule'):\n"
                  "            body = h.function(self.texts['core_srcu'], name)\n"
                  '            self.assertTrue(body)\n'
                  "        self.assertIn('sp->running = false;', h.function(self.texts['core_srcu'], "
                  "'srcu_reschedule'))\n"
                  "        for body in (*p['functions'].values(), p['guard'], p['macro']):\n"
                  '            self.assertEqual(self.code.count(body), 1)\n'
                  '\n'
                  '    def test_unsupported_srcu_or_license_profiles_fail_compilation_explicitly(self):\n'
                  '        for compiler in self.compilers:\n'
                  '            for name, code, diagnostic in (\n'
                  "                    ('no-srcu', self.code.replace('#define CONFIG_SRCU 1', ''), 'requires "
                  "CONFIG_SRCU'),\n"
                  "                    ('proprietary', '#define CONFIG_PROPRIETARY_DRIVER 1\\n' + self.code, "
                  "'GPL-compatible SRCU')):\n"
                  "                p = self.directory / (name + '-' + compiler + '.c');p.write_text(code)\n"
                  "                r = subprocess.run([self.compilers[compiler], *FLAGS, '-DBASELINE=0', "
                  "str(p), '-o', str(p.with_suffix(''))],\n"
                  '                                   capture_output=True, text=True, timeout=60)\n'
                  '                self.assertNotEqual(r.returncode, 0)\n'
                  '                self.assertIn(diagnostic, r.stderr)\n'
                  '\n'
                  '\n'
                  "if __name__ == '__main__':\n"
                  '    unittest.main()\n',
 'fwd_native_17': 'VOID wifi_fwd_register(struct wifi_fwd_func_table *table)\n'
                  '{\n'
                  '\n'
                  'wf_drv_tbl.wf_fwd_tx_hook = table->wf_fwd_tx_hook;\n'
                  'wf_drv_tbl.wf_fwd_rx_hook = table->wf_fwd_rx_hook;\n'
                  'wf_drv_tbl.wf_fwd_entry_insert_hook = table->wf_fwd_entry_insert_hook;\n'
                  'wf_drv_tbl.wf_fwd_entry_delete_hook = table->wf_fwd_entry_delete_hook;\n'
                  'wf_drv_tbl.wf_fwd_set_cb_num  =  table->wf_fwd_set_cb_num;\n'
                  'wf_drv_tbl.wf_fwd_set_debug_level_hook = table->wf_fwd_set_debug_level_hook;\n'
                  'wf_drv_tbl.wf_fwd_check_active_hook = table->wf_fwd_check_active_hook;\n'
                  'wf_drv_tbl.wf_fwd_get_rep_hook = table->wf_fwd_get_rep_hook;\n'
                  'wf_drv_tbl.wf_fwd_pro_active_hook = table->wf_fwd_pro_active_hook;\n'
                  'wf_drv_tbl.wf_fwd_pro_halt_hook \t= table->wf_fwd_pro_halt_hook;\n'
                  'wf_drv_tbl.wf_fwd_pro_enabled_hook = table->wf_fwd_pro_enabled_hook;\n'
                  'wf_drv_tbl.wf_fwd_pro_disabled_hook \t= table->wf_fwd_pro_disabled_hook;\n'
                  'wf_drv_tbl.wf_fwd_access_schedule_active_hook = '
                  'table->wf_fwd_access_schedule_active_hook;\n'
                  'wf_drv_tbl.wf_fwd_access_schedule_halt_hook =\ttable->wf_fwd_access_schedule_halt_hook;\n'
                  'wf_drv_tbl.wf_fwd_hijack_active_hook = table->wf_fwd_hijack_active_hook;\n'
                  'wf_drv_tbl.wf_fwd_hijack_halt_hook = table->wf_fwd_hijack_halt_hook;\n'
                  'wf_drv_tbl.wf_fwd_bpdu_active_hook = table->wf_fwd_bpdu_active_hook;\n'
                  'wf_drv_tbl.wf_fwd_bpdu_halt_hook \t= table->wf_fwd_bpdu_halt_hook;\n'
                  'wf_drv_tbl.wf_fwd_show_entry_hook = table->wf_fwd_show_entry_hook;\n'
                  'wf_drv_tbl.wf_fwd_needed_hook = table->wf_fwd_needed_hook;\n'
                  'wf_drv_tbl.wf_fwd_delete_entry_hook =\ttable->wf_fwd_delete_entry_hook;\n'
                  'wf_drv_tbl.packet_source_show_entry_hook = table->packet_source_show_entry_hook;\n'
                  'wf_drv_tbl.packet_source_delete_entry_hook = table->packet_source_delete_entry_hook;\n'
                  'wf_drv_tbl.wf_fwd_feedback_map_table \t= table->wf_fwd_feedback_map_table;\n'
                  'wf_drv_tbl.wf_fwd_probe_adapter =\ttable->wf_fwd_probe_adapter;\n'
                  'wf_drv_tbl.wf_fwd_insert_bridge_mapping_hook = table->wf_fwd_insert_bridge_mapping_hook;\n'
                  'wf_drv_tbl.wf_fwd_insert_repeater_mapping_hook = '
                  'table->wf_fwd_insert_repeater_mapping_hook;\n'
                  'wf_drv_tbl.wf_fwd_search_mapping_table_hook =\ttable->wf_fwd_search_mapping_table_hook;\n'
                  'wf_drv_tbl.wf_fwd_delete_entry_inform_hook =\ttable->wf_fwd_delete_entry_inform_hook;\n'
                  'wf_drv_tbl.wf_fwd_check_device_hook =\ttable->wf_fwd_check_device_hook;\n'
                  'wf_drv_tbl.wf_fwd_add_entry_inform_hook =\ttable->wf_fwd_add_entry_inform_hook;\n'
                  'wf_drv_tbl.wf_fwd_set_easy_setup_mode = table->wf_fwd_set_easy_setup_mode;\n'
                  'wf_drv_tbl.wf_fwd_set_bridge_hook = table->wf_fwd_set_bridge_hook;\n'
                  '\n'
                  '\n'
                  '\n'
                  '}\n',
 'fwd_native_18': 'VOID wifi_fwd_unregister(VOID)\n'
                  '{\n'
                  '\n'
                  'wf_drv_tbl.wf_fwd_tx_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_rx_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_entry_insert_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_entry_delete_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_set_cb_num = NULL;\n'
                  'wf_drv_tbl.wf_fwd_set_debug_level_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_check_active_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_get_rep_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_pro_active_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_pro_halt_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_pro_enabled_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_pro_disabled_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_access_schedule_active_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_access_schedule_halt_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_hijack_active_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_hijack_halt_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_bpdu_active_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_bpdu_halt_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_show_entry_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_needed_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_delete_entry_hook = NULL;\n'
                  'wf_drv_tbl.packet_source_show_entry_hook = NULL;\n'
                  'wf_drv_tbl.packet_source_delete_entry_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_feedback_map_table = NULL;\n'
                  'wf_drv_tbl.wf_fwd_probe_adapter = NULL;\n'
                  'wf_drv_tbl.wf_fwd_insert_bridge_mapping_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_insert_repeater_mapping_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_search_mapping_table_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_delete_entry_inform_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_check_device_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_add_entry_inform_hook = NULL;\n'
                  'wf_drv_tbl.wf_fwd_set_easy_setup_mode = NULL;\n'
                  'wf_drv_tbl.wf_fwd_set_bridge_hook = NULL;\n'
                  '\n'
                  '\n'
                  '}\n',
 'fwd_native_19': 'INT Set_WifiFwdShowEntry(\n'
                  '\tIN PRTMP_ADAPTER pAd,\n'
                  '\tIN RTMP_STRING *arg)\n'
                  '{\n'
                  '\tif (wf_drv_tbl.wf_fwd_show_entry_hook)\n'
                  '\t\twf_drv_tbl.wf_fwd_show_entry_hook();\n'
                  '\n'
                  '\treturn TRUE;\n'
                  '}\n',
 'fwd_native_20': '{\n'
                  '  "wifi_fwd_register.c": {\n'
                  '    "source_commit": "60ae6bf98bd46b68c648620c599f1aa78073131e",\n'
                  '    "source_path": '
                  '"trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_profile.c",\n'
                  '    "function": "wifi_fwd_register",\n'
                  '    "sha256": "6d8ec3c3063bb030f27a4bf9f2de2eeaf4d38c8abbaf77c739428eeff2dd4f4f"\n'
                  '  },\n'
                  '  "wifi_fwd_unregister.c": {\n'
                  '    "source_commit": "60ae6bf98bd46b68c648620c599f1aa78073131e",\n'
                  '    "source_path": '
                  '"trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/rt_profile.c",\n'
                  '    "function": "wifi_fwd_unregister",\n'
                  '    "sha256": "07d8a495c878ec81db3fd3c3c5ff7c1cf02ccff8e99323da17ec639f3f497ed5"\n'
                  '  },\n'
                  '  "Set_WifiFwdShowEntry.c": {\n'
                  '    "source_commit": "60ae6bf98bd46b68c648620c599f1aa78073131e",\n'
                  '    "source_path": '
                  '"trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/cmm_info.c",\n'
                  '    "function": "Set_WifiFwdShowEntry",\n'
                  '    "sha256": "069401939065dcc183a7e847d291ac571f6f1468eaf7b04526363fcfb85f0029"\n'
                  '  }\n'
                  '}\n'}

def native_boundary_fixture():
    return dict(NATIVE_BOUNDARY_FIXTURE)


WTBL_FIXTURE_DATA = {'SOURCE_PATHS': {'fw': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/mcu/fw_cmd.c',
                  'core': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/mcu/andes_core.c',
                  'header': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/mcu/mt_cmd.h',
                  'os': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h',
                  'asic': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/hw_ctrl/cmm_asic_mt.h'},
 'FUNCTION_SOURCES': {'AndesAllocCmdMsg': 'core',
                      'AndesAppendCmdMsg': 'core',
                      'wtbl_tlv_size': 'fw',
                      'wtbl_tlv_validate': 'fw',
                      'CmdExtWtblUpdateCb': 'fw',
                      'CmdExtWtblUpdate': 'fw'},
 'BODY_ORDER': ('AndesAllocCmdMsg',
                'AndesAppendCmdMsg',
                'wtbl_tlv_size',
                'wtbl_tlv_validate',
                'CmdExtWtblUpdateCb',
                'CmdExtWtblUpdate'),
 'SOURCE_ONLY_FUNCTION_SOURCES': {'AndesInitCmdMsg': 'core',
                                  'AndesSendCmdMsg': 'core',
                                  'AndesForceFreeCmdMsg': 'core',
                                  'WtblDwQuery': 'fw'},
 'SOURCE_DECLARATIONS': {'header': (('enum WTBL_TLV {', '} CMD_WTBL_DUMP_T, *P_CMD_WTBL_DUMP_T;'),
                                    ('typedef struct GNU_PACKED _EVENT_EXT_CMD_RESULT_T {',
                                     '} EVENT_EXT_CMD_RESULT_T, *PEVENT_EXT_CMD_RESULT_T;'),
                                    ('#define SET_CMD_ATTR_MCU_DEST',
                                     '/* CMD ATTRIBUTE ctrl flags related Macro */'))},
 'SOURCE_ENUM_NAMES': ('HOST2N9', 'EXT_CID', 'EXT_CMD_ID_WTBL_UPDATE', 'INIT_CMD_SET_AND_WAIT_RETRY_RSP'),
 'SOURCE_ENUMS': {'header': ('HOST2N9',
                             'EXT_CID',
                             'EXT_CMD_ID_WTBL_UPDATE',
                             'INIT_CMD_SET_AND_WAIT_RETRY_RSP'),
                  'asic': ('BA_SESSION_RECP',)},
 'SOURCE_MACRO_NAMES': ('MAC_ADDR_LEN',
                        'NDIS_STATUS_SUCCESS',
                        'NDIS_STATUS_FAILURE',
                        'NDIS_STATUS_INVALID_DATA',
                        'NDIS_STATUS_RESOURCES'),
 'SOURCE_FRAGMENTS': {'header': ('\tUINT32\t\twtbl_rsp_capacity;',)},
 'MODEL_VARIANT': {'six_whole_functions_executed': True,
                   'actual_WTBL_packed_declarations_and_constants_extracted': True,
                   'kernel_cmd_msg_packet_scheduler_firmware_and_DMA_are_not_executed': True,
                   'whole_transport_status_verified_separately_by_dma_command_harness': True,
                   'query_response_prefix_is_existing_contract_not_hardware_ABI_proof': True,
                   'short_query_ACK_callback_semantics_not_transport_delivery_claim': True,
                   'allocator_seam_uses_memcpy_to_avoid_model_only_pointer_aliasing': True,
                   'MIPS_little_endian_shipping_layout_requires_target_object_binding': True,
                   'synthetic_big_endian_is_not_a_real_big_endian_ABI_test': True},
 'TAG_SIZES': (20, 12, 8, 8, 8, 8, 8, 44, 28, 8, 8, 8, 12, 8, 16, 260, 8),
 'FIELDS': ('ret',
            'alloc_length',
            'packets',
            'msgs',
            'sends',
            'wire_len',
            'elements',
            'capacity',
            'expect',
            'changed',
            'live_packets',
            'live_msgs',
            'errors'),
 'CASE_NAMES': ('tag-0',
                'tag-1',
                'tag-2',
                'tag-3',
                'tag-4',
                'tag-5',
                'tag-6',
                'tag-7',
                'tag-8',
                'tag-9',
                'tag-10',
                'tag-11',
                'tag-12',
                'tag-13',
                'tag-14',
                'tag-15',
                'tag-16',
                'reset-set-empty',
                'reset-all-empty',
                'query-generic',
                'query-dump',
                'query-multi',
                'query-duplicate-raw',
                'set-fw-error',
                'no-response',
                'wrong-cid',
                'query-short',
                'query-long',
                'query-wrong-tag',
                'query-wrong-size',
                'query-ack-zero',
                'query-ack-error',
                'query-expect-overwrite',
                'bad-operation',
                'null-adapter',
                'null-set',
                'null-nonzero',
                'reset-payload',
                'zero-buffer',
                'short-header',
                'zero-tlv-length',
                'wrong-tlv-size',
                'unknown-tag',
                'over-capacity',
                'length-overflow',
                'packet-oom',
                'msg-oom',
                'max-payload',
                'query-max-payload',
                'snapshot-copy'),
 'EXPECTED_ROWS': {'tag-0': {'ret': 0,
                             'alloc_length': 28,
                             'packets': 1,
                             'msgs': 1,
                             'sends': 1,
                             'wire_len': 28,
                             'elements': 1,
                             'capacity': 0,
                             'expect': 8,
                             'changed': 0,
                             'live_packets': 0,
                             'live_msgs': 0,
                             'errors': 0},
                   'tag-1': {'ret': 0,
                             'alloc_length': 20,
                             'packets': 1,
                             'msgs': 1,
                             'sends': 1,
                             'wire_len': 20,
                             'elements': 1,
                             'capacity': 0,
                             'expect': 8,
                             'changed': 0,
                             'live_packets': 0,
                             'live_msgs': 0,
                             'errors': 0},
                   'tag-2': {'ret': 0,
                             'alloc_length': 16,
                             'packets': 1,
                             'msgs': 1,
                             'sends': 1,
                             'wire_len': 16,
                             'elements': 1,
                             'capacity': 0,
                             'expect': 8,
                             'changed': 0,
                             'live_packets': 0,
                             'live_msgs': 0,
                             'errors': 0},
                   'tag-3': {'ret': 0,
                             'alloc_length': 16,
                             'packets': 1,
                             'msgs': 1,
                             'sends': 1,
                             'wire_len': 16,
                             'elements': 1,
                             'capacity': 0,
                             'expect': 8,
                             'changed': 0,
                             'live_packets': 0,
                             'live_msgs': 0,
                             'errors': 0},
                   'tag-4': {'ret': 0,
                             'alloc_length': 16,
                             'packets': 1,
                             'msgs': 1,
                             'sends': 1,
                             'wire_len': 16,
                             'elements': 1,
                             'capacity': 0,
                             'expect': 8,
                             'changed': 0,
                             'live_packets': 0,
                             'live_msgs': 0,
                             'errors': 0},
                   'tag-5': {'ret': 0,
                             'alloc_length': 16,
                             'packets': 1,
                             'msgs': 1,
                             'sends': 1,
                             'wire_len': 16,
                             'elements': 1,
                             'capacity': 0,
                             'expect': 8,
                             'changed': 0,
                             'live_packets': 0,
                             'live_msgs': 0,
                             'errors': 0},
                   'tag-6': {'ret': 0,
                             'alloc_length': 16,
                             'packets': 1,
                             'msgs': 1,
                             'sends': 1,
                             'wire_len': 16,
                             'elements': 1,
                             'capacity': 0,
                             'expect': 8,
                             'changed': 0,
                             'live_packets': 0,
                             'live_msgs': 0,
                             'errors': 0},
                   'tag-7': {'ret': 0,
                             'alloc_length': 52,
                             'packets': 1,
                             'msgs': 1,
                             'sends': 1,
                             'wire_len': 52,
                             'elements': 1,
                             'capacity': 0,
                             'expect': 8,
                             'changed': 0,
                             'live_packets': 0,
                             'live_msgs': 0,
                             'errors': 0},
                   'tag-8': {'ret': 0,
                             'alloc_length': 36,
                             'packets': 1,
                             'msgs': 1,
                             'sends': 1,
                             'wire_len': 36,
                             'elements': 1,
                             'capacity': 0,
                             'expect': 8,
                             'changed': 0,
                             'live_packets': 0,
                             'live_msgs': 0,
                             'errors': 0},
                   'tag-9': {'ret': 0,
                             'alloc_length': 16,
                             'packets': 1,
                             'msgs': 1,
                             'sends': 1,
                             'wire_len': 16,
                             'elements': 1,
                             'capacity': 0,
                             'expect': 8,
                             'changed': 0,
                             'live_packets': 0,
                             'live_msgs': 0,
                             'errors': 0},
                   'tag-10': {'ret': 0,
                              'alloc_length': 16,
                              'packets': 1,
                              'msgs': 1,
                              'sends': 1,
                              'wire_len': 16,
                              'elements': 1,
                              'capacity': 0,
                              'expect': 8,
                              'changed': 0,
                              'live_packets': 0,
                              'live_msgs': 0,
                              'errors': 0},
                   'tag-11': {'ret': 0,
                              'alloc_length': 16,
                              'packets': 1,
                              'msgs': 1,
                              'sends': 1,
                              'wire_len': 16,
                              'elements': 1,
                              'capacity': 0,
                              'expect': 8,
                              'changed': 0,
                              'live_packets': 0,
                              'live_msgs': 0,
                              'errors': 0},
                   'tag-12': {'ret': 0,
                              'alloc_length': 20,
                              'packets': 1,
                              'msgs': 1,
                              'sends': 1,
                              'wire_len': 20,
                              'elements': 1,
                              'capacity': 0,
                              'expect': 8,
                              'changed': 0,
                              'live_packets': 0,
                              'live_msgs': 0,
                              'errors': 0},
                   'tag-13': {'ret': 0,
                              'alloc_length': 16,
                              'packets': 1,
                              'msgs': 1,
                              'sends': 1,
                              'wire_len': 16,
                              'elements': 1,
                              'capacity': 0,
                              'expect': 8,
                              'changed': 0,
                              'live_packets': 0,
                              'live_msgs': 0,
                              'errors': 0},
                   'tag-14': {'ret': 0,
                              'alloc_length': 24,
                              'packets': 1,
                              'msgs': 1,
                              'sends': 1,
                              'wire_len': 24,
                              'elements': 1,
                              'capacity': 0,
                              'expect': 8,
                              'changed': 0,
                              'live_packets': 0,
                              'live_msgs': 0,
                              'errors': 0},
                   'tag-15': {'ret': 0,
                              'alloc_length': 268,
                              'packets': 1,
                              'msgs': 1,
                              'sends': 1,
                              'wire_len': 268,
                              'elements': 1,
                              'capacity': 0,
                              'expect': 8,
                              'changed': 0,
                              'live_packets': 0,
                              'live_msgs': 0,
                              'errors': 0},
                   'tag-16': {'ret': 0,
                              'alloc_length': 16,
                              'packets': 1,
                              'msgs': 1,
                              'sends': 1,
                              'wire_len': 16,
                              'elements': 1,
                              'capacity': 0,
                              'expect': 8,
                              'changed': 0,
                              'live_packets': 0,
                              'live_msgs': 0,
                              'errors': 0},
                   'reset-set-empty': {'ret': 0,
                                       'alloc_length': 8,
                                       'packets': 1,
                                       'msgs': 1,
                                       'sends': 1,
                                       'wire_len': 8,
                                       'elements': 0,
                                       'capacity': 0,
                                       'expect': 8,
                                       'changed': 0,
                                       'live_packets': 0,
                                       'live_msgs': 0,
                                       'errors': 0},
                   'reset-all-empty': {'ret': 0,
                                       'alloc_length': 8,
                                       'packets': 1,
                                       'msgs': 1,
                                       'sends': 1,
                                       'wire_len': 8,
                                       'elements': 0,
                                       'capacity': 0,
                                       'expect': 8,
                                       'changed': 0,
                                       'live_packets': 0,
                                       'live_msgs': 0,
                                       'errors': 0},
                   'query-generic': {'ret': 0,
                                     'alloc_length': 28,
                                     'packets': 1,
                                     'msgs': 1,
                                     'sends': 1,
                                     'wire_len': 28,
                                     'elements': 1,
                                     'capacity': 20,
                                     'expect': 48,
                                     'changed': 1,
                                     'live_packets': 0,
                                     'live_msgs': 0,
                                     'errors': 0},
                   'query-dump': {'ret': 0,
                                  'alloc_length': 268,
                                  'packets': 1,
                                  'msgs': 1,
                                  'sends': 1,
                                  'wire_len': 268,
                                  'elements': 1,
                                  'capacity': 260,
                                  'expect': 288,
                                  'changed': 1,
                                  'live_packets': 0,
                                  'live_msgs': 0,
                                  'errors': 0},
                   'query-multi': {'ret': 0,
                                   'alloc_length': 40,
                                   'packets': 1,
                                   'msgs': 1,
                                   'sends': 1,
                                   'wire_len': 40,
                                   'elements': 2,
                                   'capacity': 32,
                                   'expect': 60,
                                   'changed': 1,
                                   'live_packets': 0,
                                   'live_msgs': 0,
                                   'errors': 0},
                   'query-duplicate-raw': {'ret': 0,
                                           'alloc_length': 40,
                                           'packets': 1,
                                           'msgs': 1,
                                           'sends': 1,
                                           'wire_len': 40,
                                           'elements': 2,
                                           'capacity': 32,
                                           'expect': 60,
                                           'changed': 1,
                                           'live_packets': 0,
                                           'live_msgs': 0,
                                           'errors': 0},
                   'set-fw-error': {'ret': 5,
                                    'alloc_length': 28,
                                    'packets': 1,
                                    'msgs': 1,
                                    'sends': 1,
                                    'wire_len': 28,
                                    'elements': 1,
                                    'capacity': 0,
                                    'expect': 8,
                                    'changed': 0,
                                    'live_packets': 0,
                                    'live_msgs': 0,
                                    'errors': 0},
                   'no-response': {'ret': 1,
                                   'alloc_length': 28,
                                   'packets': 1,
                                   'msgs': 1,
                                   'sends': 1,
                                   'wire_len': 28,
                                   'elements': 1,
                                   'capacity': 0,
                                   'expect': 8,
                                   'changed': 0,
                                   'live_packets': 0,
                                   'live_msgs': 0,
                                   'errors': 0},
                   'wrong-cid': {'ret': 2,
                                 'alloc_length': 28,
                                 'packets': 1,
                                 'msgs': 1,
                                 'sends': 1,
                                 'wire_len': 28,
                                 'elements': 1,
                                 'capacity': 0,
                                 'expect': 8,
                                 'changed': 0,
                                 'live_packets': 0,
                                 'live_msgs': 0,
                                 'errors': 0},
                   'query-short': {'ret': 2,
                                   'alloc_length': 28,
                                   'packets': 1,
                                   'msgs': 1,
                                   'sends': 1,
                                   'wire_len': 28,
                                   'elements': 1,
                                   'capacity': 20,
                                   'expect': 48,
                                   'changed': 0,
                                   'live_packets': 0,
                                   'live_msgs': 0,
                                   'errors': 0},
                   'query-long': {'ret': 2,
                                  'alloc_length': 28,
                                  'packets': 1,
                                  'msgs': 1,
                                  'sends': 1,
                                  'wire_len': 28,
                                  'elements': 1,
                                  'capacity': 20,
                                  'expect': 48,
                                  'changed': 0,
                                  'live_packets': 0,
                                  'live_msgs': 0,
                                  'errors': 0},
                   'query-wrong-tag': {'ret': 2,
                                       'alloc_length': 16,
                                       'packets': 1,
                                       'msgs': 1,
                                       'sends': 1,
                                       'wire_len': 16,
                                       'elements': 1,
                                       'capacity': 8,
                                       'expect': 36,
                                       'changed': 0,
                                       'live_packets': 0,
                                       'live_msgs': 0,
                                       'errors': 0},
                   'query-wrong-size': {'ret': 2,
                                        'alloc_length': 28,
                                        'packets': 1,
                                        'msgs': 1,
                                        'sends': 1,
                                        'wire_len': 28,
                                        'elements': 1,
                                        'capacity': 20,
                                        'expect': 48,
                                        'changed': 0,
                                        'live_packets': 0,
                                        'live_msgs': 0,
                                        'errors': 0},
                   'query-ack-zero': {'ret': 2,
                                      'alloc_length': 28,
                                      'packets': 1,
                                      'msgs': 1,
                                      'sends': 1,
                                      'wire_len': 28,
                                      'elements': 1,
                                      'capacity': 20,
                                      'expect': 48,
                                      'changed': 0,
                                      'live_packets': 0,
                                      'live_msgs': 0,
                                      'errors': 0},
                   'query-ack-error': {'ret': 5,
                                       'alloc_length': 28,
                                       'packets': 1,
                                       'msgs': 1,
                                       'sends': 1,
                                       'wire_len': 28,
                                       'elements': 1,
                                       'capacity': 20,
                                       'expect': 48,
                                       'changed': 0,
                                       'live_packets': 0,
                                       'live_msgs': 0,
                                       'errors': 0},
                   'query-expect-overwrite': {'ret': 0,
                                              'alloc_length': 28,
                                              'packets': 1,
                                              'msgs': 1,
                                              'sends': 1,
                                              'wire_len': 28,
                                              'elements': 1,
                                              'capacity': 20,
                                              'expect': 48,
                                              'changed': 1,
                                              'live_packets': 0,
                                              'live_msgs': 0,
                                              'errors': 0},
                   'bad-operation': {'ret': 2,
                                     'alloc_length': 0,
                                     'packets': 0,
                                     'msgs': 0,
                                     'sends': 0,
                                     'wire_len': 0,
                                     'elements': 0,
                                     'capacity': 0,
                                     'expect': 0,
                                     'changed': 0,
                                     'live_packets': 0,
                                     'live_msgs': 0,
                                     'errors': 0},
                   'null-adapter': {'ret': 2,
                                    'alloc_length': 0,
                                    'packets': 0,
                                    'msgs': 0,
                                    'sends': 0,
                                    'wire_len': 0,
                                    'elements': 0,
                                    'capacity': 0,
                                    'expect': 0,
                                    'changed': 0,
                                    'live_packets': 0,
                                    'live_msgs': 0,
                                    'errors': 0},
                   'null-set': {'ret': 2,
                                'alloc_length': 0,
                                'packets': 0,
                                'msgs': 0,
                                'sends': 0,
                                'wire_len': 0,
                                'elements': 0,
                                'capacity': 0,
                                'expect': 0,
                                'changed': 0,
                                'live_packets': 0,
                                'live_msgs': 0,
                                'errors': 0},
                   'null-nonzero': {'ret': 2,
                                    'alloc_length': 0,
                                    'packets': 0,
                                    'msgs': 0,
                                    'sends': 0,
                                    'wire_len': 0,
                                    'elements': 0,
                                    'capacity': 0,
                                    'expect': 0,
                                    'changed': 0,
                                    'live_packets': 0,
                                    'live_msgs': 0,
                                    'errors': 0},
                   'reset-payload': {'ret': 2,
                                     'alloc_length': 0,
                                     'packets': 0,
                                     'msgs': 0,
                                     'sends': 0,
                                     'wire_len': 0,
                                     'elements': 0,
                                     'capacity': 0,
                                     'expect': 0,
                                     'changed': 0,
                                     'live_packets': 0,
                                     'live_msgs': 0,
                                     'errors': 0},
                   'zero-buffer': {'ret': 2,
                                   'alloc_length': 0,
                                   'packets': 0,
                                   'msgs': 0,
                                   'sends': 0,
                                   'wire_len': 0,
                                   'elements': 0,
                                   'capacity': 0,
                                   'expect': 0,
                                   'changed': 0,
                                   'live_packets': 0,
                                   'live_msgs': 0,
                                   'errors': 0},
                   'short-header': {'ret': 2,
                                    'alloc_length': 0,
                                    'packets': 0,
                                    'msgs': 0,
                                    'sends': 0,
                                    'wire_len': 0,
                                    'elements': 0,
                                    'capacity': 0,
                                    'expect': 0,
                                    'changed': 0,
                                    'live_packets': 0,
                                    'live_msgs': 0,
                                    'errors': 0},
                   'zero-tlv-length': {'ret': 2,
                                       'alloc_length': 0,
                                       'packets': 0,
                                       'msgs': 0,
                                       'sends': 0,
                                       'wire_len': 0,
                                       'elements': 0,
                                       'capacity': 0,
                                       'expect': 0,
                                       'changed': 0,
                                       'live_packets': 0,
                                       'live_msgs': 0,
                                       'errors': 0},
                   'wrong-tlv-size': {'ret': 2,
                                      'alloc_length': 0,
                                      'packets': 0,
                                      'msgs': 0,
                                      'sends': 0,
                                      'wire_len': 0,
                                      'elements': 0,
                                      'capacity': 0,
                                      'expect': 0,
                                      'changed': 0,
                                      'live_packets': 0,
                                      'live_msgs': 0,
                                      'errors': 0},
                   'unknown-tag': {'ret': 2,
                                   'alloc_length': 0,
                                   'packets': 0,
                                   'msgs': 0,
                                   'sends': 0,
                                   'wire_len': 0,
                                   'elements': 0,
                                   'capacity': 0,
                                   'expect': 0,
                                   'changed': 0,
                                   'live_packets': 0,
                                   'live_msgs': 0,
                                   'errors': 0},
                   'over-capacity': {'ret': 2,
                                     'alloc_length': 0,
                                     'packets': 0,
                                     'msgs': 0,
                                     'sends': 0,
                                     'wire_len': 0,
                                     'elements': 0,
                                     'capacity': 0,
                                     'expect': 0,
                                     'changed': 0,
                                     'live_packets': 0,
                                     'live_msgs': 0,
                                     'errors': 0},
                   'length-overflow': {'ret': 2,
                                       'alloc_length': 0,
                                       'packets': 0,
                                       'msgs': 0,
                                       'sends': 0,
                                       'wire_len': 0,
                                       'elements': 0,
                                       'capacity': 0,
                                       'expect': 0,
                                       'changed': 0,
                                       'live_packets': 0,
                                       'live_msgs': 0,
                                       'errors': 0},
                   'packet-oom': {'ret': 3,
                                  'alloc_length': 28,
                                  'packets': 0,
                                  'msgs': 0,
                                  'sends': 0,
                                  'wire_len': 0,
                                  'elements': 0,
                                  'capacity': 0,
                                  'expect': 0,
                                  'changed': 0,
                                  'live_packets': 0,
                                  'live_msgs': 0,
                                  'errors': 0},
                   'msg-oom': {'ret': 3,
                               'alloc_length': 28,
                               'packets': 1,
                               'msgs': 0,
                               'sends': 0,
                               'wire_len': 0,
                               'elements': 0,
                               'capacity': 0,
                               'expect': 0,
                               'changed': 0,
                               'live_packets': 0,
                               'live_msgs': 0,
                               'errors': 0},
                   'max-payload': {'ret': 0,
                                   'alloc_length': 312,
                                   'packets': 1,
                                   'msgs': 1,
                                   'sends': 1,
                                   'wire_len': 312,
                                   'elements': 38,
                                   'capacity': 0,
                                   'expect': 8,
                                   'changed': 0,
                                   'live_packets': 0,
                                   'live_msgs': 0,
                                   'errors': 0},
                   'query-max-payload': {'ret': 0,
                                         'alloc_length': 312,
                                         'packets': 1,
                                         'msgs': 1,
                                         'sends': 1,
                                         'wire_len': 312,
                                         'elements': 38,
                                         'capacity': 304,
                                         'expect': 332,
                                         'changed': 1,
                                         'live_packets': 0,
                                         'live_msgs': 0,
                                         'errors': 0},
                   'snapshot-copy': {'ret': 0,
                                     'alloc_length': 28,
                                     'packets': 1,
                                     'msgs': 1,
                                     'sends': 1,
                                     'wire_len': 28,
                                     'elements': 1,
                                     'capacity': 0,
                                     'expect': 8,
                                     'changed': 1,
                                     'live_packets': 0,
                                     'live_msgs': 0,
                                     'errors': 0}},
 'PREFIX': '\n'
           '#include <stdint.h>\n'
           '#include <stdio.h>\n'
           '#include <stdlib.h>\n'
           '#include <string.h>\n'
           '#include <stdarg.h>\n'
           'typedef uint8_t UCHAR, UINT8, *PUCHAR;\n'
           'typedef uint16_t UINT16; typedef uint32_t UINT32; typedef int32_t INT32;\n'
           'typedef char *PCHAR; typedef void VOID; typedef int BOOLEAN;\n'
           '#define TRUE 1\n'
           '#define FALSE 0\n'
           '#define GNU_PACKED __attribute__((packed))\n'
           '#define MT7615 1\n'
           '#define cpu2le16(x) ((UINT16)(x))\n'
           '#define cpu2le32(x) ((UINT32)(x))\n'
           '#define le2cpu16(x) ((UINT16)(x))\n'
           '#define le2cpu32(x) ((UINT32)(x))\n'
           '#define PRINT_MAC(x) (x)[0],(x)[1],(x)[2],(x)[3],(x)[4],(x)[5]\n'
           '#define os_move_mem memcpy\n'
           '#define os_zero_mem(p,n) memset(p,0,n)\n'
           'static void trace_log(const char *fmt,...) { (void)fmt; }\n'
           '#define MTWF_LOG(a,b,c,args) trace_log args\n'
           'struct cmd_msg;\n'
           'struct _CMD_ATTRIBUTE {\n'
           ' int mcu_dest,type,ext_type;\n'
           ' struct { int flags; UINT16 wait_ms_time,expect_size; } ctrl;\n'
           ' struct { UINT32 *wb_buf_in_calbk; void (*handler)(struct cmd_msg *,char *,UINT16); } rsp;\n'
           '};\n'
           'typedef struct _CMD_ATTRIBUTE CMD_ATTRIBUTE;\n'
           'struct packet { UCHAR data[2048]; unsigned int length,capacity,reserved; struct {struct cmd_msg '
           '*msg;} cb; };\n'
           'typedef struct packet *PNDIS_PACKET;\n'
           'struct cmd_msg { struct _CMD_ATTRIBUTE attr; void *priv; PNDIS_PACKET net_pkt;\n'
           ' INT32 cmd_return_status; UINT32 wtbl_rsp_capacity; };\n'
           'typedef struct { int cmd_header_len,cmd_padding_len; } RTMP_CHIP_CAP;\n'
           'struct MCU_CTRL { int alloc_cmd_msg; };\n'
           'typedef struct _RTMP_ADAPTER { void *hdev_ctrl; struct MCU_CTRL MCUCtrl; } RTMP_ADAPTER;\n'
           'static const char *case_name;\n'
           'static int alloc_length,packets,msgs,sends,wire_len,elements,capacity_seen,expect_seen,errors;\n'
           'static int live_packets,live_msgs;\n'
           'static PNDIS_PACKET retained_packet;static PUCHAR retained_msg;\n'
           'static UCHAR input[512],before[512],response[600],wire[512];\n'
           'static RTMP_CHIP_CAP chip_cap={16,4};\n'
           'static RTMP_CHIP_CAP *hc_get_chip_cap(void *p) { (void)p; return &chip_cap; }\n'
           'static int selected(const char *s) { return strcmp(case_name,s)==0; }\n'
           'static PNDIS_PACKET RTMP_AllocateFragPacketBuffer(RTMP_ADAPTER *ad,int n) {\n'
           ' (void)ad;alloc_length=n-chip_cap.cmd_header_len-chip_cap.cmd_padding_len;\n'
           ' if(selected("packet-oom"))return NULL;\n'
           ' if(n<0 || n>1024){errors++;return NULL;}\n'
           ' PNDIS_PACKET p=calloc(1,sizeof(*p));if(!p)abort();p->capacity=(unsigned)n;\n'
           ' packets++;live_packets++;retained_packet=p;return p;\n'
           '}\n'
           'static void reserve_packet(PNDIS_PACKET p,unsigned int n) {p->reserved=n;p->length=n;}\n'
           '#define OS_PKT_RESERVE(p,n) reserve_packet(p,n)\n'
           '#define CMD_MSG_CB(p) (&(p)->cb)\n'
           'static void os_alloc_mem(void *ad,void *out,size_t n) {\n'
           ' (void)ad;PUCHAR allocated=NULL;\n'
           ' '
           'if(!selected("msg-oom")){allocated=malloc(n);if(!allocated)abort();memset(allocated,0xa5,n);msgs++;live_msgs++;retained_msg=allocated;}\n'
           ' memcpy(out,&allocated,sizeof(allocated));\n'
           ' if(allocated && selected("snapshot-copy")){UINT16 '
           'tag=1,len=12;memcpy(input+8,&tag,2);memcpy(input+10,&len,2);}\n'
           '}\n'
           'static void RTMPFreeNdisPacket(RTMP_ADAPTER *ad,PNDIS_PACKET p) {\n'
           ' (void)ad;if(!p || live_packets<=0){errors++;return;}live_packets--;free(p);\n'
           '}\n'
           'static void *extend_packet(PNDIS_PACKET p,unsigned int n) {\n'
           ' if(n>p->capacity || p->length>p->capacity-n){errors++;abort();}\n'
           ' void *tail=p->data+p->length;p->length+=n;return tail;\n'
           '}\n'
           '#define OS_PKT_TAIL_BUF_EXTEND(p,n) extend_packet(p,n)\n'
           '#define AndesFreeCmdMsg(msg) do { live_msgs--;free(msg); } while(0)\n'
           'static void AndesInitCmdMsg(struct cmd_msg *msg,CMD_ATTRIBUTE attr) {\n'
           ' msg->attr=attr;msg->cmd_return_status=1;\n'
           '}\n'
           'static INT32 AndesSendCmdMsg(RTMP_ADAPTER *ad,struct cmd_msg *msg);\n',
 'TRANSPORT': '\n'
              'static INT32 AndesSendCmdMsg(RTMP_ADAPTER *ad,struct cmd_msg *msg) {\n'
              ' int query=msg->attr.rsp.wb_buf_in_calbk!=NULL;\n'
              ' sends++;wire_len=(int)(msg->net_pkt->length-msg->net_pkt->reserved);\n'
              ' if(wire_len<8 || wire_len>(int)sizeof(wire)){errors++;abort();}\n'
              ' memcpy(wire,msg->net_pkt->data+msg->net_pkt->reserved,(size_t)wire_len);\n'
              ' memcpy(&elements,wire+2,2);\n'
              ' if(memcmp(wire+8,before+8,(size_t)wire_len-8))errors++;\n'
              ' capacity_seen=(int)msg->wtbl_rsp_capacity;expect_seen=msg->attr.ctrl.expect_size;\n'
              ' if(msg->attr.mcu_dest!=HOST2N9 || msg->attr.type!=EXT_CID ||\n'
              '    msg->attr.ext_type!=EXT_CMD_ID_WTBL_UPDATE ||\n'
              '    msg->attr.ctrl.flags!=INIT_CMD_SET_AND_WAIT_RETRY_RSP)errors++;\n'
              ' UINT16 length=8;memset(response,0,sizeof(response));response[0]=EXT_CMD_ID_WTBL_UPDATE;\n'
              ' if(query) {\n'
              '  unsigned int n=(unsigned int)(wire_len-8);\n'
              '  length=(UINT16)(28+n);memcpy(response+28,wire+8,n);\n'
              '  for(unsigned int offset=0;offset<n;){\n'
              '   UINT16 len;memcpy(&len,response+28+offset+2,2);\n'
              '   if(len<4 || len>n-offset){errors++;abort();}\n'
              '   if(len>4)response[28+offset+4]=0x5a;\n'
              '   offset+=len;\n'
              '  }\n'
              '  if(selected("query-short"))length--;\n'
              '  if(selected("query-long"))length++;\n'
              '  if(selected("query-wrong-tag")){UINT16 tag=3;memcpy(response+28,&tag,2);}\n'
              '  if(selected("query-wrong-size")){UINT16 len=4;memcpy(response+30,&len,2);}\n'
              '  if(selected("query-ack-zero")||selected("query-ack-error")) {\n'
              '   memset(response,0,8);response[0]=EXT_CMD_ID_WTBL_UPDATE;length=8;\n'
              '   if(selected("query-ack-error"))response[4]=5;\n'
              '  }\n'
              ' }\n'
              ' if(selected("set-fw-error"))response[4]=5;\n'
              ' if(selected("wrong-cid"))response[0]=0x33;\n'
              ' if(selected("query-expect-overwrite")) {\n'
              '  msg->attr.ctrl.expect_size=29; /* mutable transport state must not become capacity */\n'
              ' }\n'
              ' if(!selected("no-response"))msg->attr.rsp.handler(msg,(char *)response,length);\n'
              ' INT32 ret=msg->cmd_return_status;\n'
              ' RTMPFreeNdisPacket(ad,msg->net_pkt);live_msgs--;free(msg);return ret;\n'
              '}\n',
 'SUFFIX': '\n'
           'static const unsigned int tag_sizes[17]={20,12,8,8,8,8,8,44,28,8,8,8,12,8,16,260,8};\n'
           'static unsigned int add_tlv(unsigned int offset,UINT16 tag) {\n'
           ' UINT16 len=(UINT16)tag_sizes[tag];memcpy(input+offset,&tag,2);memcpy(input+offset+2,&len,2);\n'
           ' return offset+len;\n'
           '}\n'
           'int main(int argc,char **argv) {\n'
           ' if(argc!=2)return 91;\n'
           ' case_name=argv[1];\n'
           ' CASE_ADMISSION\n'
           ' memset(input,0,sizeof(input));input[0]=0x11;input[511]=0x22;\n'
           ' unsigned int length=add_tlv(8,0)-8;UINT8 operation=SET_WTBL;\n'
           ' if(!strncmp(case_name,"tag-",4))length=add_tlv(8,(UINT16)atoi(case_name+4))-8;\n'
           ' if(!strncmp(case_name,"query-",6))operation=QUERY_WTBL;\n'
           ' if(selected("query-dump"))length=add_tlv(8,15)-8;\n'
           ' if(selected("query-wrong-tag"))length=add_tlv(8,2)-8;\n'
           ' if(selected("query-multi"))length=add_tlv(add_tlv(8,0),1)-8;\n'
           ' if(selected("query-duplicate-raw"))length=add_tlv(add_tlv(8,14),14)-8;\n'
           ' if(selected("max-payload")||selected("query-max-payload")) {\n'
           '  unsigned int off=8;for(int i=0;i<38;i++)off=add_tlv(off,2);length=off-8;\n'
           ' }\n'
           ' VOID *buffer=input+8;RTMP_ADAPTER ad={0};RTMP_ADAPTER *adapter=&ad;\n'
           ' if(selected("reset-set-empty")){buffer=NULL;length=0;operation=RESET_WTBL_AND_SET;}\n'
           ' if(selected("reset-all-empty")){buffer=NULL;length=0;operation=RESET_ALL_WTBL;}\n'
           ' if(selected("bad-operation"))operation=0;\n'
           ' if(selected("null-adapter"))adapter=NULL;\n'
           ' if(selected("null-set")){buffer=NULL;length=0;}\n'
           ' if(selected("null-nonzero"))buffer=NULL;\n'
           ' if(selected("reset-payload"))operation=RESET_ALL_WTBL;\n'
           ' if(selected("zero-buffer"))length=0;\n'
           ' if(selected("short-header"))length=3;\n'
           ' if(selected("zero-tlv-length")){UINT16 len=0;memcpy(input+10,&len,2);}\n'
           ' if(selected("wrong-tlv-size")){UINT16 len=8;memcpy(input+10,&len,2);length=8;}\n'
           ' if(selected("unknown-tag")){UINT16 tag=17;memcpy(input+8,&tag,2);}\n'
           ' if(selected("over-capacity"))length=305;\n'
           ' if(selected("length-overflow"))length=UINT32_MAX;\n'
           ' memcpy(before,input,sizeof(input));\n'
           ' INT32 ret=CmdExtWtblUpdate(adapter,7,operation,buffer,length);\n'
           ' int changed=memcmp(input,before,sizeof(input))!=0;\n'
           ' if(input[0]!=0x11 || input[511]!=0x22)errors++;\n'
           ' '
           'printf("{\\"ret\\":%d,\\"alloc_length\\":%d,\\"packets\\":%d,\\"msgs\\":%d,\\"sends\\":%d,\\"wire_len\\":%d,\\"elements\\":%d,\\"capacity\\":%d,\\"expect\\":%d,\\"changed\\":%d,\\"live_packets\\":%d,\\"live_msgs\\":%d,\\"errors\\":%d}\\n",ret,alloc_length,packets,msgs,sends,wire_len,elements,capacity_seen,expect_seen,changed,live_packets,live_msgs,errors);\n'
           ' if(live_msgs)free(retained_msg);\n'
           ' if(live_packets)free(retained_packet);\n'
           ' /* The fixed old early-return fixture is allowed to demonstrate, then release,\n'
           '  * its private model allocations so historical regression tests are ASan clean. */\n'
           ' return 0;\n'
           '}\n'}
WTBL_FIXTURE_INPUTS = {'wtbl_fw': 'static UINT16 wtbl_tlv_size(UINT16 tag)\n'
            '{\n'
            '\tswitch (tag) {\n'
            '\tcase WTBL_GENERIC: return sizeof(CMD_WTBL_GENERIC_T);\n'
            '\tcase WTBL_RX: return sizeof(CMD_WTBL_RX_T);\n'
            '\tcase WTBL_HT: return sizeof(CMD_WTBL_HT_T);\n'
            '\tcase WTBL_VHT: return sizeof(CMD_WTBL_VHT_T);\n'
            '\tcase WTBL_PEER_PS: return sizeof(CMD_WTBL_PEER_PS_T);\n'
            '\tcase WTBL_TX_PS: return sizeof(CMD_WTBL_TX_PS_T);\n'
            '\tcase WTBL_HDR_TRANS: return sizeof(CMD_WTBL_HDR_TRANS_T);\n'
            '\tcase WTBL_SECURITY_KEY: return sizeof(CMD_WTBL_SECURITY_KEY_T);\n'
            '\tcase WTBL_BA: return sizeof(CMD_WTBL_BA_T);\n'
            '\tcase WTBL_RDG: return sizeof(CMD_WTBL_RDG_T);\n'
            '\tcase WTBL_PROTECTION: return sizeof(CMD_WTBL_PROTECTION_T);\n'
            '\tcase WTBL_CLEAR: return sizeof(CMD_WTBL_CLEAR_T);\n'
            '\tcase WTBL_BF: return sizeof(CMD_WTBL_BF_T);\n'
            '\tcase WTBL_SMPS: return sizeof(CMD_WTBL_SMPS_T);\n'
            '\tcase WTBL_RAW_DATA_RW: return sizeof(CMD_WTBL_RAW_DATA_RW_T);\n'
            '\tcase WTBL_DUMP: return sizeof(CMD_WTBL_DUMP_T);\n'
            '\tcase WTBL_SPE: return sizeof(CMD_WTBL_SPE_T);\n'
            '\tdefault: return 0;\n'
            '\t}\n'
            '}\n'
            'static INT32 wtbl_tlv_validate(const UCHAR *buffer, UINT32 length,\n'
            '\tBOOLEAN wire, const UCHAR *expected, UINT16 *count, UINT32 *features)\n'
            '{\n'
            '\tCMD_WTBL_GENERIC_TLV_T tlv, requested;\n'
            '\tUINT16 number = 0;\n'
            '\tUINT32 mask = 0;\n'
            '\n'
            '\tif ((length && !buffer) || !count || !features)\n'
            '\t\treturn NDIS_STATUS_INVALID_DATA;\n'
            '\twhile (length) {\n'
            '\t\tif (length < sizeof(tlv))\n'
            '\t\t\treturn NDIS_STATUS_INVALID_DATA;\n'
            '\t\tos_move_mem(&tlv, buffer, sizeof(tlv));\n'
            '\t\tif (wire) {\n'
            '\t\t\ttlv.u2Tag = le2cpu16(tlv.u2Tag);\n'
            '\t\t\ttlv.u2Length = le2cpu16(tlv.u2Length);\n'
            '\t\t}\n'
            '\t\tif (tlv.u2Tag >= WTBL_MAX_NUM ||\n'
            '\t\t\ttlv.u2Length != wtbl_tlv_size(tlv.u2Tag) ||\n'
            '\t\t\t!tlv.u2Length || tlv.u2Length > length || number == 0xffffU)\n'
            '\t\t\treturn NDIS_STATUS_INVALID_DATA;\n'
            '\t\tif (expected) {\n'
            '\t\t\tos_move_mem(&requested, expected, sizeof(requested));\n'
            '\t\t\tif (requested.u2Tag != tlv.u2Tag ||\n'
            '\t\t\t\trequested.u2Length != tlv.u2Length)\n'
            '\t\t\t\treturn NDIS_STATUS_INVALID_DATA;\n'
            '\t\t\texpected += tlv.u2Length;\n'
            '\t\t}\n'
            '\t\tmask |= 1U << tlv.u2Tag;\n'
            '\t\tbuffer += tlv.u2Length;\n'
            '\t\tlength -= tlv.u2Length;\n'
            '\t\tnumber++;\n'
            '\t}\n'
            '\t*count = number;\n'
            '\t*features = mask;\n'
            '\treturn NDIS_STATUS_SUCCESS;\n'
            '}\n'
            'static VOID CmdExtWtblUpdateCb(struct cmd_msg *msg, char *data, UINT16 len)\n'
            '{\n'
            '\tEVENT_EXT_CMD_RESULT_T result;\n'
            '\tPUCHAR pRspPayload;\n'
            '\tUINT32 capacity, features;\n'
            '\tUINT16 count;\n'
            '\tUINT32 offset = 20 + sizeof(CMD_WTBL_UPDATE_T);\n'
            '\n'
            '\tif (!msg)\n'
            '\t\treturn;\n'
            '\tmsg->cmd_return_status = NDIS_STATUS_INVALID_DATA;\n'
            '\tif (!data)\n'
            '\t\treturn;\n'
            '\tpRspPayload = (PUCHAR)msg->attr.rsp.wb_buf_in_calbk;\n'
            '\tcapacity = msg->wtbl_rsp_capacity;\n'
            '\tif (len == sizeof(result)) {\n'
            '\t\tos_move_mem(&result, data, sizeof(result));\n'
            '\t\tif (result.ucExTenCID != EXT_CMD_ID_WTBL_UPDATE)\n'
            '\t\t\treturn;\n'
            "\t\t/* A query's short result can report failure, never query success. */\n"
            '\t\tif ((!pRspPayload && !capacity) || le2cpu32(result.u4Status))\n'
            '\t\t\tmsg->cmd_return_status = le2cpu32(result.u4Status);\n'
            '\t\treturn;\n'
            '\t}\n'
            '\t/* Query replies have a 20-byte prefix plus the WTBL header.  The\n'
            '\t * transport may rewrite expect_size; it is not an output capacity. */\n'
            '\tif (!pRspPayload || !capacity ||\n'
            '\t\tcapacity > MAX_BUF_SIZE_OF_WTBL_INFO + 100 - sizeof(CMD_WTBL_UPDATE_T) ||\n'
            '\t\tcapacity > 0xffffU - offset || len != offset + capacity)\n'
            '\t\treturn;\n'
            '\tif (wtbl_tlv_validate((PUCHAR)data + offset, capacity, TRUE,\n'
            '\t\tpRspPayload, &count, &features) != NDIS_STATUS_SUCCESS)\n'
            '\t\treturn;\n'
            '\tos_move_mem(pRspPayload, data + offset, capacity);\n'
            '\tmsg->cmd_return_status = NDIS_STATUS_SUCCESS;\n'
            '}\n'
            'INT32 CmdExtWtblUpdate(RTMP_ADAPTER *pAd, UINT8 ucWlanIdx, UINT8 ucOperation,\n'
            '\t\t\t\t\t   VOID *pBuffer, UINT32 u4BufferLen)\n'
            '{\n'
            '\tstruct cmd_msg\t\t\t*msg = NULL;\n'
            '\tCMD_WTBL_UPDATE_T\tCmdWtblUpdate = {0};\n'
            '\tINT32\t\t\t\t\tRet = 0;\n'
            '\tUINT32\t\t\t\t\tu4EnableFeature = 0;\n'
            '\tUINT16\t\t\t\t\tucTLVNumber = 0;\n'
            '\tUINT16\t\t\t\t\tu2Len = 0;\n'
            '\tUINT32\t\t\t\t\t*pRspPayload = NULL;\n'
            '\tP_CMD_WTBL_GENERIC_TLV_T\tpWtblGenericTlv = NULL;\n'
            '\tUINT16\t\t\t\t\tucRemainingTLVNumber = 0;\n'
            '\tUINT32\t\t\t\t\tu4RemainingTLVBufLen = 0;\n'
            '\tPUCHAR\t\t\t\t\tTempBuffer = (PUCHAR)pBuffer;\n'
            '\tstruct _CMD_ATTRIBUTE attr = {0};\n'
            '\tUCHAR payload[MAX_BUF_SIZE_OF_WTBL_INFO + 100 - sizeof(CMD_WTBL_UPDATE_T)];\n'
            '\tUINT16 tlv_length;\n'
            '\n'
            '\t/* Validate every byte before allocating, casting a payload or adding the\n'
            '\t * command/response headers.  Preserve the existing query/DUMP capacity. */\n'
            '\tif (!pAd || ucOperation < RESET_WTBL_AND_SET || ucOperation > RESET_ALL_WTBL ||\n'
            '\t\tu4BufferLen > MAX_BUF_SIZE_OF_WTBL_INFO + 100 - sizeof(CMD_WTBL_UPDATE_T) ||\n'
            '\t\tu4BufferLen > 0xffffU - 20 - sizeof(CMD_WTBL_UPDATE_T))\n'
            '\t\treturn NDIS_STATUS_INVALID_DATA;\n'
            '\tif (ucOperation == RESET_ALL_WTBL) {\n'
            '\t\tif (pBuffer || u4BufferLen)\n'
            '\t\t\treturn NDIS_STATUS_INVALID_DATA;\n'
            '\t} else if (!pBuffer) {\n'
            '\t\tif (u4BufferLen || ucOperation != RESET_WTBL_AND_SET)\n'
            '\t\t\treturn NDIS_STATUS_INVALID_DATA;\n'
            '\t} else if (!u4BufferLen)\n'
            '\t\treturn NDIS_STATUS_INVALID_DATA;\n'
            '\n'
            '\tif (u4BufferLen)\n'
            '\t\tos_move_mem(payload, pBuffer, u4BufferLen);\n'
            '\tRet = wtbl_tlv_validate(payload, u4BufferLen, FALSE, NULL,\n'
            '\t\t&ucTLVNumber, &u4EnableFeature);\n'
            '\tif (Ret != NDIS_STATUS_SUCCESS)\n'
            '\t\treturn Ret;\n'
            '\n'
            '\tmsg = AndesAllocCmdMsg(pAd, sizeof(CMD_WTBL_UPDATE_T) + u4BufferLen);\n'
            '\tif (!msg) {\n'
            '\t\tRet = NDIS_STATUS_RESOURCES;\n'
            '\t\tgoto Error0;\n'
            '\t}\n'
            '\n'
            '\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t ("%s, ucTLVNumber = %d\\n", __func__, ucTLVNumber));\n'
            '\t/* Assign vlaue to related parameters */\n'
            '\tTempBuffer = payload;\n'
            '\tucRemainingTLVNumber = ucTLVNumber;\n'
            '\tu4RemainingTLVBufLen = u4BufferLen;\n'
            '\n'
            '\t/* Set correct length and RspPayload buffer with different operation */\n'
            '\tu2Len = sizeof(EVENT_EXT_CMD_RESULT_T);\n'
            '\tif (ucOperation == QUERY_WTBL) {\n'
            '\t\tu2Len = u4BufferLen + 20 + sizeof(CMD_WTBL_UPDATE_T);\n'
            '\t\tpRspPayload = (UINT32 *)pBuffer;\n'
            '\t}\n'
            '\n'
            '\tSET_CMD_ATTR_MCU_DEST(attr, HOST2N9);\n'
            '\tSET_CMD_ATTR_TYPE(attr, EXT_CID);\n'
            '\tSET_CMD_ATTR_EXT_TYPE(attr, EXT_CMD_ID_WTBL_UPDATE);\n'
            '\tSET_CMD_ATTR_CTRL_FLAGS(attr, INIT_CMD_SET_AND_WAIT_RETRY_RSP);\n'
            '\tSET_CMD_ATTR_RSP_WAIT_MS_TIME(attr, 0);\n'
            '\tSET_CMD_ATTR_RSP_EXPECT_SIZE(attr, u2Len);\n'
            '\tSET_CMD_ATTR_RSP_WB_BUF_IN_CALBK(attr, pRspPayload);\n'
            '\tSET_CMD_ATTR_RSP_HANDLER(attr, CmdExtWtblUpdateCb);\n'
            '\tAndesInitCmdMsg(msg, attr);\n'
            '\tmsg->wtbl_rsp_capacity = (ucOperation == QUERY_WTBL) ? u4BufferLen : 0;\n'
            '\tCmdWtblUpdate.ucWlanIdx = ucWlanIdx;\n'
            '\tCmdWtblUpdate.ucOperation = ucOperation;\n'
            '\tCmdWtblUpdate.u2TotalElementNum = cpu2le16(ucTLVNumber);\n'
            '\tAndesAppendCmdMsg(msg, (char *)&CmdWtblUpdate, sizeof(CMD_WTBL_UPDATE_T));\n'
            '\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t ("%s, ucWlanIdx = %d, ucOperation = %d, u4EnableFeature = 0x%x\\n",\n'
            '\t\t\t  __func__, ucWlanIdx, ucOperation, u4EnableFeature));\n'
            '\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t ("%s, ucRemainingTLVNumber = %d, u2RemainingTLVBufLen = %d\\n",\n'
            '\t\t\t  __func__, ucRemainingTLVNumber, u4RemainingTLVBufLen));\n'
            '\n'
            '\t/* Handle TVL request here */\n'
            '\twhile ((ucRemainingTLVNumber > 0) && (u4RemainingTLVBufLen > 0)) {\n'
            '\t\t/* The complete validated snapshot is private, including endian conversion. */\n'
            '\t\tos_move_mem(&tlv_length, TempBuffer + sizeof(UINT16), sizeof(tlv_length));\n'
            '\t\tpWtblGenericTlv = (P_CMD_WTBL_GENERIC_TLV_T)TempBuffer;\n'
            '\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t ("%s, TLV(%d, %d)\\n", __func__,\n'
            '\t\t\t\t  pWtblGenericTlv->u2Tag, pWtblGenericTlv->u2Length));\n'
            '\n'
            '\t\t/* Handle this TLV */\n'
            '\t\tswitch (pWtblGenericTlv->u2Tag) {\n'
            '\t\t/* Tag = 0 */\n'
            '\t\tcase WTBL_GENERIC: {\n'
            '\t\t\tP_CMD_WTBL_GENERIC_T pCmdWtblGeneric =\n'
            '\t\t\t\t(P_CMD_WTBL_GENERIC_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_GENERIC), ucMUARIndex = %d, ucSkipTx = %d,ucCfAck = %d, ucQos = %d, '
            'ucQos = %d, ucAdm = %d, PartialAID = %d, aucPeerAddress(%02x:%02x:%02x:%02x:%02x:%02x)\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblGeneric->ucMUARIndex,\n'
            '\t\t\t\t\t\t  pCmdWtblGeneric->ucSkipTx,\n'
            '\t\t\t\t\t\t  pCmdWtblGeneric->ucCfAck,\n'
            '\t\t\t\t\t\t  pCmdWtblGeneric->ucQos,\n'
            '\t\t\t\t\t\t  pCmdWtblGeneric->ucMesh,\n'
            '\t\t\t\t\t\t  pCmdWtblGeneric->ucAdm,\n'
            '\t\t\t\t\t\t  pCmdWtblGeneric->u2PartialAID,\n'
            '\t\t\t\t\t\t  PRINT_MAC(pCmdWtblGeneric->aucPeerAddress)));\n'
            '#ifdef RT_BIG_ENDIAN\n'
            '\t\t\t\tpCmdWtblGeneric->u2PartialAID = cpu2le16(pCmdWtblGeneric->u2PartialAID);\n'
            '#endif\n'
            '\t\t\t} else if (ucOperation == QUERY_WTBL) {\n'
            '\t\t\t\t/* No need to fill real parameters when query and\n'
            '\t\t\t\t  *\tjust append all zero data buffer to msg\n'
            '\t\t\t\t  */\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 1 */\n'
            '\t\tcase WTBL_RX: {\n'
            '\t\t\tP_CMD_WTBL_RX_T\tpCmdWtblRx = (P_CMD_WTBL_RX_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_RX), ucRcid = %d, ucRca1 = %d, ucRca2 = %d, ucRv = %d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblRx->ucRcid,\n'
            '\t\t\t\t\t\t  pCmdWtblRx->ucRca1,\n'
            '\t\t\t\t\t\t  pCmdWtblRx->ucRca2,\n'
            '\t\t\t\t\t\t  pCmdWtblRx->ucRv));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 2 */\n'
            '\t\tcase WTBL_HT: {\n'
            '\t\t\tP_CMD_WTBL_HT_T pCmdWtblHt = (P_CMD_WTBL_HT_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_HT), ucHt = %d, ucLdpc = %d, ucAf = %d, ucMm = %d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblHt->ucHt,\n'
            '\t\t\t\t\t\t  pCmdWtblHt->ucLdpc,\n'
            '\t\t\t\t\t\t  pCmdWtblHt->ucAf,\n'
            '\t\t\t\t\t\t  pCmdWtblHt->ucMm));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 3 */\n'
            '\t\tcase WTBL_VHT: {\n'
            '\t\t\tP_CMD_WTBL_VHT_T pCmdWtblVht = (P_CMD_WTBL_VHT_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_VHT), ucLdpcVht = %d, ucDynBw= %d, ucVht = %d, ucTxopPsCap = %d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblVht->ucLdpcVht,\n'
            '\t\t\t\t\t\t  pCmdWtblVht->ucDynBw,\n'
            '\t\t\t\t\t\t  pCmdWtblVht->ucVht,\n'
            '\t\t\t\t\t\t  pCmdWtblVht->ucTxopPsCap));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 4 */\n'
            '\t\tcase WTBL_PEER_PS: {\n'
            '\t\t\tP_CMD_WTBL_PEER_PS_T pCmdWtblPerPs =\n'
            '\t\t\t\t(P_CMD_WTBL_PEER_PS_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_PEER_PS), ucDuIPsm = %d, ucIPsm = %d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblPerPs->ucDuIPsm,\n'
            '\t\t\t\t\t\t  pCmdWtblPerPs->ucIPsm));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 5 */\n'
            '\t\tcase WTBL_TX_PS: {\n'
            '\t\t\tP_CMD_WTBL_TX_PS_T\tpCmdWtbTxPs = (P_CMD_WTBL_TX_PS_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_TX_PS), ucTxPs = %d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtbTxPs->ucTxPs));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 6 */\n'
            '\t\tcase WTBL_HDR_TRANS: {\n'
            '\t\t\tP_CMD_WTBL_HDR_TRANS_T\tpCmdWtblHdrTrans =\n'
            '\t\t\t\t(P_CMD_WTBL_HDR_TRANS_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_HDR_TRANS), ucTd = %d, ucFd = %d, ucDisRhtr =%d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblHdrTrans->ucTd,\n'
            '\t\t\t\t\t\t  pCmdWtblHdrTrans->ucFd,\n'
            '\t\t\t\t\t\t  pCmdWtblHdrTrans->ucDisRhtr));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 7 */\n'
            '\t\tcase WTBL_SECURITY_KEY: {\n'
            '\t\t\tP_CMD_WTBL_SECURITY_KEY_T pCmdWtblSecurityKey =\n'
            '\t\t\t\t(P_CMD_WTBL_SECURITY_KEY_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_SECURITY_KEY), ucAddRemove = %d, ucRkv = %d, ucIkv =%d, ucAlgorithmId = '
            '%d, ucKeyId = %d, ucKeyLen = %d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblSecurityKey->ucAddRemove,\n'
            '\t\t\t\t\t\t  pCmdWtblSecurityKey->ucRkv,\n'
            '\t\t\t\t\t\t  pCmdWtblSecurityKey->ucIkv,\n'
            '\t\t\t\t\t\t  pCmdWtblSecurityKey->ucAlgorithmId,\n'
            '\t\t\t\t\t\t  pCmdWtblSecurityKey->ucKeyId,\n'
            '\t\t\t\t\t\t  pCmdWtblSecurityKey->ucKeyLen));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 8 */\n'
            '\t\tcase WTBL_BA: {\n'
            '\t\t\tP_CMD_WTBL_BA_T pCmdWtblBa = (P_CMD_WTBL_BA_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tif (pCmdWtblBa->ucBaSessionType == BA_SESSION_RECP) {\n'
            '\t\t\t\t\t/* Recipient */\n'
            '\t\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t\t ("%s(WTBL_BA, Recipient), ucTid(%d), ucBaSessionType(%d), ucRstBaTid(%d), '
            'ucRstBaSel(%d), ucStartRstBaSb(%d), aucPeerAddress(%02x:%02x:%02x:%02x:%02x:%02x)\\n",\n'
            '\t\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t\t  pCmdWtblBa->ucTid,\n'
            '\t\t\t\t\t\t\t  pCmdWtblBa->ucBaSessionType,\n'
            '\t\t\t\t\t\t\t  pCmdWtblBa->ucRstBaTid,\n'
            '\t\t\t\t\t\t\t  pCmdWtblBa->ucRstBaSel,\n'
            '\t\t\t\t\t\t\t  pCmdWtblBa->ucStartRstBaSb,\n'
            '\t\t\t\t\t\t\t  PRINT_MAC(pCmdWtblBa->aucPeerAddress)));\n'
            '\t\t\t\t} else {\n'
            '\t\t\t\t\t/* Originator */\n'
            '\t\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t\t ("%s(WTBL_BA, Originator), ucTid(%d), u2Sn(%d), ucBaEn(%d), ucBaSize(%d)\\n",\n'
            '\t\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t\t  pCmdWtblBa->ucTid,\n'
            '\t\t\t\t\t\t\t  pCmdWtblBa->u2Sn,\n'
            '\t\t\t\t\t\t\t  pCmdWtblBa->ucBaEn,\n'
            '\t\t\t\t\t\t\t  pCmdWtblBa->ucBaSize));\n'
            '\t\t\t\t}\n'
            '\t\t\t}\n'
            '#ifdef RT_BIG_ENDIAN\n'
            '\t\t\tpCmdWtblBa->u2Sn = cpu2le16(pCmdWtblBa->u2Sn);\n'
            '#endif\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 9 */\n'
            '\t\tcase WTBL_RDG: {\n'
            '\t\t\tP_CMD_WTBL_RDG_T\tpCmdWtblRdg = (P_CMD_WTBL_RDG_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_RDG), ucRdgBa = %d, ucR = %d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblRdg->ucRdgBa,\n'
            '\t\t\t\t\t\t  pCmdWtblRdg->ucR));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 10 */\n'
            '\t\tcase WTBL_PROTECTION: {\n'
            '\t\t\tP_CMD_WTBL_PROTECTION_T\tpCmdWtblProtection =\n'
            '\t\t\t\t(P_CMD_WTBL_PROTECTION_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_PROTECTION), ucRts = %d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblProtection->ucRts));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 11 */\n'
            '\t\tcase WTBL_CLEAR: {\n'
            '\t\t\t/* bit 0: Clear PSM (WF_WTBLON: 0x60322300, Bit 31 set 1 then set 0) */\n'
            '\t\t\t/* bit 1: Clear BA (WTBL2.DW15) */\n'
            '\t\t\t/* bit 2: Clear Rx Counter (6019_00002, bit 14) */\n'
            '\t\t\t/* bit 3: Clear Tx Counter (6019_0000, bit 15) */\n'
            '\t\t\t/* bit 4: Clear ADM Counter (6019_0000, bit 12) */\n'
            '\t\t\t/* bit 5: Clear Cipher key (WTBL3)*/\n'
            '\t\t\tP_CMD_WTBL_CLEAR_T\tpCmdWtblClear = (P_CMD_WTBL_CLEAR_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_CLEAR), ucClear = %x\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblClear->ucClear));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 12 */\n'
            '\t\tcase WTBL_BF: {\n'
            '\t\t\tP_CMD_WTBL_BF_T\t\tpCmdWtblBf = (P_CMD_WTBL_BF_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO, ("%s(WTBL_BF), ucTiBf = %d, ucTeBf = '
            '%d, ucTibfVh = %d, ucTebfVht = %d, ucGid = %d, ucPfmuIdx = %d\\n",\n'
            '\t\t\t\t\t\t __func__,\n'
            '\t\t\t\t\t\t pCmdWtblBf->ucTiBf,\n'
            '\t\t\t\t\t\t pCmdWtblBf->ucTeBf,\n'
            '\t\t\t\t\t\t pCmdWtblBf->ucTibfVht,\n'
            '\t\t\t\t\t\t pCmdWtblBf->ucTebfVht,\n'
            '\t\t\t\t\t\t pCmdWtblBf->ucGid,\n'
            '\t\t\t\t\t\t pCmdWtblBf->ucPFMUIdx));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 13 */\n'
            '\t\tcase WTBL_SMPS: {\n'
            '\t\t\tP_CMD_WTBL_SMPS_T pCmdWtblSmPs = (P_CMD_WTBL_SMPS_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_SMPS), ucSmPs = %d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  pCmdWtblSmPs->ucSmPs));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 14 */\n'
            '\t\tcase WTBL_RAW_DATA_RW: {\n'
            '\t\t\tP_CMD_WTBL_RAW_DATA_RW_T pCmdWtblRawDataRw =\n'
            '\t\t\t\t(P_CMD_WTBL_RAW_DATA_RW_T)TempBuffer;\n'
            '\t\t\t/* Print argumrnts */\n'
            '\t\t\tMTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t ("%s(WTBL_RAW_DATA_RW), ucWtblIdx = %d, ucWhichDW = %d, u4DwMask = 0x%x, u4DwValue = '
            '0x%x\\n",\n'
            '\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t  pCmdWtblRawDataRw->ucWtblIdx,\n'
            '\t\t\t\t\t  pCmdWtblRawDataRw->ucWhichDW,\n'
            '\t\t\t\t\t  pCmdWtblRawDataRw->u4DwMask,\n'
            '\t\t\t\t\t  pCmdWtblRawDataRw->u4DwValue));\n'
            '#ifdef RT_BIG_ENDIAN\n'
            '\t\t\tpCmdWtblRawDataRw->u4DwMask = cpu2le32(pCmdWtblRawDataRw->u4DwMask);\n'
            '\t\t\tpCmdWtblRawDataRw->u4DwValue = cpu2le32(pCmdWtblRawDataRw->u4DwValue);\n'
            '#endif\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 15 */\n'
            '\t\tcase WTBL_DUMP: {\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t\t ("%s(WTBL_DUMP), WTBL_BUFFER_SIZE = %d\\n",\n'
            '\t\t\t\t\t\t  __func__,\n'
            '\t\t\t\t\t\t  WTBL_BUFFER_SIZE));\n'
            '\t\t\t\t/* Fill value  format */\n'
            '\t\t\t\t/* No need to fill this argument */\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Tag = 16 */\n'
            '\t\tcase WTBL_SPE: {\n'
            '\t\t\tP_CMD_WTBL_SPE_T\t\tpCmdWtblSpe = (P_CMD_WTBL_SPE_T)TempBuffer;\n'
            '\n'
            '\t\t\tif ((ucOperation == RESET_WTBL_AND_SET) || (ucOperation == SET_WTBL)) {\n'
            '\t\t\t\t/* Print argumrnts */\n'
            '\t\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO, ("%s(WTBL_BF), ucSpeIdx = %d\\n",\n'
            '\t\t\t\t\t\t __func__,\n'
            '\t\t\t\t\t\t pCmdWtblSpe->ucSpeIdx));\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\n'
            '\t\tdefault: {\n'
            '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t\t ("%s, Unknown WTBL TLV Tag(%d)\\n",\n'
            '\t\t\t\t\t  __func__, pWtblGenericTlv->u2Tag));\n'
            '\t\t\tbreak;\n'
            '\t\t}\n'
            '\t\t}\n'
            '\n'
            '\t\t/* Advance to next TLV */\n'
            '\t\tTempBuffer += tlv_length;\n'
            '\t\tu4RemainingTLVBufLen -= tlv_length;\n'
            '\t\tucRemainingTLVNumber--;\n'
            '#ifdef RT_BIG_ENDIAN\n'
            '\t\tpWtblGenericTlv->u2Length = cpu2le16(pWtblGenericTlv->u2Length);\n'
            '\t\tpWtblGenericTlv->u2Tag = cpu2le16(pWtblGenericTlv->u2Tag);\n'
            '#endif\n'
            '\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t\t ("%s in while loop, ucRemainingTLVNumber = %d, u2RemainingTLVBufLen = %d\\n",\n'
            '\t\t\t\t  __func__,\n'
            '\t\t\t\t  ucRemainingTLVNumber, u4RemainingTLVBufLen));\n'
            '\t}\n'
            '\n'
            '\tAndesAppendCmdMsg(msg, (char *)payload, u4BufferLen);\n'
            '\t/* Send out CMD */\n'
            '\tRet = AndesSendCmdMsg(pAd, msg);\n'
            '\tgoto Success;\n'
            'Success:\n'
            'Error0:\n'
            '\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
            '\t\t\t ("%s:(Ret = %d)\\n", __func__, Ret));\n'
            '\treturn Ret;\n'
            '}\n'
            'UINT32 WtblDwQuery(RTMP_ADAPTER *pAd, UINT8 ucWlanIdx,\n'
            '\t\t\t\t   UINT8 ucWtbl1234, UINT8 ucWhichDW)\n'
            '{\n'
            '\tCMD_WTBL_RAW_DATA_RW_T\trWtblRawDataRwWtblDw = {0};\n'
            '\n'
            '\trWtblRawDataRwWtblDw.u2Tag = WTBL_RAW_DATA_RW;\n'
            '\trWtblRawDataRwWtblDw.u2Length = sizeof(CMD_WTBL_RAW_DATA_RW_T);\n'
            '\trWtblRawDataRwWtblDw.ucWtblIdx = ucWtbl1234;\n'
            '\trWtblRawDataRwWtblDw.ucWhichDW = ucWhichDW;\n'
            '\tCmdExtWtblUpdate(pAd, ucWlanIdx, QUERY_WTBL, &rWtblRawDataRwWtblDw,\n'
            '\t\t\t\t\t rWtblRawDataRwWtblDw.u2Length);\n'
            '\treturn rWtblRawDataRwWtblDw.u4DwValue;\n'
            '}\n',
 'wtbl_core': 'struct cmd_msg *AndesAllocCmdMsg(RTMP_ADAPTER *ad, unsigned int length)\n'
              '{\n'
              '\tstruct cmd_msg *msg = NULL;\n'
              '\tRTMP_CHIP_CAP *cap = hc_get_chip_cap(ad->hdev_ctrl);\n'
              '\tstruct MCU_CTRL *ctl = &ad->MCUCtrl;\n'
              '\tPNDIS_PACKET net_pkt = NULL;\n'
              '\tINT32 AllocateSize = cap->cmd_header_len + length + cap->cmd_padding_len;\n'
              '\tnet_pkt = RTMP_AllocateFragPacketBuffer(ad, AllocateSize);\n'
              '\n'
              '\tif (!net_pkt) {\n'
              '\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t ("can not allocate net_pkt\\n"));\n'
              '\t\tgoto error0;\n'
              '\t}\n'
              '\n'
              '\tOS_PKT_RESERVE(net_pkt, cap->cmd_header_len);\n'
              '\tos_alloc_mem(NULL, (PUCHAR *)&msg, sizeof(*msg));\n'
              '\n'
              '\tif (!msg) {\n'
              '\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t ("can not allocate cmd msg\\n"));\n'
              '\t\tgoto error1;\n'
              '\t}\n'
              '\n'
              '\tCMD_MSG_CB(net_pkt)->msg = msg;\n'
              '\tos_zero_mem(msg, sizeof(*msg));\n'
              '\tmsg->priv = (void *)ad;\n'
              '\tmsg->net_pkt = net_pkt;\n'
              '\tctl->alloc_cmd_msg++;\n'
              '\treturn msg;\n'
              '\n'
              'error1:\n'
              '\tRTMPFreeNdisPacket(ad, net_pkt);\n'
              'error0:\n'
              '\treturn NULL;\n'
              '}\n'
              'VOID AndesAppendCmdMsg(struct cmd_msg *msg, char *data, unsigned int len)\n'
              '{\n'
              '\tPNDIS_PACKET net_pkt;\n'
              '\n'
              '\tif (!msg)\n'
              '\t\treturn;\n'
              '\n'
              '\tnet_pkt = msg->net_pkt;\n'
              '\n'
              '\tif (data)\n'
              '\t\tmemcpy(OS_PKT_TAIL_BUF_EXTEND(net_pkt, len), data, len);\n'
              '}\n'
              'VOID AndesInitCmdMsg(struct cmd_msg *msg, CMD_ATTRIBUTE attr)\n'
              '{\n'
              '\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
              '\t\t\t ("%s:: mcu_dest(%d), cmd_type(0x%x), ExtCmdType(0x%x)\\n",\n'
              '\t\t\t  __func__, attr.mcu_dest, attr.type, attr.ext_type));\n'
              '\tSET_CMD_MSG_PORT_QUEUE_ID(msg, GetRealPortQueueID(msg, attr.type));\n'
              '\tSET_CMD_MSG_MCU_DEST(msg, attr.mcu_dest);\n'
              '\tSET_CMD_MSG_TYPE(msg, attr.type);\n'
              '\tSET_CMD_MSG_CTRL_FLAGS(msg, attr.ctrl.flags);\n'
              '\tSET_CMD_MSG_EXT_TYPE(msg, attr.ext_type);\n'
              '\tSET_CMD_MSG_CTRL_RSP_WAIT_MS_TIME(msg, attr.ctrl.wait_ms_time);\n'
              '\n'
              '\tif (IS_CMD_MSG_NEED_SYNC_WITH_FW_FLAG_SET(msg))\n'
              '\t\tRTMP_OS_INIT_COMPLETION(&msg->ack_done);\n'
              '\n'
              '\tSET_CMD_MSG_RETRY_TIMES(msg, 0);\n'
              '\tSET_CMD_MSG_CTRL_RSP_EXPECT_SIZE(msg, attr.ctrl.expect_size);\n'
              '\tSET_CMD_MSG_RSP_WB_BUF_IN_CALBK(msg, attr.rsp.wb_buf_in_calbk);\n'
              '\tSET_CMD_MSG_RSP_HANDLER(msg, attr.rsp.handler);\n'
              '}\n'
              'INT32 AndesSendCmdMsg(PRTMP_ADAPTER ad, struct cmd_msg *msg)\n'
              '{\n'
              '\tstruct MCU_CTRL *ctl = &ad->MCUCtrl;\n'
              '\tBOOLEAN is_cmd_need_wait = IS_CMD_MSG_NEED_SYNC_WITH_FW_FLAG_SET(msg);\n'
              '\tint ret = NDIS_STATUS_SUCCESS;\n'
              '#ifdef CONFIG_RECOVERY_ON_INTERRUPT_MISS\n'
              '#ifdef INTELP6_SUPPORT\n'
              '\tstruct _RTMP_CHIP_OP *ops = hc_get_chip_ops(ad->hdev_ctrl);\n'
              '#endif\n'
              '#endif\n'
              '\n'
              '\t/* These Wsys commands require an explicit valid firmware acknowledgement. */\n'
              '\tif (msg->attr.ext_type == EXT_CMD_STAREC_UPDATE ||\n'
              '\t\tmsg->attr.ext_type == EXT_CMD_ID_DEVINFO_UPDATE ||\n'
              '\t\tmsg->attr.ext_type == EXT_CMD_ID_BSSINFO_UPDATE ||\n'
              '\t\tmsg->attr.ext_type == EXT_CMD_ID_WTBL_UPDATE)\n'
              '\t\tmsg->cmd_return_status = NDIS_STATUS_FAILURE;\n'
              '\n'
              '\t/* The send API consumes an unqueued message on every admission failure. */\n'
              '\tif (RtmpDmaStopping(ad)) {\n'
              '\t\tAndesForceFreeCmdMsg(msg);\n'
              '\t\treturn NDIS_STATUS_FAILURE;\n'
              '\t}\n'
              '\tif (in_interrupt() && IS_CMD_MSG_NEED_SYNC_WITH_FW_FLAG_SET(msg)) {\n'
              '\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t ("BUG: %s is called from invalid context\\n",\n'
              '\t\t\t\t  __func__));\n'
              '\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t ("%s: Command type = %x, Extension command type = %x\\n",\n'
              '\t\t\t\t  __func__, msg->attr.type, msg->attr.ext_type));\n'
              '\t\tAndesForceFreeCmdMsg(msg);\n'
              '\t\treturn NDIS_STATUS_FAILURE;\n'
              '\t}\n'
              '\n'
              '\tif (!RTMP_TEST_FLAG(ad, fRTMP_ADAPTER_MCU_SEND_IN_BAND_CMD)     ||\n'
              '\t\tRTMP_TEST_FLAG(ad, fRTMP_ADAPTER_NIC_NOT_EXIST)         ||\n'
              '\t\tRTMP_TEST_FLAG(ad, fRTMP_ADAPTER_SUSPEND)) {\n'
              '\t\tif (!RTMP_TEST_FLAG(ad, fRTMP_ADAPTER_MCU_SEND_IN_BAND_CMD)) {\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("%s: Could not send in band command due to '
              'diablefRTMP_ADAPTER_MCU_SEND_IN_BAND_CMD\\n",\n'
              '\t\t\t\t\t  __func__));\n'
              '\t\t} else if (RTMP_TEST_FLAG(ad, fRTMP_ADAPTER_NIC_NOT_EXIST)) {\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("%s: Could not send in band command due to fRTMP_ADAPTER_NIC_NOT_EXIST\\n",\n'
              '\t\t\t\t\t  __func__));\n'
              '\t\t} else if (RTMP_TEST_FLAG(ad, fRTMP_ADAPTER_SUSPEND)) {\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("%s: Could not send in band command due to fRTMP_ADAPTER_SUSPEND\\n",\n'
              '\t\t\t\t\t  __func__));\n'
              '\t\t}\n'
              '\n'
              '\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t ("%s: Command type = %x, Extension command type = %x\\n",\n'
              '\t\t\t\t  __func__, msg->attr.type, msg->attr.ext_type));\n'
              '\n'
              '\t\tAndesForceFreeCmdMsg(msg);\n'
              '\t\treturn NDIS_STATUS_FAILURE;\n'
              '\t}\n'
              '\n'
              '#ifdef DBG_STARVATION\n'
              '\tstarv_dbg_init(&ctl->block, &msg->starv);\n'
              '\tstarv_dbg_get(&msg->starv);\n'
              '#endif /*DBG_STARVATION*/\n'
              '\tAndesQueueTailCmdMsg(&ctl->txq, msg, tx_start);\n'
              'retransmit:\n'
              '\n'
              '\t/* The caller kicks only its own queued message.  Synchronous failures\n'
              '\t * complete its waiting object; an error after publication retains the\n'
              '\t * ack/ring owner until completion or controller cleanup.\n'
              '\t */\n'
              '\tret = AndesDequeueAndKickOutCmdMsgs(ad, msg);\n'
              '\n'
              '\t/* Wait for response */\n'
              '\tif (is_cmd_need_wait) {\n'
              '\t\tenum cmd_msg_state state = 0;\n'
              '\t\tULONG IsComplete;\n'
              '\n'
              '\t\tIsComplete = AndesWaitForCompleteTimeout(msg, msg->attr.ctrl.wait_ms_time);\n'
              '\n'
              '\t\tif (!OS_TEST_BIT(MCU_INIT, &ctl->flags)) {\n'
              '\t\t\t/*If need wait, clean up will trigger complete for here to free msg*/\n'
              '\t\t\tret = NDIS_STATUS_FAILURE;\n'
              '\t\t\tif (msg->state == tx_kickout_fail)\n'
              '\t\t\t\tAndesForceFreeCmdMsg(msg);\n'
              '\t\t\telse {\n'
              '\t\t\t\tAndesTakeQueuedCmdMsg(ctl, &ctl->ackq, msg);\n'
              '\t\t\t\tAndesFreeCmdMsg(msg);\n'
              '\t\t\t}\n'
              '\t\t\tgoto bailout;\n'
              '\t\t}\n'
              '\n'
              '\t\tif (!IsComplete) {\n'
              '\t\t\tret = NDIS_STATUS_FAILURE;\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("FWCmdTimeout: command (%x), ext_cmd_type (%x), seq(%d), timeout(%dms)\\n",\n'
              '\t\t\t\t\t  msg->attr.type, msg->attr.ext_type,\n'
              '\t\t\t\t\t  msg->seq,\n'
              '\t\t\t\t\t  (msg->attr.ctrl.wait_ms_time == 0) ?\n'
              '\t\t\t\t\t  CMD_MSG_TIMEOUT : msg->attr.ctrl.wait_ms_time));\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("pAd->Flags  = 0x%.8lx\\n", ad->Flags));\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("txq qlen = %d\\n", AndesQueueLen(ctl, &ctl->txq)));\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("rxq qlen = %d\\n", AndesQueueLen(ctl, &ctl->rxq)));\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("kickq qlen = %d\\n", AndesQueueLen(ctl, &ctl->kickq)));\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("ackq qlen = %d\\n", AndesQueueLen(ctl, &ctl->ackq)));\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("tx_doneq.qlen = %d\\n", AndesQueueLen(ctl, &ctl->tx_doneq)));\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("rx_done qlen = %d\\n", AndesQueueLen(ctl, &ctl->rx_doneq)));\n'
              '\n'
              '\t\t\tif (msg->state == wait_cmd_out_and_ack) {\n'
              '\t\t\t\tAndesTakeQueuedCmdMsg(ctl, &ctl->ackq, msg);\n'
              '\t\t\t} else if (msg->state == wait_ack)\n'
              '\t\t\t\tAndesTakeQueuedCmdMsg(ctl, &ctl->ackq, msg);\n'
              '\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("%s: msg state = %d\\n", __func__, msg->state));\n'
              '\t\t\tAndesIncErrorCount(ctl, error_tx_timeout_fail);\n'
              '\t\t\tstate = tx_timeout_fail;\n'
              '\n'
              '\t\t\tif (msg->retry_times > 0)\n'
              '\t\t\t\tmsg->retry_times--;\n'
              '\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t\t ("msg->retry_times = %d\\n", msg->retry_times));\n'
              '#ifdef CONFIG_RECOVERY_ON_INTERRUPT_MISS\n'
              '#ifdef INTELP6_SUPPORT\n'
              '\t\t\t/* To many continuous soft reboot on puma6 plateform make HW to go in unstabe state '
              'and\n'
              '\t\t\t * driver fails to communicate with FW\n'
              '\t\t\t*/\n'
              '\t\t\tad->ErrRecoveryCheck++;\n'
              '\t\t\tif (ops->heart_beat_check)\n'
              '\t\t\t\tops->heart_beat_check(ad);\n'
              '\t\t\tif (RTMP_TEST_FLAG(ad, fRTMP_ADAPTER_INTERRUPT_ACTIVE)) {\n'
              '\t\t\t\tMTWF_LOG(DBG_CAT_HIF, CATHIF_PCI, DBG_LVL_OFF, ("Disabling interrupt\\n"));\n'
              '\t\t\t\tRTMP_ASIC_INTERRUPT_DISABLE(ad);\n'
              '\t\t\t}\n'
              '\t\t\tMTWF_LOG(DBG_CAT_HIF, CATHIF_PCI, DBG_LVL_OFF, ("Enabling interrupt\\n"));\n'
              '\t\t\tRTMP_ASIC_INTERRUPT_ENABLE(ad);\n'
              '#else\n'
              '\t\t\tASSERT(FALSE);\n'
              '#endif\n'
              '#else\n'
              '\t\t\tASSERT(FALSE);\n'
              '#endif\n'
              '\t\t} else {\n'
              '\t\t\tif (msg->state == tx_kickout_fail) {\n'
              '\t\t\t\tret = NDIS_STATUS_FAILURE;\n'
              '\t\t\t\tstate = tx_kickout_fail;\n'
              '\t\t\t\tif (msg->retry_times > 0)\n'
              '\t\t\t\t\tmsg->retry_times--;\n'
              '\t\t\t} else {\n'
              '\t\t\t\tret = NDIS_STATUS_SUCCESS;\n'
              '\t\t\t\tif (msg->state == wait_cmd_out_and_ack) {\n'
              '\t\t\t\t\tAndesTakeQueuedCmdMsg(ctl, &ctl->ackq, msg);\n'
              '\t\t\t\t} else if (msg->state == wait_ack)\n'
              '\t\t\t\t\tAndesTakeQueuedCmdMsg(ctl, &ctl->ackq, msg);\n'
              '\n'
              '\t\t\t\tstate = tx_done;\n'
              '\t\t\t\tmsg->retry_times = 0;\n'
              '\t\t\t}\n'
              '\t\t}\n'
              '\n'
              '\t\tif (RtmpDmaStopping(ad))\n'
              '\t\t\tmsg->retry_times = 0;\n'
              '\t\t/* A failed clone cannot supply a retransmission packet. */\n'
              '\t\tif (is_cmd_need_wait && (msg->retry_times > 0) && msg->retry_pkt) {\n'
              '\t\t\tif (state == tx_kickout_fail)\n'
              '\t\t\t\tRTMPFreeNdisPacket(ad, msg->net_pkt);\n'
              '\t\t\tRTMP_OS_EXIT_COMPLETION(&msg->ack_done);\n'
              '\t\t\tRTMP_OS_INIT_COMPLETION(&msg->ack_done);\n'
              '\t\t\tmsg->net_pkt = msg->retry_pkt;\n'
              '\t\t\tmsg->retry_pkt = NULL;\n'
              '\t\t\tstate = tx_retransmit;\n'
              '\t\t\tAndesQueueHeadCmdMsg(&ctl->txq, msg, state);\n'
              '\t\t\tgoto retransmit;\n'
              '\t\t} else {\n'
              '\t\t\t/* No ring owns an unpublished packet.  Its waiting sender\n'
              '\t\t\t * consumes both packet and any unused retry clone exactly once.\n'
              '\t\t\t */\n'
              '\t\t\tif (state == tx_kickout_fail) {\n'
              '\t\t\t\tAndesForceFreeCmdMsg(msg);\n'
              '\t\t\t\tgoto bailout;\n'
              '\t\t\t}\n'
              '\t\t\tif (ret == NDIS_STATUS_SUCCESS &&\n'
              '\t\t\t\t(msg->attr.ext_type == EXT_CMD_STAREC_UPDATE ||\n'
              '\t\t\t\t msg->attr.ext_type == EXT_CMD_ID_DEVINFO_UPDATE ||\n'
              '\t\t\t\t msg->attr.ext_type == EXT_CMD_ID_BSSINFO_UPDATE ||\n'
              '\t\t\t\t msg->attr.ext_type == EXT_CMD_ID_WTBL_UPDATE)) {\n'
              '\t\t\t\t/* Preserve firmware rejection and malformed/missing response errors. */\n'
              '\t\t\t\tret = msg->cmd_return_status;\n'
              '\t\t\t}\n'
              '\n'
              '\t\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_INFO,\n'
              '\t\t\t\t\t ("%s: msg state = %d\\n", __func__, state));\n'
              "\t\t\t/* msg will be free after enqueuing to tx_doneq. So msg is not able to pass FW's "
              'response to caller. */\n'
              '\t\t\tAndesQueueTailCmdMsg(&ctl->tx_doneq, msg, state);\n'
              '\t\t}\n'
              '#ifdef CONFIG_RECOVERY_ON_INTERRUPT_MISS\n'
              '#ifdef INTELP6_SUPPORT\n'
              '\t\tif (IsComplete)\n'
              '\t\t\tad->ErrRecoveryCheck = 0;\n'
              '#endif\n'
              '#endif\n'
              '\t}\n'
              'bailout:\n'
              '\treturn ret;\n'
              '}\n'
              'VOID AndesForceFreeCmdMsg(struct cmd_msg *msg)\n'
              '{\n'
              '\tRTMP_ADAPTER *ad = NULL;\n'
              '\tstruct MCU_CTRL *ctl = NULL;\n'
              '\tULONG flags = 0;\n'
              '\n'
              '\tif (!msg)\n'
              '\t\treturn;\n'
              '\n'
              '\tad = (RTMP_ADAPTER *)(msg->priv);\n'
              '\n'
              '\tif (!ad) {\n'
              '\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t ("%s: pAd is null\\n", __func__));\n'
              '\t\tgoto free_memory;\n'
              '\t}\n'
              '\n'
              '\tctl = &ad->MCUCtrl;\n'
              '\n'
              '\tif (!ctl) {\n'
              '\t\tMTWF_LOG(DBG_CAT_FW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,\n'
              '\t\t\t\t ("%s: MCUCtrl is null\\n", __func__));\n'
              '\t\tgoto free_memory;\n'
              '\t}\n'
              '\n'
              '\tif (IS_CMD_MSG_NEED_SYNC_WITH_FW_FLAG_SET(msg))\n'
              '\t\tRTMP_OS_EXIT_COMPLETION(&msg->ack_done);\n'
              '\n'
              '\tOS_SPIN_LOCK_IRQSAVE(&ctl->msg_lock, &flags);\n'
              '\tctl->free_cmd_msg++;\n'
              '\tOS_SPIN_UNLOCK_IRQRESTORE(&ctl->msg_lock, &flags);\n'
              'free_memory:\n'
              '\n'
              '\tif (ad && msg->retry_pkt && msg->retry_pkt != msg->net_pkt)\n'
              '\t\tRTMPFreeNdisPacket(ad, msg->retry_pkt);\n'
              '\tmsg->retry_pkt = NULL;\n'
              '\tif (ad && msg->net_pkt)\n'
              '\t\tRTMPFreeNdisPacket(ad, msg->net_pkt);\n'
              '\n'
              '\tos_free_mem(msg);\n'
              '}\n',
 'wtbl_header': 'enum {\n'
                '\tHOST2N9     = 0,\n'
                '};\n'
                'enum {\n'
                '\tEXT_CID = 0xED,\n'
                '};\n'
                'enum {\n'
                '\tEXT_CMD_ID_WTBL_UPDATE = 0x32,\n'
                '};\n'
                'enum {\n'
                '\tINIT_CMD_SET_AND_WAIT_RETRY_RSP\t= 0x0F,\n'
                '};\n'
                'enum WTBL_TLV {\n'
                '\tWTBL_GENERIC = 0,\n'
                '\tWTBL_RX = 1,\n'
                '\tWTBL_HT = 2,\n'
                '\tWTBL_VHT = 3,\n'
                '\tWTBL_PEER_PS = 4,\n'
                '\tWTBL_TX_PS = 5,\n'
                '\tWTBL_HDR_TRANS = 6,\n'
                '\tWTBL_SECURITY_KEY = 7,\n'
                '\tWTBL_BA = 8,\n'
                '\tWTBL_RDG = 9,\n'
                '\tWTBL_PROTECTION = 10,\n'
                '\tWTBL_CLEAR = 11,\n'
                '\tWTBL_BF = 12,\n'
                '\tWTBL_SMPS = 13,\n'
                '\tWTBL_RAW_DATA_RW = 14,\n'
                '\tWTBL_DUMP = 15,\n'
                '\tWTBL_SPE = 16,\n'
                '\tWTBL_MAX_NUM = 17,\n'
                '};\n'
                '/** @} */\n'
                '/** @} */\n'
                '\n'
                'typedef struct _CMD_WTBL_UPDATE_T {\n'
                '\tUINT8\tucWlanIdx;\n'
                '\tUINT8\tucOperation;\n'
                '\tUINT16\tu2TotalElementNum;\n'
                '\tUINT32\tu4Reserve;\n'
                '\tUINT8\taucBuffer[];\n'
                '} CMD_WTBL_UPDATE_T, *P_CMD_WTBL_UPDATE_T;\n'
                '\n'
                'enum {\n'
                '\tRESET_WTBL_AND_SET\t= 1,\n'
                '\tSET_WTBL\t\t\t\t= 2,\n'
                '\tQUERY_WTBL\t\t\t= 3,\n'
                '\tRESET_ALL_WTBL\t\t= 4,\n'
                '};\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_GENERIC_TLV_T {\n'
                '\tUINT16\tu2Tag;\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\taucBuffer[];\n'
                '} CMD_WTBL_GENERIC_TLV_T, *P_CMD_WTBL_GENERIC_TLV_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_GENERIC_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x00 */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\taucPeerAddress[6];\n'
                '\tUINT8\tucMUARIndex;\n'
                '\tUINT8\tucSkipTx;\n'
                '\tUINT8\tucCfAck;\n'
                '\tUINT8\tucQos;\n'
                '\tUINT8\tucMesh;\n'
                '\tUINT8\tucAdm;\n'
                '\tUINT16\tu2PartialAID;\n'
                '\tUINT8\tucBafEn;\n'
                '\tUINT8   ucAadOm;\n'
                '} CMD_WTBL_GENERIC_T, *P_CMD_WTBL_GENERIC_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_RX_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x01 */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucRcid;\n'
                '\tUINT8\tucRca1;\n'
                '\tUINT8\tucRca2;\n'
                '\tUINT8\tucRv;\n'
                '\tUINT8\taucReserved[4];\n'
                '} CMD_WTBL_RX_T, *P_CMD_WTBL_RX_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_HT_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x02 */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucHt;\n'
                '\tUINT8\tucLdpc;\n'
                '\tUINT8\tucAf;\n'
                '\tUINT8\tucMm;\n'
                '} CMD_WTBL_HT_T, *P_CMD_WTBL_HT_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_VHT_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x03 */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucLdpcVht;\n'
                '\tUINT8\tucDynBw;\n'
                '\tUINT8\tucVht;\n'
                '\tUINT8\tucTxopPsCap;\n'
                '} CMD_WTBL_VHT_T, *P_CMD_WTBL_VHT_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_PEER_PS_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x04 */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucDuIPsm;\n'
                '\tUINT8\tucIPsm;\n'
                '\tUINT8\tucRsvd0;\n'
                '\tUINT8\tucRsvd1;\n'
                '} CMD_WTBL_PEER_PS_T, *P_CMD_WTBL_PEER_PS_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_TX_PS_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x05 */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucTxPs;\n'
                '\tUINT8\tucRsvd0;\n'
                '\tUINT8\tucRsvd1;\n'
                '\tUINT8\tucRsvd2;\n'
                '} CMD_WTBL_TX_PS_T, *P_CMD_WTBL_TX_PS_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_HDR_TRANS_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x06 */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucTd;\n'
                '\tUINT8\tucFd;\n'
                '\tUINT8\tucDisRhtr;\n'
                '\tUINT8\tucRsvd0;\n'
                '} CMD_WTBL_HDR_TRANS_T, *P_CMD_WTBL_HDR_TRANS_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_SECURITY_KEY_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x07 */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucAddRemove; /* 0: add, 1: remove */\n'
                '\t/* UINT8\tucKeyType; */\t/* 0: SHAREDKEYTABLE, 1: PAIRWISEKEYTABLE */\n'
                '\tUINT8\tucRkv;\n'
                '\tUINT8\tucIkv;\n'
                '\tUINT8\tucAlgorithmId; /* refer to ENUM_CIPHER_SUIT_T256 */\n'
                '\tUINT8\tucKeyId;\n'
                '\tUINT8\tucKeyLen;\n'
                '\tUINT8\tucrRsvd0;\n'
                '\tUINT8\tucrRsvd1;\n'
                '\tUINT8\taucKeyMaterial[32];\n'
                '} CMD_WTBL_SECURITY_KEY_T, *P_CMD_WTBL_SECURITY_KEY_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_BA_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x08 */\n'
                '\tUINT16\tu2Length;\n'
                '\t/* Recipient + Originator */\n'
                '\tUINT8\tucTid;\n'
                '\tUINT8\tucBaSessionType;\n'
                '\tUINT8\taucReserved[2];\n'
                '\t/* Originator */\n'
                '\tUINT16\tu2Sn;\n'
                '\tUINT8\tucBaEn;\n'
                '\tUINT8\tucBaSize;\n'
                '\tUINT8\taucReserved1[2];\n'
                '\t/* Recipient */\n'
                '\tUINT8\taucPeerAddress[MAC_ADDR_LEN];\n'
                '\tUINT8\tucRstBaTid;\n'
                '\tUINT8\tucRstBaSel;\n'
                '\tUINT8\tucStartRstBaSb;\n'
                '\tUINT8\tucBandIdx;\n'
                '\tUINT8\taucReserved2[4];\n'
                '} CMD_WTBL_BA_T, *P_CMD_WTBL_BA_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_RDG_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x09 */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucRdgBa;\n'
                '\tUINT8\tucR;\n'
                '\tUINT8\tucrRsvd0;\n'
                '\tUINT8\tucrRsvd1;\n'
                '} CMD_WTBL_RDG_T, *P_CMD_WTBL_RDG_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_PROTECTION_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x0a */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucRts;\n'
                '\tUINT8\tucrRsvd0;\n'
                '\tUINT8\tucrRsvd1;\n'
                '\tUINT8\tucrRsvd2;\n'
                '} CMD_WTBL_PROTECTION_T, *P_CMD_WTBL_PROTECTION_T;\n'
                '\n'
                '/* bit 0: Clear PSM (WF_WTBLON: 0x60322300, Bit 31 set 1 then set 0) */\n'
                '/* bit 1: Clear BA (WTBL2.DW15) */\n'
                '/* bit 2: Clear Rx Counter (6019_00002, bit 14) */\n'
                '/* bit 3: Clear Tx Counter (6019_0000, bit 15) */\n'
                '/* bit 4: Clear ADM Counter (6019_0000, bit 12) */\n'
                '/* bit 5: Clear Cipher key (WTBL3)*/\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_CLEAR_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x0b */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucClear;\n'
                '\tUINT8\tucrRsvd0;\n'
                '\tUINT8\tucrRsvd1;\n'
                '\tUINT8\tucrRsvd2;\n'
                '} CMD_WTBL_CLEAR_T, *P_CMD_WTBL_CLEAR_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_BF_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x0c */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucTiBf;\n'
                '\tUINT8\tucTeBf;\n'
                '\tUINT8\tucTibfVht;\n'
                '\tUINT8\tucTebfVht;\n'
                '\tUINT8\tucGid;\n'
                '\tUINT8\tucPFMUIdx;\n'
                '\tUINT8\tucrRsvd1;\n'
                '\tUINT8\tucrRsvd2;\n'
                '} CMD_WTBL_BF_T, *P_CMD_WTBL_BF_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_SMPS_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x0d */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucSmPs;\n'
                '\tUINT8\tucrRsvd0;\n'
                '\tUINT8\tucrRsvd1;\n'
                '\tUINT8\tucrRsvd2;\n'
                '} CMD_WTBL_SMPS_T, *P_CMD_WTBL_SMPS_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_RAW_DATA_RW_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x0e */\n'
                '\tUINT16\tu2Length;\n'
                "\tUINT8\tucWtblIdx;           /* WTBL 1/2/3/4 in MT7636, the field don't care in MT7615 */\n"
                '\tUINT8\tucWhichDW;\n'
                '\tUINT8\taucReserve[2];\n'
                "\tUINT32\tu4DwMask;\t\t/* Show these bits don't be writen */\n"
                '\tUINT32\tu4DwValue;\n'
                '} CMD_WTBL_RAW_DATA_RW_T, *P_CMD_WTBL_RAW_DATA_RW_T;\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_SPE_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x10 */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\tucSpeIdx;\n'
                '\tUINT8\tucrRsvd0;\n'
                '\tUINT8\tucrRsvd1;\n'
                '\tUINT8\tucrRsvd2;\n'
                '} CMD_WTBL_SPE_T, *P_CMD_WTBL_SPE_T;\n'
                '\n'
                '#define\tMAX_BUF_SIZE_OF_WTBL_INFO\t(sizeof(CMD_WTBL_UPDATE_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_GENERIC_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_RX_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_HT_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_VHT_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_PEER_PS_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_TX_PS_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_HDR_TRANS_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_SECURITY_KEY_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_BA_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_RDG_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_PROTECTION_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_CLEAR_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_BF_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_SMPS_T) + \\\n'
                '\t\t\t\t\t\t\t\t\t sizeof(CMD_WTBL_RAW_DATA_RW_T))\n'
                '\n'
                'typedef struct GNU_PACKED _STAREC_WTBL_T {\n'
                '\t/* WTBL with STAREC update (Tag 0x0b) */\n'
                '\t/* STAREC format, content is WTBL format. */\n'
                '\tUINT16\tu2Tag;\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\taucBuffer[MAX_BUF_SIZE_OF_WTBL_INFO];\n'
                '} CMD_STAREC_WTBL_T, *P_CMD_STAREC_WTBL_T;\n'
                '\n'
                '\n'
                '#ifdef MT7615\n'
                '#define\tWTBL_BUFFER_SIZE\t\t0x100\n'
                '#endif /* MT7615 */\n'
                '\n'
                '#ifdef MT7622\n'
                '#define\tWTBL_BUFFER_SIZE\t\t0x100\n'
                '#endif /* MT7622 */\n'
                '\n'
                '\n'
                '\n'
                '\n'
                'typedef struct GNU_PACKED _WTBL_DUMP_T {\n'
                '\tUINT16\tu2Tag;\t\t/* Tag = 0x0f */\n'
                '\tUINT16\tu2Length;\n'
                '\tUINT8\taucWtblBuffer[WTBL_BUFFER_SIZE];    /* need 4 byte alignment */\n'
                '} CMD_WTBL_DUMP_T, *P_CMD_WTBL_DUMP_T;\n'
                'typedef struct GNU_PACKED _EVENT_EXT_CMD_RESULT_T {\n'
                '\tUINT8 ucExTenCID;\n'
                '\tUINT8 aucReserve[3];\n'
                '\tUINT32 u4Status;\n'
                '} EVENT_EXT_CMD_RESULT_T, *PEVENT_EXT_CMD_RESULT_T;\n'
                '#define SET_CMD_ATTR_MCU_DEST(attr, cmd_dest) \\\n'
                '\t((attr).mcu_dest = cmd_dest)\n'
                '#define SET_CMD_ATTR_TYPE(attr, cmd_type) \\\n'
                '\t((attr).type = cmd_type)\n'
                '#define SET_CMD_ATTR_EXT_TYPE(attr, ext_cmd_type) \\\n'
                '\t((attr).ext_type = ext_cmd_type)\n'
                '#define SET_CMD_ATTR_CTRL_FLAGS(attr, cmd_flags) \\\n'
                '\t((attr).ctrl.flags = cmd_flags)\n'
                '#define SET_CMD_ATTR_RSP_EXPECT_SIZE(attr, size) \\\n'
                '\t((attr).ctrl.expect_size = (UINT16)size)\n'
                '#define SET_CMD_ATTR_RSP_WAIT_MS_TIME(attr, wait_time) \\\n'
                '\t((attr).ctrl.wait_ms_time = (UINT16)wait_time)\n'
                '#define SET_CMD_ATTR_RSP_WB_BUF_IN_CALBK(attr, write_back_buffer_in_callback) \\\n'
                '\t((attr).rsp.wb_buf_in_calbk = (UINT32 *)write_back_buffer_in_callback)\n'
                '#define SET_CMD_ATTR_RSP_HANDLER(attr, callback) \\\n'
                '\t((attr).rsp.handler = callback)\n'
                '\n'
                '/* CMD ATTRIBUTE ctrl flags related Macro */\n'
                '\tUINT32\t\twtbl_rsp_capacity;\n',
 'wtbl_os': '#define MAC_ADDR_LEN\t\t6\n'
            '#define NDIS_STATUS_SUCCESS                     0x00\n'
            '#define NDIS_STATUS_FAILURE                     0x01\n'
            '#define NDIS_STATUS_INVALID_DATA\t\t0x02\n'
            '#define NDIS_STATUS_RESOURCES                   0x03\n',
 'wtbl_asic': 'enum {\n\tBA_SESSION_RECP = 2,\n};\n',
 'wtbl_harness': '"""Whole WTBL builder/validator/callback and packet/msg allocator.\n'
                 '\n'
                 'Transport, packet allocation, logging and firmware responses are inert seams.\n'
                 'The real AndesSendCmdMsg is executed separately by dma_command_harness.\n'
                 '"""\n'
                 'import hashlib\n'
                 'import re\n'
                 '\n'
                 'SOURCE_PATHS = {\n'
                 "    'fw': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/mcu/fw_cmd.c',\n"
                 "    'core': "
                 "'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/mcu/andes_core.c',\n"
                 "    'header': "
                 "'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/mcu/mt_cmd.h',\n"
                 "    'os': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/os/rt_linux.h',\n"
                 "    'asic': "
                 "'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/include/hw_ctrl/cmm_asic_mt.h',\n"
                 '}\n'
                 "FUNCTION_SOURCES = {'AndesAllocCmdMsg': 'core', 'AndesAppendCmdMsg': 'core',\n"
                 "                    'wtbl_tlv_size': 'fw', 'wtbl_tlv_validate': 'fw',\n"
                 "                    'CmdExtWtblUpdateCb': 'fw', 'CmdExtWtblUpdate': 'fw'}\n"
                 "BODY_ORDER = ('AndesAllocCmdMsg', 'AndesAppendCmdMsg', 'wtbl_tlv_size',\n"
                 "              'wtbl_tlv_validate', 'CmdExtWtblUpdateCb', 'CmdExtWtblUpdate')\n"
                 "SOURCE_ONLY_FUNCTION_SOURCES = {'AndesInitCmdMsg': 'core', 'AndesSendCmdMsg': 'core',\n"
                 "                              'AndesForceFreeCmdMsg': 'core', 'WtblDwQuery': 'fw'}\n"
                 'SOURCE_DECLARATIONS = {\n'
                 "    'header': (\n"
                 "        ('enum WTBL_TLV {', '} CMD_WTBL_DUMP_T, *P_CMD_WTBL_DUMP_T;'),\n"
                 "        ('typedef struct GNU_PACKED _EVENT_EXT_CMD_RESULT_T {', '} EVENT_EXT_CMD_RESULT_T, "
                 "*PEVENT_EXT_CMD_RESULT_T;'),\n"
                 "        ('#define SET_CMD_ATTR_MCU_DEST', '/* CMD ATTRIBUTE ctrl flags related Macro "
                 "*/'),\n"
                 '    ),\n'
                 '}\n'
                 "SOURCE_ENUM_NAMES = ('HOST2N9', 'EXT_CID', 'EXT_CMD_ID_WTBL_UPDATE', "
                 "'INIT_CMD_SET_AND_WAIT_RETRY_RSP')\n"
                 "SOURCE_ENUMS = {'header': SOURCE_ENUM_NAMES, 'asic': ('BA_SESSION_RECP',)}\n"
                 "SOURCE_MACRO_NAMES = ('MAC_ADDR_LEN', 'NDIS_STATUS_SUCCESS', 'NDIS_STATUS_FAILURE',\n"
                 "                      'NDIS_STATUS_INVALID_DATA', 'NDIS_STATUS_RESOURCES')\n"
                 "SOURCE_FRAGMENTS = {'header': ('\\tUINT32\\t\\twtbl_rsp_capacity;',)}\n"
                 'MODEL_VARIANT = {\n'
                 "    'six_whole_functions_executed': True,\n"
                 "    'actual_WTBL_packed_declarations_and_constants_extracted': True,\n"
                 "    'kernel_cmd_msg_packet_scheduler_firmware_and_DMA_are_not_executed': True,\n"
                 "    'whole_transport_status_verified_separately_by_dma_command_harness': True,\n"
                 "    'query_response_prefix_is_existing_contract_not_hardware_ABI_proof': True,\n"
                 "    'short_query_ACK_callback_semantics_not_transport_delivery_claim': True,\n"
                 "    'allocator_seam_uses_memcpy_to_avoid_model_only_pointer_aliasing': True,\n"
                 "    'MIPS_little_endian_shipping_layout_requires_target_object_binding': True,\n"
                 "    'synthetic_big_endian_is_not_a_real_big_endian_ABI_test': True,\n"
                 '}\n'
                 'TAG_SIZES = (20, 12, 8, 8, 8, 8, 8, 44, 28, 8, 8, 8, 12, 8, 16, 260, 8)\n'
                 "FIELDS = ('ret', 'alloc_length', 'packets', 'msgs', 'sends', 'wire_len', 'elements',\n"
                 "          'capacity', 'expect', 'changed', 'live_packets', 'live_msgs', 'errors')\n"
                 'CASE_NAMES = (\n'
                 "    'tag-0', 'tag-1', 'tag-2', 'tag-3', 'tag-4', 'tag-5', 'tag-6', 'tag-7',\n"
                 "    'tag-8', 'tag-9', 'tag-10', 'tag-11', 'tag-12', 'tag-13', 'tag-14', 'tag-15', "
                 "'tag-16',\n"
                 "    'reset-set-empty', 'reset-all-empty', 'query-generic', 'query-dump', 'query-multi',\n"
                 "    'query-duplicate-raw', 'set-fw-error', 'no-response', 'wrong-cid',\n"
                 "    'query-short', 'query-long', 'query-wrong-tag', 'query-wrong-size',\n"
                 "    'query-ack-zero', 'query-ack-error', 'query-expect-overwrite',\n"
                 "    'bad-operation', 'null-adapter', 'null-set', 'null-nonzero', 'reset-payload',\n"
                 "    'zero-buffer', 'short-header', 'zero-tlv-length', 'wrong-tlv-size', 'unknown-tag',\n"
                 "    'over-capacity', 'length-overflow', 'packet-oom', 'msg-oom', 'max-payload', "
                 "'query-max-payload', 'snapshot-copy',\n"
                 ')\n'
                 "EXPECTED_ROWS = {'tag-0': {'ret': 0,\n"
                 "           'alloc_length': 28,\n"
                 "           'packets': 1,\n"
                 "           'msgs': 1,\n"
                 "           'sends': 1,\n"
                 "           'wire_len': 28,\n"
                 "           'elements': 1,\n"
                 "           'capacity': 0,\n"
                 "           'expect': 8,\n"
                 "           'changed': 0,\n"
                 "           'live_packets': 0,\n"
                 "           'live_msgs': 0,\n"
                 "           'errors': 0},\n"
                 " 'tag-1': {'ret': 0,\n"
                 "           'alloc_length': 20,\n"
                 "           'packets': 1,\n"
                 "           'msgs': 1,\n"
                 "           'sends': 1,\n"
                 "           'wire_len': 20,\n"
                 "           'elements': 1,\n"
                 "           'capacity': 0,\n"
                 "           'expect': 8,\n"
                 "           'changed': 0,\n"
                 "           'live_packets': 0,\n"
                 "           'live_msgs': 0,\n"
                 "           'errors': 0},\n"
                 " 'tag-2': {'ret': 0,\n"
                 "           'alloc_length': 16,\n"
                 "           'packets': 1,\n"
                 "           'msgs': 1,\n"
                 "           'sends': 1,\n"
                 "           'wire_len': 16,\n"
                 "           'elements': 1,\n"
                 "           'capacity': 0,\n"
                 "           'expect': 8,\n"
                 "           'changed': 0,\n"
                 "           'live_packets': 0,\n"
                 "           'live_msgs': 0,\n"
                 "           'errors': 0},\n"
                 " 'tag-3': {'ret': 0,\n"
                 "           'alloc_length': 16,\n"
                 "           'packets': 1,\n"
                 "           'msgs': 1,\n"
                 "           'sends': 1,\n"
                 "           'wire_len': 16,\n"
                 "           'elements': 1,\n"
                 "           'capacity': 0,\n"
                 "           'expect': 8,\n"
                 "           'changed': 0,\n"
                 "           'live_packets': 0,\n"
                 "           'live_msgs': 0,\n"
                 "           'errors': 0},\n"
                 " 'tag-4': {'ret': 0,\n"
                 "           'alloc_length': 16,\n"
                 "           'packets': 1,\n"
                 "           'msgs': 1,\n"
                 "           'sends': 1,\n"
                 "           'wire_len': 16,\n"
                 "           'elements': 1,\n"
                 "           'capacity': 0,\n"
                 "           'expect': 8,\n"
                 "           'changed': 0,\n"
                 "           'live_packets': 0,\n"
                 "           'live_msgs': 0,\n"
                 "           'errors': 0},\n"
                 " 'tag-5': {'ret': 0,\n"
                 "           'alloc_length': 16,\n"
                 "           'packets': 1,\n"
                 "           'msgs': 1,\n"
                 "           'sends': 1,\n"
                 "           'wire_len': 16,\n"
                 "           'elements': 1,\n"
                 "           'capacity': 0,\n"
                 "           'expect': 8,\n"
                 "           'changed': 0,\n"
                 "           'live_packets': 0,\n"
                 "           'live_msgs': 0,\n"
                 "           'errors': 0},\n"
                 " 'tag-6': {'ret': 0,\n"
                 "           'alloc_length': 16,\n"
                 "           'packets': 1,\n"
                 "           'msgs': 1,\n"
                 "           'sends': 1,\n"
                 "           'wire_len': 16,\n"
                 "           'elements': 1,\n"
                 "           'capacity': 0,\n"
                 "           'expect': 8,\n"
                 "           'changed': 0,\n"
                 "           'live_packets': 0,\n"
                 "           'live_msgs': 0,\n"
                 "           'errors': 0},\n"
                 " 'tag-7': {'ret': 0,\n"
                 "           'alloc_length': 52,\n"
                 "           'packets': 1,\n"
                 "           'msgs': 1,\n"
                 "           'sends': 1,\n"
                 "           'wire_len': 52,\n"
                 "           'elements': 1,\n"
                 "           'capacity': 0,\n"
                 "           'expect': 8,\n"
                 "           'changed': 0,\n"
                 "           'live_packets': 0,\n"
                 "           'live_msgs': 0,\n"
                 "           'errors': 0},\n"
                 " 'tag-8': {'ret': 0,\n"
                 "           'alloc_length': 36,\n"
                 "           'packets': 1,\n"
                 "           'msgs': 1,\n"
                 "           'sends': 1,\n"
                 "           'wire_len': 36,\n"
                 "           'elements': 1,\n"
                 "           'capacity': 0,\n"
                 "           'expect': 8,\n"
                 "           'changed': 0,\n"
                 "           'live_packets': 0,\n"
                 "           'live_msgs': 0,\n"
                 "           'errors': 0},\n"
                 " 'tag-9': {'ret': 0,\n"
                 "           'alloc_length': 16,\n"
                 "           'packets': 1,\n"
                 "           'msgs': 1,\n"
                 "           'sends': 1,\n"
                 "           'wire_len': 16,\n"
                 "           'elements': 1,\n"
                 "           'capacity': 0,\n"
                 "           'expect': 8,\n"
                 "           'changed': 0,\n"
                 "           'live_packets': 0,\n"
                 "           'live_msgs': 0,\n"
                 "           'errors': 0},\n"
                 " 'tag-10': {'ret': 0,\n"
                 "            'alloc_length': 16,\n"
                 "            'packets': 1,\n"
                 "            'msgs': 1,\n"
                 "            'sends': 1,\n"
                 "            'wire_len': 16,\n"
                 "            'elements': 1,\n"
                 "            'capacity': 0,\n"
                 "            'expect': 8,\n"
                 "            'changed': 0,\n"
                 "            'live_packets': 0,\n"
                 "            'live_msgs': 0,\n"
                 "            'errors': 0},\n"
                 " 'tag-11': {'ret': 0,\n"
                 "            'alloc_length': 16,\n"
                 "            'packets': 1,\n"
                 "            'msgs': 1,\n"
                 "            'sends': 1,\n"
                 "            'wire_len': 16,\n"
                 "            'elements': 1,\n"
                 "            'capacity': 0,\n"
                 "            'expect': 8,\n"
                 "            'changed': 0,\n"
                 "            'live_packets': 0,\n"
                 "            'live_msgs': 0,\n"
                 "            'errors': 0},\n"
                 " 'tag-12': {'ret': 0,\n"
                 "            'alloc_length': 20,\n"
                 "            'packets': 1,\n"
                 "            'msgs': 1,\n"
                 "            'sends': 1,\n"
                 "            'wire_len': 20,\n"
                 "            'elements': 1,\n"
                 "            'capacity': 0,\n"
                 "            'expect': 8,\n"
                 "            'changed': 0,\n"
                 "            'live_packets': 0,\n"
                 "            'live_msgs': 0,\n"
                 "            'errors': 0},\n"
                 " 'tag-13': {'ret': 0,\n"
                 "            'alloc_length': 16,\n"
                 "            'packets': 1,\n"
                 "            'msgs': 1,\n"
                 "            'sends': 1,\n"
                 "            'wire_len': 16,\n"
                 "            'elements': 1,\n"
                 "            'capacity': 0,\n"
                 "            'expect': 8,\n"
                 "            'changed': 0,\n"
                 "            'live_packets': 0,\n"
                 "            'live_msgs': 0,\n"
                 "            'errors': 0},\n"
                 " 'tag-14': {'ret': 0,\n"
                 "            'alloc_length': 24,\n"
                 "            'packets': 1,\n"
                 "            'msgs': 1,\n"
                 "            'sends': 1,\n"
                 "            'wire_len': 24,\n"
                 "            'elements': 1,\n"
                 "            'capacity': 0,\n"
                 "            'expect': 8,\n"
                 "            'changed': 0,\n"
                 "            'live_packets': 0,\n"
                 "            'live_msgs': 0,\n"
                 "            'errors': 0},\n"
                 " 'tag-15': {'ret': 0,\n"
                 "            'alloc_length': 268,\n"
                 "            'packets': 1,\n"
                 "            'msgs': 1,\n"
                 "            'sends': 1,\n"
                 "            'wire_len': 268,\n"
                 "            'elements': 1,\n"
                 "            'capacity': 0,\n"
                 "            'expect': 8,\n"
                 "            'changed': 0,\n"
                 "            'live_packets': 0,\n"
                 "            'live_msgs': 0,\n"
                 "            'errors': 0},\n"
                 " 'tag-16': {'ret': 0,\n"
                 "            'alloc_length': 16,\n"
                 "            'packets': 1,\n"
                 "            'msgs': 1,\n"
                 "            'sends': 1,\n"
                 "            'wire_len': 16,\n"
                 "            'elements': 1,\n"
                 "            'capacity': 0,\n"
                 "            'expect': 8,\n"
                 "            'changed': 0,\n"
                 "            'live_packets': 0,\n"
                 "            'live_msgs': 0,\n"
                 "            'errors': 0},\n"
                 " 'reset-set-empty': {'ret': 0,\n"
                 "                     'alloc_length': 8,\n"
                 "                     'packets': 1,\n"
                 "                     'msgs': 1,\n"
                 "                     'sends': 1,\n"
                 "                     'wire_len': 8,\n"
                 "                     'elements': 0,\n"
                 "                     'capacity': 0,\n"
                 "                     'expect': 8,\n"
                 "                     'changed': 0,\n"
                 "                     'live_packets': 0,\n"
                 "                     'live_msgs': 0,\n"
                 "                     'errors': 0},\n"
                 " 'reset-all-empty': {'ret': 0,\n"
                 "                     'alloc_length': 8,\n"
                 "                     'packets': 1,\n"
                 "                     'msgs': 1,\n"
                 "                     'sends': 1,\n"
                 "                     'wire_len': 8,\n"
                 "                     'elements': 0,\n"
                 "                     'capacity': 0,\n"
                 "                     'expect': 8,\n"
                 "                     'changed': 0,\n"
                 "                     'live_packets': 0,\n"
                 "                     'live_msgs': 0,\n"
                 "                     'errors': 0},\n"
                 " 'query-generic': {'ret': 0,\n"
                 "                   'alloc_length': 28,\n"
                 "                   'packets': 1,\n"
                 "                   'msgs': 1,\n"
                 "                   'sends': 1,\n"
                 "                   'wire_len': 28,\n"
                 "                   'elements': 1,\n"
                 "                   'capacity': 20,\n"
                 "                   'expect': 48,\n"
                 "                   'changed': 1,\n"
                 "                   'live_packets': 0,\n"
                 "                   'live_msgs': 0,\n"
                 "                   'errors': 0},\n"
                 " 'query-dump': {'ret': 0,\n"
                 "                'alloc_length': 268,\n"
                 "                'packets': 1,\n"
                 "                'msgs': 1,\n"
                 "                'sends': 1,\n"
                 "                'wire_len': 268,\n"
                 "                'elements': 1,\n"
                 "                'capacity': 260,\n"
                 "                'expect': 288,\n"
                 "                'changed': 1,\n"
                 "                'live_packets': 0,\n"
                 "                'live_msgs': 0,\n"
                 "                'errors': 0},\n"
                 " 'query-multi': {'ret': 0,\n"
                 "                 'alloc_length': 40,\n"
                 "                 'packets': 1,\n"
                 "                 'msgs': 1,\n"
                 "                 'sends': 1,\n"
                 "                 'wire_len': 40,\n"
                 "                 'elements': 2,\n"
                 "                 'capacity': 32,\n"
                 "                 'expect': 60,\n"
                 "                 'changed': 1,\n"
                 "                 'live_packets': 0,\n"
                 "                 'live_msgs': 0,\n"
                 "                 'errors': 0},\n"
                 " 'query-duplicate-raw': {'ret': 0,\n"
                 "                         'alloc_length': 40,\n"
                 "                         'packets': 1,\n"
                 "                         'msgs': 1,\n"
                 "                         'sends': 1,\n"
                 "                         'wire_len': 40,\n"
                 "                         'elements': 2,\n"
                 "                         'capacity': 32,\n"
                 "                         'expect': 60,\n"
                 "                         'changed': 1,\n"
                 "                         'live_packets': 0,\n"
                 "                         'live_msgs': 0,\n"
                 "                         'errors': 0},\n"
                 " 'set-fw-error': {'ret': 5,\n"
                 "                  'alloc_length': 28,\n"
                 "                  'packets': 1,\n"
                 "                  'msgs': 1,\n"
                 "                  'sends': 1,\n"
                 "                  'wire_len': 28,\n"
                 "                  'elements': 1,\n"
                 "                  'capacity': 0,\n"
                 "                  'expect': 8,\n"
                 "                  'changed': 0,\n"
                 "                  'live_packets': 0,\n"
                 "                  'live_msgs': 0,\n"
                 "                  'errors': 0},\n"
                 " 'no-response': {'ret': 1,\n"
                 "                 'alloc_length': 28,\n"
                 "                 'packets': 1,\n"
                 "                 'msgs': 1,\n"
                 "                 'sends': 1,\n"
                 "                 'wire_len': 28,\n"
                 "                 'elements': 1,\n"
                 "                 'capacity': 0,\n"
                 "                 'expect': 8,\n"
                 "                 'changed': 0,\n"
                 "                 'live_packets': 0,\n"
                 "                 'live_msgs': 0,\n"
                 "                 'errors': 0},\n"
                 " 'wrong-cid': {'ret': 2,\n"
                 "               'alloc_length': 28,\n"
                 "               'packets': 1,\n"
                 "               'msgs': 1,\n"
                 "               'sends': 1,\n"
                 "               'wire_len': 28,\n"
                 "               'elements': 1,\n"
                 "               'capacity': 0,\n"
                 "               'expect': 8,\n"
                 "               'changed': 0,\n"
                 "               'live_packets': 0,\n"
                 "               'live_msgs': 0,\n"
                 "               'errors': 0},\n"
                 " 'query-short': {'ret': 2,\n"
                 "                 'alloc_length': 28,\n"
                 "                 'packets': 1,\n"
                 "                 'msgs': 1,\n"
                 "                 'sends': 1,\n"
                 "                 'wire_len': 28,\n"
                 "                 'elements': 1,\n"
                 "                 'capacity': 20,\n"
                 "                 'expect': 48,\n"
                 "                 'changed': 0,\n"
                 "                 'live_packets': 0,\n"
                 "                 'live_msgs': 0,\n"
                 "                 'errors': 0},\n"
                 " 'query-long': {'ret': 2,\n"
                 "                'alloc_length': 28,\n"
                 "                'packets': 1,\n"
                 "                'msgs': 1,\n"
                 "                'sends': 1,\n"
                 "                'wire_len': 28,\n"
                 "                'elements': 1,\n"
                 "                'capacity': 20,\n"
                 "                'expect': 48,\n"
                 "                'changed': 0,\n"
                 "                'live_packets': 0,\n"
                 "                'live_msgs': 0,\n"
                 "                'errors': 0},\n"
                 " 'query-wrong-tag': {'ret': 2,\n"
                 "                     'alloc_length': 16,\n"
                 "                     'packets': 1,\n"
                 "                     'msgs': 1,\n"
                 "                     'sends': 1,\n"
                 "                     'wire_len': 16,\n"
                 "                     'elements': 1,\n"
                 "                     'capacity': 8,\n"
                 "                     'expect': 36,\n"
                 "                     'changed': 0,\n"
                 "                     'live_packets': 0,\n"
                 "                     'live_msgs': 0,\n"
                 "                     'errors': 0},\n"
                 " 'query-wrong-size': {'ret': 2,\n"
                 "                      'alloc_length': 28,\n"
                 "                      'packets': 1,\n"
                 "                      'msgs': 1,\n"
                 "                      'sends': 1,\n"
                 "                      'wire_len': 28,\n"
                 "                      'elements': 1,\n"
                 "                      'capacity': 20,\n"
                 "                      'expect': 48,\n"
                 "                      'changed': 0,\n"
                 "                      'live_packets': 0,\n"
                 "                      'live_msgs': 0,\n"
                 "                      'errors': 0},\n"
                 " 'query-ack-zero': {'ret': 2,\n"
                 "                    'alloc_length': 28,\n"
                 "                    'packets': 1,\n"
                 "                    'msgs': 1,\n"
                 "                    'sends': 1,\n"
                 "                    'wire_len': 28,\n"
                 "                    'elements': 1,\n"
                 "                    'capacity': 20,\n"
                 "                    'expect': 48,\n"
                 "                    'changed': 0,\n"
                 "                    'live_packets': 0,\n"
                 "                    'live_msgs': 0,\n"
                 "                    'errors': 0},\n"
                 " 'query-ack-error': {'ret': 5,\n"
                 "                     'alloc_length': 28,\n"
                 "                     'packets': 1,\n"
                 "                     'msgs': 1,\n"
                 "                     'sends': 1,\n"
                 "                     'wire_len': 28,\n"
                 "                     'elements': 1,\n"
                 "                     'capacity': 20,\n"
                 "                     'expect': 48,\n"
                 "                     'changed': 0,\n"
                 "                     'live_packets': 0,\n"
                 "                     'live_msgs': 0,\n"
                 "                     'errors': 0},\n"
                 " 'query-expect-overwrite': {'ret': 0,\n"
                 "                            'alloc_length': 28,\n"
                 "                            'packets': 1,\n"
                 "                            'msgs': 1,\n"
                 "                            'sends': 1,\n"
                 "                            'wire_len': 28,\n"
                 "                            'elements': 1,\n"
                 "                            'capacity': 20,\n"
                 "                            'expect': 48,\n"
                 "                            'changed': 1,\n"
                 "                            'live_packets': 0,\n"
                 "                            'live_msgs': 0,\n"
                 "                            'errors': 0},\n"
                 " 'bad-operation': {'ret': 2,\n"
                 "                   'alloc_length': 0,\n"
                 "                   'packets': 0,\n"
                 "                   'msgs': 0,\n"
                 "                   'sends': 0,\n"
                 "                   'wire_len': 0,\n"
                 "                   'elements': 0,\n"
                 "                   'capacity': 0,\n"
                 "                   'expect': 0,\n"
                 "                   'changed': 0,\n"
                 "                   'live_packets': 0,\n"
                 "                   'live_msgs': 0,\n"
                 "                   'errors': 0},\n"
                 " 'null-adapter': {'ret': 2,\n"
                 "                  'alloc_length': 0,\n"
                 "                  'packets': 0,\n"
                 "                  'msgs': 0,\n"
                 "                  'sends': 0,\n"
                 "                  'wire_len': 0,\n"
                 "                  'elements': 0,\n"
                 "                  'capacity': 0,\n"
                 "                  'expect': 0,\n"
                 "                  'changed': 0,\n"
                 "                  'live_packets': 0,\n"
                 "                  'live_msgs': 0,\n"
                 "                  'errors': 0},\n"
                 " 'null-set': {'ret': 2,\n"
                 "              'alloc_length': 0,\n"
                 "              'packets': 0,\n"
                 "              'msgs': 0,\n"
                 "              'sends': 0,\n"
                 "              'wire_len': 0,\n"
                 "              'elements': 0,\n"
                 "              'capacity': 0,\n"
                 "              'expect': 0,\n"
                 "              'changed': 0,\n"
                 "              'live_packets': 0,\n"
                 "              'live_msgs': 0,\n"
                 "              'errors': 0},\n"
                 " 'null-nonzero': {'ret': 2,\n"
                 "                  'alloc_length': 0,\n"
                 "                  'packets': 0,\n"
                 "                  'msgs': 0,\n"
                 "                  'sends': 0,\n"
                 "                  'wire_len': 0,\n"
                 "                  'elements': 0,\n"
                 "                  'capacity': 0,\n"
                 "                  'expect': 0,\n"
                 "                  'changed': 0,\n"
                 "                  'live_packets': 0,\n"
                 "                  'live_msgs': 0,\n"
                 "                  'errors': 0},\n"
                 " 'reset-payload': {'ret': 2,\n"
                 "                   'alloc_length': 0,\n"
                 "                   'packets': 0,\n"
                 "                   'msgs': 0,\n"
                 "                   'sends': 0,\n"
                 "                   'wire_len': 0,\n"
                 "                   'elements': 0,\n"
                 "                   'capacity': 0,\n"
                 "                   'expect': 0,\n"
                 "                   'changed': 0,\n"
                 "                   'live_packets': 0,\n"
                 "                   'live_msgs': 0,\n"
                 "                   'errors': 0},\n"
                 " 'zero-buffer': {'ret': 2,\n"
                 "                 'alloc_length': 0,\n"
                 "                 'packets': 0,\n"
                 "                 'msgs': 0,\n"
                 "                 'sends': 0,\n"
                 "                 'wire_len': 0,\n"
                 "                 'elements': 0,\n"
                 "                 'capacity': 0,\n"
                 "                 'expect': 0,\n"
                 "                 'changed': 0,\n"
                 "                 'live_packets': 0,\n"
                 "                 'live_msgs': 0,\n"
                 "                 'errors': 0},\n"
                 " 'short-header': {'ret': 2,\n"
                 "                  'alloc_length': 0,\n"
                 "                  'packets': 0,\n"
                 "                  'msgs': 0,\n"
                 "                  'sends': 0,\n"
                 "                  'wire_len': 0,\n"
                 "                  'elements': 0,\n"
                 "                  'capacity': 0,\n"
                 "                  'expect': 0,\n"
                 "                  'changed': 0,\n"
                 "                  'live_packets': 0,\n"
                 "                  'live_msgs': 0,\n"
                 "                  'errors': 0},\n"
                 " 'zero-tlv-length': {'ret': 2,\n"
                 "                     'alloc_length': 0,\n"
                 "                     'packets': 0,\n"
                 "                     'msgs': 0,\n"
                 "                     'sends': 0,\n"
                 "                     'wire_len': 0,\n"
                 "                     'elements': 0,\n"
                 "                     'capacity': 0,\n"
                 "                     'expect': 0,\n"
                 "                     'changed': 0,\n"
                 "                     'live_packets': 0,\n"
                 "                     'live_msgs': 0,\n"
                 "                     'errors': 0},\n"
                 " 'wrong-tlv-size': {'ret': 2,\n"
                 "                    'alloc_length': 0,\n"
                 "                    'packets': 0,\n"
                 "                    'msgs': 0,\n"
                 "                    'sends': 0,\n"
                 "                    'wire_len': 0,\n"
                 "                    'elements': 0,\n"
                 "                    'capacity': 0,\n"
                 "                    'expect': 0,\n"
                 "                    'changed': 0,\n"
                 "                    'live_packets': 0,\n"
                 "                    'live_msgs': 0,\n"
                 "                    'errors': 0},\n"
                 " 'unknown-tag': {'ret': 2,\n"
                 "                 'alloc_length': 0,\n"
                 "                 'packets': 0,\n"
                 "                 'msgs': 0,\n"
                 "                 'sends': 0,\n"
                 "                 'wire_len': 0,\n"
                 "                 'elements': 0,\n"
                 "                 'capacity': 0,\n"
                 "                 'expect': 0,\n"
                 "                 'changed': 0,\n"
                 "                 'live_packets': 0,\n"
                 "                 'live_msgs': 0,\n"
                 "                 'errors': 0},\n"
                 " 'over-capacity': {'ret': 2,\n"
                 "                   'alloc_length': 0,\n"
                 "                   'packets': 0,\n"
                 "                   'msgs': 0,\n"
                 "                   'sends': 0,\n"
                 "                   'wire_len': 0,\n"
                 "                   'elements': 0,\n"
                 "                   'capacity': 0,\n"
                 "                   'expect': 0,\n"
                 "                   'changed': 0,\n"
                 "                   'live_packets': 0,\n"
                 "                   'live_msgs': 0,\n"
                 "                   'errors': 0},\n"
                 " 'length-overflow': {'ret': 2,\n"
                 "                     'alloc_length': 0,\n"
                 "                     'packets': 0,\n"
                 "                     'msgs': 0,\n"
                 "                     'sends': 0,\n"
                 "                     'wire_len': 0,\n"
                 "                     'elements': 0,\n"
                 "                     'capacity': 0,\n"
                 "                     'expect': 0,\n"
                 "                     'changed': 0,\n"
                 "                     'live_packets': 0,\n"
                 "                     'live_msgs': 0,\n"
                 "                     'errors': 0},\n"
                 " 'packet-oom': {'ret': 3,\n"
                 "                'alloc_length': 28,\n"
                 "                'packets': 0,\n"
                 "                'msgs': 0,\n"
                 "                'sends': 0,\n"
                 "                'wire_len': 0,\n"
                 "                'elements': 0,\n"
                 "                'capacity': 0,\n"
                 "                'expect': 0,\n"
                 "                'changed': 0,\n"
                 "                'live_packets': 0,\n"
                 "                'live_msgs': 0,\n"
                 "                'errors': 0},\n"
                 " 'msg-oom': {'ret': 3,\n"
                 "             'alloc_length': 28,\n"
                 "             'packets': 1,\n"
                 "             'msgs': 0,\n"
                 "             'sends': 0,\n"
                 "             'wire_len': 0,\n"
                 "             'elements': 0,\n"
                 "             'capacity': 0,\n"
                 "             'expect': 0,\n"
                 "             'changed': 0,\n"
                 "             'live_packets': 0,\n"
                 "             'live_msgs': 0,\n"
                 "             'errors': 0},\n"
                 " 'max-payload': {'ret': 0,\n"
                 "                 'alloc_length': 312,\n"
                 "                 'packets': 1,\n"
                 "                 'msgs': 1,\n"
                 "                 'sends': 1,\n"
                 "                 'wire_len': 312,\n"
                 "                 'elements': 38,\n"
                 "                 'capacity': 0,\n"
                 "                 'expect': 8,\n"
                 "                 'changed': 0,\n"
                 "                 'live_packets': 0,\n"
                 "                 'live_msgs': 0,\n"
                 "                 'errors': 0},\n"
                 " 'query-max-payload': {'ret': 0,\n"
                 "                       'alloc_length': 312,\n"
                 "                       'packets': 1,\n"
                 "                       'msgs': 1,\n"
                 "                       'sends': 1,\n"
                 "                       'wire_len': 312,\n"
                 "                       'elements': 38,\n"
                 "                       'capacity': 304,\n"
                 "                       'expect': 332,\n"
                 "                       'changed': 1,\n"
                 "                       'live_packets': 0,\n"
                 "                       'live_msgs': 0,\n"
                 "                       'errors': 0},\n"
                 " 'snapshot-copy': {'ret': 0,\n"
                 "                   'alloc_length': 28,\n"
                 "                   'packets': 1,\n"
                 "                   'msgs': 1,\n"
                 "                   'sends': 1,\n"
                 "                   'wire_len': 28,\n"
                 "                   'elements': 1,\n"
                 "                   'capacity': 0,\n"
                 "                   'expect': 8,\n"
                 "                   'changed': 1,\n"
                 "                   'live_packets': 0,\n"
                 "                   'live_msgs': 0,\n"
                 "                   'errors': 0}}\n"
                 "PREFIX = r'''\n"
                 '#include <stdint.h>\n'
                 '#include <stdio.h>\n'
                 '#include <stdlib.h>\n'
                 '#include <string.h>\n'
                 '#include <stdarg.h>\n'
                 'typedef uint8_t UCHAR, UINT8, *PUCHAR;\n'
                 'typedef uint16_t UINT16; typedef uint32_t UINT32; typedef int32_t INT32;\n'
                 'typedef char *PCHAR; typedef void VOID; typedef int BOOLEAN;\n'
                 '#define TRUE 1\n'
                 '#define FALSE 0\n'
                 '#define GNU_PACKED __attribute__((packed))\n'
                 '#define MT7615 1\n'
                 '#define cpu2le16(x) ((UINT16)(x))\n'
                 '#define cpu2le32(x) ((UINT32)(x))\n'
                 '#define le2cpu16(x) ((UINT16)(x))\n'
                 '#define le2cpu32(x) ((UINT32)(x))\n'
                 '#define PRINT_MAC(x) (x)[0],(x)[1],(x)[2],(x)[3],(x)[4],(x)[5]\n'
                 '#define os_move_mem memcpy\n'
                 '#define os_zero_mem(p,n) memset(p,0,n)\n'
                 'static void trace_log(const char *fmt,...) { (void)fmt; }\n'
                 '#define MTWF_LOG(a,b,c,args) trace_log args\n'
                 'struct cmd_msg;\n'
                 'struct _CMD_ATTRIBUTE {\n'
                 ' int mcu_dest,type,ext_type;\n'
                 ' struct { int flags; UINT16 wait_ms_time,expect_size; } ctrl;\n'
                 ' struct { UINT32 *wb_buf_in_calbk; void (*handler)(struct cmd_msg *,char *,UINT16); } '
                 'rsp;\n'
                 '};\n'
                 'typedef struct _CMD_ATTRIBUTE CMD_ATTRIBUTE;\n'
                 'struct packet { UCHAR data[2048]; unsigned int length,capacity,reserved; struct {struct '
                 'cmd_msg *msg;} cb; };\n'
                 'typedef struct packet *PNDIS_PACKET;\n'
                 'struct cmd_msg { struct _CMD_ATTRIBUTE attr; void *priv; PNDIS_PACKET net_pkt;\n'
                 ' INT32 cmd_return_status; UINT32 wtbl_rsp_capacity; };\n'
                 'typedef struct { int cmd_header_len,cmd_padding_len; } RTMP_CHIP_CAP;\n'
                 'struct MCU_CTRL { int alloc_cmd_msg; };\n'
                 'typedef struct _RTMP_ADAPTER { void *hdev_ctrl; struct MCU_CTRL MCUCtrl; } RTMP_ADAPTER;\n'
                 'static const char *case_name;\n'
                 'static int '
                 'alloc_length,packets,msgs,sends,wire_len,elements,capacity_seen,expect_seen,errors;\n'
                 'static int live_packets,live_msgs;\n'
                 'static PNDIS_PACKET retained_packet;static PUCHAR retained_msg;\n'
                 'static UCHAR input[512],before[512],response[600],wire[512];\n'
                 'static RTMP_CHIP_CAP chip_cap={16,4};\n'
                 'static RTMP_CHIP_CAP *hc_get_chip_cap(void *p) { (void)p; return &chip_cap; }\n'
                 'static int selected(const char *s) { return strcmp(case_name,s)==0; }\n'
                 'static PNDIS_PACKET RTMP_AllocateFragPacketBuffer(RTMP_ADAPTER *ad,int n) {\n'
                 ' (void)ad;alloc_length=n-chip_cap.cmd_header_len-chip_cap.cmd_padding_len;\n'
                 ' if(selected("packet-oom"))return NULL;\n'
                 ' if(n<0 || n>1024){errors++;return NULL;}\n'
                 ' PNDIS_PACKET p=calloc(1,sizeof(*p));if(!p)abort();p->capacity=(unsigned)n;\n'
                 ' packets++;live_packets++;retained_packet=p;return p;\n'
                 '}\n'
                 'static void reserve_packet(PNDIS_PACKET p,unsigned int n) {p->reserved=n;p->length=n;}\n'
                 '#define OS_PKT_RESERVE(p,n) reserve_packet(p,n)\n'
                 '#define CMD_MSG_CB(p) (&(p)->cb)\n'
                 'static void os_alloc_mem(void *ad,void *out,size_t n) {\n'
                 ' (void)ad;PUCHAR allocated=NULL;\n'
                 ' '
                 'if(!selected("msg-oom")){allocated=malloc(n);if(!allocated)abort();memset(allocated,0xa5,n);msgs++;live_msgs++;retained_msg=allocated;}\n'
                 ' memcpy(out,&allocated,sizeof(allocated));\n'
                 ' if(allocated && selected("snapshot-copy")){UINT16 '
                 'tag=1,len=12;memcpy(input+8,&tag,2);memcpy(input+10,&len,2);}\n'
                 '}\n'
                 'static void RTMPFreeNdisPacket(RTMP_ADAPTER *ad,PNDIS_PACKET p) {\n'
                 ' (void)ad;if(!p || live_packets<=0){errors++;return;}live_packets--;free(p);\n'
                 '}\n'
                 'static void *extend_packet(PNDIS_PACKET p,unsigned int n) {\n'
                 ' if(n>p->capacity || p->length>p->capacity-n){errors++;abort();}\n'
                 ' void *tail=p->data+p->length;p->length+=n;return tail;\n'
                 '}\n'
                 '#define OS_PKT_TAIL_BUF_EXTEND(p,n) extend_packet(p,n)\n'
                 '#define AndesFreeCmdMsg(msg) do { live_msgs--;free(msg); } while(0)\n'
                 'static void AndesInitCmdMsg(struct cmd_msg *msg,CMD_ATTRIBUTE attr) {\n'
                 ' msg->attr=attr;msg->cmd_return_status=1;\n'
                 '}\n'
                 'static INT32 AndesSendCmdMsg(RTMP_ADAPTER *ad,struct cmd_msg *msg);\n'
                 "'''\n"
                 "TRANSPORT = r'''\n"
                 'static INT32 AndesSendCmdMsg(RTMP_ADAPTER *ad,struct cmd_msg *msg) {\n'
                 ' int query=msg->attr.rsp.wb_buf_in_calbk!=NULL;\n'
                 ' sends++;wire_len=(int)(msg->net_pkt->length-msg->net_pkt->reserved);\n'
                 ' if(wire_len<8 || wire_len>(int)sizeof(wire)){errors++;abort();}\n'
                 ' memcpy(wire,msg->net_pkt->data+msg->net_pkt->reserved,(size_t)wire_len);\n'
                 ' memcpy(&elements,wire+2,2);\n'
                 ' if(memcmp(wire+8,before+8,(size_t)wire_len-8))errors++;\n'
                 ' capacity_seen=(int)msg->wtbl_rsp_capacity;expect_seen=msg->attr.ctrl.expect_size;\n'
                 ' if(msg->attr.mcu_dest!=HOST2N9 || msg->attr.type!=EXT_CID ||\n'
                 '    msg->attr.ext_type!=EXT_CMD_ID_WTBL_UPDATE ||\n'
                 '    msg->attr.ctrl.flags!=INIT_CMD_SET_AND_WAIT_RETRY_RSP)errors++;\n'
                 ' UINT16 length=8;memset(response,0,sizeof(response));response[0]=EXT_CMD_ID_WTBL_UPDATE;\n'
                 ' if(query) {\n'
                 '  unsigned int n=(unsigned int)(wire_len-8);\n'
                 '  length=(UINT16)(28+n);memcpy(response+28,wire+8,n);\n'
                 '  for(unsigned int offset=0;offset<n;){\n'
                 '   UINT16 len;memcpy(&len,response+28+offset+2,2);\n'
                 '   if(len<4 || len>n-offset){errors++;abort();}\n'
                 '   if(len>4)response[28+offset+4]=0x5a;\n'
                 '   offset+=len;\n'
                 '  }\n'
                 '  if(selected("query-short"))length--;\n'
                 '  if(selected("query-long"))length++;\n'
                 '  if(selected("query-wrong-tag")){UINT16 tag=3;memcpy(response+28,&tag,2);}\n'
                 '  if(selected("query-wrong-size")){UINT16 len=4;memcpy(response+30,&len,2);}\n'
                 '  if(selected("query-ack-zero")||selected("query-ack-error")) {\n'
                 '   memset(response,0,8);response[0]=EXT_CMD_ID_WTBL_UPDATE;length=8;\n'
                 '   if(selected("query-ack-error"))response[4]=5;\n'
                 '  }\n'
                 ' }\n'
                 ' if(selected("set-fw-error"))response[4]=5;\n'
                 ' if(selected("wrong-cid"))response[0]=0x33;\n'
                 ' if(selected("query-expect-overwrite")) {\n'
                 '  msg->attr.ctrl.expect_size=29; /* mutable transport state must not become capacity */\n'
                 ' }\n'
                 ' if(!selected("no-response"))msg->attr.rsp.handler(msg,(char *)response,length);\n'
                 ' INT32 ret=msg->cmd_return_status;\n'
                 ' RTMPFreeNdisPacket(ad,msg->net_pkt);live_msgs--;free(msg);return ret;\n'
                 '}\n'
                 "'''\n"
                 "SUFFIX = r'''\n"
                 'static const unsigned int tag_sizes[17]={20,12,8,8,8,8,8,44,28,8,8,8,12,8,16,260,8};\n'
                 'static unsigned int add_tlv(unsigned int offset,UINT16 tag) {\n'
                 ' UINT16 '
                 'len=(UINT16)tag_sizes[tag];memcpy(input+offset,&tag,2);memcpy(input+offset+2,&len,2);\n'
                 ' return offset+len;\n'
                 '}\n'
                 'int main(int argc,char **argv) {\n'
                 ' if(argc!=2)return 91;\n'
                 ' case_name=argv[1];\n'
                 ' CASE_ADMISSION\n'
                 ' memset(input,0,sizeof(input));input[0]=0x11;input[511]=0x22;\n'
                 ' unsigned int length=add_tlv(8,0)-8;UINT8 operation=SET_WTBL;\n'
                 ' if(!strncmp(case_name,"tag-",4))length=add_tlv(8,(UINT16)atoi(case_name+4))-8;\n'
                 ' if(!strncmp(case_name,"query-",6))operation=QUERY_WTBL;\n'
                 ' if(selected("query-dump"))length=add_tlv(8,15)-8;\n'
                 ' if(selected("query-wrong-tag"))length=add_tlv(8,2)-8;\n'
                 ' if(selected("query-multi"))length=add_tlv(add_tlv(8,0),1)-8;\n'
                 ' if(selected("query-duplicate-raw"))length=add_tlv(add_tlv(8,14),14)-8;\n'
                 ' if(selected("max-payload")||selected("query-max-payload")) {\n'
                 '  unsigned int off=8;for(int i=0;i<38;i++)off=add_tlv(off,2);length=off-8;\n'
                 ' }\n'
                 ' VOID *buffer=input+8;RTMP_ADAPTER ad={0};RTMP_ADAPTER *adapter=&ad;\n'
                 ' if(selected("reset-set-empty")){buffer=NULL;length=0;operation=RESET_WTBL_AND_SET;}\n'
                 ' if(selected("reset-all-empty")){buffer=NULL;length=0;operation=RESET_ALL_WTBL;}\n'
                 ' if(selected("bad-operation"))operation=0;\n'
                 ' if(selected("null-adapter"))adapter=NULL;\n'
                 ' if(selected("null-set")){buffer=NULL;length=0;}\n'
                 ' if(selected("null-nonzero"))buffer=NULL;\n'
                 ' if(selected("reset-payload"))operation=RESET_ALL_WTBL;\n'
                 ' if(selected("zero-buffer"))length=0;\n'
                 ' if(selected("short-header"))length=3;\n'
                 ' if(selected("zero-tlv-length")){UINT16 len=0;memcpy(input+10,&len,2);}\n'
                 ' if(selected("wrong-tlv-size")){UINT16 len=8;memcpy(input+10,&len,2);length=8;}\n'
                 ' if(selected("unknown-tag")){UINT16 tag=17;memcpy(input+8,&tag,2);}\n'
                 ' if(selected("over-capacity"))length=305;\n'
                 ' if(selected("length-overflow"))length=UINT32_MAX;\n'
                 ' memcpy(before,input,sizeof(input));\n'
                 ' INT32 ret=CmdExtWtblUpdate(adapter,7,operation,buffer,length);\n'
                 ' int changed=memcmp(input,before,sizeof(input))!=0;\n'
                 ' if(input[0]!=0x11 || input[511]!=0x22)errors++;\n'
                 ' '
                 'printf("{\\"ret\\":%d,\\"alloc_length\\":%d,\\"packets\\":%d,\\"msgs\\":%d,\\"sends\\":%d,\\"wire_len\\":%d,\\"elements\\":%d,\\"capacity\\":%d,\\"expect\\":%d,\\"changed\\":%d,\\"live_packets\\":%d,\\"live_msgs\\":%d,\\"errors\\":%d}\\n",ret,alloc_length,packets,msgs,sends,wire_len,elements,capacity_seen,expect_seen,changed,live_packets,live_msgs,errors);\n'
                 ' if(live_msgs)free(retained_msg);\n'
                 ' if(live_packets)free(retained_packet);\n'
                 ' /* The fixed old early-return fixture is allowed to demonstrate, then release,\n'
                 '  * its private model allocations so historical regression tests are ASan clean. */\n'
                 ' return 0;\n'
                 '}\n'
                 "'''\n"
                 '\n'
                 '\n'
                 'def function(text, name):\n'
                 '    tokens = '
                 'r\'"(?:\\\\.|[^"\\\\])*"|\\\'(?:\\\\.|[^\\\'\\\\])*\\\'|/\\*[\\s\\S]*?\\*/|//[^\\n]*\'\n'
                 "    masked = re.sub(tokens, lambda m: ' ' * len(m.group()), text)\n"
                 "    found = list(re.finditer(r'(?m)^[A-Za-z_][\\w \\t*]*\\b' + re.escape(name) + "
                 "r'\\s*\\([^;{}]*\\)\\s*\\{', masked))\n"
                 '    if len(found) != 1:\n'
                 "        raise ValueError('Missing/ambiguous WTBL body: ' + name)\n"
                 "    start = found[0].start(); opening = masked.index('{', start); depth = 0\n"
                 "    for match in re.finditer('[{}]', masked[opening:]):\n"
                 "        depth += 1 if match.group() == '{' else -1\n"
                 '        if not depth:\n'
                 '            return text[start:opening + match.end()]\n'
                 "    raise ValueError('Unterminated WTBL body: ' + name)\n"
                 '\n'
                 '\n'
                 'def declarations(texts):\n'
                 '    pieces = []\n'
                 '    for name in SOURCE_MACRO_NAMES:\n'
                 "        values = re.findall(r'(?m)^#define\\s+' + re.escape(name) + r'\\s+[^\\n]+$', "
                 "texts['os'])\n"
                 '        if len(values) != 1:\n'
                 "            raise ValueError('Missing/ambiguous WTBL macro: ' + name)\n"
                 '        pieces.append(values[0])\n'
                 '    for key, names in SOURCE_ENUMS.items():\n'
                 '        for name in names:\n'
                 "            values = re.findall(r'(?m)^\\s*' + re.escape(name) + "
                 "r'\\s*=\\s*(?:0x[0-9A-Fa-f]+|[0-9]+)\\s*,', texts[key])\n"
                 '            if len(values) != 1:\n'
                 "                raise ValueError('Missing/ambiguous WTBL enum: ' + name)\n"
                 "            pieces.append('enum {' + values[0] + '};')\n"
                 '    for key, spans in SOURCE_DECLARATIONS.items():\n'
                 '        for begin, end in spans:\n'
                 '            if texts[key].count(begin) != 1 or texts[key].count(end) != 1:\n'
                 "                raise ValueError('Missing/ambiguous WTBL declaration')\n"
                 '            a = texts[key].index(begin); b = texts[key].index(end, a)\n'
                 '            pieces.append(texts[key][a:b + len(end)])\n'
                 "    return '\\n'.join(pieces)\n"
                 '\n'
                 '\n'
                 'def generate_source(texts):\n'
                 '    if set(texts) != set(SOURCE_PATHS):\n'
                 "        raise ValueError('Exact WTBL source set required')\n"
                 '    for key, fragments in SOURCE_FRAGMENTS.items():\n'
                 '        for fragment in fragments:\n'
                 '            if texts[key].splitlines().count(fragment) != 1:\n'
                 "                raise ValueError('Independent WTBL capacity declaration drift')\n"
                 '    for n, key in SOURCE_ONLY_FUNCTION_SOURCES.items():\n'
                 '        function(texts[key], n)\n'
                 '    admission = \'if (\' + \' && \'.join(\'strcmp(case_name,"\' + n + \'")\' for n in '
                 "CASE_NAMES) + ') return 91;'\n"
                 "    return PREFIX + declarations(texts) + '\\n' + "
                 "'\\n'.join(function(texts[FUNCTION_SOURCES[n]], n) for n in BODY_ORDER) + TRANSPORT + "
                 "SUFFIX.replace('CASE_ADMISSION', admission)\n"
                 '\n'
                 '\n'
                 'def function_manifest(texts):\n'
                 "    return {n: {'source': k, 'execution': 'whole-function', 'full_body_sha256': "
                 'hashlib.sha256(function(texts[k], n).encode()).hexdigest()} for n, k in '
                 'FUNCTION_SOURCES.items()}\n'
                 '\n'
                 '\n'
                 'def source_only_manifest(texts):\n'
                 "    return {n: {'source': k, 'execution': 'source-only-not-run', 'full_body_sha256': "
                 'hashlib.sha256(function(texts[k], n).encode()).hexdigest()} for n, k in '
                 'SOURCE_ONLY_FUNCTION_SOURCES.items()}\n'}


def coherent_fixture_aliases(inputs):
    """One coherent fixture file per physical path, matching the real reader."""
    groups={}
    for key,path in g.SOURCE_PATHS.items():groups.setdefault(path,[]).append(key)
    preferred=dict(native_boundary_fixture());preferred.update(WTBL_FIXTURE_INPUTS)
    fwd=g.SOURCE_ABI['native_boundaries']['fwd'];pci=g.SOURCE_ABI['native_boundaries']['pci'];wtbl=g.COMPONENTS['wtbl']
    fwd_functions={name for names in fwd['callers'].values()for name in names}
    all_functions=set(n for spec in g.COMPONENTS.values()for n in tuple(spec['functions'])+tuple(spec['source_only_functions']))
    all_functions.update(fwd['functions']);all_functions.update(fwd_functions);all_functions.update(pci['functions'])
    all_functions.update(('bus_add_driver','__synchronize_srcu','srcu_reschedule','process_srcu'))
    def body(text,name):
        try:return g.function(text,name)
        except ValueError:return None
    for path,keys in groups.items():
        if len(keys)<2:continue
        base=inputs[keys[0]]
        if path.endswith('.config')or'config'==Path(path).name:
            base='\n'.join(dict.fromkeys(line for key in keys for line in inputs[key].splitlines()))+'\n'
        elif'Makefile'in Path(path).name:
            for key in keys:
                if key in preferred:
                    for line in preferred[key].splitlines():
                        if line not in base.splitlines():base+='\n'+line+'\n'
        else:
            for key in keys:
                if key not in preferred:continue
                extra=preferred[key]
                for name in all_functions:
                    newer=body(extra,name)
                    if not newer:continue
                    older=body(base,name)
                    if older:
                        if name in fwd_functions and 'WIFI_FWD_GUARD(wf_fwd_snapshot);'not in older:
                            inner=newer[newer.index('{')+1:newer.rindex('}')];inner=re.sub(r'\breturn\s+0\s*;\s*$','',inner)
                            newer=older[:older.index('{')+1]+inner+older[older.index('{')+1:]
                        elif key not in WTBL_FIXTURE_INPUTS and name not in fwd['functions']:
                            continue
                        base=base.replace(older,newer,1)
                    else:base+='\n'+newer+'\n'
                # Preserve the actual packed spans and native initializer/struct regions.
                if key==wtbl['source_keys']['header']:
                    for begin,end in WTBL_FIXTURE_DATA['SOURCE_DECLARATIONS']['header']:
                        start=extra.index(begin);finish=extra.index(end,start)+len(end);value=extra[start:finish]
                        if begin in base and end in base:
                            start=base.index(begin);finish=base.index(end,start)+len(end);base=base[:start]+value+base[finish:]
                        else:
                            base=re.sub(r'(?m)^'+re.escape(begin)+r'[^\n]*\n?','',base);base+='\n'+value+'\n'
                    for fragment in WTBL_FIXTURE_DATA['SOURCE_FRAGMENTS']['header']:
                        if fragment not in base.splitlines():base+='\n'+fragment+'\n'
                for pattern in (r'^static\s+struct\s+pci_driver\s+rt_pci_driver\s*=\s*\{',r'^struct\s+wifi_fwd_func_table\s*\{',r'^struct\s+wifi_fwd_read_guard\s*\{'):
                    if re.search(pattern,g.native_mask(extra),re.M):
                        value=g.native_declaration(extra,pattern)
                        if re.search(pattern,g.native_mask(base),re.M):base=base.replace(g.native_declaration(base,pattern),value,1)
                        else:base+='\n'+value+'\n'
                macro=re.search(r'(?m)^#define WIFI_FWD_GUARD\(name\)[\s\S]*?(?=\n\n)',extra)
                if macro and '#define WIFI_FWD_GUARD(name)'not in base:base+='\n'+macro[0]+'\n\n'
                for line in re.findall(r'(?m)^#define\s+\w+[^\n]*',extra):
                    name=re.match(r'#define\s+(\w+)',line)[1]
                    if not re.search(r'(?m)^#define\s+'+re.escape(name)+r'\b',base):base+='\n'+line+'\n'
                for enum in re.findall(r'enum \{\s*(?:HOST2N9|EXT_CID|EXT_CMD_ID_WTBL_UPDATE|INIT_CMD_SET_AND_WAIT_RETRY_RSP|BA_SESSION_RECP)\s*=\s*(?:0x[0-9A-Fa-f]+|[0-9]+)\s*,\s*\};',extra):
                    name=re.search(r'\b(HOST2N9|EXT_CID|EXT_CMD_ID_WTBL_UPDATE|INIT_CMD_SET_AND_WAIT_RETRY_RSP|BA_SESSION_RECP)\b',enum)[1]
                    if not re.search(r'(?m)^\s*'+name+r'\s*=',base):base+='\n'+enum+'\n'
        for key in keys:inputs[key]=base
    return inputs


def fixture():
    inputs={k:'inert '+k for k in g.SOURCE_PATHS};specs=copy.deepcopy(g.COMPONENTS);models={}
    for c,s in specs.items():
        opts=[o for _,o in g.CASES if o['component']==c]
        d={'SOURCE_PATHS':s['paths'],'FUNCTION_SOURCES':s['functions'],'BODY_ORDER':tuple(s['functions']),
           'CASE_NAMES':tuple(o['selector']for o in opts),
           'EXPECTED_ROWS':{o['selector']:g.EXPECTED[c+':current:'+o['selector']]for o in opts},
           'PREFIX':'/* inert model */\n','SUFFIX':'\n/* CASE_ADMISSION */\n'}
        d['SOURCE_ONLY_FUNCTION_SOURCES']=s.get('source_only_functions',{})
        if c in g.SOURCE_ABI.get('model_variants',{}):d['MODEL_VARIANT']=copy.deepcopy(g.SOURCE_ABI['model_variants'][c])
        if c=='hwcmd':
            d['MODEL_BOUNDARY']=copy.deepcopy(g.SOURCE_ABI['hwcmd_boundary'])
            d['SOURCE_DECLARATIONS']=copy.deepcopy(g.SOURCE_ABI['hwcmd_declarations'])
            d['STATUS_DECLARATIONS']=copy.deepcopy(g.SOURCE_ABI['hwcmd_status_declarations'])
            d['PREFIX']='SOURCE_DEFINITIONS\n'
        models[c]=d;s['model_data_sha256']=g.model_data_hash(d)
        inputs[s['harness_key']]='\n'.join(k+'='+repr(v)for k,v in d.items())+'\ndef generate_source():\n raise AssertionError("Do not execute generator")\n'
        for name,local in {**s['functions'],**s.get('source_only_functions',{})}.items():
            key=s['source_keys'][local]
            if inputs[key].startswith('inert '):inputs[key]=''
            body='NDIS_STATUS '+name+'(void) { return 0; }\n'
            if name=='rt_pci_probe':body='static int DEVINIT rt_pci_probe(struct pci_dev *pdev) {\n'+g.SOURCE_ABI['probe_rejection_fragment']+'\nreturn pci_enable_device(pdev);\n}\n'
            if name=='tm_init':body='NDIS_STATUS tm_init(void) {\n'+'\n'.join(g.SOURCE_ABI['cmwq_runtime_selector_fragments'])+'\nreturn 0;\n}\n'
            if name in g.SOURCE_ABI['beacon_lifecycle_fragments']:
                direct=''if name=='RTMPFreeAdapter'else'struct _PCI_HIF_T *hif = &pAd->PciHif;\n'
                body='NDIS_STATUS '+name+'(void) {\n'+direct+'\n'.join(g.SOURCE_ABI['beacon_lifecycle_fragments'][name])+'\nreturn 0;\n}\n'
            if name in g.SOURCE_ABI.get('wdev_retirement_fragments',{}):
                fragments='\n'.join(g.SOURCE_ABI['wdev_retirement_fragments'][name])
                # Fragment-order fixtures are parsed, never compiled/executed.
                # Supply any closing loop braces omitted by the selected fragments.
                closing='}\n'*(fragments.count('{')-fragments.count('}'))
                body='NDIS_STATUS '+name+'(void) {\n'+fragments+'\n'+closing+'return 0;\n}\n'
            if body not in inputs[key]:inputs[key]+=body
    hw=specs['hwcmd']
    for pattern,key in g.SOURCE_ABI['hwcmd_declarations'].items():
        inputs[hw['source_keys'][key]]+='\n'+HWCMD_DECLARATION_FIXTURES[pattern]+'\n'
    inputs[hw['source_keys']['kernel_task']]=g.SOURCE_ABI['hwcmd_threadfn_skip_fragment']
    inputs[specs['probe']['source_keys']['header']]+='\nBOOLEAN BcnContentLockInitialized;\n'
    inputs['os_header']='#define NDIS_STATUS_SUCCESS 0x00\n#define NDIS_STATUS_FAILURE 0x01\n#define NDIS_STATUS_INVALID_DATA 0x02\n#define NDIS_STATUS_RESOURCES 0x03\n#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)\n#define KTHREAD_SUPPORT 1\n#endif\n'
    inputs[specs['hwcmd']['source_keys']['os_header']]=inputs['os_header']
    inputs['wifi_config']='\n'.join(g.SOURCE_ABI['enabled_config']+g.SOURCE_ABI['disabled_config'])+'\n'
    make='DRV_NAME = mt_7615e\nifeq ($(CONFIG_CHIP_MT7615E),y)\nEXTRA_CFLAGS += -DMT7615 -DRTMP_MAC_PCI -DRTMP_PCI_SUPPORT -DLINUX\nendif\n'
    inputs['flags']=inputs['wifi_makefile']=make
    inputs['kernel_makefile']='VERSION = 4\nPATCHLEVEL = 4\nKBUILD_CFLAGS += -fno-strict-aliasing\n'
    inputs['driver_config']='HAS_RESOURCE_PRE_ALLOC=y\nHAS_RX_CUT_THROUGH=n\nHAS_CUT_THROUGH_DBG=n\nWFLAGS += -DERR_RECOVERY -DLINUX\n'
    inputs['chip']='MT7615_ChipCap.qm = FAST_PATH_QM;\nMT7615_ChipCap.qm_tm = TASKLET_METHOD;\nMT7615_ChipCap.hif_tm = TASKLET_METHOD;\n'+g.SOURCE_ABI['chip_hif_type_fragment']+'\n'
    inputs['irq_shim']=g.SOURCE_ABI['irq_quarantine_fragment']+'\n'
    inputs['module_core']='#define MODULE_REF_BASE\t1\n'+'\n'.join(v for n,v in KERNEL_REFERENCE_BODIES.items()if n!='module_is_live')+'\n'+g.SOURCE_ABI['no_force_unload_fragment']+'\n'
    inputs['module_header']=KERNEL_REFERENCE_BODIES['module_is_live']+'\n'+'\n'.join(g.SOURCE_ABI['module_reference_declarations'])+'\n'
    inputs[specs['dma']['source_keys']['chip_header']]='NDIS_STATUS (*FwInit)(struct _RTMP_ADAPTER *pAd);\nBOOLEAN (*hif_wait_dma_idle)(struct _RTMP_ADAPTER *pAd, INT round, INT wait_us);\n'
    by_path={}
    for key,path in g.SOURCE_PATHS.items():by_path.setdefault(path,[]).append(key)
    for keys in by_path.values():
        if len(keys)==1:continue
        bodies={};other=[];declarations={}
        names={name for spec in specs.values() for name in
               (*spec['functions'],*spec.get('source_only_functions',{}))
               if any(spec['paths'][spec.get('functions',{}).get(name,spec.get('source_only_functions',{}).get(name))]
                      ==g.SOURCE_PATHS[key]for key in keys)}
        for key in keys:
            remainder=inputs[key]
            for name in names:
                try:body=g.function(remainder,name)
                except ValueError:continue
                if name in bodies:assert bodies[name]==body
                bodies[name]=body;remainder=remainder.replace(body,'')
            for pattern in g.SOURCE_ABI["hwcmd_declarations"]:
                for declaration in re.findall(pattern,remainder,re.M):
                    token="/* DECL "+g.sha(declaration.encode())+" */"
                    declarations[token]=declaration;remainder=remainder.replace(declaration,token)
            other.extend(remainder.splitlines())
        text='\n'.join(dict.fromkeys(other))+'\n'+'\n'.join(bodies.values())+'\n'
        for token,declaration in declarations.items():text=text.replace(token,declaration)
        for key in keys:inputs[key]=text
    inputs.update(native_boundary_fixture())
    inputs.update(WTBL_FIXTURE_INPUTS)
    models['wtbl']=copy.deepcopy(WTBL_FIXTURE_DATA)
    specs['wtbl']['model_data_sha256']=g.model_data_hash(models['wtbl'])
    inputs=coherent_fixture_aliases(inputs)
    return inputs,specs,models


def compiled_fixture():
    inputs,_,_=fixture();allnames=tuple(dict.fromkeys(n for _,_,names in g.COMPILED_OBJECTS.values()for n in names))
    mod=module_elf(allnames);agg=g.BUILT_MODULE.removesuffix('.ko')+'.o'
    files={'target-wifi-built.ko':mod,'target-wifi-shipped.ko':mod,
      'target-wifi-module.cmd':('ld -r -o '+g.BUILT_MODULE+' '+agg).encode(),
      'target-wifi-link.cmd':('ld -r -o '+agg+' '+' '.join(v[0]for v in g.COMPILED_OBJECTS.values())).encode()}
    for label,(path,_,names)in g.COMPILED_OBJECTS.items():
        stem='target-init-dma-lifecycle-'+label;files[stem+'.o']=module_elf(names)
        files[stem+'.cmd']=('gcc '+' '.join(g.REQUIRED_OBJECT_FLAGS)+' -c '+path[:-2]+'.c -o '+path).encode()
    parent={'schema_version':1,'status':'PASS','profile':'k2p-4.4','phase':'final-module-image-reference-bound',
      'source_sha256':{k:g.sha(inputs[k].encode())for k in ('wifi_makefile','wifi_config')},
      'required_cases':['factory'+str(i)for i in range(49)],'checks':[{}for _ in range(49)],
      'kernel_reference':{'image_sha256':'a'*64},'module_binding':{'status':'PASS',
      'exports':{n:g.sha(files[n])for n in g.PARENT_EXPORTS},'built_module':{'ELF':{'sha256':g.sha(mod)}},
      'shipped_module':{'ELF':{'sha256':g.sha(mod)},'path':g.SHIPPED_MODULE}}}
    return inputs,files,parent


def integer_paths(value, path=()):
    if type(value) is int: yield path
    elif type(value) is list:
        for key,item in enumerate(value): yield from integer_paths(item,path+(key,))
    elif type(value) is dict:
        for key,item in value.items(): yield from integer_paths(item,path+(key,))

def set_path(value,path,replacement):
    for key in path[:-1]:value=value[key]
    value[path[-1]]=replacement

class InitDmaGateTests(unittest.TestCase):
    def rows(self):return [{'case':n,'inputs':copy.deepcopy(o),'observed':copy.deepcopy(g.EXPECTED[n])}for n,o in g.CASES]

    def test_complete_pci_callback_qualifiers_and_braces_in_literals(self):
        for qualifier in ('DEVINIT','DEVEXIT'):
            body='static int '+qualifier+' lifecycle(void) { char close=\'}\'; const char *s="{"; /* } */ return close+s[0]; }'
            text='/* lifecycle() { } */\n'+body+'\nint unrelated(void) { return 0; }\n'
            self.assertEqual(g.function(text,'lifecycle'),body)
            with self.assertRaises(ValueError):g.function(text+'\n'+body,'lifecycle')

    def test_source_only_pointer_return_signatures_bind_complete_definitions(self):
        for signature,name in [('MAC_TABLE_ENTRY *MacTableInsertEntry(void)','MacTableInsertEntry'),('struct radio_dev *RcAcquiredBandForObj(void)','RcAcquiredBandForObj')]:
            body=signature+' { return 0; }'
            self.assertEqual(g.function(signature+';\n'+body,name),body)
            with self.assertRaises(ValueError):g.function(body+'\n'+body,name)

    def test_corrected_last_vif_close_failure_rejects_the_historical_unquarantined_row(self):
        name='vif:current:down-callback-error'
        expected=[-1,0,0,0,1,1,1,1,1,1,1,0,0,0,1,1,1,0]
        self.assertEqual(g.EXPECTED[name],expected)
        self.assertIs(type(g.EXPECTED[name][6]),int)
        rows=[dict(case=n,inputs=copy.deepcopy(options),observed=copy.deepcopy(g.EXPECTED[n]))for n,options in g.CASES]
        g.validate_records(rows)
        next(row for row in rows if row['case']==name)['observed']=[-1,0,0,0,1,1,0,1,1,1,1,0,0,0,1,1,1,0]
        with self.assertRaises(ValueError):g.validate_records(rows)

    def test_exact_current_eleven_component_source_and_object_contract(self):
        g.validate_contract();g.validate_records(self.rows())
        self.assertEqual((len(g.CASES),len(g.SOURCE_PATHS),len(g.COMPILED_OBJECTS)),(822, 259, 48))
        self.assertEqual((len(g.compiled_export_names()),sum(len(row[2])for row in g.COMPILED_OBJECTS.values())),(96, 230))
        self.assertEqual(set(g.COMPONENTS),{'init','dma','unwind','quarantine','command','vif','probe','cmwq','resource','wdev','hwcmd','wsys','terminal','tlv','wtbl'})
        self.assertNotIn('-DCONFIG_PROPRIETARY_DRIVER',g.REQUIRED_OBJECT_FLAGS)
        relative,key,names=g.COMPILED_OBJECTS['probe_hdev']
        self.assertIn('hc_get_os_cookie',names)
        altered=tuple('other_accessor'if name=='hc_get_os_cookie'else name for name in names)
        with patch.dict(g.COMPILED_OBJECTS,{'probe_hdev':(relative,key,altered)}),self.assertRaises(ValueError):
            g.validate_contract()

    def test_every_typed_cell_schema_order_and_inventory_is_required(self):
        rows=self.rows()
        for bad in (rows[:-1],rows+rows[:1],list(reversed(rows))):
            with self.assertRaises(ValueError):g.validate_records(bad)
        for i,row in enumerate(rows):
            for path in integer_paths(row['observed']):
                bad=copy.deepcopy(rows);set_path(bad[i]['observed'],path,True)
                with self.subTest(case=row['case'],column=path),self.assertRaises(ValueError):g.validate_records(bad)
        index=next(i for i,r in enumerate(rows)if r['inputs']['component']=='tlv' and r['observed'][-1])
        sends=rows[index]['observed'][-1]
        for altered in ([],sends+sends[:1],list(reversed(sends)) if len(sends)>1 else sends+[sends[0]],sends[0]):
            bad=copy.deepcopy(rows);bad[index]['observed'][-1]=altered
            with self.subTest(tlv_sends=altered),self.assertRaises(ValueError):g.validate_records(bad)
        bad=copy.deepcopy(rows);bad[0]['extra']=0
        with self.assertRaises(ValueError):g.validate_records(bad)

    def test_literal_parser_never_runs_source_generator_or_top_level_code(self):
        for type_name in ('u32','unsigned char','struct END_DEVICE *','u8','UINT16','int __init','void __exit','struct wifi_fwd_read_guard','struct cmd_msg *'):
            declaration=type_name+' mdio_fixture(void) { /* } */ return 0; }'
            self.assertEqual(g.function(declaration,'mdio_fixture'),declaration)
            with self.assertRaises(ValueError):g.function(declaration+'\n'+declaration,'mdio_fixture')
        inputs,specs,models=fixture()
        for c,s in specs.items():self.assertEqual(g.literal_data(inputs[s['harness_key']]),models[c])
        for tail in ('\nX=dangerous()','\nraise RuntimeError()','\nimport subprocess','\nX={"a":1,"a":2}'):
            with self.assertRaises((ValueError,KeyError)):g.literal_data(inputs[specs['init']['harness_key']]+tail)

    def test_three_renderers_keep_every_complete_function(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):
            for c,s in specs.items():
                code,manifest=g.generate_component(inputs,c)
                for n,key in s['functions'].items():
                    body=g.function(inputs[s['source_keys'][key]],n);self.assertEqual(code.count(body),1)
                    self.assertEqual(manifest[n]['full_body_sha256'],g.sha(body.encode()));self.assertEqual(manifest[n]['execution'],'whole-function')
                self.assertNotIn('CASE_ADMISSION',code)

    def test_reviewed_actual_prototype_marker_is_replaced_once_and_still_pinned(self):
        inputs,specs,models=fixture()
        component='init';spec=specs[component];data=copy.deepcopy(models[component])
        data['PREFIX']+='FUNCTION_DECLARATIONS\n'
        inputs[spec['harness_key']]='\n'.join(k+'='+repr(v)for k,v in data.items())
        spec['model_data_sha256']=g.model_data_hash(data)
        with patch.dict(g.COMPONENTS,specs):code,_=g.generate_component(inputs,component)
        self.assertNotIn('FUNCTION_DECLARATIONS',code)
        for name,key in spec['functions'].items():
            signature=g.function(inputs[spec['source_keys'][key]],name).split('{',1)[0].rstrip()+';'
            self.assertEqual(code.count(signature),1)
        data['PREFIX']+='FUNCTION_DECLARATIONS'
        inputs[spec['harness_key']]='\n'.join(k+'='+repr(v)for k,v in data.items())
        spec['model_data_sha256']=g.model_data_hash(data)
        with patch.dict(g.COMPONENTS,specs),self.assertRaises(ValueError):g.generate_component(inputs,component)

    def test_resealed_wrong_path_rows_admission_and_model_pin_fail(self):
        inputs,specs,models=fixture()
        for fault in ('path','rows','admission','model'):
            local=copy.deepcopy(inputs);current=copy.deepcopy(specs);d=copy.deepcopy(models['init'])
            if fault=='path':d['SOURCE_PATHS'][next(iter(d['SOURCE_PATHS']))]='wrong.c'
            elif fault=='rows':d['EXPECTED_ROWS'][next(iter(d['EXPECTED_ROWS']))][0]=True
            elif fault=='admission':d['SUFFIX']+='CASE_ADMISSION'
            else:d['PREFIX']+='changed'
            local[current['init']['harness_key']]='\n'.join(k+'='+repr(v)for k,v in d.items())
            if fault!='model':current['init']['model_data_sha256']=g.model_data_hash(d)
            with patch.dict(g.COMPONENTS,current),self.subTest(fault=fault),self.assertRaises(ValueError):g.generate_component(local,'init')

    def test_source_profile_close_reopen_and_kernel_stop_order(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):self.assertTrue(g.source_selection(inputs)['current_K2P_profile'])
        for key,old,new in [('chip','TASKLET_METHOD','CMWQ_METHOD'),('kernel_makefile','-fno-strict-aliasing','-fstrict-aliasing'),('driver_config','HAS_RESOURCE_PRE_ALLOC=y','HAS_RESOURCE_PRE_ALLOC=n'),('os_header','NDIS_STATUS_SUCCESS 0x00','NDIS_STATUS_SUCCESS 0x01'),('quarantine_pci',g.SOURCE_ABI['probe_rejection_fragment'],''),('irq_shim',g.SOURCE_ABI['irq_quarantine_fragment'],'if (pAd == NULL) {')]:
            with patch.dict(g.COMPONENTS,specs),self.subTest(key=key),self.assertRaises(ValueError):g.source_selection(dict(inputs,**{key:inputs[key].replace(old,new)}))
        bad=dict(inputs);bad['chip']=inputs['chip'].replace(g.SOURCE_ABI['chip_hif_type_fragment'],'')
        with patch.dict(g.COMPONENTS,specs),self.assertRaises(ValueError):g.source_selection(bad)
        probe=specs['probe']
        for name,fragments in g.SOURCE_ABI['beacon_lifecycle_fragments'].items():
            key=probe['source_keys'][probe['functions'][name]]
            for fragment in fragments:
                bad=dict(inputs);bad[key]=inputs[key].replace(fragment,'')
                with patch.dict(g.COMPONENTS,specs),self.subTest(function=name,fragment=fragment),self.assertRaises(ValueError):
                    g.source_selection(bad)
            bad=dict(inputs);bad[key]=inputs[key].replace('&pAd->PciHif','hc_get_hif_ctrl(pAd->hdev_ctrl)')
            with patch.dict(g.COMPONENTS,specs),self.subTest(function=name,direct_hif=False),self.assertRaises(ValueError):
                g.source_selection(bad)
            a,b=fragments[-2:];bad=dict(inputs)
            bad[key]=inputs[key].replace(a,'BEACON_ORDER_MARKER').replace(b,a).replace('BEACON_ORDER_MARKER',b)
            with patch.dict(g.COMPONENTS,specs),self.subTest(function=name,owner_order=False),self.assertRaises(ValueError):
                g.source_selection(bad)
        key=probe['source_keys']['header'];bad=dict(inputs)
        bad[key]=inputs[key].replace('BOOLEAN BcnContentLockInitialized;','')
        with patch.dict(g.COMPONENTS,specs),self.assertRaises(ValueError):g.source_selection(bad)
        key=probe['source_keys'][probe['functions']['RTMPFreeAdapter']];bad=dict(inputs)
        bad[key]=inputs[key].replace('hif = &pAd->PciHif;','NdisFreeSpinLock(&pAd->early_lock);\nhif = &pAd->PciHif;')
        with patch.dict(g.COMPONENTS,specs),self.assertRaisesRegex(ValueError,'every adapter lock'):g.source_selection(bad)

    def test_optional_cmwq_is_compiled_but_not_current_runtime_or_real_workqueue_execution(self):
        inputs,specs,models=fixture()
        with patch.dict(g.COMPONENTS,specs):proof=g.source_selection(inputs)
        cmwq=proof['cmwq_variant_contract']
        self.assertIs(cmwq['CMWQ_present_in_nonproprietary_compilation'],True)
        self.assertIs(cmwq['current_K2P_runtime_selects_CMWQ'],False)
        self.assertIs(cmwq['inert_CMWQ_model_execution_required'],True)
        self.assertIs(cmwq['real_Linux_workqueue_execution_performed'],False)
        self.assertIs(cmwq['FQ_SCH_SUPPORT_forbidden_in_actual_objects'],True)
        self.assertEqual(cmwq['current_K2P_qm_method'],cmwq['current_K2P_hif_method'])
        self.assertEqual(cmwq['current_K2P_qm_method'],'TASKLET_METHOD')
        key=specs['init']['source_keys']['tm']
        for fragment in g.SOURCE_ABI['cmwq_runtime_selector_fragments']:
            bad=dict(inputs);bad[key]=inputs[key].replace(fragment,'')
            with patch.dict(g.COMPONENTS,specs),self.subTest(fragment=fragment),self.assertRaises(ValueError):g.source_selection(bad)
        for component in ('probe','cmwq','resource','wdev'):
            current=copy.deepcopy(specs);bad=dict(inputs);data=copy.deepcopy(models[component])
            data['MODEL_VARIANT'][next(iter(data['MODEL_VARIANT']))]='changed'
            bad[current[component]['harness_key']]='\n'.join(k+'='+repr(v)for k,v in data.items())
            current[component]['model_data_sha256']=g.model_data_hash(data)
            with patch.dict(g.COMPONENTS,current),self.subTest(component=component),self.assertRaises(ValueError):g.source_selection(bad)

    def test_probe_and_cmwq_components_keep_full_current_functions_and_source_owners(self):
        probe=g.COMPONENTS['probe'];cmwq=g.COMPONENTS['cmwq']
        for name,suffix in [('rt_pci_probe','os/linux/pci_main_dev.c'),('RTMPAllocAdapterBlock','embedded/common/rtmp_init.c')]:
            self.assertIn(name,probe['functions'])
            self.assertTrue(probe['paths'][probe['functions'][name]].endswith(suffix))
        self.assertTrue({'tm_init','tm_exit','tm_quiesce','tm_wq_prepare','tm_wq_abort','tm_wq_publish','tm_wq_destroy'}<=set(cmwq['functions']))
        self.assertTrue(set(g.SOURCE_ABI['cmwq_compiled_entrypoints'])<=set(g.COMPILED_OBJECTS['tm'][2]))
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):variant=g.source_selection(inputs)['probe_variant_contract']
        self.assertIs(variant['model_uses_current_source_not_exact_current_preprocessor_profile'],True)
        self.assertIs(variant['inert_model_forces_MULTI_INF_SUPPORT'],True)
        self.assertIs(variant['actual_K2P_MULTI_INF_SUPPORT_enabled'],False)
        self.assertIs(variant['default_MIPS_model_MSI_enabled'],False)
        self.assertIs(variant['actual_K2P_kernel_MSI_enabled'],False)
        self.assertEqual(variant['actual_K2P_hif_type'],'HIF_MT')
        self.assertIs(variant['inert_beacon_model_HIF_MT'],True)
        self.assertIs(variant['beacon_content_lock_has_explicit_owner_flag'],True)
        self.assertIs(variant['beacon_destructor_precedes_all_adapter_lock_and_hdev_retirement'],True)
        self.assertIs(variant['beacon_fixture_is_real_kernel_ABI'],False)
        self.assertIs(variant['beacon_packet_and_lock_operations_are_inert_seams'],True)
        self.assertEqual(tuple(g.COMPILED_OBJECTS['probe_bcn'][2]),('bcn_buf_init','bcn_buf_deinit'))
        for name in g.COMPILED_OBJECTS['probe_bcn'][2]:
            self.assertEqual(probe['functions'][name],'bcn')
        for row in (
                ('drivers/net/wireless/mediatek/mt7615/embedded/common/other.o','probe_bcn',('bcn_buf_init','bcn_buf_deinit')),
                ('drivers/net/wireless/mediatek/mt7615/embedded/common/bcn.o','probe_free',('bcn_buf_init','bcn_buf_deinit')),
                ('drivers/net/wireless/mediatek/mt7615/embedded/common/bcn.o','probe_bcn',('other_beacon_init','bcn_buf_deinit'))):
            with patch.dict(g.COMPILED_OBJECTS,{'probe_bcn':row}),self.subTest(beacon_object=row),self.assertRaises(ValueError):
                g.validate_contract()
        self.assertNotIn('-DHIF_MT',g.REQUIRED_OBJECT_FLAGS)
        self.assertIn('-DMULTI_INF_SUPPORT',g.FORBIDDEN_OBJECT_FLAGS)
        self.assertEqual(len(g.COMPONENTS['resource']['functions']),17)
        for name in ('WcInit','WcExit','HdevHwResourceInit','hdev_resource_init','alloc_chip_cap_dep_data',
                     'alloc_chip_cap_dep_data_cmm','alloc_chip_cap_dep_data_pci','RtmpRaDevCtrlInit','RTMPInitPCIeDevice'):
            self.assertIn(name,g.COMPONENTS['resource']['functions'])
        with patch.dict(g.COMPONENTS,specs):resource=g.source_selection(inputs)['resource_variant_contract']
        self.assertIs(resource['current_IP_ASSEMBLY_enabled'],True)
        self.assertEqual(resource['inert_model_ring_counts'],[2,2])
        self.assertEqual(resource['NDIS_success_status'],0)
        self.assertIs(resource['real_driver_kernel_or_device_execution_performed'],False)
        self.assertIs(resource['hc_get_os_cookie_fixture_seam'],True)
        self.assertIs(resource['opaque_consumer_public_accessor_required'],True)

    def test_wdev_retirement_interface_order_and_actual_active_callers_are_required(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):claim=g.source_selection(inputs)['wdev_variant_contract']
        self.assertEqual(claim['complete_current_source_functions'],15)
        self.assertEqual(claim['inert_model_MBSS_slots'],3)
        for name in ('current_K2P_MBSS_enabled','current_K2P_APCLI_enabled',
                     'all_interface_close_precedes_wdev_and_config_retirement',
                     'published_main_wdev_retired_after_detach_before_config',
                     'failed_retirement_preserves_wdev_config_and_netdev',
                     'beacon_owners_retained_until_final_adapter_release'):
            self.assertIs(claim[name],True)
        for name in ('current_K2P_WDS_enabled','current_K2P_SNIFFER_enabled',
                     'real_netdev_kernel_or_device_execution_performed',
                     'fixture_struct_layout_is_real_kernel_ABI'):
            self.assertIs(claim[name],False)
        for name,fragments in g.SOURCE_ABI['wdev_retirement_fragments'].items():
            local=specs['wdev']['functions'][name];alias=specs['wdev']['source_keys'][local]
            for fragment in fragments:
                bad=dict(inputs);bad[alias]=inputs[alias].replace(fragment,'')
                with patch.dict(g.COMPONENTS,specs),self.subTest(function=name,fragment=fragment),self.assertRaises(ValueError):
                    g.source_selection(bad)
            a,b=fragments[-2:];bad=dict(inputs)
            bad[alias]=inputs[alias].replace(a,'WDEV_STAGE_MARKER').replace(b,a).replace('WDEV_STAGE_MARKER',b)
            with patch.dict(g.COMPONENTS,specs),self.subTest(function=name,order=False),self.assertRaises(ValueError):g.source_selection(bad)
        self.assertIn('-DAPCLI_SUPPORT',g.REQUIRED_OBJECT_FLAGS)
        self.assertIn('-DMBSS_SUPPORT',g.REQUIRED_OBJECT_FLAGS)
        self.assertTrue({'-DWDS_SUPPORT','-DCONFIG_SNIFFER_SUPPORT','-DSNIFFER_SUPPORT'}<=set(g.FORBIDDEN_OBJECT_FLAGS))
        for label,names in [('wdev_mbss',('MBSS_Init','MBSS_Remove')),('wdev_apcli',('APCli_Init','ApCli_Remove','apcli_link_up')),
                            ('wdev_vendor',('init_vie_ctrl','deinit_vie_ctrl','add_vie','find_oui_oitype'))]:
            self.assertEqual(tuple(g.COMPILED_OBJECTS[label][2]),names)
        body='PNET_DEV RtmpPhyNetDevInit(void *pAd, void *ops) { return NULL; }'
        self.assertEqual(g.function(body,'RtmpPhyNetDevInit'),body)

    def test_every_compiled_optional_workqueue_callback_is_required_by_actual_object_binding(self):
        inputs,files,parent=compiled_fixture()
        for label,required in [('tm',g.SOURCE_ABI['cmwq_compiled_entrypoints']),('probe_bcn',('bcn_buf_init','bcn_buf_deinit')),('wdev_mbss',('MBSS_Init','MBSS_Remove')),('wdev_apcli',('APCli_Init','ApCli_Remove','apcli_link_up')),('wdev_vendor',('init_vie_ctrl','deinit_vie_ctrl','add_vie','find_oui_oitype'))]:
            _,_,names=g.COMPILED_OBJECTS[label]
            for name in required:
                bad=dict(files);bad['target-init-dma-lifecycle-'+label+'.o']=module_elf(tuple(n for n in names if n!=name))
                with self.subTest(callback=name,location='object'),self.assertRaisesRegex(ValueError,'symbol'):
                    g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),bad,g.spi.inspect_elf)
                allnames=tuple(dict.fromkeys(n for _,_,ns in g.COMPILED_OBJECTS.values()for n in ns if n!=name))
                bad=dict(files);p=copy.deepcopy(parent);mod=module_elf(allnames)
                for member,field in [('target-wifi-built.ko','built_module'),('target-wifi-shipped.ko','shipped_module')]:
                    bad[member]=mod;p['module_binding'][field]['ELF']['sha256']=g.sha(mod)
                p['module_binding']['exports']={n:g.sha(bad[n])for n in g.PARENT_EXPORTS}
                with self.subTest(callback=name,location='module'),self.assertRaisesRegex(ValueError,'symbol'):
                    g.compiled_binding_from_bytes(inputs,json.dumps(p).encode(),bad,g.spi.inspect_elf)

    def test_actual_kernel_module_reference_sources_and_selected_unload_branch(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):proof=g.source_selection(inputs)
        self.assertIs(proof['module_unload_configured'],True)
        self.assertIs(proof['forced_module_unload_configured'],False)
        self.assertIs(proof['kernel_reference_functions_executed'],False)
        self.assertEqual(set(proof['kernel_module_reference_manifest']),set(KERNEL_REFERENCE_BODIES))
        for row in proof['kernel_module_reference_manifest'].values():
            self.assertEqual(row['execution'],'source-only-not-run')
        for key,old,new in (
            ('wifi_config','CONFIG_MODULE_UNLOAD=y','# CONFIG_MODULE_UNLOAD is not set'),
            ('wifi_config','# CONFIG_MODULE_FORCE_UNLOAD is not set','CONFIG_MODULE_FORCE_UNLOAD=y'),
            ('module_core','return -EWOULDBLOCK;','return 0;'),
            ('module_core','module_is_live(module) &&','true &&'),
            ('module_core','atomic_sub_return(MODULE_REF_BASE,','atomic_sub_return(0,'),
            ('module_core','return 0;\n}\n#endif /* CONFIG_MODULE_FORCE_UNLOAD */','return 1;\n}\n#endif /* CONFIG_MODULE_FORCE_UNLOAD */'),
            ('module_header','extern bool try_module_get(','extern int try_module_get(')):
            self.assertIn(old,inputs[key])
            with patch.dict(g.COMPONENTS,specs),self.subTest(key=key,old=old),self.assertRaises(ValueError):
                g.source_selection(dict(inputs,**{key:inputs[key].replace(old,new)}))

    def test_exact_sixteen_actual_exports_and_module_parent_binding(self):
        inputs,files,parent=compiled_fixture();expected={'target-init-dma-lifecycle-'+n+e for n in g.COMPILED_OBJECTS for e in ('.o','.cmd')}
        self.assertEqual(g.compiled_export_names(),expected);self.assertEqual(len(expected),2*len(g.COMPILED_OBJECTS))
        p=g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),files,g.spi.inspect_elf)
        self.assertEqual(set(p['objects']),set(g.COMPILED_OBJECTS));self.assertEqual(set(p['compiled_exports_sha256']),expected)
        for name in expected:
            bad=dict(files);bad.pop(name)
            with self.subTest(missing=name),self.assertRaises(ValueError):g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),bad,g.spi.inspect_elf)
        with self.assertRaises(ValueError):g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),dict(files,**{'target-init-dma-lifecycle-pci.o':b'old'}),g.spi.inspect_elf)

    def test_resealed_symbol_command_flags_and_parent_corruption_fail(self):
        inputs,files,parent=compiled_fixture()
        for fault in ('symbol','aggregate','parent-source','parent-cases','parent-phase',*g.FORBIDDEN_OBJECT_FLAGS,*g.REQUIRED_OBJECT_FLAGS):
            current,p=copy.deepcopy(files),copy.deepcopy(parent);path,_,names=g.COMPILED_OBJECTS[next(iter(g.COMPILED_OBJECTS))];stem='target-init-dma-lifecycle-'+next(iter(g.COMPILED_OBJECTS))
            if fault=='symbol':current[stem+'.o']=module_elf(names[:-1])
            elif fault=='aggregate':current['target-wifi-link.cmd']=current['target-wifi-link.cmd'].replace(path.encode(),b'wrong.o')
            elif fault=='parent-source':p['source_sha256']['wifi_config']='b'*64
            elif fault=='parent-cases':p['required_cases']=p['required_cases'][:-1]
            elif fault=='parent-phase':p['phase']='early-source-only'
            elif fault in g.FORBIDDEN_OBJECT_FLAGS:current[stem+'.cmd']+=(' '+fault).encode()
            else:current[stem+'.cmd']=current[stem+'.cmd'].replace(fault.encode(),b'')
            p['module_binding']['exports']={n:g.sha(current[n])for n in g.PARENT_EXPORTS}
            with self.subTest(fault=fault),self.assertRaises(ValueError):g.compiled_binding_from_bytes(inputs,json.dumps(p).encode(),current,g.spi.inspect_elf)

    def test_json_and_reader_reject_duplicates_nonfinite_alias_fifo_and_limit(self):
        for text in ('{"a":1,"a":2}','{"a":NaN}'):
            with self.assertRaises(ValueError):g.decode_json(text)
        with tempfile.TemporaryDirectory(prefix='init-dma-gate-reader-')as t:
            root=Path(t);f=root/'f';f.write_bytes(b'DATA');self.assertEqual(g.read_regular(f,4),b'DATA')
            alias=root/'alias';alias.symlink_to(f)
            with self.assertRaises((OSError,ValueError)):g.read_regular(alias,4)
            fifo=root/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError):g.read_regular(fifo,4)
            with self.assertRaises(ValueError):g.read_regular(f,3)

    def check_mode(self,final):
        inputs,specs,_=fixture();_,files,parent=compiled_fixture()
        with tempfile.TemporaryDirectory(prefix='init-dma-gate-private-mode-')as t:
            root=Path(t);trunk=root/'trunk';trunk.mkdir();(trunk/'.config').write_text('CONFIG_LINUXDIR=linux-4.4.x\nCONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')
            for key,relative in g.SOURCE_PATHS.items():
                p=root/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(inputs[key])
            output=root/'out/target-init-dma-lifecycle.json';output.parent.mkdir()
            parent_path=output.parent/'target-wifi-factory.json'
            if final:
                parent_path.write_text(json.dumps(parent))
                for name in g.PARENT_EXPORTS:(output.parent/name).write_bytes(files[name])
                for label,(relative,_,_)in g.COMPILED_OBJECTS.items():
                    obj=trunk/'linux-4.4.x'/relative;obj.parent.mkdir(parents=True,exist_ok=True)
                    stem='target-init-dma-lifecycle-'+label
                    obj.write_bytes(files[stem+'.o']);obj.with_name('.'+obj.name+'.cmd').write_bytes(files[stem+'.cmd'])
            selectors={(o['component'],o['selector']):g.EXPECTED[n]for n,o in g.CASES}
            commands=[]
            def run(argv,**kwargs):
                commands.append(argv)
                if argv[0]=='/inert/compiler':
                    Path(argv[argv.index('-o')+1]).write_bytes(bytes(static_elf()))
                    return SimpleNamespace(returncode=0,stdout='',stderr='')
                self.assertEqual(argv[0],'/inert/qemu');self.assertEqual(len(argv),3)
                return SimpleNamespace(returncode=0,stdout=json.dumps(selectors[(Path(argv[1]).name.removeprefix('target-init-dma-lifecycle-').removesuffix('-current'),argv[2])])+'\n',stderr='')
            with patch.dict(g.COMPONENTS,specs),patch.object(g.shutil,'which',return_value='/inert/qemu'),patch.object(g.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO()):
                # Snapshot before patch.dict restores the shared contract map.
                report=json.loads(json.dumps(g.check(trunk,Path('/inert/compiler'),output,not final,parent_path if final else None)))
            self.assertEqual(len(commands),len(g.CASES)+len(g.COMPONENTS));self.assertEqual(sum(c[0]=='/inert/compiler'for c in commands),len(g.COMPONENTS))
            self.assertEqual(len(report['checks']),len(g.CASES));g.validate_records(report['checks'])
            self.assertEqual(set(report['probes']),set(g.COMPONENTS))
            self.assertEqual(report['phase'],'final-module-reference-bound'if final else'early-source-only')
            self.assertEqual(json.loads(output.read_text()),report)
            for comp,probe in report['probes'].items():
                item=probe['current'];self.assertEqual(g.sha((output.parent/item['source_file']).read_bytes()),item['source_sha256'])
                stdout=json.loads((output.parent/item['stdout_file']).read_text());self.assertEqual(len(stdout),sum(o['component']==comp for _,o in g.CASES))
            if final:
                self.assertEqual(set(report['compiled_binding']['compiled_exports_sha256']),g.compiled_export_names())
                self.assertTrue(all((output.parent/name).is_file()for name in g.compiled_export_names()))
            else:
                self.assertIsNone(report['compiled_binding']);self.assertFalse(any((output.parent/name).exists()for name in g.compiled_export_names()))
            return report

    def test_preflight_emits_every_static_component_source_and_full_stdout(self):
        self.check_mode(False)
        with self.assertRaises(ValueError):g.check(Path('/unused'),Path('/unused'),Path('/unused'),False,None)

    def test_final_collects_all_sixteen_actual_object_exports_and_parent(self):
        self.check_mode(True)
        with self.assertRaises(ValueError):g.check(Path('/unused'),Path('/unused'),Path('/unused'),True,Path('/unused'))


    def test_source_only_outer_functions_and_known_busy_gap_are_explicit(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):proof=g.source_selection(inputs)
        self.assertIs(proof['known_busy_teardown_release_gap'],False)
        self.assertIs(proof['failed_idle_complete_owner_graph_retained_in_models'],True)
        self.assertIs(proof['terminal_reenable_rejected_in_models'],True)
        self.assertIs(proof['hardware_DMA_or_reset_executed'],False)
        self.assertTrue(any(proof['outer_function_manifest'].values()))
        for functions in proof['outer_function_manifest'].values():
            for row in functions.values():self.assertEqual(row['execution'],'source-only-not-run')


    def test_header_declarations_require_unique_complete_locked_source_matches(self):
        spec={'source_keys':{'header':'source'}}
        data={'SOURCE_DECLARATIONS':{r'^#define VALUE [^\n]+':'header'}}
        prefix='before\nSOURCE_DEFINITIONS\nafter'
        self.assertEqual(g.source_definitions({'source':'/* header */\n#define VALUE 7\n'},spec,data,prefix),
                         'before\n#define VALUE 7\nafter')
        for source,contract,template in (
                ('#define VALUE 7\n#define VALUE 8\n',data,prefix),
                ('#define OTHER 7\n',data,prefix),
                ('#define VALUE 7\n',data,prefix+'SOURCE_DEFINITIONS'),
                ('#define VALUE 7\n',{'SOURCE_DECLARATIONS':{r'(#define) (VALUE)':'header'}},prefix),
                ('#define VALUE 7\n',{'SOURCE_DECLARATIONS':{r'#define VALUE 7':'other'}},prefix)):
            with self.assertRaises(ValueError):g.source_definitions({'source':source},spec,contract,template)
        field={'SOURCE_FIELD_CONSTRAINTS':{r'UINT8 state;':'header'}}
        template='struct model { STATE_FIELDS };'
        self.assertEqual(g.source_definitions({'source':'UINT8 state;'},spec,field,template),
                         'struct model { UINT8 state; };')
        for source,contract,target in (
                ('UINT8 state; UINT8 state;',field,template),
                ('UINT16 state;',field,template),
                ('UINT8 state;',field,template+' STATE_FIELDS'),
                ('UINT8 state;',{},template),
                ('UINT8 state;',{'SOURCE_FIELD_CONSTRAINTS':[]},template)):
            with self.assertRaises(ValueError):g.source_definitions({'source':source},spec,contract,target)


if __name__=='__main__':unittest.main()


class NativeBoundariesTests(unittest.TestCase):
    def setUp(self):self.inputs=native_boundary_fixture()

    def test_pci_manual_bind_guard_uses_nested_driver_flag_and_real_core_consumer(self):
        inputs=self.inputs;proof=g.pci_bind_native_boundary(inputs);spec=g.SOURCE_ABI['native_boundaries']['pci'];keys=spec['source_keys']
        self.assertEqual((len(proof['source_sha256']),len(proof['whole_native_functions']),proof['native_case_count'],proof['native_test_methods']),(8,5,5,7))
        self.assertFalse(proof['bus_full_body_executed']);self.assertFalse(proof['kernel_remove_or_module_unload_executed'])
        for local,old,new in (('pci','.suppress_bind_attrs = true,','.suppress_bind_attrs = false,'),
                              ('pci','.driver = {','.another_driver = {'),
                              ('bus','!drv->suppress_bind_attrs','drv->suppress_bind_attrs'),
                              ('bus','add_bind_files(drv)','another_bind_files(drv)'),
                              ('baseline','static struct pci_driver','static struct changed_driver')):
            changed=dict(inputs);key=keys[local];self.assertIn(old,changed[key]);changed[key]=changed[key].replace(old,new,1)
            with self.subTest(local=local,new=new),self.assertRaises(ValueError):g.pci_bind_native_boundary(changed)
        changed=dict(inputs);changed[keys['harness']]=changed[keys['harness']].replace("'register': [0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1]","'register': [False, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1]",1)
        self.assertNotEqual(changed,inputs)
        with self.assertRaises(ValueError):g.pci_bind_native_boundary(changed)

    def test_forwarding_scope_requires_every_caller_both_domains_and_final_work_drain(self):
        inputs=self.inputs;proof=g.fwd_native_boundary(inputs);spec=g.SOURCE_ABI['native_boundaries']['fwd'];keys=spec['source_keys']
        self.assertEqual((len(proof['source_sha256']),len(proof['whole_native_helpers']),len(proof['source_bound_callers']),len(proof['source_only_kernel_srcu']),proof['direct_calls'],proof['table_fields']),(21,5,31,3,47,36))
        self.assertEqual((proof['native_case_count'],proof['native_test_methods'],proof['MIPS_probes_added'],proof['kernel_objects_added']),(13,11,0,0))
        self.assertFalse(proof['real_kernel_provider_scheduler_or_hardware_executed']);self.assertTrue(proof['shipping_compile_define'])
        for local,names in spec['callers'].items():
            for name in names:
                key=keys[local];body=g.function(inputs[key],name);changed=dict(inputs);changed[key]=inputs[key].replace(body,body.replace('WIFI_FWD_GUARD(wf_fwd_snapshot);','/* missing reader lifetime */',1),1)
                with self.subTest(caller=name),self.assertRaises(ValueError):g.fwd_native_boundary(changed)
        for local,old,new in (('header','cleanup(wifi_fwd_read_end)','cleanup(another_end)'),
                              ('makefile','EXTRA_CFLAGS += -DCONFIG_WIFI_PKT_FWD','# disabled forwarding define'),
                              ('os/linux/rt_profile.c','flush_delayed_work(&wifi_fwd_srcu.work);','/* no final work flush */'),
                              ('os/linux/rt_profile.c','synchronize_srcu(&wifi_fwd_srcu);','/* no sleeping-reader grace */'),
                              ('os/linux/rt_profile.c','synchronize_rcu();','/* no atomic-reader grace */'),
                              ('os/linux/rt_profile.c','mutex_lock(&wifi_fwd_writer_lock);','/* no writer serialization */'),
                              ('os/linux/rt_profile.c','srcu_dereference(wifi_fwd_published, &wifi_fwd_srcu)','unsafe_dereference(wifi_fwd_published, &wifi_fwd_srcu)')):
            changed=dict(inputs);key=keys[local];self.assertIn(old,changed[key]);changed[key]=changed[key].replace(old,new,1)
            with self.subTest(local=local,new=new),self.assertRaises(ValueError):g.fwd_native_boundary(changed)
        changed=dict(inputs);changed[keys['os/linux/rt_profile.c']]+='\nstruct wifi_fwd_func_table wf_drv_tbl;\n'
        with self.assertRaises(ValueError):g.fwd_native_boundary(changed)

    def test_native_boundaries_bind_true_module_owners_without_inventing_kernel_objects(self):
        self.assertEqual(len(g.COMPILED_OBJECTS),48)
        for name in ('wifi_fwd_read_begin','wifi_fwd_read_end','wifi_fwd_register','wifi_fwd_unregister'):
            self.assertIn(name,g.COMPILED_OBJECTS['profile'][2])
        for name in ('rt_pci_init_module','rt_pci_cleanup_module'):self.assertIn(name,g.COMPILED_OBJECTS['pci'][2])
        self.assertNotIn('srcu_core',g.COMPILED_OBJECTS)
        self.assertIn('-DCONFIG_WIFI_PKT_FWD',g.REQUIRED_OBJECT_FLAGS)
        self.assertFalse(any('__pci_register_driver'in row[2]for row in g.COMPILED_OBJECTS.values()))
        for name in ('pci_bind_native_boundary','fwd_native_boundary'):
            proof=getattr(g,name)(self.inputs)
            self.assertEqual((proof['MIPS_probes_added'],proof['kernel_objects_added']),(0,0))



class WtblPackedSourceTests(unittest.TestCase):
    def setUp(self):self.inputs=fixture()[0]

    def test_wtbl_additive_cases_keep_all_preceding_rows_and_command44_observations(self):
        added_command=('command:current:wsys-wtbl-sync-error', 'command:current:wsys-wtbl-sync-noresponse', 'command:current:wsys-wtbl-sync-ok')
        preceding=[(n,o,g.EXPECTED[n])for n,o in g.CASES if o['component']!='wtbl'and n not in added_command]
        self.assertEqual(len(preceding),769)
        self.assertEqual(hashlib.sha256(json.dumps(preceding,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'8984c10564d19024ca81049c142653187881ef4de222d0c15f6d876a0af2385e')
        self.assertEqual(sum(o['component']=='wtbl'for _,o in g.CASES),50)
        self.assertEqual(sum(o['component']=='command'for _,o in g.CASES),47)
        spec=g.COMPONENTS['wtbl'];self.assertEqual((len(spec['functions']),len(spec['source_only_functions'])),(6,4))
        self.assertIn('AndesSendCmdMsg',spec['source_only_functions'])
        self.assertIn('AndesSendCmdMsg',g.COMPONENTS['command']['functions'])
        self.assertTrue(g.SOURCE_ABI['model_variants']['wtbl']['short_query_ACK_callback_semantics_not_transport_delivery_claim'])

    def test_wtbl_actual_packed_spans_enum_macros_and_capacity_fail_closed(self):
        spec=g.COMPONENTS['wtbl'];data=g.literal_data(self.inputs[spec['harness_key']])
        code,manifest=g.generate_component(self.inputs,'wtbl')
        self.assertEqual(len(manifest),6)
        for name,key in spec['functions'].items():self.assertEqual(code.count(g.function(self.inputs[spec['source_keys'][key]],name)),1)
        self.assertIn(data['TRANSPORT'],code)
        for key,spans in data['SOURCE_DECLARATIONS'].items():
            for begin,end in spans:
                changed=dict(self.inputs);alias=spec['source_keys'][key];self.assertIn(begin,changed[alias]);changed[alias]=changed[alias].replace(begin,'/* source span start removed */',1)
                with self.subTest(span=begin),self.assertRaises(ValueError):g.generate_component(changed,'wtbl')
        for key,names in data['SOURCE_ENUMS'].items():
            for name in names:
                changed=dict(self.inputs);alias=spec['source_keys'][key];changed[alias]=changed[alias].replace(name,name+'_changed')
                with self.subTest(enum=name),self.assertRaises(ValueError):g.generate_component(changed,'wtbl')
        for name in data['SOURCE_MACRO_NAMES']:
            changed=dict(self.inputs);alias=spec['source_keys']['os'];changed[alias]=re.sub(r'(?m)^(#define\s+)'+re.escape(name)+r'\b',lambda m:m[1]+name+'_changed',changed[alias]);self.assertNotEqual(changed[alias],self.inputs[alias])
            with self.subTest(macro=name),self.assertRaises(ValueError):g.generate_component(changed,'wtbl')
        changed=dict(self.inputs);alias=spec['source_keys']['header'];changed[alias]=changed[alias].replace('wtbl_rsp_capacity','unbounded_capacity')
        with self.assertRaises(ValueError):g.generate_component(changed,'wtbl')

    def test_wtbl_real_implementation_objects_and_inert_transport_are_separate(self):
        self.assertEqual(len(g.COMPILED_OBJECTS),48)
        for name in ('CmdExtWtblUpdate','CmdExtWtblUpdateCb'):self.assertIn(name,g.COMPILED_OBJECTS['wsys_fw'][2])
        for name in ('AndesAllocCmdMsg','AndesAppendCmdMsg'):self.assertIn(name,g.COMPILED_OBJECTS['quarantine_andes_core'][2])
        variants=g.SOURCE_ABI['model_variants']['wtbl'];self.assertTrue(variants['kernel_cmd_msg_packet_scheduler_firmware_and_DMA_are_not_executed'])
        self.assertTrue(variants['whole_transport_status_verified_separately_by_dma_command_harness'])
        self.assertTrue(variants['actual_WTBL_packed_declarations_and_constants_extracted'])
