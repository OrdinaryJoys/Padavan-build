"""Synthetic validator/generator controls; actual MIPS execution belongs to CI."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('hook',Path(__file__).with_name('check_target_hook.py'))
hook=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(hook)


def records():
    rows=[]
    for case in hook.CASES:
        name,role,options=case['case'],case['role'],case['inputs']
        result={key:0 for key in hook.RESULT_FIELDS-{'signals_seen','read_bytes','group_scan_backend'}}
        result.update(mask_restored=1,handlers_restored=1,forks=1,waits=2,exits_seen=1,elapsed_ms=10,
                      signals_seen=[0]*4,read_bytes=[0,0],group_scan_backend='linux-real-proc')
        post=dict(exec_audit_count=1,action_argument=None,hook_effect=None,injection_marker_exists=False,owned_child_alive=None)
        if role=='raw-exit':result['status']=7<<8 if name=='raw-exit7' else 126<<8
        if role=='raw-signal':result['status']=17 if name=='child-signal-mask-unblocked' else 15
        if role in ('timeout','background-reject','output-reject','parent-cancel','policy-reject'):
            result['status']=-1;result['error']={'timeout':145,'background-reject':16,'output-reject':27,'parent-cancel':4,'policy-reject':22}[role]
            result[{'timeout':'timeout','background-reject':'background','output-reject':'output_limit','parent-cancel':'cancelled','policy-reject':'error'}[role]]=result['error'] if role=='policy-reject' else 1
            result['group_signals']=1
        if role=='timeout':result['elapsed_ms']=options['timeout_ms']
        if role=='policy-reject':result.update(forks=0,waits=0,exits_seen=0,group_signals=0);post['exec_audit_count']=0
        if name=='descriptor-close-error-noexec':post['exec_audit_count']=0
        if name=='normal-action-exit0':post['action_argument']='2'
        if name=='literal-path-no-shebang':post['hook_effect']='literal'
        if name=='closed-stdio-cloexec-cleared':result['read_bytes']=[3,3]
        if name=='term-ignoring-group-killed':result['group_signals']=2;post['hook_effect']='ready'
        if name=='stdout128k-cap':result['read_bytes']=[131073,0]
        if name=='stderr128k-cap':result['read_bytes']=[0,131073]
        if name=='dual-stream-fair-cap':result['read_bytes']=[131073,131073]
        if role=='parent-cancel':result['signals_seen']=[1,0,0,0]
        if name in ('production30s-closed-pipes-timeout','exit0-live-background-refused','exit0-closed-pipe-background-refused','parent-term-cleanup-reraise'):post['owned_child_alive']=False
        rows.append(dict(case=name,role=role,backend=hook.BACKEND,inputs=options.copy(),result=result,
                         script_sha256=hashlib.sha256(hook.script_bytes(case)).hexdigest(),postconditions=post))
    return rows


def sources():
    header='\n'.join(('#define HOOK_RUNNER_TIMEOUT_MS 30000U','#define HOOK_RUNNER_TERM_MS 2000U',
                      '#define HOOK_RUNNER_KILL_MS 1000U','#define HOOK_RUNNER_STREAM_LIMIT (128U * 1024U)',
                      '#define HOOK_RUNNER_PROC_LIMIT 8192U'))
    return {'hook_runner.h':header,'fixture.c':'/* fixture */\n#include "hook_runner.h"\n',
            'rc.c':'#include "hook_runner.h"\nshutdown_hook_run(script_name,0);\nshutdown_hook_run(script_name,level);',
            'Makefile':'LDFLAGS += -lrt\nrc.o: hook_runner.h\n'}


def elf():
    data=bytearray(256);data[:7]=b'\x7fELF\x01\x01\x01';struct.pack_into('<HH',data,16,2,8)
    struct.pack_into('<II',data,24,0x400080,52);struct.pack_into('<HH',data,42,32,1)
    struct.pack_into('<8I',data,52,1,0,0x400000,0x400000,len(data),len(data),5,4096)
    return data


class TargetHookTests(unittest.TestCase):
    def test_fixed_twenty_cases_and_synthetic_positive_records(self):
        self.assertEqual(len(hook.CASE_NAMES),20)
        self.assertEqual(hashlib.sha256('\n'.join(hook.CASE_NAMES).encode()).hexdigest(),
                         '02b422e3bd8df464c0a909a09da6e914cc20b89569317dfc61998b51216b639b')
        hook.validate_records(records())

    def test_missing_duplicate_reordered_or_wrong_backend_is_rejected(self):
        variants=[records()[:-1],records()+records()[:1],list(reversed(records()))]
        wrong=records();wrong[0]['result']['group_scan_backend']='portable-synthetic-proc';variants.append(wrong)
        for value in variants:
            with self.assertRaises(ValueError):hook.validate_records(value)

    def test_boolean_float_and_extra_result_fields_are_rejected(self):
        for field,value in [('elapsed_ms',True),('status',0.0),('mask_restored',False),('unexpected',0)]:
            rows=records();rows[0]['result'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):hook.validate_records(rows)

    def test_mips_signal_and_errno_must_not_be_host_x86_values(self):
        for name,field,value in [('child-signal-mask-unblocked','status',12),('production30s-closed-pipes-timeout','error',110)]:
            rows=records();rows[hook.CASE_NAMES.index(name)]['result'][field]=value
            with self.assertRaises(ValueError):hook.validate_records(rows)

    def test_pid_anchor_mask_handler_and_cancel_semantics_cannot_be_weakened(self):
        for field,value in [('signal_after_reap',1),('mask_restored',0),('handlers_restored',0),('signals_seen',[0]*4)]:
            rows=records();rows[hook.CASE_NAMES.index('parent-term-cleanup-reraise')]['result'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):hook.validate_records(rows)

    def test_actual_production_deadline_cannot_be_shortened_or_exceeded(self):
        for elapsed in (29999,34001):
            rows=records();rows[hook.CASE_NAMES.index('production30s-closed-pipes-timeout')]['result']['elapsed_ms']=elapsed
            with self.assertRaises(ValueError):hook.validate_records(rows)

    def test_background_cleanup_caps_and_nonexec_have_real_postconditions(self):
        variants=[]
        value=records();value[hook.CASE_NAMES.index('exit0-live-background-refused')]['postconditions']['owned_child_alive']=True;variants.append(value)
        value=records();value[hook.CASE_NAMES.index('term-ignoring-group-killed')]['result']['group_signals']=1;variants.append(value)
        value=records();value[hook.CASE_NAMES.index('dual-stream-fair-cap')]['result']['read_bytes']=[131073,0];variants.append(value)
        value=records();value[hook.CASE_NAMES.index('nonexecutable-script-refused')]['postconditions']['hook_effect']='forbidden';variants.append(value)
        for rows in variants:
            with self.assertRaises(ValueError):hook.validate_records(rows)

    def test_nochild_policy_and_literal_path_cannot_claim_execution(self):
        for name,field,value in [('sigchld-ignore-nochild','exec_audit_count',1),('literal-path-no-shebang','injection_marker_exists',True)]:
            rows=records();rows[hook.CASE_NAMES.index(name)]['postconditions'][field]=value
            with self.assertRaises(ValueError):hook.validate_records(rows)

    def test_pure_inline_generator_binds_header_both_callers_and_link_dependency(self):
        generated=hook.generate_source(sources());self.assertIn('#define HOOK_RUNNER_TIMEOUT_MS 30000U',generated)
        self.assertNotIn('#include "hook_runner.h"',generated)
        for field in hook.SOURCE_PATHS:
            broken=sources();broken[field]=''
            with self.subTest(field=field),self.assertRaises(ValueError):hook.generate_source(broken)

    def test_static_mips_header_entry_and_segments_are_required(self):
        hook.validate_static_mips(elf())
        for change in ('dynamic','wrong-machine','wrong-type','no-exec','bounds'):
            data=elf()
            if change=='dynamic':struct.pack_into('<I',data,52,2)
            if change=='wrong-machine':struct.pack_into('<H',data,18,62)
            if change=='wrong-type':struct.pack_into('<H',data,16,3)
            if change=='no-exec':struct.pack_into('<I',data,52+24,4)
            if change=='bounds':struct.pack_into('<I',data,52+16,257)
            with self.subTest(change=change),self.assertRaises(ValueError):hook.validate_static_mips(data)

    def test_diagnostic_write_does_not_truncate_symlink_or_hardlink_victim(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);victim=root/'victim';victim.write_text('keep')
            link=root/'link';link.symlink_to(victim)
            with self.assertRaises(OSError):hook.write_report(link,{'status':'PASS'})
            hard=root/'hard';os.link(victim,hard)
            with self.assertRaises(ValueError):hook.write_report(hard,{'status':'PASS'})
            self.assertEqual(victim.read_text(),'keep')
            output=root/'report';hook.write_report(output,{'status':'RUNNING'});hook.write_report(output,{'status':'FAIL'})
            self.assertIn('FAIL',output.read_text())


if __name__=='__main__':unittest.main()
