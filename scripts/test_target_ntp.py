"""Synthetic strict-contract controls; actual NTP C/signal tests live in source."""
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SPEC=importlib.util.spec_from_file_location('ntp',Path(__file__).with_name('check_target_ntp.py'))
ntp=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(ntp)


def records():
    rows=[]
    for name in ntp.CASE_NAMES:
        result=ntp.expected_result(name)
        if name=='init-resolver-production-timeout':result['elapsed_ms']=10000
        elif ntp.role(name)=='startup-deadline':result['elapsed_ms']=1000
        elif name=='timer-async-feed':result.update(elapsed_ms=300,largest_feed_gap_ms=50)
        rows.append(dict(case=name,role=ntp.role(name),backend=ntp.BACKEND,result=result))
    return rows


def elf():
    body=bytearray(256);body[:7]=b'\x7fELF\x01\x01\x01'
    struct.pack_into('<HH',body,16,2,8);struct.pack_into('<II',body,24,0x400080,52)
    struct.pack_into('<HH',body,42,32,1)
    struct.pack_into('<8I',body,52,1,0,0x400000,0x400000,len(body),len(body),5,4096)
    return body


def sources():
    header='#define NTP_STARTUP_TIMEOUT 10\nstatic int ntp_startup_budget_begin(void){return 0;}\nstatic void ntp_startup_budget_end(void){}'
    init='static void ntp_init(void){ntp_startup_budget_begin();add_peers();ntp_startup_budget_end();bb_daemonize_or_rexec();}'
    text='#include "ntp_startup.h"\nenum {\nOPT_n = 1\n};\n'+init+'\nstatic void add_peers(void){}\nstatic void ntp_first_reply(void){}\nvoid main_loop(void){ntp_first_reply();}'
    watchdog='\n'.join('static int '+name+'(void){return 0;}' for name in ntp.FUNCTIONS['watchdog.c'])
    fixture='\n'.join(('/* NTP_STARTUP_HEADER */','/* NTP_OPTION_ENUM */','/* NTP_INIT_FUNCTIONS */','/* NTP_WATCHDOG_FUNCTIONS */'))
    return {'ntpd.c':text,'ntp_startup.h':header,'watchdog.c':watchdog,'fixture.c':fixture}


class TargetNtpTests(unittest.TestCase):
    def test_exact_twenty_four_cases_and_synthetic_positive_records(self):
        self.assertEqual(len(ntp.CASE_NAMES),24)
        self.assertEqual(len(set(ntp.CASE_NAMES)),24)
        ntp.validate_records(records())

    def test_missing_duplicate_reordered_and_unknown_cases_fail(self):
        variants=[records()[:-1],records()+records()[:1],list(reversed(records()))]
        wrong=records();wrong[0]['case']='unrelated';variants.append(wrong)
        for value in variants:
            with self.assertRaises(ValueError):ntp.validate_records(value)

    def test_wrong_role_backend_extra_boolean_or_float_fields_fail(self):
        for field,value in [('role','unrelated'),('backend','host-only')]:
            wrong=records();wrong[0][field]=value
            with self.assertRaises(ValueError):ntp.validate_records(wrong)
        for field,value in [('status',False),('elapsed_ms',1.0),('extra',0),('alarms',[10,0,10,False])]:
            wrong=records();wrong[0]['result'][field]=value
            with self.assertRaises(ValueError):ntp.validate_records(wrong)

    def test_production_deadline_cannot_be_skipped_shortened_or_extended(self):
        for elapsed in (0,9499,13001):
            wrong=records();wrong[ntp.CASE_NAMES.index('init-resolver-production-timeout')]['result']['elapsed_ms']=elapsed
            with self.assertRaises(ValueError):ntp.validate_records(wrong)
        wrong=records();wrong[ntp.CASE_NAMES.index('init-resolver-blocked')]['result']['elapsed_ms']=0
        with self.assertRaises(ValueError):ntp.validate_records(wrong)

    def test_q_first_reply_and_no_q_alarm_contract_cannot_drift(self):
        for name,alarms in [('init-q-first-reply',[10,0,10,10]),('init-noq-success',[10,0,10,0]),('init-q-success',[0,0,10,0])]:
            wrong=records();wrong[ntp.CASE_NAMES.index(name)]['result']['alarms']=alarms
            with self.assertRaises(ValueError):ntp.validate_records(wrong)

    def test_suppression_reaping_no_overlap_and_stop_are_mandatory(self):
        for name,field,value in [('refresh-inhibited','launches',1),('refresh-poststop-inhibited','launches',1),
                                 ('reap-eintr','launcher_owned',0),('reap-echild','launcher_owned',1),
                                 ('refresh-busy-no-overlap','launches',2),('stop-resolving-no-pidfile','status',0),
                                 ('refresh-fork-fail','launcher_owned',1),('init-mask-fail','resolver_reached',1)]:
            wrong=records();wrong[ntp.CASE_NAMES.index(name)]['result'][field]=value
            with self.subTest(name=name),self.assertRaises(ValueError):ntp.validate_records(wrong)

    def test_inflight_resolver_must_not_block_timer_feeds(self):
        for field,value in [('feeds',0),('largest_feed_gap_ms',750),('elapsed_ms',0),('launches',2)]:
            wrong=records();wrong[ntp.CASE_NAMES.index('timer-async-feed')]['result'][field]=value
            with self.assertRaises(ValueError):ntp.validate_records(wrong)

    def test_generator_requires_real_integration_markers_functions_and_budget(self):
        text=ntp.generate_source(sources())
        self.assertNotIn('/* NTP_',text)
        for key in ntp.SOURCE_PATHS:
            wrong=sources();wrong[key]=''
            with self.subTest(key=key),self.assertRaises((ValueError,IndexError)):ntp.generate_source(wrong)
        for old,new in [('ntp_startup_budget_begin();add_peers();','add_peers();ntp_startup_budget_begin();'),
                        ('ntp_first_reply();','missing_reply();')]:
            wrong=sources();wrong['ntpd.c']=wrong['ntpd.c'].replace(old,new)
            with self.assertRaises(ValueError):ntp.generate_source(wrong)

    def test_mips_header_class_machine_entry_and_static_dependencies_are_checked(self):
        identity=ntp.elf(elf(),True);self.assertEqual(identity['e_machine'],8)
        for field in ('machine','type','entry','dynamic','bounds'):
            body=elf()
            if field=='machine':struct.pack_into('<H',body,18,62)
            if field=='type':struct.pack_into('<H',body,16,1)
            if field=='entry':struct.pack_into('<I',body,24,1)
            if field=='dynamic':struct.pack_into('<I',body,52,3)
            if field=='bounds':struct.pack_into('<I',body,68,257)
            with self.assertRaises(ValueError):ntp.elf(body,True)

    def test_report_does_not_truncate_symlink_or_hardlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);victim=root/'victim';victim.write_text('keep')
            link=root/'link';link.symlink_to(victim)
            with self.assertRaises(OSError):ntp.write_report(link,{'status':'PASS'})
            hard=root/'hard';os.link(victim,hard)
            with self.assertRaises(ValueError):ntp.write_report(hard,{'status':'PASS'})
            self.assertEqual(victim.read_text(),'keep')
            report=root/'report';ntp.write_report(report,{'status':'RUNNING'});ntp.write_report(report,{'status':'PASS'})
            self.assertIn('PASS',report.read_text())

    def test_runtime_library_links_are_confined_and_bytes_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'lib').mkdir();body=elf();struct.pack_into('<H',body,16,3)
            (root/'lib/runtime.so').write_bytes(body);(root/'lib/libc.so.0').symlink_to('runtime.so')
            identity=ntp.runtime_library(root,'lib/libc.so.0')
            self.assertEqual(identity['resolved'],'lib/runtime.so')
            self.assertEqual(identity['bytes'],len(body))
            (root/'lib/libc.so.0').unlink();(root/'lib/libc.so.0').symlink_to('../../outside')
            with self.assertRaises(ValueError):ntp.runtime_library(root,'lib/libc.so.0')
            (root/'lib/libc.so.0').unlink();(root/'lib/libc.so.0').symlink_to('/lib/runtime.so')
            self.assertEqual(ntp.runtime_library(root,'lib/libc.so.0'),identity)
            (root/'lib/runtime.so').write_bytes(b'not-an-ELF'*12)
            with self.assertRaises(ValueError):ntp.runtime_library(root,'lib/libc.so.0')

    def test_owned_hanging_and_flooding_children_are_killed_before_leader_reap(self):
        # Native Python only: no MIPS/QEMU, DNS, router or global process kill.
        with tempfile.TemporaryDirectory() as temp:
            for mode in ('hang','stdout','stderr'):
                marker=Path(temp)/mode
                script=('import os,sys,time\n'
                        'child=os.fork()\n'
                        'if child: os._exit(0)\n'
                        'with open(sys.argv[1],"w") as stream: stream.write(str(os.getpid()))\n'
                        'mode=sys.argv[2]\n'
                        'if mode=="hang":\n'
                        ' while True: time.sleep(30)\n'
                        'else:\n'
                        ' while True: os.write(1 if mode=="stdout" else 2,b"X"*4096)\n')
                expected='timed out' if mode=='hang' else mode+' output cap exceeded'
                real_popen=subprocess.Popen;real_killpg=os.killpg;owned=[];signals=[]
                def spawn(*args,**kwargs):
                    process=real_popen(*args,**kwargs);owned.append(process);return process
                def kill_group(pid,sig):
                    self.assertEqual(len(owned),1)
                    self.assertEqual(pid,owned[0].pid)
                    self.assertIsNone(owned[0].returncode,'Leader was reaped before its PG was signalled')
                    signals.append(sig);return real_killpg(pid,sig)
                with self.subTest(mode=mode),mock.patch.object(ntp.subprocess,'Popen',spawn),mock.patch.object(ntp.os,'killpg',kill_group):
                    with self.assertRaisesRegex(ValueError,expected):
                        ntp.run_target([sys.executable,'-c',script,str(marker),mode],seconds=.5,
                                       stdout_limit=8192,stderr_limit=16384)
                self.assertEqual(signals,[ntp.signal.SIGKILL])
                self.assertTrue(marker.exists())
                pid=int(marker.read_text());deadline=time.monotonic()+2
                while True:
                    state=subprocess.run(['ps','-o','stat=','-p',str(pid)],capture_output=True,text=True).stdout.strip()
                    if not state or state.startswith('Z'):break
                    self.assertLess(time.monotonic(),deadline,'Owned harmless child remained alive')
                    time.sleep(.02)


if __name__=='__main__':unittest.main()
