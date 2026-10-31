"""Pure timing/RSS/protocol corruption controls. No target, listener or mount."""
import copy
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import check_target_reload_latency as gate

OLD=['192.0.2.51','192.0.2.61'];NEW=['192.0.2.52','192.0.2.62']


def requests():
    return [dict(query_id=i,phase=phase,scheduled_ns=i*20000000,sent_ns=i*20000000+100000,
                 received_ns=i*20000000+1100000,addresses=OLD.copy())
            for i,phase in enumerate(('baseline','reload','settled'))]


class ReloadLatencyMetricsControls(unittest.TestCase):
    def test_native_proc_memory_and_ambiguous_counters_rejected(self):
        text='Name:\tqemu-mipsel\nVmRSS:\t8192 kB\nVmHWM:\t12288 kB\nVmData:\t4096 kB\n'
        self.assertEqual(gate.parse_proc_status(text),dict(rss_kib=8192,hwm_kib=12288,data_kib=4096))
        for wrong in (text+'VmRSS: 1 kB\n',text.replace('8192','0'),text.replace('12288','1'),text.replace('kB','bytes')):
            with self.assertRaises(ValueError):gate.parse_proc_status(wrong)
        self.assertEqual(gate.parse_pss_rollup('Pss: 1024 kB\n'),1024)
        for wrong in ('','Pss: 1 kB\nPss: 2 kB\n','Pss: -1 kB\n'):
            with self.assertRaises(ValueError):gate.parse_pss_rollup(wrong)

    def test_proc_stat_parent_and_starttime_with_parentheses_and_spaces(self):
        tail=['1']+['0']*17+['12345']
        record=gate.parse_proc_stat('42 (qemu (test) name) S '+' '.join(tail))
        self.assertEqual(record,dict(pid=42,parent=1,starttime=12345,state='S'))
        for wrong in ('42 broken','42 (qemu) Z '+' '.join(tail),'42 (qemu) S 1'):
            with self.assertRaises(ValueError):gate.parse_proc_stat(wrong)

    def test_quantile_and_outlier_not_averaged_away(self):
        self.assertEqual(gate.percentile([1]*94+[900]*6,95),900)
        self.assertEqual(gate.percentile([1,2,3,4],50),2)
        for values in ([],[True],[float('nan')],[-1],[float('inf')]):
            with self.assertRaises(ValueError):gate.percentile(values,95)

    def test_request_summary_reports_scheduler_gap_and_loss_separately(self):
        rows=requests();rows[1]['received_ns']=None;rows[1]['addresses']=None
        value=gate.summarize_requests(rows,[OLD,NEW])
        self.assertEqual((value['sent'],value['received'],value['timeouts']),(3,2,1))
        self.assertEqual(value['rtt_max_ms'],1)
        self.assertEqual(value['send_gap_max_ms'],20)
        self.assertEqual(value['send_lateness_max_ms'],.1)
        self.assertIsNone(value['phases']['reload']['rtt_p95_ms'])

    def test_partial_policy_wrong_time_identity_and_missing_reply_cannot_hide(self):
        for field,wrong in [('addresses',[OLD[0],NEW[1]]),('received_ns',1),('query_id',True),
                            ('phase','unknown'),('scheduled_ns',999999999)]:
            rows=requests();rows[1][field]=wrong
            with self.subTest(field=field),self.assertRaises(ValueError):gate.summarize_requests(rows,[OLD,NEW])
        rows=requests();rows[1]['query_id']=rows[0]['query_id']
        with self.assertRaises(ValueError):gate.summarize_requests(rows,[OLD,NEW])
        rows=requests();rows[1]['received_ns']=None
        with self.assertRaises(ValueError):gate.summarize_requests(rows,[OLD,NEW])

    def test_memory_summary_distinguishes_observed_peak_lifetime_hwm_and_children(self):
        rows=[dict(at_ns=1,phase='baseline',rss_kib=100,hwm_sum_kib=200,pss_kib=80,processes=1),
              dict(at_ns=10000001,phase='reload',rss_kib=300,hwm_sum_kib=400,pss_kib=160,processes=2)]
        value=gate.summarize_memory(rows)
        self.assertEqual((value['rss_max_kib'],value['hwm_sum_max_kib'],value['max_processes']),(300,400,2))
        self.assertEqual(value['phases']['reload']['pss_max_kib'],160)
        self.assertIsNone(value['phases']['settled'])
        for field,wrong in [('rss_kib',0),('hwm_sum_kib',1),('processes',True),('pss_kib',-1),('at_ns',0)]:
            bad=copy.deepcopy(rows);bad[1][field]=wrong
            with self.subTest(field=field),self.assertRaises(ValueError):gate.summarize_memory(bad)

    def test_actual_rrset_packet_requires_full_atomic_pair(self):
        name='atomic.latency.fixture';question=gate.encode_question(name)
        data=struct.pack('!6H',42,0x8180,1,2,0,0)+question
        for address in OLD:
            import ipaddress
            data+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+ipaddress.IPv4Address(address).packed
        self.assertEqual(gate.parse_rrset(data,42,name),OLD)
        for wrong in (data+b'x',data[:-1],data[:6]+b'\x00\x01'+data[8:]):
            with self.assertRaises((ValueError,RuntimeError)):gate.parse_rrset(wrong,42,name)
        with self.assertRaises(ValueError):gate.parse_rrset(data,43,name)
        with self.assertRaises(ValueError):gate.parse_rrset(data,42,'other.fixture')



def measured_rows():
    result=[]
    for name in gate.CASE_NAMES:
        final=NEW if name==gate.CASE_NAMES[1] else gate.FALLBACK if name==gate.CASE_NAMES[3] else OLD
        records=[]
        for i in range(75):
            phase=gate.PHASES[min(i//25,2)]
            addresses=final if phase=='settled' else OLD
            records.append(dict(query_id=i,phase=phase,scheduled_ns=i*20000000,sent_ns=i*20000000+100000,
                                received_ns=i*20000000+1100000,addresses=addresses.copy()))
        memory=[dict(at_ns=i*10000000+1,phase=gate.PHASES[min(i//50,2)],rss_kib=10000,hwm_sum_kib=15000,pss_kib=None,processes=1)for i in range(150)]
        initial,candidate=gate.fixture_counts(name);old,new=gate.fixture_payloads(name)
        dhcp=[dict(xid=0x4b320000+i,phase=gate.PHASES[min(i//6,2)],scheduled_ns=i*100000000,sent_ns=i*100000000+100000,received_ns=i*100000000+1100000,policy=gate.DHCP_POLICY)for i in range(18)]
        row=dict(case=name,outcome='rejected-old-retained' if name==gate.CASE_NAMES[2] else 'cold-accepted' if name==gate.CASE_NAMES[0] else 'committed',
                 startup_ready_ms=500,fixture=dict(initial_unique_per_file=initial,candidate_entries=candidate,initial=gate.fingerprints(old),candidate=gate.fingerprints(new)),
                 final_rrset=final,rejection_observed=name==gate.CASE_NAMES[2],requests=records,memory=memory,
                 request_summary=gate.summarize_requests(records,[OLD,NEW,gate.FALLBACK]),memory_summary=gate.summarize_memory(memory),dhcp_requests=dhcp,dhcp_summary=gate.summarize_dhcp(dhcp),lease_bytes=0,daemon_stopped=True)
        result.append(row)
    return result


class ReloadLatencyContractControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.good=measured_rows()

    def test_exact_four_actual_workloads_and_generated_fingerprints(self):
        self.assertTrue(gate.validate_records(copy.deepcopy(self.good)))
        for bad in (self.good[:-1],self.good[::-1],self.good+[self.good[0]]):
            with self.assertRaises(ValueError):gate.validate_records(bad)
        for field,value in [('initial_unique_per_file',1),('candidate_entries',1)]:
            bad=copy.deepcopy(self.good);bad[0]['fixture'][field]=value
            with self.assertRaises(ValueError):gate.validate_records(bad)
        bad=copy.deepcopy(self.good);bad[0]['fixture']['initial'][0]['sha256']='0'*64
        with self.assertRaises(ValueError):gate.validate_records(bad)

    def test_raw_latency_memory_summary_cannot_hide_an_outlier(self):
        bad=copy.deepcopy(self.good);bad[0]['request_summary']['rtt_max_ms']=0
        with self.assertRaises(ValueError):gate.validate_records(bad)
        bad=copy.deepcopy(self.good);bad[0]['memory_summary']['rss_max_kib']=1
        with self.assertRaises(ValueError):gate.validate_records(bad)
        bad=copy.deepcopy(self.good);row=bad[0];row['requests'][30]['received_ns']=row['requests'][30]['sent_ns']+1001000000
        row['request_summary']=gate.summarize_requests(row['requests'],[OLD,NEW,gate.FALLBACK])
        with self.assertRaises(ValueError):gate.validate_records(bad)

    def test_rejection_old_rrset_cannot_silently_accept_candidate(self):
        bad=copy.deepcopy(self.good);row=bad[2];row['requests'][30]['addresses']=NEW.copy()
        row['request_summary']=gate.summarize_requests(row['requests'],[OLD,NEW,gate.FALLBACK])
        with self.assertRaises(ValueError):gate.validate_records(bad)
        for field,value in [('outcome','committed'),('rejection_observed',False),('daemon_stopped',False),('startup_ready_ms',20001)]:
            bad=copy.deepcopy(self.good);bad[2][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):gate.validate_records(bad)

    def test_unmeasured_child_or_memory_growth_is_not_single_process_success(self):
        for field,value in [('rss_kib',270000),('processes',2),('hwm_sum_kib',270000),('hwm_sum_kib',110000)]:
            bad=copy.deepcopy(self.good);row=bad[0];row['memory'][70][field]=value
            if field=='rss_kib':row['memory'][70]['hwm_sum_kib']=value
            row['memory_summary']=gate.summarize_memory(row['memory'])
            with self.subTest(field=field),self.assertRaises(ValueError):gate.validate_records(bad)

    def test_complete_response_owner_and_truncated_flags_required(self):
        name='atomic.latency.fixture';question=gate.encode_question(name)
        data=struct.pack('!6H',42,0x8180,1,2,0,0)+question
        import ipaddress
        for address in OLD:data+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+ipaddress.IPv4Address(address).packed
        for bad in (data[:2]+b'\x83\x80'+data[4:],data.replace(b'\xc0\x0c',b'\xc0\x0d')):
            with self.assertRaises(ValueError):gate.parse_rrset(bad,42,name)

    def test_full_report_binds_actual_image_limits_and_namespace_not_native_stub(self):
        sources={'locked':'a'*64};shipped={'dnsmasq':{'sha256':'b'*64}}
        iso=dict(namespaces={key:dict(parent_inode=10,worker_inode=20)for key in ('mnt','net','pid')},worker_pid=1,loopback_only=True,private_mount_propagation=True,anchors_cloexec=True,namespace_exit_confirmed=True,private_dev_log=True)
        original=dict(schema_version=1,status='PASS',profile='k2p-4.4',execution_role=gate.MEASUREMENT_ROLE,source_sha256=sources,shipped=shipped,required_cases=list(gate.CASE_NAMES),checks=copy.deepcopy(self.good),filesystem_limits=gate.FILESYSTEM_LIMITS,limits=gate.LIMITS,workload=gate.WORKLOAD,contract=gate.CONTRACT,isolation=iso,failure=None)
        self.assertTrue(gate.validate_report(original,sources,shipped))
        for key,bad in [('schema_version',True),('status','SKIP'),('profile','native'),('execution_role',{}),('source_sha256',{}),('shipped',{}),('limits',{}),('workload',{}),('contract',{}),('required_cases',[]),('failure','ignored')]:
            value=copy.deepcopy(original);value[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):gate.validate_report(value,sources,shipped)
        value=copy.deepcopy(original);value['isolation']['namespaces']['net']['worker_inode']=10
        with self.assertRaises(RuntimeError):gate.validate_report(value,sources,shipped)

    def test_independent_dhcp_trace_identity_lease_and_slow_reply_controls(self):
        row=copy.deepcopy(self.good[0]);self.assertEqual(gate.summarize_dhcp(row['dhcp_requests'])['sent'],18)
        for field,bad in [('xid',True),('xid',123),('policy','wrong.fixture'),('received_ns',None)]:
            records=copy.deepcopy(row['dhcp_requests']);records[2][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):gate.summarize_dhcp(records)
        for field,bad in [('lease_bytes',1),('dhcp_summary',{})]:
            rows=copy.deepcopy(self.good);rows[0][field]=bad
            with self.assertRaises(ValueError):gate.validate_records(rows)
        rows=copy.deepcopy(self.good);row=rows[0]
        row['dhcp_requests'][7]['received_ns']=row['dhcp_requests'][7]['sent_ns']+1001000000
        row['dhcp_summary']=gate.summarize_dhcp(row['dhcp_requests'])
        with self.assertRaises(ValueError):gate.validate_records(rows)

    def test_dhcp_ack_normalizes_only_verified_real_xid(self):
        import socket
        packet=bytearray(gate.previous.inform_packet()[:240]);packet[0]=2
        struct.pack_into('!I',packet,4,0x4b320001);packet[20:24]=socket.inet_aton('127.0.0.1')
        policy=gate.DHCP_POLICY.encode();packet=bytes(packet)+bytes((53,1,5,15,len(policy)))+policy+b'\xff'
        self.assertEqual(gate.parse_dhcp(packet,0x4b320001),gate.DHCP_POLICY)
        for bad in (packet[:20]+b'\0'*4+packet[24:],packet.replace(policy,b'wrongxx.fixture'),packet[:-1]):
            with self.assertRaises((RuntimeError,ValueError)):gate.parse_dhcp(bad,0x4b320001)
        with self.assertRaises(ValueError):gate.parse_dhcp(packet,0x4b320002)

if __name__=='__main__':unittest.main()
