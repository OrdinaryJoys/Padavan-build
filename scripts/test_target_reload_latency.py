"""Pure timing/RSS/protocol corruption controls. No target, listener or mount."""
import copy
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
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
        rows=[dict(at_ns=1,phase='baseline',rss_kib=100,hwm_sum_kib=200,pss_kib=80,processes=1,pid=42,starttime=12345),
              dict(at_ns=10000001,phase='reload',rss_kib=300,hwm_sum_kib=400,pss_kib=160,processes=2,pid=42,starttime=12345)]
        value=gate.summarize_memory(rows)
        self.assertEqual((value['rss_max_kib'],value['hwm_sum_max_kib'],value['max_processes']),(300,400,2))
        self.assertEqual(value['phases']['reload']['pss_max_kib'],160)
        self.assertIsNone(value['phases']['settled'])
        for field,wrong in [('rss_kib',0),('hwm_sum_kib',1),('processes',True),('pss_kib',-1),('at_ns',0)]:
            bad=copy.deepcopy(rows);bad[1][field]=wrong
            with self.subTest(field=field),self.assertRaises(ValueError):gate.summarize_memory(bad)

    def test_sampler_exports_actual_parsed_identity_and_rejects_before_after_race(self):
        def stat(start=12345,pid=42):return str(pid)+' (qemu (public)) S '+' '.join(['1']+['0']*17+[str(start)])
        class Proc:
            records=[]
            def __init__(self,path):self.path=str(path)
            def __truediv__(self,part):return Proc(self.path+'/'+str(part))
            def read_text(self):
                if self.path.endswith('/stat'):return self.records.pop(0)
                if self.path.endswith('/status'):return 'VmRSS: 8192 kB\nVmHWM: 12288 kB\nVmData: 4096 kB\n'
                if self.path.endswith('/children'):return ''
                raise AssertionError(self.path)
        for end in (stat(),stat(54321),stat(pid=43)):
            Proc.records=[stat(),stat(),end]
            with patch.object(gate,'Path',Proc):
                measured=gate.Measurements(42)
                if end==stat():
                    row=measured.memory_observation();self.assertEqual((row['pid'],row['starttime']),(42,12345))
                    self.assertEqual(measured.memory,[row])
                else:
                    with self.assertRaisesRegex(ValueError,'PID identity'):measured.memory_observation()
        rows=[dict(at_ns=i+1,phase=phase,rss_kib=100,hwm_sum_kib=200,pss_kib=None,processes=1,pid=42,starttime=12345)
              for i,phase in enumerate(gate.PHASES)]
        for field,value in [('pid',True),('pid',0),('pid',43),('starttime',0),('starttime',54321)]:
            bad=copy.deepcopy(rows);bad[1][field]=value
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



def ptr_row(index):
    address,name=gate.ptr_fixture(index);indices=(0,10000,19999);ident=65100+indices.index(index)
    question=gate.encode_question(name)[:-4]+struct.pack('!HH',12,1)
    value=gate.encode_question('crowded.latency.fixture')[:-4]
    wire=struct.pack('!6H',ident,0x8180,1,1,0,0)+question+b'\xc0\x0c'+struct.pack('!HHIH',12,1,0,len(value))+value
    return dict(index=index,address=address,query_id=ident,query_name=name,expected='crowded.latency.fixture',observed='crowded.latency.fixture',reply_hex=wire.hex())


def measured_rows():
    result=[]
    for name in gate.CASE_NAMES:
        repeated=name==gate.CASE_NAMES[5]
        def phase_at(milliseconds):
            return 'baseline' if milliseconds<500 else 'reload' if milliseconds<(2000 if repeated else 1000) else 'settled'
        final=NEW if name in (gate.CASE_NAMES[1],gate.CASE_NAMES[2]) else gate.FALLBACK if name==gate.CASE_NAMES[3] else OLD
        records=[]
        for i in range(125 if repeated else 75):
            phase=phase_at(i*20)
            addresses=final if phase=='settled' else OLD
            records.append(dict(query_id=i,phase=phase,scheduled_ns=i*20000000,sent_ns=i*20000000+100000,
                                received_ns=i*20000000+1100000,addresses=addresses.copy()))
        memory=[dict(at_ns=i*10000000+1,phase=phase_at(i*10),rss_kib=10000,hwm_sum_kib=15000,pss_kib=None,processes=1,pid=42,starttime=12345)for i in range(250 if repeated else 150)]
        cycles=[]
        if name==gate.CASE_NAMES[5]:
            for cycle in range(1,21):
                sample=copy.deepcopy(memory[56+(cycle-1)*7]);expected=NEW if cycle&1 else OLD
                cycles.append(dict(cycle=cycle,expected_rrset=expected.copy(),observed_rrset=expected.copy(),
                    started_ns=sample['at_ns']-51000000,completed_ns=sample['at_ns']-50000000,settled_memory=sample))
        initial,candidate=gate.fixture_counts(name);old,new=gate.fixture_payloads(name)
        dhcp=[dict(xid=0x4b320000+i,phase=phase_at(i*100),scheduled_ns=i*100000000,sent_ns=i*100000000+100000,received_ns=i*100000000+1100000,policy=gate.DHCP_POLICY)for i in range(25 if repeated else 15)]
        rejected=name==gate.CASE_NAMES[4]
        row=dict(case=name,outcome='rejected-old-retained' if rejected else 'cold-accepted' if name==gate.CASE_NAMES[0] else 'committed',
                 startup_ready_ms=500,fixture=dict(initial_unique_per_file=initial,candidate_entries=candidate,initial=gate.fingerprints(old),candidate=gate.fingerprints(new)),
                 final_rrset=final,rejection_observed=rejected,requests=records,memory=memory,
                 request_summary=gate.summarize_requests(records,[OLD,NEW,gate.FALLBACK]),memory_summary=gate.summarize_memory(memory),dhcp_requests=dhcp,dhcp_summary=gate.summarize_dhcp(dhcp),lease_bytes=0,daemon_stopped=True,
                 rejection_reason='input-byte-limit' if rejected else None,partial_preparation_observed=True if rejected else None,
                 cycles=cycles,ptr_samples=[ptr_row(i)for i in (0,10000,19999)]if name==gate.CASE_NAMES[2]else [])
        result.append(row)
    return result


class ReloadLatencyContractControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.good=measured_rows()

    def test_exact_six_actual_workloads_and_generated_fingerprints(self):
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
        bad=copy.deepcopy(self.good);row=bad[4];row['requests'][30]['addresses']=NEW.copy()
        row['request_summary']=gate.summarize_requests(row['requests'],[OLD,NEW,gate.FALLBACK])
        with self.assertRaises(ValueError):gate.validate_records(bad)
        for field,value in [('outcome','committed'),('rejection_observed',False),('daemon_stopped',False),('startup_ready_ms',20001)]:
            bad=copy.deepcopy(self.good);bad[4][field]=value
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
        row=copy.deepcopy(self.good[0]);self.assertEqual(gate.summarize_dhcp(row['dhcp_requests'])['sent'],15)
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

    def test_same_name_requires_success_and_stricter_phase_latency(self):
        for field,value in [('outcome','rejected-old-retained'),('final_rrset',OLD),('rejection_observed',True)]:
            rows=copy.deepcopy(self.good);rows[2][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):gate.validate_records(rows)
        for protocol in ('requests','dhcp_requests'):
            rows=copy.deepcopy(self.good);row=rows[2]
            values=[r for r in row[protocol]if r['phase']=='reload']
            for record in values:record['received_ns']=record['sent_ns']+101000000
            if protocol=='requests':row['request_summary']=gate.summarize_requests(row[protocol],[OLD,NEW,gate.FALLBACK])
            else:row['dhcp_summary']=gate.summarize_dhcp(row[protocol])
            with self.subTest(protocol=protocol),self.assertRaisesRegex(ValueError,'stricter latency'):gate.validate_records(rows)
        self.assertEqual(self.good[4]['fixture']['candidate'][1]['bytes'],16*1024*1024+1)
        for field,value in [('partial_preparation_observed',False),('rejection_reason','hot-time-budget')]:
            rows=copy.deepcopy(self.good);rows[4][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):gate.validate_records(rows)

    def test_repeated_commits_require_every_epoch_and_bounded_warm_retention(self):
        for mutation in ('missing','same-policy','time-reversed','fabricated-memory'):
            rows=copy.deepcopy(self.good);cycles=rows[5]['cycles']
            if mutation=='missing':cycles.pop()
            elif mutation=='same-policy':cycles[1]['observed_rrset']=NEW.copy()
            elif mutation=='time-reversed':cycles[1]['started_ns']=cycles[0]['started_ns']
            else:cycles[1]['settled_memory']['rss_kib']+=1
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):gate.validate_records(rows)
        for growth in (8192,8193):
            rows=copy.deepcopy(self.good);row=rows[5]
            sample=next(item for item in row['memory']if item['at_ns']==row['cycles'][-1]['settled_memory']['at_ns'])
            sample['rss_kib']=10000+growth;sample['hwm_sum_kib']=max(sample['hwm_sum_kib'],sample['rss_kib'])
            row['cycles'][-1]['settled_memory']=copy.deepcopy(sample)
            row['memory_summary']=gate.summarize_memory(row['memory'])
            if growth==8192:self.assertTrue(gate.validate_records(rows))
            else:
                with self.assertRaisesRegex(ValueError,'retained excessive'):gate.validate_records(rows)

    def test_ptr_samples_reparse_actual_wire_for_first_middle_last(self):
        self.assertEqual(len(self.good[2]['ptr_samples']),3)
        for mutation in ('missing','index','observed','trailing','owner','type','qid'):
            rows=copy.deepcopy(self.good);samples=rows[2]['ptr_samples'];row=samples[0]
            if mutation=='missing':samples.pop()
            elif mutation=='index':row['index']=1
            elif mutation=='observed':row['observed']='other.fixture'
            else:
                wire=bytearray.fromhex(row['reply_hex'])
                if mutation=='trailing':wire+=b'x'
                elif mutation=='qid':wire[1]^=1
                else:
                    q=gate.encode_question(row['query_name']);cursor=12+len(q)
                    if mutation=='owner':wire[cursor+1]=13
                    else:wire[cursor+3]=5
                row['reply_hex']=wire.hex()
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):gate.validate_records(rows)

if __name__=='__main__':unittest.main()
