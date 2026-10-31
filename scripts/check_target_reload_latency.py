#!/usr/bin/env python3
"""Measurement primitives for actual shipped DNS reload latency gates.

The eventual target worker must use private PID/mount/network namespaces.
RSS/HWM/PSS refer to native host QEMU processes, not router/guest heap usage.
No target execution occurs at import or during pure host corruption controls.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import math
import re
import struct

import check_target_snapshot as base
import check_target_log_reload as previous
import check_target_runtime_dns as runtime

PHASES = ('baseline', 'reload', 'settled')
MAX_SAMPLES = 16384
RSS_KEYS = {'at_ns', 'phase', 'rss_kib', 'hwm_sum_kib', 'pss_kib', 'processes', 'pid', 'starttime'}
REQUEST_KEYS = {'query_id', 'phase', 'scheduled_ns', 'sent_ns', 'received_ns', 'addresses'}
MEASUREMENT_ROLE = {
    'program': 'Actual shipped MIPS DNS daemon under user-mode QEMU',
    'clock': 'Native private-worker monotonic timestamps, not emulated CPU cycles',
    'memory': 'Native single-QEMU RSS/reported HWM with raw PID/starttime; no PSS or guest/router heap claim',
    'latency': 'Private loopback UDP client RTT including QEMU, kernel and host scheduling',
    'dhcp': 'Actual shipped MIPS DHCP INFORM to fixed option15 policy; no lease allocation or client connectivity claim',
    'limit': 'Neither metric is a router memory/performance measurement or hardware acceptance',
}


def require(value, message):
    if not value:raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def percentile(values, percent):
    """Nearest-rank quantile, preserving actual observed outliers."""
    require(type(values) is list and values and type(percent) is int and 0 < percent <= 100,
            'Quantile requires nonempty observations and an integer percentile')
    require(all(type(x) in (int, float) and math.isfinite(x) and x >= 0 for x in values),
            'Invalid timing observation')
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)]


def parse_proc_status(text):
    """Parse native /proc/PID/status; never label these as guest measurements."""
    fields = {}
    for line in text.splitlines():
        match = re.fullmatch(r'(VmRSS|VmHWM|VmData):\s+([0-9]+) kB', line)
        if match:
            require(match[1] not in fields, 'Duplicate process memory counter')
            fields[match[1]] = int(match[2])
    require(set(fields) == {'VmRSS', 'VmHWM', 'VmData'} and fields['VmRSS'] > 0 and
            fields['VmHWM'] >= fields['VmRSS'], 'Missing/invalid live native QEMU memory counters')
    return dict(rss_kib=fields['VmRSS'],hwm_kib=fields['VmHWM'],data_kib=fields['VmData'])


def parse_proc_stat(text):
    """Parent/starttime identity, robust to spaces and parentheses in comm."""
    match = re.fullmatch(r'([0-9]+) \((.*)\) ([A-Za-z]) (.*)', text.strip())
    require(match is not None, 'Malformed native process stat')
    tail = match[4].split()
    require(len(tail) >= 19 and tail[0].isdigit() and tail[18].isdigit(), 'Truncated native process identity')
    require(match[3] not in ('Z', 'X', 'x'), 'Measured target is dead/zombie')
    return dict(pid=int(match[1]),parent=int(tail[0]),starttime=int(tail[18]),state=match[3])


def parse_pss_rollup(text):
    values = re.findall(r'^Pss:\s+([0-9]+) kB$', text, re.M)
    require(len(values) == 1, 'Missing/duplicate native PSS counter')
    return int(values[0])


def summarize_memory(samples):
    require(type(samples) is list and 1 <= len(samples) <= MAX_SAMPLES, 'Missing/excessive memory trace')
    last = -1
    identity = None
    for row in samples:
        require(type(row) is dict and set(row) == RSS_KEYS and row['phase'] in PHASES and
                integer(row['at_ns']) and row['at_ns'] > last and integer(row['rss_kib'],1) and
                integer(row['hwm_sum_kib'],1) and row['hwm_sum_kib'] >= row['rss_kib'] and
                integer(row['processes'],1) and (row['pss_kib'] is None or integer(row['pss_kib'])) and
                integer(row['pid'],1) and integer(row['starttime'],1),
                'Malformed/out-of-order native memory trace')
        current = (row['pid'], row['starttime'])
        require(identity is None or current == identity, 'Measured process PID/starttime changed')
        identity = current
        last = row['at_ns']
    phases = {}
    for phase in PHASES:
        rows = [r for r in samples if r['phase'] == phase]
        phases[phase] = None if not rows else dict(samples=len(rows),
            rss_max_kib=max(r['rss_kib'] for r in rows),rss_median_kib=percentile([r['rss_kib'] for r in rows],50),
            hwm_sum_max_kib=max(r['hwm_sum_kib'] for r in rows),
            pss_max_kib=None if any(r['pss_kib'] is None for r in rows) else max(r['pss_kib'] for r in rows),
            max_processes=max(r['processes'] for r in rows))
    return dict(samples=len(samples),first_ns=samples[0]['at_ns'],last_ns=samples[-1]['at_ns'],
                identity=dict(pid=identity[0],starttime=identity[1]),
                sample_gap_max_ms=max([0]+[(b['at_ns']-a['at_ns'])/1e6 for a,b in zip(samples,samples[1:])]),
                rss_max_kib=max(r['rss_kib'] for r in samples),
                hwm_sum_max_kib=max(r['hwm_sum_kib'] for r in samples),
                max_processes=max(r['processes'] for r in samples),phases=phases)


def summarize_requests(records, allowed_rrsets):
    require(type(records) is list and 1 <= len(records) <= MAX_SAMPLES and type(allowed_rrsets) is list and
            allowed_rrsets and all(type(s) in (tuple,list) and len(s)==2 and len(set(s))==2 for s in allowed_rrsets),
            'Missing request trace/atomic RRset contract')
    allowed = {tuple(sorted(s)) for s in allowed_rrsets}
    for rrset in allowed:
        require(all(ipaddress.ip_address(x).version == 4 for x in rrset), 'Non-IPv4 fixture RRset')
    last = -1; identities = set()
    for row in records:
        require(type(row) is dict and set(row) == REQUEST_KEYS and integer(row['query_id']) and
                row['query_id'] <= 65535 and row['query_id'] not in identities and row['phase'] in PHASES and
                integer(row['scheduled_ns']) and integer(row['sent_ns']) and row['sent_ns'] >= row['scheduled_ns'] and
                row['sent_ns'] > last, 'Malformed request identity/schedule')
        last=row['sent_ns'];identities.add(row['query_id'])
        if row['received_ns'] is None:
            require(row['addresses'] is None,'Unreceived query has an answer')
        else:
            require(integer(row['received_ns']) and row['received_ns'] >= row['sent_ns'] and
                    type(row['addresses']) is list and len(row['addresses']) == 2 and
                    tuple(sorted(row['addresses'])) in allowed, 'Mixed/unknown atomic DNS answer or negative RTT')
    phases = {}
    for phase in PHASES:
        rows=[r for r in records if r['phase']==phase]
        received=[r for r in rows if r['received_ns'] is not None]
        times=[(r['received_ns']-r['sent_ns'])/1e6 for r in received]
        phases[phase]=dict(sent=len(rows),received=len(received),timeouts=len(rows)-len(received),
            rtt_max_ms=max(times) if times else None,rtt_p95_ms=percentile(times,95) if times else None,
            send_lateness_max_ms=max([(r['sent_ns']-r['scheduled_ns'])/1e6 for r in rows],default=None))
    times=[(r['received_ns']-r['sent_ns'])/1e6 for r in records if r['received_ns'] is not None]
    return dict(sent=len(records),received=len(times),timeouts=len(records)-len(times),
        rtt_max_ms=max(times) if times else None,rtt_p95_ms=percentile(times,95) if times else None,
        send_gap_max_ms=max([0]+[(b['sent_ns']-a['sent_ns'])/1e6 for a,b in zip(records,records[1:])]),
        send_lateness_max_ms=max((r['sent_ns']-r['scheduled_ns'])/1e6 for r in records),phases=phases)


def encode_question(name):
    require(type(name) is str and re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',name) is not None,'Invalid fixed DNS fixture name')
    labels=name.split('.')
    require(all(0<len(label)<=63 for label in labels),'DNS label limit')
    encoded=b''.join(bytes([len(label)])+label.encode('ascii') for label in labels)+b'\0'
    require(len(encoded)<=255,'DNS name limit')
    return encoded+b'\0\x01\0\x01'


def parse_rrset(data, query_id, name):
    require(type(data) is bytes and 12<=len(data)<=4096 and integer(query_id) and query_id<=65535,
            'Invalid DNS fixture packet')
    ident,flags,qd,answers,authority,additional=struct.unpack_from('!6H',data)
    require(ident==query_id and flags&0x8000 and flags&0x7a0f==0 and qd==1 and answers==2 and authority==additional==0,
            'DNS reply does not contain one complete two-record RRset')
    question=encode_question(name);require(data[12:12+len(question)]==question,'DNS reply question differs')
    cursor=12+len(question);addresses=[]
    for _ in range(answers):
        owner_end=base.skip_name(data,cursor)
        require(data[cursor:owner_end] in (b'\xc0\x0c',question[:-4]),'DNS answer owner differs')
        cursor=owner_end
        require(cursor+14<=len(data),'Truncated DNS A record')
        kind,cls,_,size=struct.unpack_from('!HHIH',data,cursor)
        require(kind==cls==1 and size==4,'Unexpected DNS RR type')
        addresses.append(str(ipaddress.IPv4Address(data[cursor+10:cursor+14])));cursor+=14
    require(cursor==len(data) and len(set(addresses))==2,'Duplicate/trailing DNS answer data')
    return sorted(addresses)


SOURCE_PATHS = dict(previous.SOURCE_PATHS, **{'hosts-util.c': 'user/dnsmasq/dnsmasq-2.93/src/util.c'})

def source_proof(trunk):
    proof = dict(previous.source_proof(trunk))
    proof['hosts-util.c'] = base.sha((trunk / SOURCE_PATHS['hosts-util.c']).read_bytes())
    return proof

CASE_NAMES = ('cold-large-unique-accepted','hot-small-commit','hot-same-name-commit','large-to-empty-commit',
              'overlimit-second-hosts-rejected','repeated-hot-commit')
NAME = 'atomic.latency.fixture'
OLD = ['192.0.2.51','192.0.2.61']
NEW = ['192.0.2.52','192.0.2.62']
FALLBACK = ['192.0.2.53','192.0.2.63']
WORKLOAD = dict(cold_unique_per_file=20000,hot_unique_per_file=512,pathological_same_name=20000,
                repeat_unique_per_file=2000,repeat_cycles=20,cycle_settle_ms=50,retention_window_cycles=5,
                overlimit_bytes=16*1024*1024+1,
                hosts_files=2,query_interval_ms=20,dhcp_interval_ms=100,memory_interval_ms=10,
                baseline_ms=600,settled_ms=800)
FILESYSTEM_LIMITS = dict(previous.FILESYSTEM_LIMITS,tmp=64*1024*1024)
LIMITS = dict(worker_seconds=180,command_seconds=20,output_bytes=131072,report_bytes=1048576,
              query_seconds=4,reload_seconds=6,startup_ready_ms=20000,
              rtt_max_ms=1000,rtt_p95_ms=500,send_lateness_max_ms=250,
              send_gap_max_ms=300,memory_sample_gap_max_ms=300,
              rss_max_kib=262144,rss_growth_max_kib=98304,query_timeout_ms=1500)
LIMITS.update(same_name_rtt_max_ms=150,same_name_rtt_p95_ms=100,repeat_retention_max_kib=8192)
CONTRACT = dict(policy='Every observed response is one whole OLD/NEW/FALLBACK two-A RRset; rejected candidate retains OLD',
                hot='250ms cooperative production prepare budget; gate1000ms max observed loopback RTT includes cleanup/QEMU/host scheduling',
                cold='40k unique synthetic hosts accepted at initial load; startup readiness and lifetime native HWM reported separately',
                rss='Sampled main QEMU RSS and lifetime HWM both capped; HWM minus baseline RSS includes cold startup/JIT; no fork; not guest/router heap',
                sampling='10ms requested samples are a lower bound on transient peaks; send/sample gaps checked independently',
                pss='Not sampled: single daemon PID; no forked candidate worker or claimed PSS estimate',
                same_name='20k distinct-address same-name candidate must commit; DNS and INFORM max150/p95100ms also apply within reload phase',
                rejection='Second hosts file exceeds original16MiB limit after a small first candidate; entire OLD model must remain; not a time-budget proof',
                repeated='20 alternating commits of4k unique hosts plus markers; last5 completion RSS max minus first5 max at most8MiB',
                identity='Each raw sample exports actual PID/starttime checked before and after native proc status; one process, no children',
                ptr='After timed clients stop, actual PTR wire samples at first/middle/last of20k must identify crowded.latency.fixture; three samples are not exhaustive enumeration',
                scope='Private loopback only. Not a universal latency SLA, kernel I/O deadline or router performance benchmark')
ROW_KEYS={'case','outcome','startup_ready_ms','fixture','final_rrset','rejection_observed','requests','memory',
          'request_summary','memory_summary','dhcp_requests','dhcp_summary','lease_bytes','daemon_stopped',
          'rejection_reason','partial_preparation_observed','cycles','ptr_samples'}
CYCLE_KEYS={'cycle','expected_rrset','observed_rrset','started_ns','completed_ns','settled_memory'}
PTR_KEYS={'index','address','query_id','query_name','expected','observed','reply_hex'}


def fixture_counts(name):
    require(name in CASE_NAMES,'Unknown latency workload')
    initial=WORKLOAD['cold_unique_per_file'] if name in (CASE_NAMES[0],CASE_NAMES[3]) else WORKLOAD['repeat_unique_per_file'] if name==CASE_NAMES[5] else 1
    candidate=WORKLOAD['hot_unique_per_file'] if name==CASE_NAMES[1] else WORKLOAD['pathological_same_name'] if name==CASE_NAMES[2] else WORKLOAD['repeat_unique_per_file'] if name==CASE_NAMES[5] else 0
    return initial,candidate


DHCP_POLICY='latency.fixture'
DHCP_KEYS={'xid','phase','scheduled_ns','sent_ns','received_ns','policy'}


def parse_dhcp(data,xid):
    require(type(data)is bytes and len(data)>=8 and integer(xid) and xid<=0xffffffff and
            struct.unpack_from('!I',data,4)[0]==xid,'DHCP measured xid differs')
    # The existing exact BOOTP/option parser has a fixed public fixture xid.
    # Verify the real correlation first, then normalize only that field on a
    # private copy; every other production reply byte retains its checks.
    copied=data[:4]+bytes.fromhex('4b325531')+data[8:]
    policy=previous.parse_inform(copied)
    require(policy==DHCP_POLICY,'Fixed measured DHCP option15 policy changed')
    return policy


def summarize_dhcp(records):
    require(type(records)is list and 1<=len(records)<=MAX_SAMPLES,'Missing/excessive DHCP trace')
    normalized=[]
    for index,row in enumerate(records):
        require(type(row)is dict and set(row)==DHCP_KEYS and type(row['xid'])is int and row['xid']==0x4b320000+index,
                'DHCP unique xid/schema differs')
        require(row['policy']==(None if row['received_ns']is None else DHCP_POLICY),'DHCP missing/unknown fixed policy')
        normalized.append(dict(query_id=index,phase=row['phase'],scheduled_ns=row['scheduled_ns'],sent_ns=row['sent_ns'],
            received_ns=row['received_ns'],addresses=None if row['received_ns']is None else OLD.copy()))
    return summarize_requests(normalized,[OLD])


def ptr_fixture(index):
    require(index in (0,WORKLOAD['pathological_same_name']//2,WORKLOAD['pathological_same_name']-1),'Unexpected PTR sample index')
    address=str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('198.18.0.1'))+index))
    return address,ipaddress.IPv4Address(address).reverse_pointer


def decode_name(data,start):
    labels=[];position=start;end=None;seen=set()
    for _ in range(128):
        require(0<=position<len(data) and position not in seen,'Invalid/cyclic DNS name')
        seen.add(position);length=data[position]
        if length&0xc0==0xc0:
            require(position+1<len(data),'Truncated DNS name pointer')
            pointer=((length&63)<<8)|data[position+1]
            require(pointer<position,'Forward DNS name pointer')
            if end is None:end=position+2
            position=pointer;continue
        require(length<=63 and position+1+length<=len(data),'Invalid DNS label extent')
        position+=1
        if not length:
            return '.'.join(labels).lower(),position if end is None else end
        label=data[position:position+length].decode('ascii')
        require(re.fullmatch('[A-Za-z0-9-]+',label)is not None,'Invalid fixed PTR label')
        labels.append(label);position+=length
        require(sum(map(len,labels))+len(labels)<=255,'DNS name too long')
    raise ValueError('Excessive DNS name indirection')


def parse_ptr(data,query_id,name):
    require(type(data)is bytes and 12<=len(data)<=4096 and integer(query_id) and query_id<=65535,'Invalid PTR packet')
    ident,flags,qd,answers,authority,additional=struct.unpack_from('!6H',data)
    require(ident==query_id and flags&0x8000 and flags&0x7a0f==0 and qd==answers==1 and authority==additional==0,'PTR header/answer count differs')
    question=encode_question(name)[:-4]+struct.pack('!HH',12,1)
    require(data[12:12+len(question)]==question,'PTR question differs')
    cursor=12+len(question);owner,cursor=decode_name(data,cursor)
    require(owner==name and cursor+10<=len(data),'PTR owner/truncation differs')
    kind,cls,_,length=struct.unpack_from('!HHIH',data,cursor);cursor+=10
    require(kind==12 and cls==1 and length>0 and cursor+length==len(data),'PTR type/extent differs')
    value,end=decode_name(data,cursor);require(end==cursor+length,'PTR RDATA extent differs')
    return value


def validate_ptr_samples(rows,required):
    indices=(0,WORKLOAD['pathological_same_name']//2,WORKLOAD['pathological_same_name']-1)
    require(type(rows)is list and len(rows)==(3 if required else 0),'Missing/excess PTR samples')
    for index,row in zip(indices,rows):
        address,name=ptr_fixture(index);ident=65100+indices.index(index)
        require(type(row)is dict and set(row)==PTR_KEYS and row['index']==index and type(row['index'])is int and
                row['address']==address and row['query_name']==name and row['query_id']==ident and type(row['query_id'])is int and
                row['expected']=='crowded.latency.fixture' and type(row['reply_hex'])is str and
                re.fullmatch('(?:[0-9a-f]{2}){12,4096}',row['reply_hex'])is not None,'PTR sample identity/schema differs')
        value=parse_ptr(bytes.fromhex(row['reply_hex']),ident,name)
        require(row['observed']==value==row['expected'],'PTR sample did not load expected candidate address')


def validate_cycles(rows,memory,required):
    require(type(rows)is list and len(rows)==(WORKLOAD['repeat_cycles'] if required else 0),'Missing/excess commit cycles')
    last=-1
    for index,row in enumerate(rows,1):
        expected=NEW if index&1 else OLD
        require(type(row)is dict and set(row)==CYCLE_KEYS and type(row['cycle'])is int and row['cycle']==index and
                row['expected_rrset']==row['observed_rrset']==expected and integer(row['started_ns']) and
                integer(row['completed_ns']) and row['started_ns']>last and row['completed_ns']>=row['started_ns'],
                'Commit cycle identity/policy/time differs')
        sample=row['settled_memory']
        require(sample in memory and sample['phase']=='reload' and
                sample['at_ns']-row['completed_ns']>=WORKLOAD['cycle_settle_ms']*1000000,
                'Cycle completion memory was not sampled from the measured process')
        last=sample['at_ns']
    if rows:
        window=WORKLOAD['retention_window_cycles']
        first=max(row['settled_memory']['rss_kib']for row in rows[:window])
        final=max(row['settled_memory']['rss_kib']for row in rows[-window:])
        require(final-first<=LIMITS['repeat_retention_max_kib'],'Repeated commit retained excessive native RSS')


def validate_records(records):
    require(type(records)is list and len(records)==len(CASE_NAMES),'Missing reload latency cases')
    for name,row in zip(CASE_NAMES,records):
        require(type(row)is dict and set(row)==ROW_KEYS and row['case']==name and row['daemon_stopped']is True,'Latency case schema/order/cleanup differs')
        rejected=name==CASE_NAMES[4]
        final=NEW if name in (CASE_NAMES[1],CASE_NAMES[2]) else FALLBACK if name==CASE_NAMES[3] else OLD
        outcome='rejected-old-retained' if rejected else 'cold-accepted' if name==CASE_NAMES[0] else 'committed'
        require(row['outcome']==outcome and row['final_rrset']==final and row['rejection_observed']is rejected,'Reload state/policy differs')
        require(row['rejection_reason']==('input-byte-limit' if rejected else None) and
                row['partial_preparation_observed']is (True if rejected else None),'Rejection stage/reason differs')
        require(type(row['startup_ready_ms'])is int and 0<=row['startup_ready_ms']<=LIMITS['startup_ready_ms'],'Cold readiness exceeded bound')
        fixture=row['fixture'];initial,candidate=fixture_counts(name)
        require(type(fixture)is dict and set(fixture)=={'initial_unique_per_file','candidate_entries','initial','candidate'} and
                type(fixture['initial_unique_per_file'])is int and fixture['initial_unique_per_file']==initial and
                type(fixture['candidate_entries'])is int and fixture['candidate_entries']==candidate,'Latency workload changed')
        for key in ('initial','candidate'):
            files=fixture[key]
            require(type(files)is list and len(files)==2,'Missing workload file fingerprints')
            for index,item in enumerate(files):
                limit=WORKLOAD['overlimit_bytes'] if rejected and key=='candidate' and index==1 else 16*1024*1024
                require(type(item)is dict and set(item)=={'bytes','sha256'} and integer(item['bytes']) and item['bytes']<=limit and
                        type(item['sha256'])is str and re.fullmatch('[0-9a-f]{64}',item['sha256'])is not None,'Invalid workload bytes/SHA')
        old_payloads,new_payloads=fixture_payloads(name)
        require(fixture['initial']==fingerprints(old_payloads) and fixture['candidate']==fingerprints(new_payloads),'Public workload payload fingerprints differ')
        requests=summarize_requests(row['requests'],[OLD,NEW,FALLBACK]);memory=summarize_memory(row['memory']);dhcp=summarize_dhcp(row['dhcp_requests'])
        require(row['request_summary']==requests and row['memory_summary']==memory and row['dhcp_summary']==dhcp,'Metrics were not recomputed from raw observations')
        require(requests['timeouts']==0 and requests['sent']>=40 and requests['rtt_max_ms']<=LIMITS['rtt_max_ms'] and
                requests['rtt_p95_ms']<=LIMITS['rtt_p95_ms'] and requests['send_gap_max_ms']<=LIMITS['send_gap_max_ms'] and
                requests['send_lateness_max_ms']<=LIMITS['send_lateness_max_ms'],'Observed reload responsiveness failed')
        require(type(row['lease_bytes'])is int and row['lease_bytes']==0,'INFORM unexpectedly allocated/persisted a lease')
        require(dhcp['timeouts']==0 and dhcp['sent']>=14 and dhcp['rtt_max_ms']<=LIMITS['rtt_max_ms'] and dhcp['rtt_p95_ms']<=LIMITS['rtt_p95_ms'] and
                dhcp['send_gap_max_ms']<=LIMITS['send_gap_max_ms'] and dhcp['send_lateness_max_ms']<=LIMITS['send_lateness_max_ms'],'Observed DHCP responsiveness failed')
        require(memory['samples']>=50 and memory['sample_gap_max_ms']<=LIMITS['memory_sample_gap_max_ms'] and
                memory['rss_max_kib']<=LIMITS['rss_max_kib'] and memory['hwm_sum_max_kib']<=LIMITS['rss_max_kib'] and memory['max_processes']==1 and
                all(sample['pss_kib']is None for sample in row['memory']),'Native QEMU memory/sampling gate failed')
        for phase in PHASES:
            require(requests['phases'][phase]['sent']>=10 and dhcp['phases'][phase]['sent']>=2 and memory['phases'][phase]is not None,'Missing measured reload phase')
        baseline=memory['phases']['baseline']['rss_median_kib']
        require(memory['rss_max_kib']-baseline<=LIMITS['rss_growth_max_kib'] and memory['hwm_sum_max_kib']-baseline<=LIMITS['rss_growth_max_kib'],'Observed candidate memory growth exceeded gate')
        if name==CASE_NAMES[2]:
            for summary in (requests,dhcp):
                for values in (summary,summary['phases']['reload']):
                    require(values['rtt_max_ms']<=LIMITS['same_name_rtt_max_ms'] and
                            values['rtt_p95_ms']<=LIMITS['same_name_rtt_p95_ms'],'Same-name candidate did not meet stricter latency gate')
        permitted=[tuple(OLD)] if name in (CASE_NAMES[0],CASE_NAMES[4]) else [tuple(OLD),tuple(NEW)] if name==CASE_NAMES[5] else [tuple(OLD),tuple(final)]
        require(all(tuple(r['addresses'])in permitted for r in row['requests']),'Rejected/partial candidate leaked into queries')
        settled=[r for r in row['requests'] if r['phase']=='settled']
        require(all(r['addresses']==final for r in settled),'Settled policy not committed or old policy lost')
        validate_cycles(row['cycles'],row['memory'],name==CASE_NAMES[5])
        validate_ptr_samples(row['ptr_samples'],name==CASE_NAMES[2])
    return True


def validate_report(report,sources,shipped):
    require(type(report)is dict and set(report)=={'schema_version','status','profile','execution_role','source_sha256','shipped',
            'required_cases','checks','filesystem_limits','limits','workload','contract','isolation','failure'},'Latency report schema differs')
    require(type(report['schema_version'])is int and report['schema_version']==1 and report['status']=='PASS' and report['profile']=='k2p-4.4' and report['failure']is None,'Latency proof not PASS')
    require(report['execution_role']==MEASUREMENT_ROLE and report['source_sha256']==sources and report['shipped']==shipped and
            report['required_cases']==list(CASE_NAMES) and report['filesystem_limits']==FILESYSTEM_LIMITS and report['limits']==LIMITS and
            report['workload']==WORKLOAD and report['contract']==CONTRACT,'Latency source/image/workload/limits changed')
    import check_target_syslog_producers as producer
    producer.validate_isolation(report['isolation']);return validate_records(report['checks'])


class PairUpstream:
    def __init__(self):
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.sock.bind(('127.0.0.1',11532));self.sock.settimeout(.1)
        self.stop_event=threading.Event();self.thread=threading.Thread(target=self.run,daemon=True);self.failure=None;self.thread.start()
    def run(self):
        try:
            while not self.stop_event.is_set():
                try:packet,peer=self.sock.recvfrom(4096)
                except socket.timeout:continue
                require(peer[0]=='127.0.0.1' and 12<=len(packet)<=4096,'Unexpected synthetic upstream peer/size')
                ident,flags,qd,an,ns,ar=struct.unpack_from('!6H',packet)
                question=encode_question(NAME);end=12+len(question)
                require(flags&0x8000==0 and qd==1 and an==ns==0 and ar<=1 and packet[12:end]==question,'Unexpected synthetic upstream question')
                if ar:
                    require(packet[end:end+1]==b'\0' and end+11<=len(packet),'Malformed fixture EDNS record')
                    kind,_,_,length=struct.unpack_from('!HHIH',packet,end+1)
                    require(kind==41 and end+11+length==len(packet),'Unexpected fixture EDNS extent')
                else:require(end==len(packet),'Unexpected trailing upstream data')
                answer=struct.pack('!6H',ident,0x8180,1,2,0,0)+question
                for address in FALLBACK:answer+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+socket.inet_aton(address)
                self.sock.sendto(answer,peer)
        except Exception as error:self.failure=str(error)
    def close(self):
        self.stop_event.set();self.thread.join(1);self.sock.close()
        require(not self.thread.is_alive() and self.failure is None,'Synthetic upstream failed: '+str(self.failure))


class Measurements:
    def __init__(self,pid):
        self.pid=pid;self.phase='baseline';self.requests=[];self.dhcp_requests=[];self.memory=[];self.failures=[];self.stop_event=threading.Event()
        self.memory_lock=threading.Lock()
        self.identity=parse_proc_stat(Path('/proc/'+str(pid)+'/stat').read_text())
        self.threads=[threading.Thread(target=self.client,daemon=True),threading.Thread(target=self.dhcp_client,daemon=True),threading.Thread(target=self.sampler,daemon=True)]
    def start(self):
        for thread in self.threads:thread.start()
    def client(self):
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.setblocking(False);pending={};next_send=time.monotonic_ns();ident=0
                while not self.stop_event.is_set() or pending:
                    now=time.monotonic_ns()
                    if not self.stop_event.is_set() and now>=next_send:
                        require(ident<MAX_SAMPLES,'Query trace exceeded budget')
                        scheduled=next_send;next_send+=WORKLOAD['query_interval_ms']*1000000
                        # Skip missed slots, but preserve actual scheduling lateness/gap.
                        if next_send<now:next_send=now+WORKLOAD['query_interval_ms']*1000000
                        row=dict(query_id=ident,phase=self.phase,scheduled_ns=scheduled,sent_ns=time.monotonic_ns(),received_ns=None,addresses=None)
                        sock.sendto(struct.pack('!6H',ident,0x100,1,0,0,0)+encode_question(NAME),('127.0.0.1',10530))
                        self.requests.append(row);pending[ident]=row;ident+=1
                    for key,row in list(pending.items()):
                        if now-row['sent_ns']>LIMITS['query_timeout_ms']*1000000:del pending[key]
                    ready,_,_=select.select([sock],[],[],.005)
                    if ready:
                        packet,peer=sock.recvfrom(4097);received=time.monotonic_ns()
                        require(peer==('127.0.0.1',10530) and len(packet)>=12,'Unexpected measured DNS peer/packet')
                        key=struct.unpack_from('!H',packet)[0];require(key in pending,'Unknown/duplicate/late measured DNS reply')
                        row=pending.pop(key);row['addresses']=parse_rrset(packet,key,NAME);row['received_ns']=received
        except Exception as error:self.failures.append('query: '+str(error));self.stop_event.set()
    def dhcp_client(self):
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.bind(('127.0.0.2',0));sock.setblocking(False);pending={};next_send=time.monotonic_ns();ident=0
                while not self.stop_event.is_set() or pending:
                    now=time.monotonic_ns()
                    if not self.stop_event.is_set() and now>=next_send:
                        require(ident<MAX_SAMPLES,'DHCP trace exceeded budget')
                        scheduled=next_send;next_send+=WORKLOAD['dhcp_interval_ms']*1000000
                        if next_send<now:next_send=now+WORKLOAD['dhcp_interval_ms']*1000000
                        xid=0x4b320000+ident;packet=bytearray(previous.inform_packet());struct.pack_into('!I',packet,4,xid)
                        row=dict(xid=xid,phase=self.phase,scheduled_ns=scheduled,sent_ns=time.monotonic_ns(),received_ns=None,policy=None)
                        sock.sendto(packet,('127.0.0.1',67));self.dhcp_requests.append(row);pending[xid]=row;ident+=1
                    for key,row in list(pending.items()):
                        if now-row['sent_ns']>LIMITS['query_timeout_ms']*1000000:del pending[key]
                    ready,_,_=select.select([sock],[],[],.005)
                    if ready:
                        packet,peer=sock.recvfrom(4097);received=time.monotonic_ns()
                        require(peer==('127.0.0.1',67) and len(packet)>=8,'Unexpected measured DHCP peer/packet')
                        xid=struct.unpack_from('!I',packet,4)[0];require(xid in pending,'Unknown/duplicate/late measured INFORM reply')
                        row=pending.pop(xid);row['policy']=parse_dhcp(packet,xid);row['received_ns']=received
        except Exception as error:self.failures.append('DHCP: '+str(error));self.stop_event.set()
    def memory_observation(self):
        with self.memory_lock:
            now=time.monotonic_ns();root=Path('/proc/'+str(self.pid));before=parse_proc_stat((root/'stat').read_text())
            counters=parse_proc_status((root/'status').read_text());after=parse_proc_stat((root/'stat').read_text())
            require(before['pid']==after['pid']==self.identity['pid'] and before['starttime']==after['starttime']==self.identity['starttime'],'QEMU PID identity changed')
            require(not (root/'task'/str(self.pid)/'children').read_text().strip(),'Reload introduced unmeasured child processes')
            row=dict(at_ns=now,phase=self.phase,rss_kib=counters['rss_kib'],hwm_sum_kib=counters['hwm_kib'],pss_kib=None,processes=1,
                     pid=after['pid'],starttime=after['starttime'])
            require(len(self.memory)<MAX_SAMPLES,'Memory trace exceeded budget')
            self.memory.append(row)
            return dict(row)
    def sampler(self):
        try:
            while not self.stop_event.is_set():
                self.memory_observation();self.stop_event.wait(WORKLOAD['memory_interval_ms']/1000)
        except Exception as error:self.failures.append('memory: '+str(error));self.stop_event.set()
    def finish(self):
        self.stop_event.set()
        for thread in self.threads:thread.join(3)
        require(not any(thread.is_alive()for thread in self.threads) and not self.failures,'Measurement worker failed: '+repr(self.failures))


def payload(index,count,pair):
    return ((pair+' '+NAME+'\n')+''.join('192.0.2.1 u'+str(index)+'-'+str(i)+'.latency.fixture\n'for i in range(count))).encode()


def fixture_payloads(name):
    initial,candidate=fixture_counts(name)
    old=[payload(i,initial,OLD[i])for i in range(2)]
    if name==CASE_NAMES[1]:new=[payload(i,candidate,NEW[i])for i in range(2)]
    elif name==CASE_NAMES[2]:
        crowded=''.join(str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('198.18.0.1'))+i))+' crowded.latency.fixture\n'for i in range(candidate)).encode()
        new=[payload(0,1,NEW[0])+crowded,payload(1,1,NEW[1])]
    elif name==CASE_NAMES[3]:new=[b'',b'']
    elif name==CASE_NAMES[4]:
        new=[payload(0,1,NEW[0]),(b'#'+b' '*62+b'\n')*(16*1024*1024//64)+b'\n']
    elif name==CASE_NAMES[5]:new=[payload(i,candidate,NEW[i])for i in range(2)]
    else:new=old
    return old,new


def fingerprints(files):return [dict(bytes=len(data),sha256=base.sha(data))for data in files]


def ready_pair(expected,timeout=6):
    deadline=time.monotonic()+timeout
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(.1)
        while time.monotonic()<deadline:
            sock.sendto(struct.pack('!6H',65000,0x100,1,0,0,0)+encode_question(NAME),('127.0.0.1',10530))
            try:packet,peer=sock.recvfrom(4097)
            except (socket.timeout,ConnectionRefusedError):continue
            require(peer==('127.0.0.1',10530),'Unexpected readiness DNS peer')
            observed=parse_rrset(packet,65000,NAME)
            if observed==expected:return dict(rrset=observed,received_ns=time.monotonic_ns())
    raise RuntimeError('Measured DNS expected RRset not ready: '+repr(expected))


def sample_ptrs():
    rows=[]
    indices=(0,WORKLOAD['pathological_same_name']//2,WORKLOAD['pathological_same_name']-1)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(LIMITS['query_seconds'])
        for sample,index in enumerate(indices):
            address,name=ptr_fixture(index);ident=65100+sample
            question=encode_question(name)[:-4]+struct.pack('!HH',12,1)
            sock.sendto(struct.pack('!6H',ident,0x100,1,0,0,0)+question,('127.0.0.1',10530))
            packet,peer=sock.recvfrom(4097)
            require(peer==('127.0.0.1',10530),'Unexpected PTR sample peer')
            rows.append(dict(index=index,address=address,query_id=ident,query_name=name,expected='crowded.latency.fixture',
                             observed=parse_ptr(packet,ident,name),reply_hex=packet.hex()))
    validate_ptr_samples(rows,True)
    return rows


def exercise(args,name):
    directory=Path('/tmp/reload-latency-case');directory.mkdir(mode=0o755)
    initial,candidate=fixture_counts(name);old,new=fixture_payloads(name)
    paths=[directory/('hosts'+str(i))for i in range(2)]
    for path,data in zip(paths,old):base.regular(path,data,0o644)
    # The actual option parser prepends each addn-hosts node. Emit in reverse
    # so the small hosts0 candidate is prepared before the overlimit hosts1.
    config=''.join('addn-hosts='+str(path)+'\n'for path in reversed(paths))
    config+='dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h\ndhcp-option=option:domain-name,'+DHCP_POLICY+'\ndhcp-leasefile='+str(directory/'leases')+'\n'
    begin=time.monotonic();pid=previous.launch(args,directory,config);measure=None
    try:
        ready_pair(OLD,timeout=LIMITS['startup_ready_ms']/1000)
        if initial>1:previous.query('u1-'+str(initial-1)+'.latency.fixture','192.0.2.1')
        previous.inform(DHCP_POLICY)
        startup_ms=int((time.monotonic()-begin)*1000)
        measure=Measurements(pid);measure.start();time.sleep(WORKLOAD['baseline_ms']/1000)
        measure.phase='reload';offset=(directory/'daemon.log').stat().st_size
        cycles=[];rejected=False;reason=None;partial=None
        if name==CASE_NAMES[5]:
            for cycle in range(1,WORKLOAD['repeat_cycles']+1):
                desired=NEW if cycle&1 else OLD;payloads=new if cycle&1 else old
                for path,data in zip(paths,payloads):previous.replace(path,data)
                started=time.monotonic_ns();os.kill(pid,signal.SIGHUP)
                observation=ready_pair(desired)
                time.sleep(WORKLOAD['cycle_settle_ms']/1000)
                cycles.append(dict(cycle=cycle,expected_rrset=desired.copy(),observed_rrset=observation['rrset'],
                    started_ns=started,completed_ns=observation['received_ns'],settled_memory=measure.memory_observation()))
        elif name!=CASE_NAMES[0]:
            for path,data in zip(paths,new):previous.replace(path,data)
            os.kill(pid,signal.SIGHUP)
        final=NEW if name in (CASE_NAMES[1],CASE_NAMES[2]) else FALLBACK if name==CASE_NAMES[3] else OLD
        if name==CASE_NAMES[4]:
            deadline=time.monotonic()+LIMITS['reload_seconds']
            while time.monotonic()<deadline:
                text=(directory/'daemon.log').read_bytes()[offset:]
                if b'reload transaction rejected; previous hosts/DHCP configuration retained' in text:
                    require(b'runtime DNS input exceeds its byte limit'in text,'Overlimit candidate rejected for unexpected reason')
                    first=b'read '+str(paths[0]).encode()+b' - '
                    require(first in text and text.index(first)<text.index(b'reload transaction rejected;'),'First file was not prepared before second-file rejection')
                    rejected=True;reason='input-byte-limit';partial=True;break
                time.sleep(.01)
            require(rejected,'Overlimit candidate was not rejected within deadline')
        else:ready_pair(final)
        # Retain enough reload-phase samples even for very fast legitimate commits.
        time.sleep(.25)
        measure.phase='settled';time.sleep(WORKLOAD['settled_ms']/1000);measure.finish()
        ptr_samples=sample_ptrs() if name==CASE_NAMES[2] else []
        lease_bytes=(directory/'leases').stat().st_size;require(lease_bytes==0,'INFORM allocated a lease')
        previous.stop(args)
        row=dict(case=name,outcome='rejected-old-retained' if rejected else 'cold-accepted' if name==CASE_NAMES[0] else 'committed',
                 startup_ready_ms=startup_ms,fixture=dict(initial_unique_per_file=initial,candidate_entries=candidate,initial=fingerprints(old),candidate=fingerprints(new)),
                 final_rrset=final,rejection_observed=rejected,requests=measure.requests,memory=measure.memory,
                 request_summary=summarize_requests(measure.requests,[OLD,NEW,FALLBACK]),memory_summary=summarize_memory(measure.memory),
                 dhcp_requests=measure.dhcp_requests,dhcp_summary=summarize_dhcp(measure.dhcp_requests),lease_bytes=lease_bytes,daemon_stopped=True)
        row.update(rejection_reason=reason,partial_preparation_observed=partial,cycles=cycles,ptr_samples=ptr_samples)
        return row
    finally:
        if measure is not None and any(t.is_alive()for t in measure.threads):measure.finish()
        import shutil
        shutil.rmtree(directory)


def worker(args):
    namespaces=base.namespace_guard(json.loads(args.anchor_fds))
    for name,size in FILESYSTEM_LIMITS.items():
        subprocess.run(['mount','-n','-t','tmpfs','-o','size='+str(size)+',mode=0755','tmpfs','/'+name],check=True,capture_output=True)
        prefix=args.sysroot/name;require(not prefix.is_symlink(),'QEMU private mount alias');prefix.mkdir(exist_ok=True)
        subprocess.run(['mount','-n','--bind','/'+name,str(prefix)],check=True,capture_output=True)
    for name,minor,mode in (('null',3,0o666),('urandom',9,0o444)):
        os.mknod('/dev/'+name,stat.S_IFCHR|mode,os.makedev(1,minor));os.chmod('/dev/'+name,mode)
    subprocess.run(['ip','link','set','lo','up'],check=True,capture_output=True)
    require({name for _,name in socket.if_nameindex()}=={'lo'},'Private network has another interface')
    base.regular(Path('/etc/passwd'),b'root:x:0:0:root:/:/bin/sh\nnobody:x:99:99:nobody:/:/bin/false\n',0o644)
    base.regular(Path('/etc/group'),b'root:x:0:\nnobody:x:99:\n',0o644);Path('/var/run').mkdir(mode=0o755)
    report=dict(schema_version=1,status='FAIL',profile='k2p-4.4',execution_role=MEASUREMENT_ROLE,source_sha256=source_proof(args.trunk),
        shipped=base.shipped_proof(args.rootfs),required_cases=list(CASE_NAMES),checks=[],filesystem_limits=FILESYSTEM_LIMITS,limits=LIMITS,workload=WORKLOAD,contract=CONTRACT,failure=None,
        isolation=dict(namespaces=namespaces,worker_pid=os.getpid(),loopback_only=True,private_mount_propagation=True,anchors_cloexec=True,namespace_exit_confirmed=False,private_dev_log=True))
    upstream=PairUpstream()
    try:
        for name in CASE_NAMES:
            print('Target reload latency CASE '+name,flush=True);report['checks'].append(exercise(args,name))
            require(runtime.quiescent(),'Latency case left a target process');print('Target reload latency PASS '+name,flush=True)
        validate_records(report['checks']);report['status']='PASS'
    except Exception as error:report['failure']=str(error)[:4096];raise
    finally:
        try:upstream.close()
        finally:base.write_output(args.output,json.loads(args.expected_output),report)


def root_parent(args):
    require(sys.platform.startswith('linux') and os.geteuid()==0,'Linux root launcher required')
    expected=json.loads(args.expected_output);require(base.output_identity(args.output)==expected,'Parent-owned latency output changed')
    anchors={name:os.open('/proc/self/ns/'+name,os.O_RDONLY|os.O_CLOEXEC)for name in ('mnt','net','pid')}
    command=['unshare','--mount','--net','--pid','--fork','--mount-proc','--kill-child=KILL','--propagation','private',sys.executable,str(Path(__file__).resolve()),'--worker']
    for key in ('trunk','rootfs','sysroot','output'):command+=['--'+key,str(getattr(args,key))]
    command+=['--expected-output',args.expected_output,'--anchor-fds',json.dumps(anchors)]
    try:subprocess.run(command,check=True,timeout=LIMITS['worker_seconds'],pass_fds=tuple(anchors.values()))
    finally:
        for fd in anchors.values():os.close(fd)
    report=json.loads(args.output.read_text());require(report['status']=='PASS','Latency worker failed')
    report['isolation']['namespace_exit_confirmed']=True;base.write_output(args.output,expected,report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('trunk','rootfs','sysroot','output'):parser.add_argument('--'+key,type=Path,required=True)
    modes=parser.add_mutually_exclusive_group();modes.add_argument('--worker',action='store_true');modes.add_argument('--root-parent',action='store_true')
    parser.add_argument('--expected-output');parser.add_argument('--anchor-fds');args=parser.parse_args()
    for key in ('trunk','rootfs','sysroot'):setattr(args,key,getattr(args,key).resolve())
    args.output=args.output.parent.resolve()/args.output.name
    if args.worker:return worker(args)
    if args.root_parent:return root_parent(args)
    require(sys.platform.startswith('linux'),'Linux actual MIPS latency gate required; no fallback PASS')
    for path in (args.trunk,args.rootfs,args.sysroot,args.output,Path(__file__).resolve()):
        require(not any(path.is_relative_to('/'+name)for name in FILESYSTEM_LIMITS),'Latency input hidden by private mounts')
    sources,shipped=source_proof(args.trunk),base.shipped_proof(args.rootfs);expected=base.prepare_output(args.output)
    command=(['sudo','-n','env','PATH='+os.environ['PATH']]if os.geteuid()else[])+[sys.executable,str(Path(__file__).resolve()),'--root-parent','--trunk',str(args.trunk),'--rootfs',str(args.rootfs),'--sysroot',str(args.sysroot),'--output',str(args.output),'--expected-output',json.dumps(expected)]
    subprocess.run(command,check=True,timeout=LIMITS['worker_seconds']+30)
    require(base.output_identity(args.output)==expected,'Root worker changed latency output owner/inode')
    validate_report(json.loads(args.output.read_text()),sources,shipped)
    print('Target reload latency: '+str(len(CASE_NAMES))+' actual shipped private namespace cases PASS')

if __name__=='__main__':main()
