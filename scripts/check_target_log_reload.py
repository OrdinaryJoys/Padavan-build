#!/usr/bin/env python3
"""Actual shipped MIPS DNS and libshared checks in private Linux namespaces.

All sockets, /dev/log, configuration and leases are synthetic. No host-network
listener, router, MTD, clock setting or target execution on the authoring host.
The normal firmware profile disables inotify; this gate tests SIGHUP reloads.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

import check_target_runtime_dns as runtime
import check_target_ntp as ntp
base = runtime.base
require = base.require
sha = base.sha
SOURCE_PATHS = dict(runtime.SOURCE_PATHS, **{
    'dnsmasq.h': 'user/dnsmasq/dnsmasq-2.93/src/dnsmasq.h',
    'inotify.c': 'user/dnsmasq/dnsmasq-2.93/src/inotify.c',
    'firmware-dns-Makefile': 'user/dnsmasq/Makefile',
    'shared-shutils.c': 'user/shared/shutils.c',
    'shared-Makefile': 'user/shared/Makefile',
    'dhcp.c': 'user/dnsmasq/dnsmasq-2.93/src/dhcp.c',
    'rfc2131.c': 'user/dnsmasq/dnsmasq-2.93/src/rfc2131.c',
    'reload_file.c': 'user/dnsmasq/dnsmasq-2.93/src/reload_file.c',
    'reload_file.h': 'user/dnsmasq/dnsmasq-2.93/src/reload_file.h',
    'dns-config.h': 'user/dnsmasq/dnsmasq-2.93/src/config.h'})
CASE_NAMES = (
    'syslog-full-responsive-recovery', 'syslog-full-bounded-exit',
    'syslog-absent-recovery', 'shared-literal-pressure-recovery',
    'hosts-fifo-group-preserved', 'hosts-missing-group-preserved',
    'hosts-oversize-group-preserved', 'hosts-long-line-group-preserved',
    'hosts-malformed-group-preserved', 'hosts-default-fifo-group-preserved',
    'hosts-empty-commit', 'dhcp-hosts-fifo-preserved',
    'dhcp-hosts-malformed-preserved', 'dhcp-options-fifo-preserved',
    'dhcp-options-malformed-preserved', 'dhcp-cross-group-preserved',
    'dhcp-hosts-empty-commit', 'dhcp-options-empty-commit',
    'cross-hosts-reject-preserves-dhcp', 'cross-dhcp-reject-preserves-hosts',
    'ethers-fifo-preserved', 'ethers-malformed-preserved', 'ethers-empty-commit',
    'cross-ethers-reject-preserves-hosts')
ROLE = ('Actual shipped MIPS DNS daemon and actual shipped libshared logmessage; '
        'private PID/mount/network namespaces and synthetic loopback DNS/DHCP INFORM/syslog peers')
FILESYSTEM_LIMITS = dict(base.FILESYSTEM_LIMITS, dev=1048576)
LIMITS = dict(worker_seconds=300, command_seconds=20, query_seconds=4,
              output_bytes=131072, report_bytes=1048576, case_ms=30000,
              probe_ms=3000, syslog_fill_datagrams=1024, shared_pressure_calls=256)
CONTRACT = dict(reload='SIGHUP', dns_cache=False, dhcp='INFORM only; no address allocation',
                inotify='disabled in shipped firmware; not claimed by this gate',
                syslog='private /dev/log; kernel datagram queue EAGAIN witnessed',
                private_dev='scratch tmpfs only; null1:3 and read-only urandom1:9; no host socket or node changes')
ROW_KEYS = {'case', 'kind', 'before', 'after', 'repaired', 'rejection_observed',
            'queue_full', 'receiver_recovered', 'query_count', 'probe_results',
            'elapsed_ms', 'daemon_stopped'}
OLD_HOSTS = {'first.fixture': '192.0.2.51', 'second.fixture': '192.0.2.61',
             'leak.fixture': '192.0.2.53'}
NEW_HOSTS = {'first.fixture': '192.0.2.52', 'second.fixture': '192.0.2.62',
             'leak.fixture': '192.0.2.53'}
EMPTY_HOSTS = dict(NEW_HOSTS, **{'first.fixture': '192.0.2.53'})
OLD_HARDWARE = bytes.fromhex('020000000051')
NEW_HARDWARE = bytes.fromhex('020000000052')
OLD_ETHERS = dict(old_peer='old.fixture', new_peer='fallback.fixture')
NEW_ETHERS = dict(old_peer='fallback.fixture', new_peer='old.fixture')


def case_contract(name):
    require(name in CASE_NAMES, 'Unknown log/reload case')
    if name.startswith('ethers-'):
        return dict(kind='ethers-inform', before=dict(OLD_ETHERS),
                    after=dict(old_peer='fallback.fixture', new_peer='fallback.fixture') if name == 'ethers-empty-commit' else dict(OLD_ETHERS),
                    repaired=dict(NEW_ETHERS), rejection_observed=name != 'ethers-empty-commit',
                    queue_full=None, receiver_recovered=None, query_count=6, probe_results=[])
    if name == 'cross-ethers-reject-preserves-hosts':
        return dict(kind='cross-ethers', before=dict(OLD_HOSTS, **OLD_ETHERS),
                    after=dict(OLD_HOSTS, **OLD_ETHERS), repaired=dict(NEW_HOSTS, **NEW_ETHERS),
                    rejection_observed=True, queue_full=None, receiver_recovered=None, query_count=15, probe_results=[])
    if name.startswith('cross-'):
        return dict(kind='cross-group', before=dict(OLD_HOSTS, dhcp='old.fixture'),
                    after=dict(OLD_HOSTS, dhcp='old.fixture'), repaired=dict(NEW_HOSTS, dhcp='new.fixture'),
                    rejection_observed=True, queue_full=None, receiver_recovered=None, query_count=12, probe_results=[])
    if name.startswith('hosts-'):
        return dict(kind='hosts', before=dict(OLD_HOSTS),
                    after=dict(EMPTY_HOSTS) if name == 'hosts-empty-commit' else dict(OLD_HOSTS),
                    repaired=dict(NEW_HOSTS), rejection_observed=name != 'hosts-empty-commit',
                    queue_full=None, receiver_recovered=None, query_count=9, probe_results=[])
    if name.startswith('dhcp-'):
        return dict(kind='dhcp-inform', before='old.fixture',
                    after='fallback.fixture' if name.endswith('empty-commit') else 'old.fixture',
                    repaired='new.fixture', rejection_observed=not name.endswith('empty-commit'),
                    queue_full=None, receiver_recovered=None, query_count=3, probe_results=[])
    if name == 'shared-literal-pressure-recovery':
        return dict(kind='actual-libshared', before='literal%n normal', after=None,
                    repaired='literal%n recovered', rejection_observed=None,
                    queue_full=True, receiver_recovered=True, query_count=0)
    quitting = name == 'syslog-full-bounded-exit'
    return dict(kind='syslog', before='192.0.2.53', after=None if quitting else '192.0.2.53',
                repaired=None if quitting else '192.0.2.53', rejection_observed=None,
                queue_full=None if name == 'syslog-absent-recovery' else True,
                receiver_recovered=not quitting, query_count=1 if quitting else 3, probe_results=[])


def validate_records(records):
    require(type(records) is list and len(records) == len(CASE_NAMES), 'Missing log/reload cases')
    for name, row in zip(CASE_NAMES, records):
        require(type(row) is dict and set(row) == ROW_KEYS and row['case'] == name,
                'Log/reload exact case schema/order mismatch')
        expected = case_contract(name)
        for key, value in expected.items():
            require(type(row[key]) is type(value) and row[key] == value, 'Log/reload observation differs: ' + name + ':' + key)
        require(row['daemon_stopped'] is True and type(row['elapsed_ms']) is int and
                0 <= row['elapsed_ms'] <= LIMITS['case_ms'], 'Log/reload timing/cleanup failed')
        if name == 'shared-literal-pressure-recovery':
            require(type(row['probe_results']) is list and len(row['probe_results']) == 3,
                    'Missing actual shared-library invocations')
            for calls, observation in zip((1, 256, 1), row['probe_results']):
                require(type(observation) is dict and set(observation) == {
                    'calls', 'fd_before', 'fd_after', 'errno_preserved', 'elapsed_ms'}, 'Shared probe schema differs')
                require(type(observation['calls']) is int and observation['calls'] == calls and
                        all(type(observation[key]) is int and observation[key] >= 3 for key in ('fd_before', 'fd_after')) and
                        observation['fd_before'] == observation['fd_after'] and observation['errno_preserved'] is True and
                        type(observation['elapsed_ms']) is int and 0 <= observation['elapsed_ms'] <= LIMITS['probe_ms'],
                        'Shared logmessage blocked, leaked FDs, changed errno or skipped pressure calls')
    return True


def validate_report(report, sources, shipped):
    require(type(report) is dict and set(report) == {'schema_version', 'status', 'profile', 'execution_role',
        'source_sha256', 'shipped', 'required_cases', 'checks', 'filesystem_limits', 'limits', 'contract',
        'isolation', 'probe', 'failure'}, 'Log/reload report schema differs')
    require(type(report['schema_version']) is int and report['schema_version'] == 1 and report['status'] == 'PASS' and
            report['profile'] == 'k2p-4.4' and report['failure'] is None, 'Log/reload proof failed')
    require(report['execution_role'] == ROLE and report['source_sha256'] == sources and report['shipped'] == shipped and
            report['required_cases'] == list(CASE_NAMES) and report['filesystem_limits'] == FILESYSTEM_LIMITS and
            report['limits'] == LIMITS and report['contract'] == CONTRACT, 'Log/reload source/image/contract changed')
    iso = report['isolation']
    require(type(iso) is dict and set(iso) == {'namespaces', 'worker_pid', 'loopback_only',
        'private_mount_propagation', 'anchors_cloexec', 'namespace_exit_confirmed', 'private_dev_log'} and
        type(iso['worker_pid']) is int and iso['worker_pid'] == 1 and
        all(iso[key] is True for key in ('loopback_only', 'private_mount_propagation', 'anchors_cloexec',
                                       'namespace_exit_confirmed', 'private_dev_log')), 'Unsafe log/reload isolation')
    require(type(iso['namespaces']) is dict and set(iso['namespaces']) == {'mnt', 'net', 'pid'}, 'Missing namespace anchors')
    for value in iso['namespaces'].values():
        require(type(value) is dict and set(value) == {'parent_inode', 'worker_inode'} and
                all(type(x) is int and x > 0 for x in value.values()) and value['parent_inode'] != value['worker_inode'],
                'Initial namespace used for log/reload proof')
    probe = report['probe']
    require(type(probe) is dict and set(probe) == {'source_sha256', 'elf', 'sha256', 'bytes', 'dynamic', 'libraries', 'library_dynamic'} and
            probe['source_sha256'] == sha(generate_source().encode()) and re.fullmatch('[0-9a-f]{64}', probe['sha256']) and
            type(probe['bytes']) is int and 52 <= probe['bytes'] <= 1048576 and
            probe['elf']['elf_class'] == 32 and probe['elf']['byte_order'] == 'little' and
            probe['elf']['e_machine'] == 8 and probe['elf']['e_type'] in (2, 3), 'Unbound shared-library probe')
    require(probe['dynamic']['interpreter'] == '/lib/ld-uClibc.so.0' and
            'libshared.so' in probe['dynamic']['needed'] and 'lib/libshared.so' in probe['libraries'] and
            probe['libraries']['lib/libshared.so']['sha256'] == shipped['libshared']['sha256'],
            'Shared probe is not bound to actual image libshared')
    validate_probe_closure(probe)
    return validate_records(report['checks'])


def validate_probe_closure(probe):
    libraries, dynamic = probe['libraries'], probe['library_dynamic']
    require(type(libraries) is dict and 1 <= len(libraries) <= 32 and type(dynamic) is dict and
            set(libraries) == set(dynamic), 'Missing shared probe runtime metadata')
    pending = [probe['dynamic']['interpreter'].lstrip('/')] + ['lib/' + name for name in probe['dynamic']['needed']]
    visited = set()
    while pending:
        name = pending.pop(0)
        if name in visited:continue
        require(re.fullmatch(r'lib/[A-Za-z0-9_.+-]+', name) is not None and name in libraries,
                'Unbound shared probe dependency')
        visited.add(name); item, metadata = libraries[name], dynamic[name]
        require(type(item) is dict and set(item) == {'resolved', 'sha256', 'bytes', 'elf_class', 'byte_order', 'e_machine', 'e_type'} and
                re.fullmatch(r'lib/[A-Za-z0-9_.+-]+', item['resolved']) is not None and
                re.fullmatch('[0-9a-f]{64}', item['sha256']) is not None and type(item['bytes']) is int and
                52 <= item['bytes'] <= 16 * 1024 * 1024 and item['elf_class'] == 32 and item['byte_order'] == 'little' and
                item['e_machine'] == 8 and item['e_type'] == 3, 'Invalid shared probe runtime ELF identity')
        require(type(metadata) is dict and set(metadata) == {'interpreter', 'needed'} and
                metadata['interpreter'] in (None, '/lib/ld-uClibc.so.0', '/lib/ld-uClibc.so.1') and
                type(metadata['needed']) is list and len(metadata['needed']) <= 16 and
                all(type(dep) is str and re.fullmatch('[A-Za-z0-9_.+-]+', dep) for dep in metadata['needed']) and
                len(set(metadata['needed'])) == len(metadata['needed']), 'Invalid runtime dynamic metadata')
        if metadata['interpreter']:pending.append(metadata['interpreter'].lstrip('/'))
        pending += ['lib/' + dep for dep in metadata['needed']]
    require(visited == set(libraries), 'Unreachable/unchecked extra runtime library')
    return True


def source_proof(trunk):
    require('CONFIG_LINUXDIR=linux-4.4.x' in (trunk / '.config').read_text(), 'Log/reload proof requires4.4')
    require('-DNO_INOTIFY' in (trunk / 'user/dnsmasq/Makefile').read_text(), 'Inotify profile must be reviewed explicitly')
    return {key: sha((trunk / path).read_bytes()) for key, path in SOURCE_PATHS.items()}


def shipped_proof(rootfs):
    result = base.shipped_proof(rootfs)
    path = rootfs / 'lib/libshared.so'
    require(stat.S_ISREG(path.lstat().st_mode), 'Actual libshared must be a regular image file')
    data = path.read_bytes()
    result['libshared'] = dict(path='lib/libshared.so', sha256=sha(data), bytes=len(data), elf=base.elf(data))
    return result


def generate_source():
    return r'''#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern void logmessage(char *,char *,...);
static int descriptors(void) {
  DIR *d=opendir("/proc/self/fd");struct dirent *entry;int count=0;
  if(!d)return -1;
  while((entry=readdir(d)))if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,".."))count++;
  if(closedir(d))return -1;
  return count;
}
int main(int argc,char **argv) {
  int calls,i,before,after,kept=1;char *end;
  if(argc!=3)return 90;
  calls=(int)strtol(argv[1],&end,10);
  if(*end||(calls!=1&&calls!=256))return 91;
  before=descriptors();if(before<3)return 92;
  for(i=0;i<calls;i++) {
    errno=E2BIG;logmessage("K2P_SHARED","%s",argv[2]);if(errno!=E2BIG)kept=0;
  }
  after=descriptors();
  printf("calls=%d fd_before=%d fd_after=%d errno_preserved=%d\n",calls,before,after,kept);
  return before==after&&kept?0:93;
}
'''


def compile_probe(args):
    source = args.output.with_name('target-log-reload-probe.c')
    binary = args.output.with_name('target-log-reload-probe')
    require(not source.exists() and not binary.exists(), 'Shared probe exports already exist')
    source.write_text(generate_source()); source.chmod(0o644)
    result = subprocess.run([str(args.compiler), '-std=gnu99', '-Wall', '-Wextra', '-Werror', '-O2',
        str(source), '-L' + str(args.rootfs / 'lib'), '-lshared', '-o', str(binary)], capture_output=True, timeout=90)
    require(result.returncode == 0, 'Actual libshared probe compile failed: ' + result.stderr.decode(errors='replace')[:4096])
    binary.chmod(0o755); data = binary.read_bytes(); dynamic = ntp.elf_dynamic(data)
    require(dynamic['interpreter'] == '/lib/ld-uClibc.so.0' and 'libshared.so' in dynamic['needed'],
            'Unexpected shared probe loader/dependency')
    pending = [dynamic['interpreter'].lstrip('/')] + ['lib/' + x for x in dynamic['needed']]
    libraries, metadata = {}, {}
    while pending:
        name = pending.pop(0)
        require(len(libraries) < 32, 'Shared runtime closure too large')
        if name in libraries: continue
        # Dependencies must be simple library names. No arbitrary path probing.
        require(re.fullmatch(r'lib/[A-Za-z0-9_.+-]+', name), 'Unsafe shared dependency path')
        identity, payload = ntp._runtime_library(args.sysroot, name)
        image, image_payload = ntp._runtime_library(args.rootfs, name)
        require(identity == image and payload == image_payload, 'Shared probe runtime differs from image: ' + name)
        item = ntp.elf_dynamic(payload); libraries[name] = identity; metadata[name] = item
        require(item['interpreter'] in (None, '/lib/ld-uClibc.so.0', '/lib/ld-uClibc.so.1'), 'Unexpected dependency interpreter')
        if item['interpreter']:pending.append(item['interpreter'].lstrip('/'))
        for dep in item['needed']:
            require(re.fullmatch('[A-Za-z0-9_.+-]+', dep), 'Unsafe library DT_NEEDED')
            pending.append('lib/' + dep)
    return dict(source_sha256=sha(source.read_bytes()), elf=base.elf(data), sha256=sha(data), bytes=len(data),
                dynamic=dynamic, libraries=libraries, library_dynamic=metadata), binary


def query(name, expected):
    labels = b''.join(bytes([len(x)]) + x.encode('ascii') for x in name.split('.')) + b'\0'
    packet = struct.pack('!6H', 0x4b33, 0x100, 1, 0, 0, 0) + labels + b'\0\x01\0\x01'
    deadline = time.monotonic() + LIMITS['query_seconds']
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.15)
        while time.monotonic() < deadline:
            sock.sendto(packet, ('127.0.0.1', 10530))
            try:
                data, peer = sock.recvfrom(4097)
            except (socket.timeout, ConnectionRefusedError): continue
            require(peer == ('127.0.0.1', 10530) and 12 <= len(data) <= 4096, 'Invalid private DNS reply')
            ident, flags, qd, an, _, _ = struct.unpack_from('!6H', data)
            require(ident == 0x4b33 and flags & 0x8000 and flags & 15 == 0 and qd == 1 and an == 1, 'Invalid private DNS answer')
            pos = base.skip_name(data, 12) + 4
            pos = base.skip_name(data, pos)
            require(pos + 10 <= len(data), 'Truncated DNS answer')
            kind, cls, _, size = struct.unpack_from('!HHIH', data, pos)
            require(kind == cls == 1 and size == 4 and pos + 14 == len(data), 'Unexpected DNS answer type')
            answer = socket.inet_ntoa(data[pos + 10:pos + 14])
            if answer == expected:return answer
    raise RuntimeError('DNS policy mismatch for ' + name + ': expected ' + expected)


def inform_packet(hardware=OLD_HARDWARE):
    data = bytearray(240)
    data[:4] = bytes((1, 1, 6, 0))
    struct.pack_into('!I', data, 4, 0x4b325531)
    data[12:16] = socket.inet_aton('127.0.0.2')
    require(type(hardware) is bytes and len(hardware) == 6, 'Invalid INFORM fixture hardware')
    data[28:34] = hardware
    data[236:240] = bytes.fromhex('63825363')
    return bytes(data) + bytes((53, 1, 8, 55, 1, 15, 255))


def _parse_inform(data, hardware=OLD_HARDWARE):
    require(240 <= len(data) <= 4096 and data[0] == 2 and data[4:8] == bytes.fromhex('4b325531') and
            data[1:3] == bytes((1, 6)) and struct.unpack_from('!H', data, 10)[0] == 0 and
            data[12:16] == socket.inet_aton('127.0.0.2') and data[16:20] == b'\0' * 4 and
            data[20:24] == socket.inet_aton('127.0.0.1') and data[24:28] == b'\0' * 4 and
            data[28:34] == hardware and data[236:240] == bytes.fromhex('63825363'), 'Invalid INFORM reply')
    options = {}; pos = 240; ended = False
    while pos < len(data):
        key = data[pos]; pos += 1
        if key == 255:
            ended = True
            require(not any(data[pos:]), 'Nonzero data after DHCP END option')
            break
        if key == 0: continue
        require(pos < len(data) and pos + 1 + data[pos] <= len(data), 'Truncated DHCP option')
        length = data[pos]; pos += 1
        require(key not in options, 'Duplicate DHCP option')
        options[key] = data[pos:pos + length]; pos += length
    require(ended and options.get(53) == b'\x05' and 15 in options and 51 not in options and 52 not in options,
            'INFORM was not an ACK or unexpectedly allocated a lease')
    return options[15].decode('ascii')


def parse_inform(data, hardware=OLD_HARDWARE):
    try:
        return _parse_inform(data, hardware)
    except (RuntimeError, UnicodeError) as error:
        # Show only a bounded public fixture BOOTP header, not arbitrary
        # options/output. This distinguishes header assumptions from policy.
        raise RuntimeError(str(error)[:256] + '; bytes=' + str(len(data)) +
                           ' header[0:44]=' + data[:44].hex()) from error


def inform(expected, hardware=OLD_HARDWARE):
    deadline = time.monotonic() + LIMITS['query_seconds']
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.2', 0)); sock.settimeout(0.15)
        while time.monotonic() < deadline:
            sock.sendto(inform_packet(hardware), ('127.0.0.1', 67))
            try: data, peer = sock.recvfrom(4097)
            except (socket.timeout, ConnectionRefusedError): continue
            require(peer == ('127.0.0.1', 67), 'DHCP reply outside private peer')
            value = parse_inform(data, hardware)
            if value == expected:return value
    raise RuntimeError('DHCP INFORM option15 mismatch: expected ' + expected)


class Receiver:
    def __init__(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind('/dev/log'); os.chmod('/dev/log', 0o666); self.sock.setblocking(False)

    def drain(self):
        output = bytearray()
        while True:
            try: data = self.sock.recv(4096)
            except BlockingIOError: break
            output.extend(data)
            require(len(output) <= LIMITS['output_bytes'], 'Private log drain exceeded cap')
        return bytes(output)

    def fill(self):
        self.drain()
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            sender.setblocking(False)
            for count in range(LIMITS['syslog_fill_datagrams']):
                try: sender.sendto(b'K2P_NATIVE_QUEUE_FILLER', '/dev/log')
                except BlockingIOError:
                    require(count > 0, 'No positive syslog queue-fill control')
                    return True
        raise RuntimeError('Private syslog queue never reached EAGAIN')

    def marker(self, needle):
        deadline = time.monotonic() + 2; collected = bytearray()
        while time.monotonic() < deadline:
            collected.extend(self.drain())
            require(len(collected) <= LIMITS['output_bytes'], 'Log marker output exceeded cap')
            if needle in collected:return True
            time.sleep(0.02)
        raise RuntimeError('Actual program log marker missing: ' + repr(needle))

    def close(self):
        self.sock.close(); Path('/dev/log').unlink()


def row(name, start, **values):
    return dict(case=name, elapsed_ms=int((time.monotonic() - start) * 1000), daemon_stopped=True, **values)


def launch(args, directory, extra='', system_log=False):
    config = directory / 'dnsmasq.conf'
    common = ('port=10530\nlisten-address=127.0.0.1\nbind-interfaces\nuser=nobody\ngroup=nobody\n'
              'no-hosts\nno-resolv\ncache-size=0\nserver=127.0.0.1#11532\n'
              'pid-file=/var/run/snapshot-daemon.pid\n')
    if not system_log:common += 'log-facility=' + str(directory / 'daemon.log') + '\n'
    else: common += 'log-queries\n'
    if extra.startswith('DEFAULT_HOSTS\n'):
        common = common.replace('no-hosts\n', ''); extra = extra[len('DEFAULT_HOSTS\n'):]
    base.regular(config, (common + extra).encode(), 0o644)
    status, out, err = base.run_bounded(['qemu-mipsel', '-L', str(args.sysroot), str(args.rootfs / 'usr/sbin/dnsmasq'),
                                      '-C', str(config)], limits=LIMITS)
    require(status == 0, 'Log/reload daemon startup failed: ' + (out + err).decode(errors='replace')[:4096])
    return runtime.daemon_pid(args.rootfs)


def stop(args):
    require(base.stop_daemon(args.rootfs) and runtime.quiescent(), 'Log/reload daemon cleanup failed')
    Path('/var/run/snapshot-daemon.pid').unlink(missing_ok=True)
    return True


def replace(path, data=None, missing=False):
    replacement = path.with_name(path.name + '.new')
    if missing:
        path.unlink(); return
    if data is None:os.mkfifo(replacement, 0o644)
    else:base.regular(replacement, data, 0o644)
    os.replace(replacement, path)


def rejection(directory):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        text = (directory / 'daemon.log').read_text(errors='replace')
        if 'reload transaction rejected; previous hosts/DHCP configuration retained' in text:return True
        time.sleep(0.02)
    raise RuntimeError('Transactional reload rejection diagnostic missing')


def exercise_hosts(args, name, directory):
    start = time.monotonic(); first, second = directory / 'hosts-a', directory / 'hosts-b'
    default = name == 'hosts-default-fifo-group-preserved'
    if default:first = Path('/etc/hosts')
    base.regular(first, b'192.0.2.51 first.fixture\n', 0o644)
    base.regular(second, b'192.0.2.61 second.fixture\n', 0o644)
    extra = ('DEFAULT_HOSTS\n' if default else 'addn-hosts=' + str(first) + '\n') + 'addn-hosts=' + str(second) + '\n'
    pid = launch(args, directory, extra)
    before = {key: query(key, value) for key, value in OLD_HOSTS.items()}
    replace(first, b'192.0.2.52 first.fixture\n')
    if name == 'hosts-empty-commit':replace(first, b''); replace(second, b'192.0.2.62 second.fixture\n')
    elif name == 'hosts-default-fifo-group-preserved':replace(first)
    elif name == 'hosts-missing-group-preserved':replace(second, missing=True)
    elif name == 'hosts-oversize-group-preserved':replace(second, b'#' + b'x' * (16 * 1024 * 1024))
    elif name == 'hosts-long-line-group-preserved':replace(second, b'#' + b'x' * 16384 + b'\n')
    elif name == 'hosts-malformed-group-preserved':replace(second, b'192.0.2.99 leak.fixture\nnot-an-ip invalid.fixture\n')
    else:replace(second)
    os.kill(pid, signal.SIGHUP)
    rejected = False if name == 'hosts-empty-commit' else rejection(directory)
    # Diagnostic first proves the failing reload was consumed before checking old answers.
    if not rejected:time.sleep(0.15)
    expected = EMPTY_HOSTS if name == 'hosts-empty-commit' else OLD_HOSTS
    after = {key: query(key, value) for key, value in expected.items()}
    replace(first, b'192.0.2.52 first.fixture\n'); replace(second, b'192.0.2.62 second.fixture\n')
    os.kill(pid, signal.SIGHUP); time.sleep(0.15)
    repaired = {key: query(key, value) for key, value in NEW_HOSTS.items()}
    stopped = stop(args)
    if default:first.unlink()
    return row(name, start, kind='hosts', before=before, after=after, repaired=repaired,
               rejection_observed=rejected, queue_full=None, receiver_recovered=None, query_count=9, probe_results=[])


def host_tag(which):return ('02:00:00:00:00:51,set:policy' + str(which) + '\n').encode()
def option_policy(which, value):return ('tag:policy' + str(which) + ',option:domain-name,' + value + '\n').encode()


def exercise_dhcp(args, name, directory):
    start = time.monotonic(); hosts, opts = directory / 'dhcp-hosts', directory / 'dhcp-options'
    base.regular(hosts, host_tag(51), 0o644)
    base.regular(opts, option_policy(51, 'old.fixture') + option_policy(52, 'new.fixture'), 0o644)
    extra = ('dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h\ndhcp-leasefile=' + str(directory / 'leases') + '\n'
             'dhcp-hostsfile=' + str(hosts) + '\ndhcp-optsfile=' + str(opts) + '\n'
             'dhcp-option=option:domain-name,fallback.fixture\n')
    pid = launch(args, directory, extra)
    before = inform('old.fixture')
    if name == 'dhcp-hosts-fifo-preserved':replace(hosts)
    elif name == 'dhcp-hosts-malformed-preserved':replace(hosts, host_tag(52) + b'02:00:00:00:00:GG,192.0.2.52\n')
    elif name == 'dhcp-options-fifo-preserved':replace(opts)
    elif name in ('dhcp-options-malformed-preserved', 'dhcp-cross-group-preserved'):
        if name == 'dhcp-cross-group-preserved':replace(hosts, host_tag(52))
        replace(opts, option_policy(51, 'leak.fixture') + b'option:totally-unknown-option,x\n')
    elif name == 'dhcp-hosts-empty-commit':replace(hosts, b'')
    else:replace(opts, b'')
    os.kill(pid, signal.SIGHUP)
    rejected = False if name.endswith('empty-commit') else rejection(directory)
    if not rejected:time.sleep(0.15)
    after = inform('fallback.fixture' if name.endswith('empty-commit') else 'old.fixture')
    replace(hosts, host_tag(52)); replace(opts, option_policy(52, 'new.fixture'))
    os.kill(pid, signal.SIGHUP); time.sleep(0.15)
    repaired = inform('new.fixture')
    lease_data = (directory / 'leases').read_bytes()
    require(lease_data == b'', 'INFORM fixture allocated or persisted a lease')
    stop(args)
    return row(name, start, kind='dhcp-inform', before=before, after=after, repaired=repaired,
               rejection_observed=rejected, queue_full=None, receiver_recovered=None, query_count=3, probe_results=[])


def exercise_cross(args, name, directory):
    start = time.monotonic(); first, second = directory / 'hosts-a', directory / 'hosts-b'
    hosts, opts = directory / 'dhcp-hosts', directory / 'dhcp-options'
    base.regular(first, b'192.0.2.51 first.fixture\n', 0o644)
    base.regular(second, b'192.0.2.61 second.fixture\n', 0o644)
    base.regular(hosts, host_tag(51), 0o644)
    base.regular(opts, option_policy(51, 'old.fixture'), 0o644)
    extra = ('addn-hosts=' + str(first) + '\naddn-hosts=' + str(second) + '\n'
             'dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h\ndhcp-leasefile=' + str(directory / 'leases') + '\n'
             'dhcp-hostsfile=' + str(hosts) + '\ndhcp-optsfile=' + str(opts) + '\n'
             'dhcp-option=option:domain-name,fallback.fixture\n')
    pid = launch(args, directory, extra)
    before = dict({key: query(key, value) for key, value in OLD_HOSTS.items()}, dhcp=inform('old.fixture'))
    replace(first, b'192.0.2.52 first.fixture\n'); replace(second, b'192.0.2.62 second.fixture\n')
    replace(hosts, host_tag(52)); replace(opts, option_policy(52, 'new.fixture'))
    if name == 'cross-hosts-reject-preserves-dhcp':replace(second, b'invalid-address malformed.fixture\n')
    else:replace(opts, b'option:totally-unknown-option,x\n')
    os.kill(pid, signal.SIGHUP); rejected = rejection(directory)
    after = dict({key: query(key, value) for key, value in OLD_HOSTS.items()}, dhcp=inform('old.fixture'))
    replace(second, b'192.0.2.62 second.fixture\n'); replace(opts, option_policy(52, 'new.fixture'))
    os.kill(pid, signal.SIGHUP); time.sleep(0.15)
    repaired = dict({key: query(key, value) for key, value in NEW_HOSTS.items()}, dhcp=inform('new.fixture'))
    require((directory / 'leases').read_bytes() == b'', 'Cross-group INFORM allocated a lease')
    stop(args)
    return row(name, start, kind='cross-group', before=before, after=after, repaired=repaired,
               rejection_observed=rejected, queue_full=None, receiver_recovered=None, query_count=12, probe_results=[])


def ethers_answers(expected):
    return dict(old_peer=inform(expected['old_peer'], OLD_HARDWARE),
                new_peer=inform(expected['new_peer'], NEW_HARDWARE))


def exercise_ethers(args, name, directory):
    start = time.monotonic(); ethers = Path('/etc/ethers')
    base.regular(ethers, b'02:00:00:00:00:51 127.0.0.51\n', 0o644)
    cross = name == 'cross-ethers-reject-preserves-hosts'
    first, second = directory / 'hosts-a', directory / 'hosts-b'
    extra = ('read-ethers\ndhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h\ndhcp-leasefile=' + str(directory / 'leases') + '\n'
             'dhcp-option=tag:known,option:domain-name,old.fixture\ndhcp-option=option:domain-name,fallback.fixture\n')
    if cross:
        base.regular(first, b'192.0.2.51 first.fixture\n', 0o644)
        base.regular(second, b'192.0.2.61 second.fixture\n', 0o644)
        extra += 'addn-hosts=' + str(first) + '\naddn-hosts=' + str(second) + '\n'
    pid = launch(args, directory, extra)
    before = ethers_answers(OLD_ETHERS)
    if cross:before = dict({key: query(key, value) for key, value in OLD_HOSTS.items()}, **before)
    if name == 'ethers-fifo-preserved':replace(ethers)
    elif name == 'ethers-empty-commit':replace(ethers, b'')
    else:replace(ethers, b'02:00:00:00:00:52 127.0.0.52\nnot-a-mac invalid.fixture\n')
    if cross:
        replace(first, b'192.0.2.52 first.fixture\n');replace(second, b'192.0.2.62 second.fixture\n')
    os.kill(pid, signal.SIGHUP)
    rejected = False if name == 'ethers-empty-commit' else rejection(directory)
    if not rejected:time.sleep(0.15)
    expected = dict(old_peer='fallback.fixture', new_peer='fallback.fixture') if name == 'ethers-empty-commit' else OLD_ETHERS
    after = ethers_answers(expected)
    if cross:after = dict({key: query(key, value) for key, value in OLD_HOSTS.items()}, **after)
    replace(ethers, b'02:00:00:00:00:52 127.0.0.52\n')
    os.kill(pid, signal.SIGHUP);time.sleep(0.15)
    repaired = ethers_answers(NEW_ETHERS)
    if cross:repaired = dict({key: query(key, value) for key, value in NEW_HOSTS.items()}, **repaired)
    require((directory / 'leases').read_bytes() == b'', 'Ethers INFORM fixture allocated a lease')
    stop(args);ethers.unlink()
    return row(name, start, kind='cross-ethers' if cross else 'ethers-inform', before=before, after=after, repaired=repaired,
               rejection_observed=rejected, queue_full=None, receiver_recovered=None, query_count=15 if cross else 6, probe_results=[])


def run_shared(args, calls, marker):
    start = time.monotonic()
    code, out, err = base.run_bounded(['qemu-mipsel', '-L', str(args.sysroot), str(args.probe_binary), str(calls), marker], limits=LIMITS)
    require(code == 0 and not err, 'Actual libshared logmessage probe failed: ' + (out + err).decode(errors='replace'))
    match = re.fullmatch(rb'calls=([0-9]+) fd_before=([0-9]+) fd_after=([0-9]+) errno_preserved=([01])\n', out)
    require(match is not None, 'Shared probe result marker mismatch')
    values = list(map(int, match.groups()))
    require(values[0] == calls and values[1] >= 3 and values[1] == values[2] and values[3] == 1, 'Shared logmessage fd/errno failure')
    elapsed = int((time.monotonic() - start) * 1000)
    require(elapsed <= LIMITS['probe_ms'], 'Shared logmessage did not return promptly')
    return dict(calls=calls, fd_before=values[1], fd_after=values[2], errno_preserved=True, elapsed_ms=elapsed)


def exercise_log(args, name, directory):
    start = time.monotonic(); receiver = None
    if name != 'syslog-absent-recovery':receiver = Receiver()
    try:
        if name == 'shared-literal-pressure-recovery':
            normal = run_shared(args, 1, 'literal%n normal'); receiver.marker(b'K2P_SHARED: literal%n normal')
            full = receiver.fill(); pressure = run_shared(args, 256, 'literal%n pressure')
            receiver.drain(); recovered = run_shared(args, 1, 'literal%n recovered')
            receiver.marker(b'K2P_SHARED: literal%n recovered')
            require(runtime.quiescent(), 'Shared probe process left behind')
            return row(name, start, kind='actual-libshared', before='literal%n normal', after=None,
                       repaired='literal%n recovered', rejection_observed=None, queue_full=full,
                       receiver_recovered=True, query_count=0, probe_results=[normal, pressure, recovered])
        launch(args, directory, system_log=True)
        before = query('before.fixture', '192.0.2.53')
        if receiver is not None:
            receiver.marker(b'before.fixture'); full = receiver.fill()
        else:full = None
        if name == 'syslog-full-bounded-exit':
            stop(args)
            return row(name, start, kind='syslog', before=before, after=None, repaired=None,
                       rejection_observed=None, queue_full=full, receiver_recovered=False, query_count=1, probe_results=[])
        after = query('pressure.fixture', '192.0.2.53')
        if receiver is None:receiver = Receiver()
        else:receiver.drain()
        repaired = query('recovered.fixture', '192.0.2.53')
        receiver.marker(b'recovered.fixture')
        stop(args)
        return row(name, start, kind='syslog', before=before, after=after, repaired=repaired,
                   rejection_observed=None, queue_full=full, receiver_recovered=True, query_count=3, probe_results=[])
    finally:
        if receiver is not None:receiver.close()


def worker_cases(args, rows=None):
    if rows is None:rows = []
    upstream = runtime.Upstream(11532, '192.0.2.53')
    try:
        for name in CASE_NAMES:
            print('Target log/reload CASE ' + name, flush=True)
            directory = Path('/tmp/log-reload-case'); directory.mkdir(mode=0o755)
            if name.startswith('ethers-') or name == 'cross-ethers-reject-preserves-hosts':value = exercise_ethers(args, name, directory)
            elif name.startswith('cross-'):value = exercise_cross(args, name, directory)
            elif name.startswith('hosts-'):value = exercise_hosts(args, name, directory)
            elif name.startswith('dhcp-'):value = exercise_dhcp(args, name, directory)
            else:value = exercise_log(args, name, directory)
            require(runtime.quiescent(), 'Log/reload case left a process')
            shutil.rmtree(directory)
            rows.append(value)
            print('Target log/reload PASS ' + name, flush=True)
        validate_records(rows)
        return rows
    finally:upstream.close()


def worker(args):
    namespaces = base.namespace_guard(json.loads(args.anchor_fds))
    # No mount is attempted until the PID1/anchored-mnt/net/pid guards pass.
    for name, size in FILESYSTEM_LIMITS.items():
        subprocess.run(['mount', '-n', '-t', 'tmpfs', '-o', 'size=' + str(size) + ',mode=0755', 'tmpfs', '/' + name], check=True, capture_output=True)
        prefix = args.sysroot / name
        require(not prefix.is_symlink(), 'QEMU mount target is a symlink')
        prefix.mkdir(exist_ok=True)
        subprocess.run(['mount', '-n', '--bind', '/' + name, str(prefix)], check=True, capture_output=True)
    # This is a new node on a private scratch mount, never the host /dev/null.
    os.mknod('/dev/null', stat.S_IFCHR | 0o666, os.makedev(1, 3)); os.chmod('/dev/null', 0o666)
    # config.h fixes RANDFILE=/dev/urandom. Preserve that legitimate startup
    # input on our private mount without exposing the host's device nodes.
    os.mknod('/dev/urandom', stat.S_IFCHR | 0o444, os.makedev(1, 9)); os.chmod('/dev/urandom', 0o444)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, capture_output=True)
    require({name for _, name in socket.if_nameindex()} == {'lo'}, 'Private network contains another interface')
    base.regular(Path('/etc/passwd'), b'root:x:0:0:root:/:/bin/sh\nnobody:x:99:99:nobody:/:/bin/false\n', 0o644)
    base.regular(Path('/etc/group'), b'root:x:0:\nnobody:x:99:\n', 0o644)
    Path('/var/run').mkdir(mode=0o755)
    # Both absolute and QEMU-prefix socket lookups must refer to our scratch /dev.
    require(os.stat('/dev').st_dev == os.stat(args.sysroot / 'dev').st_dev and
            os.stat('/dev').st_ino == os.stat(args.sysroot / 'dev').st_ino, 'QEMU /dev prefix is not isolated')
    report = dict(schema_version=1, status='FAIL', profile='k2p-4.4', execution_role=ROLE,
                  source_sha256=source_proof(args.trunk), shipped=shipped_proof(args.rootfs),
                  required_cases=list(CASE_NAMES), checks=[], filesystem_limits=FILESYSTEM_LIMITS,
                  limits=LIMITS, contract=CONTRACT, probe=json.loads(args.probe_metadata), failure=None,
                  isolation=dict(namespaces=namespaces, worker_pid=os.getpid(), loopback_only=True,
                    private_mount_propagation=True, anchors_cloexec=True, namespace_exit_confirmed=False, private_dev_log=True))
    try:worker_cases(args, report['checks']); report['status'] = 'PASS'
    except Exception as error:report['failure'] = str(error)[:4096]; raise
    finally:base.write_output(args.output, json.loads(args.expected_output), report)


def root_parent(args):
    require(sys.platform.startswith('linux') and os.geteuid() == 0, 'Linux root launcher required')
    expected = json.loads(args.expected_output)
    require(base.output_identity(args.output) == expected, 'Parent-owned log/reload report changed')
    anchors = {name: os.open('/proc/self/ns/' + name, os.O_RDONLY | os.O_CLOEXEC) for name in ('mnt', 'net', 'pid')}
    command = ['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc', '--kill-child=KILL',
               '--propagation', 'private', sys.executable, str(Path(__file__).resolve()), '--worker']
    for name in ('trunk', 'rootfs', 'sysroot', 'output', 'probe_binary'):command += ['--' + name.replace('_', '-'), str(getattr(args, name))]
    command += ['--expected-output', args.expected_output, '--anchor-fds', json.dumps(anchors), '--probe-metadata', args.probe_metadata]
    try:subprocess.run(command, check=True, timeout=LIMITS['worker_seconds'], pass_fds=tuple(anchors.values()))
    finally:
        for fd in anchors.values():os.close(fd)
    report = json.loads(args.output.read_text()); require(report['status'] == 'PASS', 'Private log/reload worker failed')
    report['isolation']['namespace_exit_confirmed'] = True; base.write_output(args.output, expected, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'rootfs', 'sysroot', 'output'):parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--compiler', type=Path)
    mode = parser.add_mutually_exclusive_group();mode.add_argument('--worker', action='store_true');mode.add_argument('--root-parent', action='store_true')
    parser.add_argument('--expected-output');parser.add_argument('--anchor-fds');parser.add_argument('--probe-metadata');parser.add_argument('--probe-binary', type=Path)
    args = parser.parse_args()
    for name in ('trunk', 'rootfs', 'sysroot'):setattr(args, name, getattr(args, name).resolve())
    args.output = args.output.parent.resolve() / args.output.name
    if args.worker:return worker(args)
    if args.root_parent:return root_parent(args)
    require(sys.platform.startswith('linux') and args.compiler is not None, 'Linux actual target proof requires --compiler; no fallback PASS')
    for path in (args.trunk, args.rootfs, args.sysroot, args.output, Path(__file__).resolve()):
        require(not any(path.is_relative_to('/' + name) for name in FILESYSTEM_LIMITS), 'Input/output would be hidden by private mounts')
    sources, shipped = source_proof(args.trunk), shipped_proof(args.rootfs)
    expected = base.prepare_output(args.output)
    probe, binary = compile_probe(args)
    command = (['sudo', '-n', 'env', 'PATH=' + os.environ['PATH']] if os.geteuid() else []) + [
        sys.executable, str(Path(__file__).resolve()), '--root-parent', '--trunk', str(args.trunk), '--rootfs', str(args.rootfs),
        '--sysroot', str(args.sysroot), '--output', str(args.output), '--expected-output', json.dumps(expected),
        '--probe-metadata', json.dumps(probe), '--probe-binary', str(binary)]
    subprocess.run(command, check=True, timeout=LIMITS['worker_seconds'] + 30)
    require(base.output_identity(args.output) == expected, 'Root child changed log/reload report inode/owner')
    validate_report(json.loads(args.output.read_text()), sources, shipped)
    print('Target log/reload: ' + str(len(CASE_NAMES)) + ' actual shipped private-namespace cases PASS')


if __name__ == '__main__':main()
