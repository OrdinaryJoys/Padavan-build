#!/usr/bin/env python3
"""Actual shipped DNS runtime-file checks, in private Linux namespaces only.

No host-network listener, real lease database, clock change or router is used.
The older snapshot proof remains mandatory and unchanged.
"""
import argparse
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
import threading
import time

import check_target_snapshot as base

SOURCE_PATHS = {name: 'user/dnsmasq/dnsmasq-2.93/' + name for name in (
    'Makefile', 'src/runtime_file.c', 'src/runtime_file.h', 'src/option.c',
    'src/network.c', 'src/cache.c', 'src/log.c', 'src/lease.c',
    'src/dnsmasq.c', 'src/dynamic_conf.c', 'src/dynamic_conf.h')}
CASE_NAMES = ('regular-servers', 'symlink-regular-servers', 'hardlink-regular-servers',
              'fifo-servers-startup', 'symlink-fifo-servers-startup',
              'directory-servers-startup', 'oversize-servers-startup',
              'long-line-servers-startup', 'many-lines-servers-startup',
              'fifo-servers-reload', 'oversize-servers-reload',
              'atomic-servers-reload', 'fifo-resolv-domain-test',
              'fifo-resolv-domain-capture', 'fifo-live-resolv',
              'fifo-addn-hosts', 'fifo-default-hosts', 'fifo-dhcp-hostsfile',
              'fifo-dhcp-optsfile', 'fifo-log-startup', 'fifo-lease-startup',
              'regular-lease-startup', 'lease-init-valid', 'lease-init-exit7',
              'lease-init-timeout', 'lease-init-output-over2M', 'null-log-startup',
              'null-lease-startup', 'symlink-null-log-refused', 'symlink-null-lease-refused')
PARSER_CASES = {'fifo-resolv-domain-test', 'fifo-resolv-domain-capture'}
FATAL_CASES = {'fifo-log-startup', 'fifo-lease-startup', 'lease-init-exit7',
               'lease-init-timeout', 'lease-init-output-over2M',
               'symlink-null-log-refused', 'symlink-null-lease-refused'}
REJECT_CASES = set(CASE_NAMES) - {'regular-servers', 'symlink-regular-servers',
                               'hardlink-regular-servers', 'atomic-servers-reload',
                               'regular-lease-startup', 'lease-init-valid',
                               'null-log-startup', 'null-lease-startup'}
FILESYSTEM_LIMITS = base.FILESYSTEM_LIMITS.copy()
LIMITS = {'worker_seconds': 180, 'command_seconds': 20, 'nonregular_seconds': 5,
          'query_seconds': 4, 'report_bytes': 1048576, 'output_bytes': 131072,
          'lease_init_min_ms': 9500, 'lease_init_max_ms': 15000}
ROLE = 'Actual shipped MIPS DNS daemon/parser under QEMU; isolated synthetic files and loopback upstreams'
KEYS = {'case', 'exit_code', 'rejected', 'diagnostic_observed', 'first_answer',
        'after_answer', 'daemon_stopped', 'elapsed_ms', 'null_identity_preserved'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_proof(trunk):
    require('CONFIG_LINUXDIR=linux-4.4.x' in (trunk / '.config').read_text(), 'Runtime DNS proof requires4.4')
    return {name: sha((trunk / path).read_bytes()) for name, path in SOURCE_PATHS.items()}


def validate_records(records):
    require(type(records) is list and len(records) == len(CASE_NAMES), 'Missing runtime DNS cases')
    for name, row in zip(CASE_NAMES, records):
        require(type(row) is dict and set(row) == KEYS and row['case'] == name, 'Runtime DNS case schema/order mismatch')
        fatal = name in PARSER_CASES | FATAL_CASES
        status = 17 if name == 'lease-init-exit7' else (3 if fatal else 0)
        require(type(row['exit_code']) is int and row['exit_code'] == status, 'Unexpected runtime DNS status')
        require(row['rejected'] is (name in REJECT_CASES) and row['diagnostic_observed'] is True,
                'Runtime DNS rejection/diagnostic missing')
        first = None if fatal else '192.0.2.51'
        after = None if fatal else ('192.0.2.52' if name == 'atomic-servers-reload' else first)
        require(row['first_answer'] == first and row['after_answer'] == after and row['daemon_stopped'] is True,
                'Runtime DNS answer/cleanup mismatch')
        require(row['null_identity_preserved'] is (True if 'null-' in name else None),
                'Standard null device ownership/mode/identity was not preserved')
        require(type(row['elapsed_ms']) is int and 0 <= row['elapsed_ms'] <= LIMITS['command_seconds'] * 1000,
                'Runtime DNS case exceeded deadline')
        if name == 'lease-init-timeout':
            require(LIMITS['lease_init_min_ms'] <= row['elapsed_ms'] <= LIMITS['lease_init_max_ms'],
                    'Lease-init production timeout did not actually run')
    return True


def validate_report(report, sources, shipped):
    require(type(report) is dict and set(report) == {'schema_version', 'status', 'profile', 'execution_role',
            'source_sha256', 'shipped', 'required_cases', 'checks', 'filesystem_limits', 'limits', 'isolation', 'failure'},
            'Runtime DNS report schema changed')
    require(type(report['schema_version']) is int and report['schema_version'] == 1 and report['status'] == 'PASS' and
            report['profile'] == 'k2p-4.4' and report['failure'] is None, 'Runtime DNS proof failed')
    require(report['execution_role'] == ROLE and report['source_sha256'] == sources and report['shipped'] == shipped and
            report['required_cases'] == list(CASE_NAMES) and report['filesystem_limits'] == FILESYSTEM_LIMITS and
            report['limits'] == LIMITS, 'Runtime DNS source/image/contract differs')
    isolation = report['isolation']
    require(type(isolation) is dict and set(isolation) == {'namespaces', 'worker_pid', 'loopback_only',
            'private_mount_propagation', 'anchors_cloexec', 'namespace_exit_confirmed'} and
            type(isolation['worker_pid']) is int and isolation['worker_pid'] == 1 and
            all(isolation[key] is True for key in ('loopback_only', 'private_mount_propagation', 'anchors_cloexec',
                                                 'namespace_exit_confirmed')), 'Runtime DNS isolation not confirmed')
    require(set(isolation['namespaces']) == {'mnt', 'net', 'pid'}, 'Missing runtime namespace anchors')
    for value in isolation['namespaces'].values():
        require(type(value) is dict and set(value) == {'parent_inode', 'worker_inode'} and
                all(type(x) is int and x > 0 for x in value.values()) and value['parent_inode'] != value['worker_inode'],
                'Parent namespace used for runtime test')
    return validate_records(report['checks'])


class Upstream:
    def __init__(self, port, answer):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', port))
        self.sock.settimeout(0.1)
        self.answer = socket.inet_aton(answer)
        self.stop = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                data, peer = self.sock.recvfrom(4097)
                require(12 < len(data) <= 4096 and peer[0] == '127.0.0.1', 'Unexpected upstream packet')
                require(struct.unpack_from('!H', data, 4)[0] == 1, 'Unexpected upstream questions')
                end = base.skip_name(data, 12) + 4
                require(end <= len(data) and struct.unpack_from('!HH', data, end - 4) == (1, 1),
                        'Unexpected upstream question')
                # dnsmasq may add an EDNS OPT record; this synthetic A-only
                # upstream returns the bounded original question without OPT.
                reply = data[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + data[12:end]
                reply += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + self.answer
                self.sock.sendto(reply, peer)
            except socket.timeout:
                continue
            except Exception as error:
                self.error = str(error)
                return

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()
        require(not self.thread.is_alive() and self.error is None, 'Private upstream failed: ' + str(self.error))


def query(expected):
    # Cache is disabled. Both responses must traverse the current upstream policy.
    data = struct.pack('!6H', 0x4b32, 0x100, 1, 0, 0, 0) + b'\x08snapshot\x07fixture\0\0\x01\0\x01'
    deadline = time.monotonic() + LIMITS['query_seconds']
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.2)
        while time.monotonic() < deadline:
            try:
                sock.sendto(data, ('127.0.0.1', 10530))
                reply, peer = sock.recvfrom(4097)
                require(peer == ('127.0.0.1', 10530), 'DNS reply outside private listener')
                require(12 <= len(reply) <= 4096, 'Invalid DNS reply length')
                ident, flags, questions, answers, _, _ = struct.unpack_from('!6H', reply)
                require(ident == 0x4b32 and flags & 0x8000 and flags & 15 == 0 and questions == 1 and answers == 1,
                        'Unexpected DNS reply header')
                pos = base.skip_name(reply, 12) + 4
                pos = base.skip_name(reply, pos)
                require(pos + 14 == len(reply) and struct.unpack_from('!HHIH', reply, pos) == (1, 1, 0, 4),
                        'Unexpected DNS answer record')
                address = socket.inet_ntoa(reply[pos + 10:])
                if address == expected:
                    return address
            except (socket.timeout, ConnectionRefusedError):
                continue
    raise RuntimeError('Private DNS did not return expected current policy: ' + expected)


def daemon_pid(rootfs):
    raw = Path('/var/run/snapshot-daemon.pid').read_text()
    require(re.fullmatch('[0-9]+\n', raw) is not None, 'Invalid private daemon PID')
    pid = int(raw)
    require(pid > 1 and str(rootfs / 'usr/sbin/dnsmasq').encode() in
            Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0'), 'Private daemon identity mismatch')
    return pid


def no_daemon(rootfs):
    needle = str(rootfs / 'usr/sbin/dnsmasq').encode()
    for proc in Path('/proc').iterdir():
        if proc.name.isdigit():
            try:
                require(needle not in (proc / 'cmdline').read_bytes().split(b'\0'), 'Rejected startup left a DNS process')
            except (FileNotFoundError, ProcessLookupError):
                pass
    return True


def quiescent():
    """PID1 can also observe descendants which no longer mention the script."""
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        for _ in range(128):
            try:
                child, _ = os.waitpid(-1, os.WNOHANG)
                if child == 0: break
            except ChildProcessError: break
        processes = []
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit() and int(proc.name) != 1:
                try:
                    proc.stat(); processes.append(proc.name)
                except (FileNotFoundError, ProcessLookupError): pass
        if not processes: return True
        time.sleep(0.02)
    raise RuntimeError('Runtime DNS case left processes in its private PID tree: ' + ','.join(processes))


def worker_cases(args):
    upstreams = [Upstream(11530, '192.0.2.51'), Upstream(11531, '192.0.2.52'), Upstream(11532, '192.0.2.53')]
    rows = []
    try:
        for case in CASE_NAMES:
            start = time.monotonic()
            directory = Path('/tmp/runtime-dns-case')
            directory.mkdir(mode=0o755)
            source = directory / 'input'
            config = directory / 'dnsmasq.conf'
            log = directory / 'daemon.log'
            common = ('port=10530\nlisten-address=127.0.0.1\nbind-interfaces\nuser=nobody\ngroup=nobody\n'
                      'no-hosts\nno-resolv\ncache-size=0\nserver=127.0.0.1#11530\n'
                      'pid-file=/var/run/snapshot-daemon.pid\nlog-facility=' + str(log) + '\n')
            payload = b'server=/snapshot.fixture/127.0.0.1#11530\n'
            null_before = os.stat('/dev/null') if 'null-' in case else None
            if 'servers' in case and (case not in REJECT_CASES or case.endswith('reload')):
                # A different fallback makes the positive/reload answers prove
                # that the file's more specific policy was really installed.
                common = common.replace('server=127.0.0.1#11530', 'server=127.0.0.1#11532')
            if case.startswith('fifo-') or case == 'symlink-fifo-servers-startup':
                os.mkfifo(source, 0o644)
            elif case.startswith('symlink-null-'):
                source.symlink_to('/dev/null')
            elif case == 'directory-servers-startup':
                source.mkdir()
            elif case.startswith('oversize-'):
                base.regular(source, b'#' + b'x' * (2 * 1024 * 1024) + b'\n', 0o644)
            elif case == 'long-line-servers-startup':
                base.regular(source, b'#' + b'x' * 16384 + b'\n', 0o644)
            elif case == 'many-lines-servers-startup':
                base.regular(source, b'#\n' * 65537, 0o644)
            else:
                base.regular(source, payload, 0o644)
            if case in ('symlink-regular-servers', 'symlink-fifo-servers-startup'):
                alias = directory / 'alias'; alias.symlink_to(source); source = alias
            elif case == 'hardlink-regular-servers':
                alias = directory / 'alias'; os.link(source, alias); source = alias
            if 'resolv-domain' in case:
                common = common.replace('no-resolv\n', '') + 'domain=#\nresolv-file=' + str(source) + '\n'
            elif case == 'fifo-live-resolv':
                common = common.replace('no-resolv\n', '') + 'resolv-file=' + str(source) + '\n'
            elif case == 'fifo-addn-hosts':
                common += 'addn-hosts=' + str(source) + '\n'
            elif case == 'fifo-default-hosts':
                source = Path('/etc/hosts'); os.mkfifo(source, 0o644)
                common = common.replace('no-hosts\n', '')
            elif case in ('fifo-dhcp-hostsfile', 'fifo-dhcp-optsfile'):
                leases = directory / 'leases'; base.regular(leases, b'', 0o644)
                common += 'dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h\ndhcp-leasefile=' + str(leases) + '\n'
                common += ('dhcp-hostsfile=' if case == 'fifo-dhcp-hostsfile' else 'dhcp-optsfile=') + str(source) + '\n'
            elif case == 'fifo-log-startup':
                common = common.replace('log-facility=' + str(log), 'log-facility=' + str(source))
            elif case in ('null-log-startup', 'symlink-null-log-refused'):
                if case == 'null-log-startup': source = Path('/dev/null')
                common = common.replace('log-facility=' + str(log), 'log-facility=' + str(source))
            elif case in ('null-lease-startup', 'symlink-null-lease-refused'):
                if case == 'null-lease-startup': source = Path('/dev/null')
                common += 'dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h\ndhcp-leasefile=' + str(source) + '\n'
            elif case in ('fifo-lease-startup', 'regular-lease-startup'):
                if case == 'regular-lease-startup': base.regular(source, b'', 0o644)
                common += 'dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h\ndhcp-leasefile=' + str(source) + '\n'
            elif case.startswith('lease-init-'):
                source = directory / 'lease-init.sh'
                action = {'lease-init-valid': 'exit 0', 'lease-init-exit7': 'exit 7',
                          'lease-init-timeout': 'while :; do sleep 1; done',
                          'lease-init-output-over2M': '/usr/bin/yes x | /usr/bin/head -c 2097153'}[case]
                base.regular(source, ('#!/bin/sh\ncase "$1" in init) ' + action + ';; *) exit 0;; esac\n').encode(), 0o755)
                common += ('dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h\nleasefile-ro\n'
                           'dhcp-script=' + str(source) + '\n')
            else:
                common += 'servers-file=' + str(source) + '\n'
            # Reload cases begin with a valid file, then atomically replace it.
            bad_payload = source.read_bytes() if case == 'oversize-servers-reload' else None
            if case in ('fifo-servers-reload', 'oversize-servers-reload'):
                source.unlink(); base.regular(source, payload, 0o644)
            base.regular(config, common.encode(), 0o644)
            command = ['qemu-mipsel', '-L', str(args.sysroot), str(args.rootfs / 'usr/sbin/dnsmasq'),
                       '--conf-file=' + str(config)]
            if case in PARSER_CASES:
                command += ['--test']
                if case.endswith('capture'):
                    directory.chmod(0o700)
                    cache = directory / 'cache'  # capture itself must create a fresh private directory
                    custom, candidate = directory / 'custom', directory / 'candidate'
                    base.regular(custom, common.encode(), 0o600)
                    base.regular(candidate, common.encode(), 0o600)
                    base.regular(config, ('conf-file=' + str(custom) + '\n').encode(), 0o644)
                    command += ['--snapshot-capture', str(cache), '--snapshot-overlay', str(custom),
                                '--snapshot-candidate', str(candidate), '--snapshot-managed']
            status, out, err = base.run_bounded(command, limits=LIMITS)
            rejected = case in REJECT_CASES
            first = after = None
            if case in PARSER_CASES | FATAL_CASES:
                expected_status = 17 if case == 'lease-init-exit7' else 3
                budget = LIMITS['command_seconds'] if case == 'lease-init-timeout' else LIMITS['nonregular_seconds']
                require(status == expected_status and time.monotonic() - start < budget,
                        'Nonregular startup input did not fail promptly: ' + case)
                diagnostic = (b'runtime DNS input' if case in PARSER_CASES else
                              b'exit code 7' if case == 'lease-init-exit7' else
                              b'bounded lease-init failed' if case.startswith('lease-init-') else str(source).encode())
                require(diagnostic in out + err,
                        'Rejected startup diagnostic lacks the runtime input failure')
                stopped = no_daemon(args.rootfs)
                if case.startswith('lease-init-'):
                    # Collector cleanup, independently of final PID-namespace destruction.
                    for proc in Path('/proc').iterdir():
                        if proc.name.isdigit():
                            try: require(str(source).encode() not in (proc / 'cmdline').read_bytes().split(b'\0'),
                                         'Lease-init left its script running')
                            except (FileNotFoundError, ProcessLookupError): pass
            else:
                require(status == 0, 'Runtime daemon launcher failed: ' + case + ': ' + (out + err).decode(errors='replace'))
                pid = daemon_pid(args.rootfs)
                first = query('192.0.2.51')
                if case in ('fifo-servers-reload', 'oversize-servers-reload', 'atomic-servers-reload'):
                    replacement = directory / 'replacement'
                    if case == 'fifo-servers-reload': os.mkfifo(replacement, 0o644)
                    else: base.regular(replacement, bad_payload if bad_payload else b'server=/snapshot.fixture/127.0.0.1#11531\n', 0o644)
                    os.replace(replacement, source)
                    os.kill(pid, signal.SIGHUP)
                    time.sleep(0.15)
                after = query('192.0.2.52' if case == 'atomic-servers-reload' else '192.0.2.51')
                if rejected:
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline and (not log.exists() or str(source) not in log.read_text()):
                        time.sleep(0.02)
                    require(log.exists() and str(source) in log.read_text(), 'Missing runtime rejection diagnostic: ' + case)
                stopped = base.stop_daemon(args.rootfs)
                Path('/var/run/snapshot-daemon.pid').unlink(missing_ok=True)
            require(quiescent(), 'Runtime DNS process-tree cleanup failed')
            null_identity = None
            if null_before is not None:
                after_null = os.stat('/dev/null')
                attributes = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_rdev')
                require(all(getattr(null_before, key) == getattr(after_null, key) for key in attributes),
                        'DNS changed the standard null device owner, permissions or identity')
                null_identity = True
            rows.append(dict(case=case, exit_code=status, rejected=rejected, diagnostic_observed=True,
                             first_answer=first, after_answer=after, daemon_stopped=stopped,
                             elapsed_ms=int((time.monotonic() - start) * 1000), null_identity_preserved=null_identity))
            shutil.rmtree(directory)
            if case == 'fifo-default-hosts': source.unlink()
        validate_records(rows)
    finally:
        for upstream in upstreams:
            upstream.close()
    return rows


def worker(args):
    namespaces = base.namespace_guard(json.loads(args.anchor_fds))
    for name, size in FILESYSTEM_LIMITS.items():
        subprocess.run(['mount', '-n', '-t', 'tmpfs', '-o', 'size=' + str(size) + ',mode=0755',
                        'tmpfs', '/' + name], check=True, capture_output=True)
        (args.sysroot / name).mkdir(exist_ok=True)
        subprocess.run(['mount', '-n', '--bind', '/' + name, str(args.sysroot / name)], check=True, capture_output=True)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, capture_output=True)
    require({name for _, name in socket.if_nameindex()} == {'lo'}, 'Private interface set changed')
    base.regular(Path('/etc/passwd'), b'root:x:0:0:root:/:/bin/sh\nnobody:x:99:99:nobody:/:/bin/false\n', 0o644)
    base.regular(Path('/etc/group'), b'root:x:0:\nnobody:x:99:\n', 0o644)
    Path('/var/run').mkdir(mode=0o755)
    report = dict(schema_version=1, status='FAIL', profile='k2p-4.4', execution_role=ROLE,
                  source_sha256=source_proof(args.trunk), shipped=base.shipped_proof(args.rootfs),
                  required_cases=list(CASE_NAMES), checks=[], filesystem_limits=FILESYSTEM_LIMITS,
                  limits=LIMITS, failure=None,
                  isolation=dict(namespaces=namespaces, worker_pid=os.getpid(), loopback_only=True,
                                 private_mount_propagation=True, anchors_cloexec=True, namespace_exit_confirmed=False))
    try:
        report['checks'] = worker_cases(args)
        report['status'] = 'PASS'
    except Exception as error:
        report['failure'] = str(error)[:4096]
        raise
    finally:
        base.write_output(args.output, json.loads(args.expected_output), report)


def root_parent(args):
    require(sys.platform.startswith('linux') and os.geteuid() == 0, 'Linux root launcher required')
    expected = json.loads(args.expected_output)
    require(base.output_identity(args.output) == expected, 'Parent-owned runtime report changed')
    anchors = {name: os.open('/proc/self/ns/' + name, os.O_RDONLY | os.O_CLOEXEC) for name in ('mnt', 'net', 'pid')}
    command = ['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc', '--kill-child=KILL',
               '--propagation', 'private', sys.executable, str(Path(__file__).resolve()), '--worker',
               '--trunk', str(args.trunk), '--rootfs', str(args.rootfs), '--sysroot', str(args.sysroot),
               '--output', str(args.output), '--expected-output', args.expected_output, '--anchor-fds', json.dumps(anchors)]
    try:
        subprocess.run(command, check=True, timeout=LIMITS['worker_seconds'], pass_fds=tuple(anchors.values()))
    finally:
        for fd in anchors.values(): os.close(fd)
    report = json.loads(args.output.read_text())
    require(report['status'] == 'PASS', 'Private runtime DNS worker failed')
    report['isolation']['namespace_exit_confirmed'] = True
    base.write_output(args.output, expected, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'rootfs', 'sysroot', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(); mode.add_argument('--worker', action='store_true'); mode.add_argument('--root-parent', action='store_true')
    parser.add_argument('--expected-output'); parser.add_argument('--anchor-fds')
    args = parser.parse_args()
    for name in ('trunk', 'rootfs', 'sysroot'): setattr(args, name, getattr(args, name).resolve())
    args.output = args.output.parent.resolve() / args.output.name
    if args.worker: return worker(args)
    if args.root_parent: return root_parent(args)
    require(sys.platform.startswith('linux'), 'Runtime DNS proof requires Linux; no skipped/fallback PASS')
    for path in (args.trunk, args.rootfs, args.sysroot, args.output, Path(__file__).resolve()):
        require(not any(path.is_relative_to('/' + name) for name in FILESYSTEM_LIMITS), 'Input/output would be hidden by private mounts')
    sources, shipped = source_proof(args.trunk), base.shipped_proof(args.rootfs)
    expected = base.prepare_output(args.output)
    command = (['sudo', '-n', 'env', 'PATH=' + os.environ['PATH']] if os.geteuid() else []) + [
        sys.executable, str(Path(__file__).resolve()), '--root-parent', '--trunk', str(args.trunk),
        '--rootfs', str(args.rootfs), '--sysroot', str(args.sysroot), '--output', str(args.output), '--expected-output', json.dumps(expected)]
    subprocess.run(command, check=True, timeout=LIMITS['worker_seconds'] + 30)
    require(base.output_identity(args.output) == expected, 'Root child changed report inode/ownership')
    validate_report(json.loads(args.output.read_text()), sources, shipped)
    print('Target runtime DNS: ' + str(len(CASE_NAMES)) + ' private-namespace cases PASS')


if __name__ == '__main__':
    main()
