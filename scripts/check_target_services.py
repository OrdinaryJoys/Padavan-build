#!/usr/bin/env python3
"""Run shipped DNS/SSH parsers under QEMU; never start a network service."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def check(rootfs, sysroot, output):
    records = []

    def target(program, *args, expected=0):
        result = subprocess.run(['qemu-mipsel', '-L', str(sysroot), str(rootfs / program), *map(str, args)],
                                capture_output=True, text=True, timeout=60)
        if (result.returncode != 0) != (expected != 0):
            raise RuntimeError(f'{program} parser returned {result.returncode}: {result.stdout}{result.stderr}')
        return result

    # Ephemeral private host keys stay here and are removed before uploading.
    with tempfile.TemporaryDirectory(prefix='k2p-target-parsers-') as temp:
        temp = Path(temp)
        dns = temp / 'dnsmasq.conf'
        dns.write_text('port=0\nno-hosts\nno-resolv\ncache-size=128\nfilter-aaaa\nmin-ttl=60\nserver=/example.invalid/127.0.0.1\n')
        result = target('usr/sbin/dnsmasq', '--test', '--conf-file=' + str(dns))
        records.append({'program': 'dnsmasq', 'case': 'valid-generated-options', 'exit_code': result.returncode,
                        'diagnostic': (result.stdout + result.stderr).strip()})
        dns.write_text('k2p-definitely-invalid=yes\n')
        result = target('usr/sbin/dnsmasq', '--test', '--conf-file=' + str(dns), expected=1)
        records.append({'program': 'dnsmasq', 'case': 'invalid-option-rejected', 'exit_code': result.returncode})

        key = temp / 'host_ed25519'
        target('usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key)
        ssh = temp / 'sshd_config'
        ssh.write_text(f'Port 22222\nListenAddress 127.0.0.1\nHostKey {key}\nPasswordAuthentication no\nPermitRootLogin no\nAllowUsers fixture\n')
        target('usr/sbin/sshd', '-t', '-f', ssh)
        result = target('usr/sbin/sshd', '-T', '-f', ssh)
        actual = result.stdout.lower().splitlines()
        for policy in ('passwordauthentication no', 'permitrootlogin no', 'allowusers fixture'):
            if policy not in actual:
                raise RuntimeError('Target sshd lost policy: ' + policy)
        records.append({'program': 'sshd', 'case': 'valid-restrictive-policy', 'exit_code': 0,
                        'effective_policy': ['passwordauthentication no', 'permitrootlogin no', 'allowusers fixture']})
        ssh.write_text(ssh.read_text() + 'K2PDefinitelyInvalid yes\n')
        result = target('usr/sbin/sshd', '-t', '-f', ssh, expected=1)
        records.append({'program': 'sshd', 'case': 'invalid-option-rejected', 'exit_code': result.returncode})

    output.write_text(json.dumps({'checks': records, 'target': 'shipped MIPS DNS/SSH parsers with real target libraries',
                                 'mode': 'dnsmasq --test and sshd -t/-T only; no daemon listener started'}, indent=2) + '\n')
    print('Target DNS/SSH configuration parsers: 4 cases PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    check(args.rootfs.resolve(), args.sysroot.resolve(), args.output)
