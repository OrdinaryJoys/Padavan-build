#!/usr/bin/env python3
"""Fail early on MIPS compiler/ABI defects in the inert writer core protocol probe.

This uses static toolchain libc, not the later shipped dynamic runtime. It
does not replace the final23-case gate and never executes the real writer or resident finalizer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import check_target_writer as writer


def check(trunk, compiler, output):
    writer.require(sys.platform.startswith('linux'), 'Static MIPS preflight requires Linux')
    qemu = shutil.which('qemu-mipsel')
    writer.require(qemu is not None, 'qemu-mipsel is required')
    texts = {name: (trunk / relative).read_text() for name, relative in writer.SOURCE_PATHS.items()}
    generated = writer.generate_source(texts).encode()
    source = output.with_suffix('.c')
    binary = output.with_suffix('')
    source.write_bytes(generated)
    compiled = subprocess.run([str(compiler), '-static', '-std=gnu99', '-Wall', '-Wextra', '-Werror',
                               '-DFWUP_TEST_UID=geteuid()', str(source), '-o', str(binary)],
                              capture_output=True, text=True, timeout=60)
    writer.require(compiled.returncode == 0, 'Static MIPS writer probe compile failed: ' + compiled.stdout + compiled.stderr)
    writer.require(writer.validate_elf_binding(binary.read_bytes()) == 'static-no-dynamic-segment',
                   'Preflight must use a static MIPS executable')
    binary.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix='k2p-writer-preflight-', dir='/tmp') as temporary:
        base = Path(temporary)
        records = [writer.run_probe_case([qemu, str(binary)], base, spec) for spec in writer.CASES]
    writer.validate_records(records, expected_owner=os.geteuid(), include_shipped=False)
    report = dict(status='PASS', target='static MIPS probe with toolchain libc and inert ordinary-file backends',
                  cases=len(records), checks=records, source_sha256={name: hashlib.sha256(text.encode()).hexdigest() for name, text in texts.items()},
                  generated_source_sha256=hashlib.sha256(generated).hexdigest(),
                  mips_probe_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  limitations=['No shipped writer, daemon, MTD, hardware ioctl, real mlockall or reboot executed.',
                               'Uses static toolchain libc; final23-case shipped-runtime writer check remains mandatory.'])
    output.write_text(json.dumps(report, indent=2) + '\n')
    print('Static MIPS writer preflight:22 inert source cases PASS; final shipped-runtime gate still required')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    check(args.trunk.resolve(), args.compiler.resolve(), args.output.resolve())
