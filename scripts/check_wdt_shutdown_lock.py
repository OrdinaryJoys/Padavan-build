#!/usr/bin/env python3
"""Check target watchdog shutdown contention tests and MIPS executable."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from check_target_spi_nor import inspect_elf


def require(value, message):
    if not value:
        raise ValueError(message)


def inspect(directory):
    log=(directory/'wdt-shutdown-lock-target-tests.txt').read_bytes()
    text=log.decode('utf-8')
    require(text.count('WDT_SHUTDOWN_LOCK_TARGET=mipsel-linux-uclibc;RUNNER=qemu-mipsel')==1,
            'MIPS target execution marker absent or duplicated')
    for name in ('test_actual_bodies_and_concurrent_owners',
                 'test_unreported_failure_negative_control'):
        require(len(re.findall(r'^'+name+r'\s+\([^\n]+\)\s+\.\.\.\s+ok$',text,re.M))==1,
                'Missing target test: '+name)
    require(len(re.findall(r'^Ran 2 tests in ',text,re.M))==1 and text.rstrip().endswith('OK'),
            'Target tests failed or skipped')
    source=(directory/'target-wdt-shutdown-lock.c').read_bytes()
    elf=(directory/'target-wdt-shutdown-lock.elf').read_bytes()
    require(0<len(source)<=1024*1024,'Target source size')
    meta=inspect_elf(elf,2)
    return {'status':'PASS','tests':2,'source_sha256':hashlib.sha256(source).hexdigest(),
            'elf_sha256':meta['sha256'],'log_sha256':hashlib.sha256(log).hexdigest()}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts',type=Path,required=True)
    p.add_argument('--write-report',action='store_true')
    a=p.parse_args();result=inspect(a.artifacts);report=a.artifacts/'target-wdt-shutdown-lock.json'
    if a.write_report:
        report.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    else:
        require(json.loads(report.read_text())==result,'Target receipt differs')
    print(json.dumps(result))

if __name__=='__main__':
    main()
