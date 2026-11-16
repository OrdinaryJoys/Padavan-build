#!/usr/bin/env python3
"""Verify RAETH thread-exit test receipt and all three MIPS fixtures."""
import argparse, hashlib, json, re
from pathlib import Path
from check_target_spi_nor import inspect_elf

def require(value, message):
    if not value: raise ValueError(message)

def inspect(directory):
    raw=(directory/'raeth-thread-exit-target-tests.txt').read_bytes(); text=raw.decode()
    require(text.count('RAETH_THREAD_EXIT_TARGET=mipsel-linux-uclibc;RUNNER=qemu-mipsel')==1,'target marker')
    for name in ('test_actual_open_close_remove_timeout_preserves_owners','test_late_worker_completion_does_not_release_owners','test_open_failure_errno_survives_successful_thread_join','test_returning_from_quarantine_is_detected','test_missing_failure_publication_is_rejected'):
        require(len(re.findall(r'^'+name+r'\s+\([^\n]+\)\s+\.\.\.\s+ok$',text,re.M))==1,'missing '+name)
    require(len(re.findall(r'^Ran 5 tests in ',text,re.M))==1 and text.rstrip().endswith('OK'),'test count or skipped/failed')
    fixtures={}
    for stem in ('runtime','remove','late'):
        src=(directory/('target-raeth-thread-'+stem+'.c')).read_bytes(); elf=(directory/('target-raeth-thread-'+stem+'.elf')).read_bytes()
        require(0<len(src)<=1024*1024,'fixture size'); meta=inspect_elf(elf,2)
        fixtures[stem]={'source_sha256':hashlib.sha256(src).hexdigest(),'elf_sha256':meta['sha256']}
    return {'status':'PASS','tests':5,'fixtures':fixtures,'log_sha256':hashlib.sha256(raw).hexdigest()}

def main():
    p=argparse.ArgumentParser();p.add_argument('--artifacts',type=Path,required=True);p.add_argument('--write-report',action='store_true');a=p.parse_args();r=inspect(a.artifacts);report=a.artifacts/'target-raeth-thread-exit.json'
    if a.write_report:report.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    else:require(json.loads(report.read_text())==r,'receipt differs')
    print(json.dumps(r))
if __name__=='__main__':main()
