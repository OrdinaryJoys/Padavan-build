#!/usr/bin/env python3
"""Check exact target test receipt and its static MIPS executable."""
import argparse,hashlib,json,re
from pathlib import Path
from check_target_spi_nor import inspect_elf

def require(ok,message):
 if not ok:raise ValueError(message)
def inspect(directory):
 log=(directory/'exec-residency-target-tests.txt').read_bytes();text=log.decode('utf-8')
 require(text.count('EXEC_RESIDENCY_TARGET=mipsel-linux-uclibc;RUNNER=qemu-mipsel')==1,'Target execution marker absent or duplicated')
 for name in ('test_valid_segments_and_transient_reads','test_invalid_segments_and_failure_are_rejected','test_missing_or_ignored_segment_lock_controls_are_detected'):
  require(len(re.findall(r'^'+name+r'\s+\([^\n]+\)\s+\.\.\.\s+ok$',text,re.M))==1,'Missing exact target test: '+name)
 require(len(re.findall(r'^Ran 3 tests in ',text,re.M))==1 and text.rstrip().endswith('OK'),'Target test failed or skipped')
 source=(directory/'target-exec-residency.c').read_bytes();elf=(directory/'target-exec-residency.elf').read_bytes()
 require(0<len(source)<=1024*1024,'Target source size differs');meta=inspect_elf(elf,2)
 return {'status':'PASS','tests':3,'marker':'mipsel-linux-uclibc/qemu-mipsel','source_sha256':hashlib.sha256(source).hexdigest(),'elf_sha256':meta['sha256'],'log_sha256':hashlib.sha256(log).hexdigest()}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifacts',type=Path,required=True);p.add_argument('--write-report',action='store_true');a=p.parse_args()
 result=inspect(a.artifacts);report=a.artifacts/'target-exec-residency.json'
 if a.write_report:report.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 else:require(json.loads(report.read_text())==result,'Target execution report differs')
 print(json.dumps(result))
if __name__=='__main__':main()
