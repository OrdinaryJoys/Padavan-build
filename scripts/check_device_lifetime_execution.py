#!/usr/bin/env python3
"""Validate an explicit MIPS/QEMU execution record, not just unittest counts."""
import argparse
import hashlib
import json
from pathlib import Path
from check_target_spi_nor import inspect_elf

CASES = {
 'production': ('probe-wins','remove-wins','overlap','module-refusal','dependency','dependency-removing','driver-race','nonroot','depth','safe-oom','uncertain','ordinary','direct-bind','other-driver','unrelated-release','release','parent-release','delete','unregister','bus-remove','driver-unregister','driver-detach','driver-bus','devres','platform-del','platform-unregister','spi-master','pci-stop','pci-destroy','pci-remove','pci-tree','pci-bus','pci-root-stop','pci-root-remove','pci-driver','pci-bus-direct'),
 'peer-production': ('chain-pins','late-ancestor','deep-rollback','no-readd','exact-depth','failed-probe-owner','pci-probe-blocked','pci-probe-admitted','pci-probe-irq-failure'),
 'disabled': ('disabled',),
 'peer-negative-pin': ('chain-pins',),
 'peer-negative-readd': ('no-readd',),
 'peer-negative-pci': ('pci-probe-blocked',),
}
def require(ok,message):
 if not ok:raise ValueError(message)
def sha(data):return hashlib.sha256(data).hexdigest()
def inspect(directory):
 report=json.loads((directory/'target-device-lifetime-execution.json').read_text())
 require(set(report)=={'schema_version','binaries','executions'} and report['schema_version']==1,'Execution receipt schema differs')
 require(set(report['binaries'])=={name+'-mips'for name in CASES},'MIPS binary inventory differs')
 observed={}
 for binary,record in report['binaries'].items():
  name=record['name'];require(name in CASES and binary==name+'-mips','MIPS binary name differs')
  stem='target-device-lifetime-exec-'+name
  require(record['elf_file']==stem+'.elf'and record['source_file']==stem+'.c','Unsafe execution artifact path')
  data=(directory/record['elf_file']).read_bytes();source=(directory/record['source_file']).read_bytes()
  require(sha(data)==record['elf_sha256']and sha(source)==record['source_sha256'],'Execution artifact digest differs')
  elf=inspect_elf(data,2)
  require(record['compiler_target']=='mipsel-linux-uclibc' and Path(record['compiler']).name=='mipsel-linux-uclibc-gcc','Wrong target compiler')
  require(Path(record['runner']).name=='qemu-mipsel'and record['runner_version'].startswith('qemu-mipsel version '),'Wrong target runner')
  observed[binary]={}
 for row in report['executions']:
  require(set(row)=={'binary','case','returncode','stdout','stderr'},'Execution row schema differs')
  binary=row['binary'];require(binary in observed,'Unknown execution binary')
  name=report['binaries'][binary]['name'];case=row['case']
  require(case in CASES[name]and case not in observed[binary],'Unknown or duplicate target case')
  require(type(row['returncode'])is int and isinstance(row['stdout'],str)and isinstance(row['stderr'],str),'Invalid execution observation')
  if name.startswith('peer-negative-'):
   require(row['returncode']in(-6,134)and 'assert' in row['stderr'].lower(),'Negative control did not reach target assertion')
  else:require(row['returncode']==0 and row['stdout']==''and row['stderr']=='','Target positive case failed')
  observed[binary][case]=row['returncode']
 require(all(set(observed[name+'-mips'])==set(cases)for name,cases in CASES.items()),'Missing target execution cases')
 return {'status':'PASS','positive_scenarios':45,'disabled_profile':1,'target_negative_controls':3,'binaries':6,'execution_records':49,'receipt_sha256':sha((directory/'target-device-lifetime-execution.json').read_bytes())}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifacts',type=Path,required=True);a=p.parse_args();print(json.dumps(inspect(a.artifacts)))
if __name__=='__main__':main()
