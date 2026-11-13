import copy,hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import check_device_lifetime_execution as gate
class LifetimeExecutionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name)
  raw=b'ELF checked by the independent kernel parser';source=b'complete source fixture'
  self.report={'schema_version':1,'binaries':{},'executions':[]}
  for name,cases in gate.CASES.items():
   stem='target-device-lifetime-exec-'+name;binary=name+'-mips'
   (self.path/(stem+'.elf')).write_bytes(raw);(self.path/(stem+'.c')).write_bytes(source)
   self.report['binaries'][binary]={'name':name,'elf_file':stem+'.elf','source_file':stem+'.c','elf_sha256':gate.sha(raw),'source_sha256':gate.sha(source),'compiler':'/cc/mipsel-linux-uclibc-gcc','compiler_target':'mipsel-linux-uclibc','runner':'/bin/qemu-mipsel','runner_version':'qemu-mipsel version 6.2.0'}
   for case in cases:self.report['executions'].append({'binary':binary,'case':case,'returncode':-6 if name.startswith('peer-negative-')else 0,'stdout':'','stderr':'Assertion failed'if name.startswith('peer-negative-')else ''})
 def check(self):
  (self.path/'target-device-lifetime-execution.json').write_text(json.dumps(self.report));return gate.inspect(self.path)
 def test_all_target_cases_and_real_elf_parser_are_required(self):
  with patch.object(gate,'inspect_elf',return_value={'machine':8})as elf:
   self.assertEqual(self.check()['execution_records'],49);self.assertEqual(elf.call_count,6)
  with self.assertRaises(ValueError):self.check()
 def test_missing_or_duplicate_case_and_wrong_runner_fail(self):
  original=copy.deepcopy(self.report)
  for kind in ('missing','duplicate','runner','target'):
   self.report=copy.deepcopy(original)
   if kind=='missing':self.report['executions'].pop()
   elif kind=='duplicate':self.report['executions'].append(self.report['executions'][0])
   elif kind=='runner':self.report['binaries']['production-mips']['runner']='/bin/true'
   else:self.report['binaries']['production-mips']['compiler_target']='x86_64-linux'
   with self.subTest(kind=kind),patch.object(gate,'inspect_elf',return_value={}),self.assertRaises(ValueError):self.check()
 def test_negative_must_reach_assertion_and_bytes_must_match(self):
  original=copy.deepcopy(self.report)
  for kind in ('exit-only','fake-assert','changed-elf','changed-source'):
   self.report=copy.deepcopy(original)
   if kind=='exit-only':self.report['executions'][-1]['stderr']='runner failed'
   elif kind=='fake-assert':self.report['executions'][-1]['returncode']=1
   elif kind=='changed-elf':self.report['binaries']['production-mips']['elf_sha256']='0'*64
   else:self.report['binaries']['production-mips']['source_sha256']='0'*64
   with self.subTest(kind=kind),patch.object(gate,'inspect_elf',return_value={}),self.assertRaises(ValueError):self.check()
