import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import check_exec_residency as g
class ExecResidencyGateTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name)
  self.log='EXEC_RESIDENCY_TARGET=mipsel-linux-uclibc;RUNNER=qemu-mipsel\ntest_invalid_segments_and_failure_are_rejected (a.b) ... ok\ntest_valid_segments_and_transient_reads (a.b) ... ok\ntest_missing_or_ignored_segment_lock_controls_are_detected (a.b) ... ok\n\nRan 3 tests in 1.000s\n\nOK\n'
  (self.p/'target-exec-residency.c').write_text('source');(self.p/'target-exec-residency.elf').write_bytes(b'elf')
 def run_gate(self,text):
  (self.p/'exec-residency-target-tests.txt').write_text(text)
  with patch.object(g,'inspect_elf',return_value={'sha256':'a'*64}):return g.inspect(self.p)
 def test_target_execution_and_both_cases_required(self):
  self.assertEqual(self.run_gate(self.log)['tests'],3)
  for old in ('EXEC_RESIDENCY_TARGET=mipsel-linux-uclibc;RUNNER=qemu-mipsel','test_invalid_segments_and_failure_are_rejected','test_valid_segments_and_transient_reads','test_missing_or_ignored_segment_lock_controls_are_detected','Ran 3 tests in','OK'):
   with self.subTest(old=old),self.assertRaises(ValueError):self.run_gate(self.log.replace(old,'missing'))
 def test_elf_architecture_is_checked(self):
  (self.p/'exec-residency-target-tests.txt').write_text(self.log)
  with self.assertRaises(ValueError):g.inspect(self.p)
