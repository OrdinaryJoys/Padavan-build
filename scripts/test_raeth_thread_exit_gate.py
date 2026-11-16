import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import check_raeth_thread_exit as gate

class RaethThreadExitGateTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.d=Path(self.tmp.name)
  self.log='RAETH_THREAD_EXIT_TARGET=mipsel-linux-uclibc;RUNNER=qemu-mipsel\n'+''.join(n+' (case) ... ok\n' for n in ('test_actual_open_close_remove_timeout_preserves_owners','test_late_worker_completion_does_not_release_owners','test_open_failure_errno_survives_successful_thread_join','test_returning_from_quarantine_is_detected','test_missing_failure_publication_is_rejected'))+'Ran 5 tests in 1s\n\nOK\n'
  (self.d/'raeth-thread-exit-target-tests.txt').write_text(self.log)
  for n in ('runtime','remove','late'):
   (self.d/('target-raeth-thread-'+n+'.c')).write_text('source');(self.d/('target-raeth-thread-'+n+'.elf')).write_bytes(b'fake')
 def test_exact_log_and_all_fixtures_required(self):
  with patch.object(gate,'inspect_elf',return_value={'sha256':'elf'}):
   self.assertEqual(gate.inspect(self.d)['status'],'PASS')
   for bad in (self.log.replace('... ok','... skipped',1),self.log.replace('Ran 5','Ran 4'),self.log.replace('RAETH_THREAD_EXIT_TARGET','NO_TARGET')):
    (self.d/'raeth-thread-exit-target-tests.txt').write_text(bad)
    with self.assertRaises(ValueError):gate.inspect(self.d)
   (self.d/'raeth-thread-exit-target-tests.txt').write_text(self.log);(self.d/'target-raeth-thread-late.c').write_bytes(b'')
   with self.assertRaises(ValueError):gate.inspect(self.d)
 def test_fake_elf_rejected(self):
  with self.assertRaises((ValueError,AssertionError,IndexError)):gate.inspect(self.d)
if __name__=='__main__':unittest.main()
