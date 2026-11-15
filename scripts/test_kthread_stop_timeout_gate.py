"""kthread stop timeout target gate rejects missing tests, markers and fake MIPS binaries."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import check_kthread_stop_timeout as gate

class KthreadStopTimeoutGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.d=Path(self.tmp.name)
        self.log=('KTHREAD_STOP_TIMEOUT_TARGET=mipsel-linux-uclibc;RUNNER=qemu-mipsel\n'
                  'test_actual_stop_balances_refs_and_separates_exit_code (case) ... ok\n'
                  'test_timeout_without_reference_is_detected (case) ... ok\n'
                  'Ran 2 tests in 1.00s\n\nOK\n')
        (self.d/'kthread-stop-timeout-target-tests.txt').write_text(self.log)
        (self.d/'target-kthread-stop-timeout.c').write_text('fixture source')
        (self.d/'target-kthread-stop-timeout.elf').write_bytes(b'fixture')

    def test_valid_and_incomplete_results(self):
        with patch.object(gate,'inspect_elf',return_value={'sha256':'elf'}):
            self.assertEqual(gate.inspect(self.d)['status'],'PASS')
            for bad in (self.log.replace('KTHREAD_STOP_TIMEOUT_TARGET=','NO_TARGET='),
                        self.log.replace('... ok','... skipped',1),
                        self.log.replace('Ran 2 tests','Ran 1 test'),self.log+'FAILED\n'):
                (self.d/'kthread-stop-timeout-target-tests.txt').write_text(bad)
                with self.assertRaises(ValueError):gate.inspect(self.d)
            (self.d/'kthread-stop-timeout-target-tests.txt').write_text(self.log)
            (self.d/'target-kthread-stop-timeout.c').write_bytes(b'')
            with self.assertRaises(ValueError):gate.inspect(self.d)

    def test_fake_elf_is_rejected(self):
        with self.assertRaises((ValueError,AssertionError,IndexError)):
            gate.inspect(self.d)

if __name__=='__main__':
    unittest.main()
