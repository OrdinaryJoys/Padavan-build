"""NOR shutdown watchdog target gate rejects missing tests, markers and fake MIPS binaries."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import check_nor_shutdown_watch as gate

class NorShutdownWatchGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.d=Path(self.tmp.name)
        self.log=('NOR_SHUTDOWN_WATCH_TARGET=mipsel-linux-uclibc;RUNNER=qemu-mipsel\n'
                  'test_actual_shutdown_with_stalled_and_late_spi (case) ... ok\n'
                  'test_dropping_failure_report_is_detected (case) ... ok\n'
                  'Ran 2 tests in 1.00s\n\nOK\n')
        (self.d/'nor-shutdown-watch-target-tests.txt').write_text(self.log)
        (self.d/'target-nor-shutdown-watch.c').write_text('fixture source')
        (self.d/'target-nor-shutdown-watch.elf').write_bytes(b'fixture')

    def test_valid_and_incomplete_results(self):
        with patch.object(gate,'inspect_elf',return_value={'sha256':'elf'}):
            self.assertEqual(gate.inspect(self.d)['status'],'PASS')
            for bad in (self.log.replace('NOR_SHUTDOWN_WATCH_TARGET=','NO_TARGET='),
                        self.log.replace('... ok','... skipped',1),
                        self.log.replace('Ran 2 tests','Ran 1 test'),self.log+'FAILED\n'):
                (self.d/'nor-shutdown-watch-target-tests.txt').write_text(bad)
                with self.assertRaises(ValueError):gate.inspect(self.d)
            (self.d/'nor-shutdown-watch-target-tests.txt').write_text(self.log)
            (self.d/'target-nor-shutdown-watch.c').write_bytes(b'')
            with self.assertRaises(ValueError):gate.inspect(self.d)

    def test_fake_elf_is_rejected(self):
        with self.assertRaises((ValueError,AssertionError,IndexError)):
            gate.inspect(self.d)

if __name__=='__main__':
    unittest.main()
