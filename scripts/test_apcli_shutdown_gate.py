"""The APCLI target gate must fail closed on absent or fake evidence."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import check_apcli_shutdown as gate


class ApCliShutdownGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.log = ('APCLI_SHUTDOWN_TARGET=mipsel-linux-uclibc;RUNNER=qemu-mipsel\n'
                    'test_production_lock_interleavings_and_mutant (case) ... ok\n'
                    'test_production_shutdown_and_mlme_paths_are_wired (case) ... ok\n'
                    'Ran 2 tests in 1.00s\n\nOK\n')
        (self.d / 'apcli-shutdown-target-tests.txt').write_text(self.log)
        (self.d / 'target-apcli-shutdown.c').write_text('fixture source')
        (self.d / 'target-apcli-shutdown.elf').write_bytes(b'fixture')

    def test_valid_and_tampered_receipts(self):
        with patch.object(gate, 'inspect_elf', return_value={'sha256':'elf'}):
            self.assertEqual(gate.inspect(self.d)['status'], 'PASS')
            for bad in (self.log.replace('APCLI_SHUTDOWN_TARGET=', 'NO_TARGET='),
                        self.log.replace('... ok', '... skipped', 1),
                        self.log.replace('Ran 2 tests', 'Ran 1 test'),
                        self.log + 'FAILED\n'):
                (self.d / 'apcli-shutdown-target-tests.txt').write_text(bad)
                with self.assertRaises(ValueError):
                    gate.inspect(self.d)
            (self.d / 'apcli-shutdown-target-tests.txt').write_text(self.log)
            (self.d / 'target-apcli-shutdown.c').write_bytes(b'')
            with self.assertRaises(ValueError):
                gate.inspect(self.d)

    def test_real_elf_validator_rejects_fake_binary(self):
        with self.assertRaises((ValueError, AssertionError, IndexError)):
            gate.inspect(self.d)


if __name__ == '__main__':
    unittest.main()
