"""Generator/strict-validator tests; native traces are not a MIPS/flash claim."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('upgrade', Path(__file__).with_name('check_target_upgrade.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)

HEADER = 'int write_storage_to_mtd(void);\n'
# Small synthetic contract for testing the generator itself. The actual target
# proof reads its functions from --trunk, never this fixture or repository tests.
SOURCE = r'''
int write_storage_to_mtd(void)
{
 return doSystem("/sbin/mtd_storage.sh %s", "save");
}
static int flash_firmware(void)
{
 int status;char *services[]={"pppd",NULL};
 storage_save_time(60);
 status=write_storage_to_mtd();
 if(status!=0){logmessage("firmware","first failed");return 0;}
 if(check_if_file_exist(SCRIPT_SHUTDOWN)){
  status=doSystem("%s %d",SCRIPT_SHUTDOWN,0);
  if(status!=0){logmessage("firmware","hook failed");return 0;}
  status=write_storage_to_mtd();
  if(status!=0){logmessage("firmware","second failed");return 0;}
 }
 stop_misc();stop_services(0);
#if defined(USE_STORAGE)
 safe_remove_all_stor_devices(0);
#endif
#if defined(USE_USB_SUPPORT)
 stop_usb_printer_spoolers();
#endif
 stop_igmpproxy(NULL);kill_services(services,6,1);sync();sleep(1);
 if(eval("/tmp/mtd_write","-r","write",FW_IMG_NAME,FW_MTD_NAME)!=0)start_watchdog();
 return 1;
}
'''
EXPECTED_NAMES = (
    'status-success', 'status-system-minus1', 'status-exit1-wait256', 'status-signal15',
    'first-save-exit1', 'first-save-system-minus1', 'first-save-signal15', 'first-save-lock-failure',
    'hook-exit1', 'hook-system-minus1', 'hook-signal15', 'second-save-exit1',
    'second-save-system-minus1', 'second-save-signal15', 'no-hook-one-save-success',
    'hook-two-saves-success', 'firmware-eval-failure-restarts-watchdog')


class TargetUpgradeProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='test-upgrade-proof-')
        cls.root = Path(cls.temp.name)
        cls.binary = cls.compile_source(SOURCE, 'positive')
        cls.records = upgrade.execute_cases([str(cls.binary)])

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def compile_source(cls, source, name):
        generated, _ = upgrade.generate_source(source, HEADER)
        path, binary = cls.root / (name + '.c'), cls.root / name
        path.write_text(generated)
        result = subprocess.run(['cc', '-std=gnu99', '-Wall', '-Wextra', '-Werror',
                                 '-Wno-unused-parameter', '-Wno-unused-function', str(path), '-o', str(binary)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)
        return binary

    def test_native_generator_runs_all_seventeen_contract_cases(self):
        self.assertEqual(upgrade.CASE_NAMES, EXPECTED_NAMES)
        self.assertEqual(tuple(row['case'] for row in self.records), EXPECTED_NAMES)
        upgrade.validate_records(self.records)

    def test_missing_duplicate_or_reordered_case_is_rejected(self):
        variants = [self.records[:-1], [self.records[0], *self.records], list(reversed(self.records))]
        for records in variants:
            with self.subTest(length=len(records)), self.assertRaisesRegex(ValueError, 'case set/order'):
                upgrade.validate_records(records)

    def test_wrong_phase_trace_status_and_types_are_rejected(self):
        for key, value in [('phase', 1), ('trace', ['time', 'save', 'stop_misc', 'log']),
                           ('phase', False), ('save_calls', 1.0)]:
            records = copy.deepcopy(self.records); records[4]['observed'][key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'mismatch'):
                upgrade.validate_records(records)

    def test_broken_raw_status_propagation_is_caught_by_native_control(self):
        wrong = SOURCE.replace('return doSystem("/sbin/mtd_storage.sh %s", "save");',
                               'doSystem("/sbin/mtd_storage.sh %s", "save"); return 0;')
        binary = self.compile_source(wrong, 'wrong-status')
        with self.assertRaisesRegex(ValueError, 'status-system-minus1'):
            upgrade.execute_cases([str(binary)])

    def test_stopping_services_before_gate_is_caught_by_native_control(self):
        wrong = SOURCE.replace('storage_save_time(60);', 'stop_misc();storage_save_time(60);')
        binary = self.compile_source(wrong, 'unsafe-stop')
        with self.assertRaisesRegex(ValueError, 'first-save-exit1'):
            upgrade.execute_cases([str(binary)])

    def test_old_missing_ambiguous_helpers_and_header_fail_closed(self):
        for text, header in [(SOURCE.replace('int write_storage_to_mtd', 'void write_storage_to_mtd'), HEADER),
                             (SOURCE.split('static int flash_firmware')[0], HEADER),
                             (SOURCE + SOURCE, HEADER),
                             (SOURCE, 'void write_storage_to_mtd(void);')]:
            with self.subTest(header=header), self.assertRaises(ValueError):
                upgrade.generate_source(text, header)

    def test_braces_in_comments_and_strings_do_not_truncate_extraction(self):
        function = 'static int flash_firmware(void) { const char *text="}"; /* { */ return 0; }'
        self.assertEqual(upgrade.extract_int_function(function, 'flash_firmware'), function)

    def test_new_unstubbed_effect_callback_is_rejected_before_compilation(self):
        wrong = SOURCE.replace('storage_save_time(60);', 'system("must not run");storage_save_time(60);')
        with self.assertRaisesRegex(ValueError, 'Unstubbed callback.*system'):
            upgrade.generate_source(wrong, HEADER)

    def test_mips_gate_rejects_native_binary_and_wrong_endianness(self):
        with self.assertRaisesRegex(ValueError, 'ELF32 MIPS'):
            upgrade.validate_mips_elf(self.binary.read_bytes())
        header = bytearray(52); header[:7] = b'\x7fELF\x01\x01\x01'; struct.pack_into('<H', header, 18, 8)
        upgrade.validate_mips_elf(header)
        header[5] = 2
        with self.assertRaisesRegex(ValueError, 'ELF32 MIPS'):
            upgrade.validate_mips_elf(header)

    def test_export_preserves_exact_generated_and_compiled_diagnostic_bytes(self):
        generated_data = self.binary.with_suffix('.c').read_bytes()
        binary_data = self.binary.read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'target-upgrade.json'
            upgrade.export_probe(output, generated_data, binary_data)
            for name, expected in [('target-upgrade-probe.c', generated_data),
                                   ('target-upgrade-probe', binary_data)]:
                with self.subTest(name=name):
                    exported = (output.parent / name).read_bytes()
                    self.assertEqual(exported, expected)
                    self.assertEqual(hashlib.sha256(exported).hexdigest(),
                                     hashlib.sha256(expected).hexdigest())
            self.assertEqual((output.parent / 'target-upgrade-probe').stat().st_mode & 0o777, 0o755)
            self.assertFalse(output.exists())

    def test_susu_config_never_silently_uses_new_upgrade_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            trunk = Path(temp)
            (trunk / '.config').write_text('CONFIG_LINUXDIR=linux-3.4.x\nCONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')
            with self.assertRaisesRegex(ValueError, 'no legacy/SUSU fallback'):
                upgrade.check(trunk, Path('/missing-cross-gcc'), trunk, trunk / 'result.json')


if __name__ == '__main__':
    unittest.main()
