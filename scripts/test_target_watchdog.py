import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('watchdog_gate', Path(__file__).with_name('check_target_watchdog.py'))
gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)


def records():
    return [{'case': name, 'exit_code': 0, 'stdout': '', 'stderr': ''} for name in gate.CASE_NAMES]


class WatchdogTargetControls(unittest.TestCase):
    def test_exact_enabled_and_disabled_cases_are_required(self):
        gate.validate_records(records())
        self.assertEqual(len(records()), 11)
        for wrong in (records()[:-1], records() + records()[:1], list(reversed(records()))):
            with self.assertRaises(ValueError): gate.validate_records(wrong)

    def test_signal_boolean_failure_or_unexpected_output_rejected(self):
        for key, value in (('exit_code', -9), ('exit_code', False), ('exit_code', 1),
                           ('stdout', 'fake success'), ('stderr', 'runtime error')):
            with self.subTest(key=key, value=value):
                wrong = records(); wrong[0][key] = value
                with self.assertRaises(ValueError): gate.validate_records(wrong)

    def test_extra_fields_and_wrong_profile_order_rejected(self):
        wrong = records(); wrong[0]['extra'] = True
        with self.assertRaises(ValueError): gate.validate_records(wrong)
        wrong = records(); wrong[-1]['case'] = 'ss-on:timer'
        with self.assertRaises(ValueError): gate.validate_records(wrong)

    def test_generation_only_accepts_c_constants_and_complete_source_set(self):
        with self.assertRaises(ValueError): gate.generate_source({}, True)
        texts = dict.fromkeys(gate.SOURCE_PATHS, '')
        texts['fixture'] = "PRELUDE=__import__('os').getcwd()\nSUFFIX=''\n"
        with self.assertRaises(ValueError): gate.generate_source(texts, True)
        texts['fixture'] = "PRELUDE=''\nPRELUDE=''\nSUFFIX=''\n"
        with self.assertRaises(ValueError): gate.generate_source(texts, True)


if __name__ == '__main__':
    unittest.main()
