"""Pure-data controls for the inert source-MIPS transaction proof."""
import copy
import json
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock


_path = Path(__file__).with_name('check_target_upgrade_transaction.py')
gate = types.ModuleType('checked_target_upgrade_transaction_tests')
gate.__file__ = str(_path)
sys.modules[gate.__name__] = gate
exec(compile(_path.read_bytes(), str(_path), 'exec'), gate.__dict__)


def synthetic_elf(dynamic=False, now_tag=30, now_value=8, object_type=2, interpreter=True):
    data = bytearray(512)
    data[:7] = b'\x7fELF\x01\x01\x01'
    count = (3 if interpreter else 2) if dynamic else 1
    struct.pack_into('<HHIIIIIHHHHHH', data, 16,
                     object_type, 8, 1, 0x400100, 52, 0, 0, 52, 32, count, 0, 0, 0)
    struct.pack_into('<IIIIIIII', data, 52,
                     1, 0, 0x400000, 0x400000, len(data), len(data), 5, 4096)
    if dynamic:
        if interpreter:
            value = b'/lib/ld-uClibc.so.0\0'
            data[0x100:0x100 + len(value)] = value
            struct.pack_into('<IIIIIIII', data, 84,
                             3, 0x100, 0x400100, 0, len(value), len(value), 4, 1)
        pool = b'libc.so.0\0'
        data[0x1c0:0x1c0 + len(pool)] = pool
        tags = [(5, 0x4001c0), (10, len(pool)), (1, 0),
                (now_tag, now_value), (0, 0)]
        for index, (tag, value) in enumerate(tags):
            struct.pack_into('<II', data, 0x140 + index * 8, tag, value)
        struct.pack_into('<IIIIIIII', data, 116 if interpreter else 84,
                         2, 0x140, 0x400140, 0, len(tags) * 8, len(tags) * 8, 6, 4)
    return data


def synthetic_inputs():
    """Only parser/generator contract fixtures, not production source or C execution."""
    data = {key:'' for key in gate.SOURCE_PATHS}
    mapping = {**gate.FUNCTION_SOURCES, **gate.FLASH_FUNCTION_SOURCES}
    for name, key in mapping.items():
        body = 'int ' + name + '(void) { return 0; }'
        if name == 'firmware_upgrade_signal_inhibited':
            body = 'int ' + name + '(void) { return firmware_upgrade_pid1_active; }'
        elif name == 'firmware_upgrade_signal_fault':
            body = 'void ' + name + '(void) { firmware_upgrade_pid1_fault = 1; }'
        data[key] += body + '\n'
    data['rc'] = ('static volatile sig_atomic_t firmware_upgrade_pid1_active;\n'
                  'static volatile sig_atomic_t firmware_upgrade_pid1_fault;\n' + data['rc'])
    data['rc_header'] = ('int firmware_upgrade_signal_inhibited(void);\n'
                         'void firmware_upgrade_signal_fault(void);\n')
    data['rc_makefile'] = 'LDFLAGS += -Wl,-z,now\n'
    data['shared_makefile'] = '\t$(LD) -shared -z now -o $@ $(OBJS)\n'
    return data


def synthetic_module(transform=lambda text:text):
    boundaries = ('#define kill fixture_kill\n#define reboot fixture_reboot\n'
                  '#define pause fixture_pause\n#define ioctl fixture_ioctl\n'
                  '#define reboot fake_reboot\n#define mlockall fixture_mlockall\n'
                  '#define sync fake_sync\nstatic int _eval(\nstatic int doSystem(\n')
    def generate(texts, fixture_root, owner_uid=0):
        if type(fixture_root) is not str or type(owner_uid) is not int:
            raise ValueError('Wrong pure fixture API')
        return transform('\n'.join(texts.values()) + boundaries)
    return types.SimpleNamespace(SOURCE_PATHS=gate.HARNESS_SOURCE_PATHS,
        CASES=tuple(gate.COMPONENT_EXPECTED.items()),
        FLASH_CASES=tuple(gate.FLASH_EXPECTED.items()),
        generate_source=generate, generate_flash_source=generate)


def records():
    return [{'case':name, 'inputs':copy.deepcopy(options),
             'observed':copy.deepcopy(gate.EXPECTED[name])} for name,options in gate.CASES]


class UpgradeTransactionDataControls(unittest.TestCase):
    def test_frozen_contract_has_all_component_and_flash_cases(self):
        self.assertEqual(len(gate.CASES), 56)
        self.assertEqual(len(gate.COMPONENT_EXPECTED), 50)
        self.assertEqual(len(gate.FLASH_EXPECTED), 6)
        self.assertEqual(len(gate.HARNESS_SOURCE_PATHS), 13)
        self.assertEqual(len(gate.SOURCE_PATHS), 17)
        self.assertEqual(len(gate.FUNCTION_SOURCES), 37)
        self.assertEqual(len(gate.FLASH_FUNCTION_SOURCES), 24)
        self.assertIn('init_signals', gate.FUNCTION_SOURCES)
        self.assertIn('flash_firmware', gate.FLASH_FUNCTION_SOURCES)
        gate.validate_records(records())

    def test_empty_contract_cannot_be_a_passing_gate(self):
        with mock.patch.object(gate, 'CASES', ()), mock.patch.object(gate, 'EXPECTED', {}):
            with self.assertRaisesRegex(ValueError, 'not been frozen'):
                gate.validate_records([])

    def test_mips_static_identity_and_bounds(self):
        gate.validate_mips_elf(synthetic_elf())
        mutations = [
            lambda b: b.__setitem__(5, 2),
            lambda b: struct.pack_into('<H', b, 18, 62),
            lambda b: struct.pack_into('<H', b, 16, 3),
            lambda b: struct.pack_into('<I', b, 24, 0),
            lambda b: struct.pack_into('<I', b, 76, 4),
            lambda b: struct.pack_into('<I', b, 28, len(b) + 1),
            lambda b: struct.pack_into('<H', b, 44, 129),
            lambda b: struct.pack_into('<I', b, 52, 4),
            lambda b: struct.pack_into('<I', b, 68, len(b) + 1),
        ]
        for mutate in mutations:
            data = synthetic_elf()
            mutate(data)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                gate.validate_mips_elf(data)
        with self.assertRaises(ValueError):
            gate.validate_mips_elf(b'\x7fELF')

    def test_static_adapter_refuses_dynamic_runtime(self):
        with self.assertRaisesRegex(ValueError, 'static'):
            gate.validate_mips_elf(synthetic_elf(dynamic=True))

    def test_missing_duplicate_reordered_and_unknown_case_reject(self):
        original = records()
        for rows in (original[:-1], [original[0], *original], list(reversed(original))):
            with self.assertRaisesRegex(ValueError, 'case'):
                gate.validate_records(rows)
        changed = copy.deepcopy(original)
        changed[0]['case'] = 'not-a-frozen-case'
        with self.assertRaisesRegex(ValueError, 'case'):
            gate.validate_records(changed)

    def test_wrong_schema_input_and_value_types_reject(self):
        for mutate in [
            lambda row: row.update(extra=True),
            lambda row: row['inputs'].update(adapter='other'),
            lambda row: row['inputs'].update(case=False),
            lambda row: row['observed'].update(trace='not-an-array'),
            lambda row: row['observed'].update(case=False),
            lambda row: row['observed'].update(phase=0),
        ]:
            rows = records()
            mutate(rows[0])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                gate.validate_records(rows)

    def test_effect_phase_mask_handoff_and_order_corruption_reject(self):
        corruptions = {
            'phase-active-TERM': lambda row: row['trace'].insert(0, 'PID1-TERM'),
            'phase-active-SEGV': lambda row: row['trace'].remove('fault-quarantine'),
            'init-signal-masks': lambda row: row['trace'].__setitem__(0, 'fatal-masks-valid:0'),
            'upgrade-request-handoff': lambda row: row['trace'].remove('handoff-exclusive:free'),
            'flash-safe-prewrite-return': lambda row: row['trace'].__setitem__(1, 'active:1'),
            'flash-unknown-return': lambda row: row['trace'].__setitem__(6, 'raw-shared-after:1'),
            'flash-verified-reboot-return': lambda row: row['trace'].__setitem__(2, 'marker:0'),
        }
        for name, mutate in corruptions.items():
            rows = records()
            row = next(row for row in rows if row['case'] == name)
            mutate(row['observed'])
            with self.subTest(case=name), self.assertRaises(ValueError):
                gate.validate_records(rows)
        rows = records()
        rows[0]['observed']['trace'] = list(reversed(rows[0]['observed']['trace']))
        with self.assertRaises(ValueError):
            gate.validate_records(rows)

    def test_shipped_rc_requires_actual_binary_bind_now(self):
        for tag, value in [(24, 0), (30, 8), (0x6ffffffb, 1)]:
            with self.subTest(tag=tag):
                record = gate.validate_shipped_rc(synthetic_elf(True, tag, value))
                self.assertTrue(record['BIND_NOW'])
                self.assertEqual(record['PT_INTERP'], '/lib/ld-uClibc.so.0')
                self.assertEqual(record['DT_NEEDED'], ['libc.so.0'])
                self.assertFalse(record['whole_rc_executed'])
        for tag, value in [(30, 0), (0x6ffffffb, 0), (21, 123)]:
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, 'BIND_NOW'):
                gate.validate_shipped_rc(synthetic_elf(True, tag, value))
        with self.assertRaisesRegex(ValueError, 'dynamic'):
            gate.validate_shipped_rc(synthetic_elf())

    def test_shipped_rc_dynamic_string_and_terminator_bounds(self):
        mutations = [
            lambda b: struct.pack_into('<I', b, 0x144, 0xffffffff),
            lambda b: struct.pack_into('<I', b, 0x14c, len(b) + 1),
            lambda b: struct.pack_into('<I', b, 0x154, 10),
            lambda b: b.__setitem__(0x1c9, 65),
            lambda b: struct.pack_into('<I', b, 116 + 16, 32),
            lambda b: b.__setitem__(0x100 + len(b'/lib/ld-uClibc.so.0'), 65),
        ]
        for mutate in mutations:
            data = synthetic_elf(dynamic=True)
            mutate(data)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                gate.validate_shipped_rc(data)

    def test_shipped_libshared_requires_dso_now_without_interpreter(self):
        result = gate.validate_shipped_libshared(
            synthetic_elf(True, object_type=3, interpreter=False))
        self.assertEqual(result['e_type'], 3)
        self.assertIsNone(result['PT_INTERP'])
        self.assertTrue(result['BIND_NOW'])
        for data in (synthetic_elf(True),
                     synthetic_elf(True, object_type=3),
                     synthetic_elf(True, now_value=0, object_type=3, interpreter=False)):
            with self.assertRaises(ValueError):
                gate.validate_shipped_libshared(data)

    def test_exact_actual_bodies_and_required_sources_cannot_be_omitted(self):
        data = synthetic_inputs()
        with mock.patch.object(gate, 'load_checked_harness', return_value=synthetic_module()):
            for adapter in ('components', 'flash'):
                generated, functions = gate.generate_source(data, '/private-fixture-not-accessed',
                                                              owner_uid=123, adapter=adapter)
                for body in functions.values():
                    self.assertEqual(generated.count(body), 1)
            missing = data.copy()
            del missing['init']
            with self.assertRaisesRegex(ValueError, 'source set'):
                gate.generate_source(missing, '/private-fixture-not-accessed')
        query = gate.extract_function(data['rc'], 'firmware_upgrade_signal_inhibited')
        for transform in (lambda text:text.replace(query, '/* omitted */'),
                          lambda text:text.replace('#define kill fixture_kill', '')):
            with mock.patch.object(gate, 'load_checked_harness',
                                   return_value=synthetic_module(transform)):
                with self.assertRaises(ValueError):
                    gate.generate_source(data, '/private-fixture-not-accessed')

    def test_production_signal_globals_and_prototypes_are_not_fixture_assumptions(self):
        original = synthetic_inputs()
        changes = [
            ('rc', 'volatile sig_atomic_t firmware_upgrade_pid1_active',
             'int firmware_upgrade_pid1_active'),
            ('rc', 'static volatile sig_atomic_t firmware_upgrade_pid1_fault',
             'volatile sig_atomic_t firmware_upgrade_pid1_fault'),
            ('rc_header', 'void firmware_upgrade_signal_fault', 'int firmware_upgrade_signal_fault'),
            ('rc_header', 'int firmware_upgrade_signal_inhibited', 'void firmware_upgrade_signal_inhibited'),
            ('rc', 'return firmware_upgrade_pid1_active;', 'return open(\"bad\",0);'),
        ]
        with mock.patch.object(gate, 'load_checked_harness', return_value=synthetic_module()):
            for key, before, after in changes:
                data = original.copy()
                self.assertIn(before, data[key])
                data[key] = data[key].replace(before, after)
                with self.subTest(key=key, before=before), self.assertRaises(ValueError):
                    gate.generate_source(data, '/private-fixture-not-accessed')

    def test_changed_source_contract_and_linker_requests_reject(self):
        original = synthetic_inputs()
        for key in ('rc_makefile', 'shared_makefile'):
            data = original.copy()
            data[key] = ''
            with mock.patch.object(gate, 'load_checked_harness', return_value=synthetic_module()):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    gate.generate_source(data, '/private-fixture-not-accessed')
        changed = synthetic_module()
        changed.CASES = changed.CASES[:-1]
        with mock.patch.object(gate, 'load_checked_harness', return_value=changed):
            with self.assertRaisesRegex(ValueError, 'contract'):
                gate.generate_source(original, '/private-fixture-not-accessed')

    def test_checked_source_loader_ignores_cached_module(self):
        name = '_locked_upgrade_transaction_harness'
        sentinel = types.ModuleType(name)
        sentinel.generate_source = lambda *args: 'CACHED-NOT-SOURCE'
        previous = sys.modules.get(name)
        sys.modules[name] = sentinel
        try:
            module = gate.load_checked_harness(
                "def generate_source(inputs, fixture_root, owner_uid=0):\n"
                "    return 'EXACT-SUPPLIED-SOURCE'\n")
            self.assertEqual(module.generate_source({}, Path('/not-accessed')), 'EXACT-SUPPLIED-SOURCE')
            self.assertIs(sys.modules[name], sentinel)
            with self.assertRaisesRegex(RuntimeError, 'fixture error'):
                gate.load_checked_harness("raise RuntimeError('fixture error')\n")
            self.assertIs(sys.modules[name], sentinel)
        finally:
            if previous is None:
                del sys.modules[name]
            else:
                sys.modules[name] = previous

    def test_exported_diagnostics_keep_exact_bytes_and_binary_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'target-upgrade-transaction.json'
            source = b'/* pure inert C fixture */\n'
            binary = bytes(synthetic_elf())
            gate.export_probe(output, source, binary)
            self.assertEqual((output.parent / 'target-upgrade-transaction-components.c').read_bytes(), source)
            exported = output.parent / 'target-upgrade-transaction-components'
            self.assertEqual(exported.read_bytes(), binary)
            self.assertEqual(exported.stat().st_mode & 0o777, 0o755)
            gate.export_probe(output, source, binary, 'flash')
            self.assertEqual((output.parent / 'target-upgrade-transaction-flash.c').read_bytes(), source)
            self.assertEqual((output.parent / 'target-upgrade-transaction-flash').read_bytes(), binary)


if __name__ == '__main__':
    unittest.main()
