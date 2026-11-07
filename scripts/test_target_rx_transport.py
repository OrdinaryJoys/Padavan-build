"""Offline typed, source, actual-object and pipeline controls for the RX gate."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check_target_rx_transport as gate
from test_build_provenance import required_fixture_paths
from test_target_wifi_factory import module_elf as base_module_elf


def module_elf(names):
    # The shared small fixture uses substring lookup. This larger symbol set
    # contains both free_rx_buf and free_rx_buf_1k, so bind complete strings.
    names = tuple(names)
    data = bytearray(base_module_elf(names))
    strings = b'\0' + b''.join(n.encode() + b'\0' for n in names)
    for i, name in enumerate(names):
        struct.pack_into('<I', data, 6500 + 16 * (i + 1), strings.index(b'\0' + name.encode() + b'\0') + 1)
    return bytes(data)


def compiled_fixture():
    inputs = {key: 'inert source ' + key for key in gate.SOURCE_PATHS}
    names = tuple(dict.fromkeys(n for _, _, symbols in gate.COMPILED_OBJECTS.values() for n in symbols))
    built = module_elf(names)
    aggregate = gate.BUILT_MODULE.removesuffix('.ko') + '.o'
    artifacts = {
        'target-wifi-built.ko': built, 'target-wifi-shipped.ko': built,
        'target-wifi-module.cmd': ('cmd := ld -r -o ' + gate.BUILT_MODULE + ' ' + aggregate).encode(),
        'target-wifi-link.cmd': ('cmd := ld -r -o ' + aggregate + ' ' +
                                 ' '.join(v[0] for v in gate.COMPILED_OBJECTS.values())).encode(),
    }
    for label, (relative, _, symbols) in gate.COMPILED_OBJECTS.items():
        stem = 'target-rx-' + label
        artifacts[stem + '.o'] = module_elf(symbols)
        artifacts[stem + '.cmd'] = ('cmd := gcc -fno-strict-aliasing -DMT7615 -DRTMP_PCI_SUPPORT -DUNIFY_FW_CMD -DRX_SCATTER -DRESOURCE_PRE_ALLOC -DCUT_THROUGH -DHDR_TRANS_RX_SUPPORT -c ' +
                                    relative.removesuffix('.o') + '.c -o ' + relative).encode()
    parent = {
        'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4',
        'phase': 'final-module-image-reference-bound',
        'source_sha256': {k: gate.sha(inputs[k].encode()) for k in ('wifi_makefile', 'wifi_config')},
        'required_cases': ['parent' + str(i) for i in range(49)], 'checks': [{} for _ in range(49)],
        'kernel_reference': {'image_sha256': 'a' * 64},
        'module_binding': {
            'status': 'PASS', 'exports': {n: gate.sha(artifacts[n]) for n in gate.PARENT_EXPORTS},
            'built_module': {'ELF': {'sha256': gate.sha(built)}},
            'shipped_module': {'ELF': {'sha256': gate.sha(built)}, 'path': gate.SHIPPED_MODULE},
        },
    }
    return inputs, artifacts, parent


def source_selection_fixture():
    inputs = {key: 'inert source ' + key for key in gate.SOURCE_PATHS}
    inputs['wifi_config'] = 'CONFIG_CHIP_MT7615E=y\nCONFIG_MT7615_AP=m\nCONFIG_HDR_TRANS_RX_SUPPORT=y\n'
    inputs['wifi_makefile'] = ('DRV_NAME = mt_7615e\nifeq ($(CONFIG_CHIP_MT7615E),y)\n'
                              'EXTRA_CFLAGS += -DRTMP_PCI_SUPPORT -DUNIFY_FW_CMD -DRX_SCATTER -DRESOURCE_PRE_ALLOC -DCUT_THROUGH\nendif\n')
    inputs['kernel_makefile'] = 'KBUILD_CFLAGS += -fno-strict-aliasing\n'
    return inputs


def cmdq_model_fixture():
    inputs = {key: 'inert source ' + key for key in gate.SOURCE_PATHS}
    spec = copy.deepcopy(gate.COMPONENTS['cmdq'])
    spec['functions'] = {'toy_cmdq': 'queue'}
    values = {
        'SOURCE_PATHS': spec['paths'], 'FUNCTION_SOURCES': spec['functions'],
        'BODY_ORDER': ('toy_cmdq',), 'PREFIX': '/* literal prefix */\n',
        'SEAMS': '/* inert seams */', 'MAIN': '\n/* inert main */',
        'CASES': tuple((o['selector'], gate.EXPECTED[n]) for n, o in gate.CASES if o['component'] == 'cmdq'),
    }
    spec['model_data_sha256'] = gate.model_data_hash(values)
    local = {'queue': 'NDIS_STATUS toy_cmdq(void) { return 0; }',
             'header': 'typedef struct _CmdQElmt { int inert; } CmdQElmt;\n#define NDIS_OID int\n',
             'os': 'typedef enum _RTMP_TASK_STATUS_ { RUNNING=1 } RTMP_TASK_STATUS;\n#define RTMP_OS_TASK_NAME_LEN 16\n',
             'linux': '#define NDIS_STATUS_SUCCESS 0x00\n#define NDIS_STATUS_FAILURE 0x01\n#define NDIS_STATUS_RESOURCES 0x03\n'}
    inputs.update({spec['source_keys'][key]: text for key, text in local.items()})
    inputs[spec['harness_key']] = '\n'.join(k + '=' + repr(v) for k, v in values.items()) + \
        '\ndef generate_source(*args):\n raise AssertionError("Never execute source generator")\n'
    return inputs, spec, values


def rx_model_fixture():
    inputs = {key: 'inert source ' + key for key in gate.SOURCE_PATHS}
    spec = copy.deepcopy(gate.COMPONENTS['rx'])
    spec['functions'] = {'toy_rx': 'hif'}
    anchors = {'wire_header': ['struct real_event {unsigned length;};'],
               'sizes': ['#define RXD_SIZE 16'],
               'dma_header': ['struct real_descriptor {unsigned posted;};'],
               'rxd_header': ['#define RMAC_INERT 7'],
               'frame_header': ['struct real_frame_control {unsigned short flags;};'],
               'comm_header': ['#define LENGTH_802_11 24']}
    values = {
        'SOURCE_PATHS': spec['paths'], 'FUNCTION_SOURCES': spec['functions'],
        'BODY_ORDER': ('toy_rx',), 'VARIANT_PREFIXES': {'build': '#define CONFIG_WIFI_BUILD_SKB\n', 'legacy': ''},
        'CASE_NAMES': tuple(o['selector'] for _, o in gate.CASES if o['component'] == 'rx' and o['variant'] == 'build'),
        'EXPECTED_ROWS': {variant: {o['selector']: gate.EXPECTED[n] for n, o in gate.CASES
                                    if o['component'] == 'rx' and o['variant'] == variant}
                          for variant in ('build', 'legacy')},
        'SOURCE_ANCHORS': anchors,
        'PREFIX': '/* literal RX prefix */\n' + '\n'.join(f for fragments in anchors.values() for f in fragments),
        'SUFFIX': '\n/* CASE_ADMISSION */\n',
    }
    inputs[spec['source_keys']['hif']] = 'INT toy_rx(void) { return 0; }'
    for key, fragments in anchors.items():
        inputs[spec['source_keys'][key]] = '\n'.join(fragments)
    spec['model_data_sha256'] = gate.model_data_hash(values)
    inputs[spec['harness_key']] = '\n'.join(k + '=' + repr(v) for k, v in values.items()) + \
        '\ndef generate_source(*args):\n raise AssertionError("Never execute RX source generator")\n'
    return inputs, spec, values


def pool_model_fixture():
    inputs, rx_spec, rx_values = rx_model_fixture()
    spec = copy.deepcopy(gate.COMPONENTS['pool'])
    spec['functions'] = {'toy_pool': 'pool'}
    fifo = '#define INC_INDEX(i,n) ((i)=((i)+1)%(n))\n'
    anchors = {'ring_header': [fifo], 'os_header': ['enum MEM_ALLOC_TYPE { A,B,C };']}
    values = {'SOURCE_PATHS': spec['paths'], 'FUNCTION_SOURCES': spec['functions'],
              'BODY_ORDER': ('toy_pool',), 'SOURCE_ANCHORS': anchors,
              'PREFIX': '#define CONFIG_WIFI_BUILD_SKB\n' + rx_values['PREFIX'] + '\n' + fifo,
              'POOL_SEAMS': '/* inert pool seams */', 'SUFFIX': '\n/* CASE_ADMISSION */\n',
              'CASE_NAMES': tuple(o['selector'] for _, o in gate.CASES if o['component'] == 'pool'),
              'EXPECTED_ROWS': {o['selector']: gate.EXPECTED[n] for n, o in gate.CASES if o['component'] == 'pool'}}
    inputs[spec['source_keys']['pool']] = 'VOID *toy_pool(void) { return 0; }'
    for key, fragments in anchors.items():
        # ring_header is the shared descriptor source: retain RX's anchors.
        flat = spec['source_keys'][key]
        inputs[flat] += '\n' + '\n'.join(fragments)
    spec['model_data_sha256'] = gate.model_data_hash(values)
    inputs[spec['harness_key']] = '\n'.join(k + '=' + repr(v) for k, v in values.items()) + \
        '\ndef generate_source(*args):\n raise AssertionError("Never execute pool source generator")\n'
    return inputs, spec, values, rx_spec


def startup_model_fixture():
    inputs = {key: 'inert source ' + key for key in gate.SOURCE_PATHS}
    spec = copy.deepcopy(gate.COMPONENTS['startup'])
    spec['functions'] = {'toy_common': 'pool', 'toy_pre': 'pool'}
    spec['function_regions'] = {'toy_pre': 'prealloc'}
    values = {'SOURCE_PATHS': spec['paths'], 'FUNCTION_SOURCES': spec['functions'],
              'BODY_ORDER': ('toy_common', 'toy_pre'), 'FUNCTION_REGIONS': spec['function_regions'],
              'PREALLOC_START': '#ifdef RESOURCE_PRE_ALLOC\nstatic INT desc_ring_free',
              'PREALLOC_END': '\n#else\n/* UNIQUE_NORMAL_BRANCH */',
              'SOURCE_ANCHORS': {'sizes': ['#define REAL_SIZE 16'],
                                 'flags': ['EXTRA_CFLAGS += -DRESOURCE_PRE_ALLOC']},
              'PREFIX': '#define RESOURCE_PRE_ALLOC\n/* literal startup prefix */',
              'SUFFIX': '\n/* CASE_ADMISSION */\n',
              'CASE_NAMES': tuple(o['selector'] for _, o in gate.CASES if o['component'] == 'startup'),
              'EXPECTED_ROWS': {o['selector']: gate.EXPECTED[n] for n, o in gate.CASES if o['component'] == 'startup'}}
    source = ('INT toy_common(void) { return 0; }\n' + values['PREALLOC_START'] +
              '(void) { return 0; }\nINT toy_pre(void) { return 7; }' + values['PREALLOC_END'] +
              '\nINT toy_pre(void) { return 99; }\n#endif\n')
    inputs[spec['source_keys']['pool']] = source
    for key, fragments in values['SOURCE_ANCHORS'].items():
        inputs[spec['source_keys'][key]] = '\n'.join(fragments)
    spec['model_data_sha256'] = gate.model_data_hash(values)
    inputs[spec['harness_key']] = '\n'.join(k + '=' + repr(v) for k, v in values.items()) + \
        '\ndef generate_source(*args):\n raise AssertionError("Never execute startup source generator")\n'
    return inputs, spec, values


class RxTransportGateTests(unittest.TestCase):
    def rows(self):
        return [{'case': n, 'inputs': copy.deepcopy(o), 'observed': copy.deepcopy(gate.EXPECTED[n])}
                for n, o in gate.CASES]

    def test_complete_current_only_contract(self):
        gate.validate_contract()
        self.assertEqual(set(gate.COMPONENTS), {'cmdq', 'rx', 'pool', 'startup'})
        self.assertEqual(sum(o['component'] == 'cmdq' for _, o in gate.CASES), 16)
        self.assertTrue(all(set(o) == {'component', 'variant', 'selector'} for _, o in gate.CASES))
        self.assertEqual(len(gate.PARENT_EXPORTS), 4)
        self.assertIn('-fno-strict-aliasing', gate.FLAGS)
        self.assertTrue(any('no independent replay' in t.lower() or 'no independent compiler' in t.lower()
                            for t in gate.LIMITS))

    def test_elf_fixture_keeps_prefix_function_names_distinct(self):
        names = ('some_free_rx_buf', 'free_rx_buf_1k', 'free_rx_buf')
        symbols = gate.spi.inspect_elf(module_elf(names), 1)['function_symbols']
        self.assertEqual(set(symbols), set(names))
        self.assertTrue(all(len(symbols[n]) == 1 for n in names))

    def test_compiled_contract_rejects_wrong_source_alias_and_missing_implementation_symbols(self):
        objects = copy.deepcopy(gate.COMPILED_OBJECTS)
        relative, key, names = objects['cmdq']
        for broken in ((relative, 'hif', names), (relative + '.wrong', key, names), (relative, key, ())):
            with patch.dict(gate.COMPILED_OBJECTS, {'cmdq': broken}), self.assertRaises(ValueError):
                gate.validate_contract()

    def test_missing_duplicate_reordered_extra_and_schema_rows_rejected(self):
        rows = self.rows()
        gate.validate_records(rows)
        for bad in ([], rows[:-1], rows + rows[:1], list(reversed(rows))):
            with self.assertRaises(ValueError):
                gate.validate_records(bad)
        for fault in ('input', 'extra', 'case', 'type'):
            bad = copy.deepcopy(rows)
            if fault == 'input':
                bad[0]['inputs']['selector'] = 'unknown'
            elif fault == 'extra':
                bad[0]['extra'] = 1
            elif fault == 'case':
                bad[0]['case'] = False
            else:
                bad = tuple(bad)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                gate.validate_records(bad)

    def test_typed_observation_values_reject_boolean_integer_aliases(self):
        rows = self.rows()
        for i, row in enumerate(rows):
            observed = row['observed']
            if isinstance(observed, list):
                for at, value in enumerate(observed):
                    if type(value) is not int:
                        continue
                    bad = copy.deepcopy(rows)
                    bad[i]['observed'][at] = bool(value)
                    with self.subTest(case=row['case'], field=at), self.assertRaises(ValueError):
                        gate.validate_records(bad)
            elif isinstance(observed, dict):
                for field, value in observed.items():
                    bad = copy.deepcopy(rows)
                    bad[i]['observed'][field] = bool(value) if type(value) is int else None
                    with self.subTest(case=row['case'], field=field), self.assertRaises(ValueError):
                        gate.validate_records(bad)

    def test_literal_reader_rejects_execution_imports_calls_duplicates_and_dynamic_data(self):
        self.assertEqual(gate.literal_data('A="x"\nB=A+"y"\ndef f():\n raise RuntimeError()\n'),
                         {'A': 'x', 'B': 'xy'})
        for data in ('import os\n', 'A=unknown()\n', 'raise RuntimeError()\n',
                     'A=1\nA=2\n', 'A={"x":1,"x":2}\n', 'A=B\n',
                     'if True:\n A=1\n', 'from os import system\n'):
            with self.subTest(data=data), self.assertRaises((ValueError, SyntaxError)):
                gate.literal_data(data)

    def test_cmdq_literal_model_rebuild_uses_complete_source_without_generator_execution(self):
        inputs, spec, _ = cmdq_model_fixture()
        with patch.dict(gate.COMPONENTS, {'cmdq': spec}):
            code, manifest = gate.generate_component(inputs, 'cmdq')
            self.assertEqual(code.count('NDIS_STATUS toy_cmdq(void) { return 0; }'), 1)
            item = manifest['toy_cmdq']
            self.assertEqual(item['execution'], 'whole-function')
            self.assertEqual(item['full_body_sha256'], item['executed_fragment_sha256'])
            changed = dict(inputs)
            changed[spec['harness_key']] = changed[spec['harness_key']].replace('literal prefix', 'changed prefix')
            with self.assertRaises(ValueError):
                gate.generate_component(changed, 'cmdq')
            for key in ('queue', 'header', 'os', 'linux'):
                changed = {**inputs, spec['source_keys'][key]: ''}
                with self.subTest(key=key), self.assertRaises(ValueError):
                    gate.generate_component(changed, 'cmdq')

    def test_function_extractor_is_comment_string_aware_and_rejects_ambiguity(self):
        text = '/* NDIS_STATUS target(void) { bad; } */\nNDIS_STATUS target(void) { const char*x="}"; return 0; }\n'
        body = gate.function(text, 'target')
        self.assertTrue(body.startswith('NDIS_STATUS target('))
        self.assertTrue(body.endswith('return 0; }'))
        for bad in ('', body + '\n' + body, 'NDIS_STATUS target(void) {'):
            with self.assertRaises(ValueError):
                gate.function(bad, 'target')

    def test_rx_both_literal_variants_use_actual_whole_body_and_wire_declarations(self):
        inputs, spec, values = rx_model_fixture()
        with patch.dict(gate.COMPONENTS, {'rx': spec}):
            for variant in ('build', 'legacy'):
                code, manifest = gate.generate_component(inputs, 'rx', variant)
                self.assertEqual(code.count('INT toy_rx(void) { return 0; }'), 1)
                self.assertEqual(manifest['toy_rx']['execution'], 'whole-function')
                self.assertTrue(all(code.count(f) == 1 for fragments in values['SOURCE_ANCHORS'].values() for f in fragments))
            with self.assertRaises(ValueError):
                gate.generate_component(inputs, 'rx', 'unknown')

    def test_rx_resealed_model_wire_constants_headers_selectors_and_expected_rows_rejected(self):
        inputs, spec, values = rx_model_fixture()
        for fault in ('wire-prefix', 'source-header', 'selector', 'observation', 'variant', 'function'):
            local_inputs, local_spec, local_values = copy.deepcopy(inputs), copy.deepcopy(spec), copy.deepcopy(values)
            if fault == 'wire-prefix':
                local_values['PREFIX'] = local_values['PREFIX'].replace('#define RXD_SIZE 16', '#define RXD_SIZE 24')
            elif fault == 'source-header':
                local_inputs[spec['source_keys']['wire_header']] = ''
            elif fault == 'selector':
                local_values['CASE_NAMES'] += ('unknown-case',)
            elif fault == 'observation':
                name = next(iter(local_values['EXPECTED_ROWS']['build']))
                local_values['EXPECTED_ROWS']['build'][name] = None
            elif fault == 'variant':
                local_values['VARIANT_PREFIXES']['unknown'] = ''
            else:
                local_inputs[spec['source_keys']['hif']] = ''
            # Reseal literal metadata to ensure source/semantic guards reject;
            # this is not merely rejection by the enclosing model digest.
            local_spec['model_data_sha256'] = gate.model_data_hash(local_values)
            local_inputs[spec['harness_key']] = '\n'.join(k + '=' + repr(v) for k, v in local_values.items())
            with patch.dict(gate.COMPONENTS, {'rx': local_spec}), self.subTest(fault=fault), self.assertRaises(ValueError):
                gate.generate_component(local_inputs, 'rx', 'build')

    def test_pool_literal_model_retains_whole_body_fifo_and_shared_wire_contract(self):
        inputs, spec, values, rx_spec = pool_model_fixture()
        with patch.dict(gate.COMPONENTS, {'pool': spec, 'rx': rx_spec}):
            code, manifest = gate.generate_component(inputs, 'pool', 'build')
            self.assertEqual(code.count('VOID *toy_pool(void) { return 0; }'), 1)
            self.assertEqual(manifest['toy_pool']['execution'], 'whole-function')
            self.assertIn(values['SOURCE_ANCHORS']['ring_header'][0], code)
            with self.assertRaises(ValueError):
                gate.generate_component(inputs, 'pool', 'legacy')

    def test_pool_resealed_model_fifo_ownership_and_shared_model_substitution_rejected(self):
        inputs, spec, values, rx_spec = pool_model_fixture()
        for fault in ('fifo-source', 'fifo-prefix', 'wire-prefix', 'shared-model', 'observation', 'function'):
            local_inputs, local_spec, local_values = copy.deepcopy(inputs), copy.deepcopy(spec), copy.deepcopy(values)
            if fault == 'fifo-source':
                flat = spec['source_keys']['ring_header']
                local_inputs[flat] = local_inputs[flat].replace(values['SOURCE_ANCHORS']['ring_header'][0], '')
            elif fault == 'fifo-prefix':
                local_values['PREFIX'] = local_values['PREFIX'].replace('((i)+1)%(n)', '((i)+2)%(n)')
            elif fault == 'wire-prefix':
                local_values['PREFIX'] = local_values['PREFIX'].replace('#define RXD_SIZE 16', '#define RXD_SIZE 24')
            elif fault == 'shared-model':
                key = rx_spec['harness_key']
                local_inputs[key] = local_inputs[key].replace('literal RX prefix', 'different RX prefix')
            elif fault == 'observation':
                name = next(iter(local_values['EXPECTED_ROWS']))
                local_values['EXPECTED_ROWS'][name] = None
            else:
                local_inputs[spec['source_keys']['pool']] = ''
            local_spec['model_data_sha256'] = gate.model_data_hash(local_values)
            local_inputs[spec['harness_key']] = '\n'.join(k + '=' + repr(v) for k, v in local_values.items())
            with patch.dict(gate.COMPONENTS, {'pool': local_spec, 'rx': rx_spec}), self.subTest(fault=fault), self.assertRaises(ValueError):
                gate.generate_component(local_inputs, 'pool', 'build')

    def test_startup_selects_complete_configured_body_and_excludes_normal_branch(self):
        inputs, spec, _ = startup_model_fixture()
        with patch.dict(gate.COMPONENTS, {'startup': spec}):
            code, manifest = gate.generate_component(inputs, 'startup', 'prealloc')
            self.assertEqual(code.count('INT toy_pre(void) { return 7; }'), 1)
            self.assertNotIn('return 99;', code)
            self.assertEqual(manifest['toy_pre']['execution'], 'whole-function')
            with self.assertRaises(ValueError):
                gate.generate_component(inputs, 'startup', 'normal')

    def test_startup_resealed_region_flag_anchor_and_observation_faults_rejected(self):
        inputs, spec, values = startup_model_fixture()
        for fault in ('start', 'end-duplicate', 'region-map', 'prefix-flag', 'source-flag', 'observation'):
            local_inputs, local_spec, local_values = copy.deepcopy(inputs), copy.deepcopy(spec), copy.deepcopy(values)
            if fault == 'start':
                key = spec['source_keys']['pool']
                local_inputs[key] = local_inputs[key].replace(values['PREALLOC_START'], '#ifdef OTHER_BRANCH\nstatic INT desc_ring_free')
            elif fault == 'end-duplicate':
                local_inputs[spec['source_keys']['pool']] += values['PREALLOC_END']
            elif fault == 'region-map':
                local_values['FUNCTION_REGIONS'] = {}
            elif fault == 'prefix-flag':
                local_values['PREFIX'] = local_values['PREFIX'].replace('#define RESOURCE_PRE_ALLOC', '')
            elif fault == 'source-flag':
                local_inputs[spec['source_keys']['flags']] = ''
            else:
                name = next(iter(local_values['EXPECTED_ROWS']))
                local_values['EXPECTED_ROWS'][name] = None
            local_spec['model_data_sha256'] = gate.model_data_hash(local_values)
            local_inputs[spec['harness_key']] = '\n'.join(k + '=' + repr(v) for k, v in local_values.items())
            with patch.dict(gate.COMPONENTS, {'startup': local_spec}), self.subTest(fault=fault), self.assertRaises(ValueError):
                gate.generate_component(local_inputs, 'startup', 'prealloc')

    def test_function_extractor_preserves_escaped_newline_strings_and_next_function(self):
        first = 'NDIS_STATUS target(void) { const char*x="open }' + chr(92) + '\n{ still string"; return 0; }'
        second = 'NDIS_STATUS next_target(void) { return 1; }'
        character = "NDIS_STATUS character(void) { int c='" + chr(92) + "\n}'; return 0; }"
        source = first + '\n' + character + '\n' + second
        self.assertEqual(gate.function(source, 'target'), first)
        self.assertEqual(gate.function(source, 'character'), character)
        self.assertEqual(gate.function(source, 'next_target'), second)

    def test_actual_selected_pci_scatter_firmware_and_compiler_flags_required(self):
        inputs = source_selection_fixture()
        gate.source_selection(inputs)
        for key, token in [('wifi_config', 'CONFIG_CHIP_MT7615E=y'),
                           ('wifi_config', 'CONFIG_MT7615_AP=m'),
                           ('wifi_config', 'CONFIG_HDR_TRANS_RX_SUPPORT=y'), ('wifi_makefile', '-DRX_SCATTER'),
                           ('wifi_makefile', '-DUNIFY_FW_CMD'), ('wifi_makefile', '-DRTMP_PCI_SUPPORT'),
                           ('wifi_makefile', '-DRESOURCE_PRE_ALLOC'), ('wifi_makefile', '-DCUT_THROUGH'),
                           ('kernel_makefile', '-fno-strict-aliasing')]:
            with self.subTest(token=token), self.assertRaises(ValueError):
                gate.source_selection({**inputs, key: inputs[key].replace(token, 'changed')})

    def test_same_image_parent_and_actual_compiled_function_binding(self):
        inputs, files, parent = compiled_fixture()
        result = gate.compiled_binding_from_bytes(inputs, json.dumps(parent).encode(), files, gate.spi.inspect_elf)
        self.assertEqual(result['factory_cases'], 49)
        self.assertEqual(len(result['objects']), len(gate.COMPILED_OBJECTS))
        self.assertEqual(len(result['compiled_exports_sha256']), len(gate.COMPILED_OBJECTS) * 2)

    def test_resealed_real_elf_fixtures_missing_symbols_wrong_commands_and_parent_rejected(self):
        inputs, files, parent = compiled_fixture()
        label = next(iter(gate.COMPILED_OBJECTS))
        stem = 'target-rx-' + label
        relative, _, names = gate.COMPILED_OBJECTS[label]
        for fault in ('missing-symbol', 'wrong-machine', 'source-command', 'suffix-command', 'aggregate', 'profile',
                      'no-hdr-profile', 'no-cut-profile', 'no-prealloc-profile',
                      'module-symbol', 'missing-export', 'parent-image', 'parent-module', 'parent-source',
                      'parent-case', 'parent-phase', 'parent-type'):
            a, p = copy.deepcopy(files), copy.deepcopy(parent)
            if fault == 'missing-symbol':
                a[stem + '.o'] = module_elf(('inert_absent_symbol',))
            elif fault == 'wrong-machine':
                b = bytearray(a[stem + '.o']); b[18:20] = b'\x03\0'; a[stem + '.o'] = bytes(b)
            elif fault == 'source-command':
                a[stem + '.cmd'] = b'cmd := gcc -c wrong.c -o wrong.o'
            elif fault == 'suffix-command':
                a[stem + '.cmd'] = a[stem + '.cmd'].replace(relative.encode(), (relative + '.missing').encode())
            elif fault == 'aggregate':
                a['target-wifi-link.cmd'] = a['target-wifi-link.cmd'].replace(relative.encode(), b'wrong.o')
            elif fault == 'profile':
                a[stem + '.cmd'] += b' -URX_SCATTER'
            elif fault in ('no-hdr-profile', 'no-cut-profile', 'no-prealloc-profile'):
                flag = {'no-hdr-profile': b'-DHDR_TRANS_RX_SUPPORT', 'no-cut-profile': b'-DCUT_THROUGH',
                        'no-prealloc-profile': b'-DRESOURCE_PRE_ALLOC'}[fault]
                a[stem + '.cmd'] = a[stem + '.cmd'].replace(flag, b'')
            elif fault == 'module-symbol':
                a['target-wifi-built.ko'] = module_elf(('inert_absent_symbol',))
                p['module_binding']['built_module']['ELF']['sha256'] = gate.sha(a['target-wifi-built.ko'])
            elif fault == 'missing-export':
                a.pop(stem + '.o')
            elif fault == 'parent-image':
                p['kernel_reference']['image_sha256'] = 'bad'
            elif fault == 'parent-module':
                p['module_binding']['shipped_module']['path'] = 'wrong.ko'
            elif fault == 'parent-source':
                p['source_sha256']['wifi_config'] = '0' * 64
            elif fault == 'parent-case':
                p['required_cases'][1] = p['required_cases'][0]
            elif fault == 'parent-phase':
                p['phase'] = 'early-source-only'
            else:
                p['schema_version'] = True
            p['module_binding']['exports'] = {n: gate.sha(a[n]) for n in gate.PARENT_EXPORTS}
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                gate.compiled_binding_from_bytes(inputs, json.dumps(p).encode(), a, gate.spi.inspect_elf)

    def test_strict_json_and_regular_reader_reject_alias_fifo_nonfinite_and_size(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                gate.decode_json(raw)
        with tempfile.TemporaryDirectory(prefix='rx-reader-') as temporary:
            root = Path(temporary)
            file = root / 'file'; file.write_bytes(b'DATA')
            self.assertEqual(gate.read_regular(file, 4), b'DATA')
            alias = root / 'alias'; alias.symlink_to(file)
            with self.assertRaises(ValueError):
                gate.read_regular(alias, 8)
            hard = root / 'hard'; os.link(file, hard)
            with self.assertRaises(ValueError):
                gate.read_regular(file, 8)
            hard.unlink()
            fifo = root / 'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                gate.read_regular(fifo, 8)
            with self.assertRaises(ValueError):
                gate.read_regular(file, 3)

    def test_preflight_final_modes_reject_missing_or_extra_parent(self):
        for preflight, parent in ((True, Path('/parent')), (False, None), (1, None)):
            with self.assertRaises(ValueError):
                gate.check(Path('/absent'), Path('/compiler'), Path('/output'), preflight, parent)

    def test_full_pipeline_preflight_and_final_exports_without_actual_target_execution(self):
        from test_target_resident_upgrade import elf as static_elf
        binary = bytes(static_elf())
        inputs = source_selection_fixture()
        _, artifacts, parent = compiled_fixture()
        parent['source_sha256'] = {k: gate.sha(inputs[k].encode()) for k in ('wifi_makefile', 'wifi_config')}

        def run(command, **kwargs):
            if command[0] == '/inert/compiler':
                Path(command[-1]).write_bytes(binary)
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            component, variant = Path(command[1]).name.removeprefix('target-rx-transport-').rsplit('-', 1)
            return SimpleNamespace(returncode=0, stdout=json.dumps(gate.EXPECTED[component + ':' + variant + ':' + command[2]]) + '\n', stderr='')

        with tempfile.TemporaryDirectory(prefix='rx-pipeline-') as temporary:
            root = Path(temporary); checkout = root / 'source'; trunk = checkout / 'trunk'; trunk.mkdir(parents=True)
            (trunk / '.config').write_text('CONFIG_LINUXDIR=linux-4.4.x\nCONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')
            for key, path in gate.SOURCE_PATHS.items():
                file = checkout / path; file.parent.mkdir(parents=True, exist_ok=True); file.write_text(inputs[key])
            parent_file = root / 'target-wifi-factory.json'; parent_file.write_text(json.dumps(parent))
            with patch.object(gate, 'generate_component', return_value=('/* inert adapter */', {})), \
                    patch.object(gate.shutil, 'which', return_value='/inert/qemu'), \
                    patch.object(gate.subprocess, 'run', side_effect=run), \
                    patch.object(gate, 'collect_compiled', return_value=artifacts):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    early = gate.check(trunk, Path('/inert/compiler'), root / 'early/target-rx-transport.json', True)
                    late = gate.check(trunk, Path('/inert/compiler'), root / 'late/target-rx-transport.json', False, parent_file)
                self.assertEqual(stdout.getvalue(), 'RX transport: ' + str(len(gate.CASES)) + ' inert source/MIPS cases PASS\n' +
                                 'RX transport: ' + str(len(gate.CASES)) + ' inert source/MIPS cases PASS\n')
                self.assertEqual(early['phase'], 'early-source-only')
                self.assertIsNone(early['compiled_binding'])
                self.assertEqual(late['phase'], 'final-module-reference-bound')
                self.assertEqual(len(late['compiled_binding']['objects']), len(gate.COMPILED_OBJECTS))
                for component, spec in gate.COMPONENTS.items():
                    for variant in spec['variants']:
                        stem = 'target-rx-transport-' + component + '-' + variant
                        self.assertTrue((root / 'late' / (stem + '.c')).is_file())
                        self.assertTrue((root / 'late' / stem).is_file())
                        self.assertTrue((root / 'late' / (stem + '.stdout.json')).is_file())
                self.assertTrue(all((root / 'late' / name).is_file() for name in gate.compiled_export_names()))

    def test_build_wiring_requires_source_suites_parent_order_and_every_rx_export(self):
        script = Path(__file__).with_name('build_k2p.sh').read_text()
        self.assertIn('set -euo pipefail', script)
        flat = script.replace(chr(92) + '\n', ' ')
        calls = list(re.finditer(r'(?m)^\s*python3 "\$root/scripts/check_target_rx_transport.py"[^\n]+', flat))
        self.assertEqual(len(calls), 2)
        early, late = calls
        self.assertIn('--preflight', early.group())
        self.assertIn('"$diagnostics/rx-transport-preflight/target-rx-transport.json"', early.group())
        self.assertNotIn('--preflight', late.group())
        self.assertIn('--wifi-report "$diagnostics/target-wifi-factory.json"', late.group())
        self.assertIn('--output "$diagnostics/target-rx-transport.json"', late.group())
        factories = [m for m in re.finditer(r'(?m)^\s*python3 "\$root/scripts/check_target_wifi_factory.py"[^\n]+', flat)
                     if '--preflight' not in m.group()]
        self.assertEqual(len(factories), 1)
        self.assertLess(early.start(), flat.index('fakeroot ./build_firmware_modify'))
        self.assertLess(factories[0].start(), late.start())
        copy_lines = [line.strip() for line in script.splitlines()
                      if line.lstrip().startswith('cp ') and '$diagnostics/target-rx-' in line]
        self.assertEqual(len(copy_lines), 1)
        self.assertLess(late.start(), flat.index(copy_lines[0]))
        for call in calls:
            self.assertNotIn('||', call.group())
            self.assertNotIn(' &', call.group())

        with tempfile.TemporaryDirectory(prefix='rx-build-wiring-') as temporary:
            root = Path(temporary); bin_dir = root / 'bin'; bin_dir.mkdir()
            fake = bin_dir / 'python3'
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$RX_CALLS"\nexit "$RX_EXIT"\n')
            fake.chmod(0o755)
            marker = root / 'following-step'; recorded = root / 'calls'
            for call in calls:
                for code in (0, 23):
                    marker.unlink(missing_ok=True)
                    result = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + call.group() +
                                             '\ntouch "$RX_MARKER"\n'],
                                            env={**os.environ, 'PATH': str(bin_dir) + os.pathsep + os.environ.get('PATH', ''),
                                                 'root': str(root), 'trunk': str(root / 'trunk'),
                                                 'toolchain': str(root / 'toolchain'), 'diagnostics': str(root / 'diagnostics'),
                                                 'RX_CALLS': str(recorded), 'RX_EXIT': str(code), 'RX_MARKER': str(marker)},
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertEqual(marker.exists(), code == 0)
                    self.assertEqual(recorded.read_text().splitlines()[0], str(root / 'scripts/check_target_rx_transport.py'))

            at = script.index('for required_test in test_config_publish')
            start = script.rfind('if [ "$flavor" = "k2p-4.4" ]; then', 0, at)
            block = script[start:script.index('# Keep Linux /tmp rewriting', at)]
            required = tuple(word.rstrip(';') for word in block.split() if word.startswith('test_'))
            new_suites = ('test_cmd_queue', 'test_rx_transport', 'test_rx_pool', 'test_rx_startup', 'test_raeth_shutdown', 'test_raeth_phy_poll', 'test_pci_bind_guard', 'test_wtbl_tlv', 'test_fwd_lifecycle')
            self.assertTrue(set(new_suites) <= set(required))
            tests = root / 'source/tests'; tests.mkdir(parents=True)
            for name in required:
                (tests / (name + '.py')).touch()
            fixture_paths=required_fixture_paths(block)
            for name in fixture_paths:
                path=tests/name;path.parent.mkdir(parents=True,exist_ok=True);path.touch()
            for missing in ('', *new_suites):
                marker.unlink(missing_ok=True)
                if missing:
                    (tests / (missing + '.py')).unlink()
                result = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + block + '\ntouch "$RX_MARKER"\n'],
                                        env={**os.environ, 'root': str(root), 'flavor': 'k2p-4.4', 'RX_MARKER': str(marker)},
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, not bool(missing), result.stderr)
                self.assertEqual(marker.exists(), not bool(missing))
                if missing:
                    (tests / (missing + '.py')).touch()
            for name in fixture_paths:
                marker.unlink(missing_ok=True);path=tests/name;path.unlink()
                result=subprocess.run(['bash','-c','set -euo pipefail\n'+block+'\ntouch "$RX_MARKER"\n'],
                    env={**os.environ,'root':str(root),'flavor':'k2p-4.4','RX_MARKER':str(marker)},
                    capture_output=True,text=True,timeout=10)
                with self.subTest(missing_fixture=name):
                    self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists())
                path.touch()

            diagnostics, dist = root / 'exports', root / 'dist'
            diagnostics.mkdir(); dist.mkdir()
            names = set(gate.compiled_export_names()) | {'target-rx-transport.json'}
            for component, spec in gate.COMPONENTS.items():
                for variant in spec['variants']:
                    stem = 'target-rx-transport-' + component + '-' + variant
                    names.update((stem, stem + '.c', stem + '.stdout.json'))
            for name in names:
                (diagnostics / name).write_text(name + '\n')
            result = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + copy_lines[0]],
                                    env={**os.environ, 'diagnostics': str(diagnostics), 'dist': str(dist)},
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({p.name for p in dist.iterdir()}, names)
            self.assertTrue(all((dist / name).read_bytes() == (diagnostics / name).read_bytes() for name in names))


if __name__ == '__main__':
    unittest.main()
