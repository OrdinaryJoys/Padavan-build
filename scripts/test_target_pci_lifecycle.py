"""Self-contained PCI gate controls; source clone, target and devices are inert."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check_target_pci_lifecycle as gate
from test_target_wifi_factory import module_elf
from test_target_resident_upgrade import elf as static_elf


DRIVER_DECLARATION = ('static struct pci_driver rt_pci_driver = {\n'
 '    /* A failed DMA stop retains owners, but the driver core still unbinds.\n'
 '     * Keep manual bind/unbind unavailable until that transition is supported.\n'
 '     * Normal module exit and PCI shutdown callbacks remain registered.\n'
 '     */\n'
 '    .driver = {\n'
 '        .suppress_bind_attrs = true,\n'
 '    },\n'
 'name:\n'
 '\tRTMP_DRV_NAME,\n'
 'id_table :\n'
 '\trt_pci_tbl,\n'
 'probe :\n'
 '\trt_pci_probe,\n'
 'shutdown :\n'
 '\trt_pci_shutdown,\n'
 '#if LINUX_VERSION_CODE >= 0x20412\n'
 'remove :\n'
 '\tDEVEXIT_P(rt_pci_remove),\n'
 '#else\n'
 'remove :\n'
 '\t__devexit(rt_pci_remove),\n'
 '#endif\n'
 '\n'
 '#if (KERNEL_VERSION(2, 5, 0) <= LINUX_VERSION_CODE)\n'
 '#ifdef CONFIG_PM\n'
 'suspend :\n'
 '\trt_pci_suspend,\n'
 'resume :\n'
 '\trt_pci_resume,\n'
 '#endif\n'
 '#endif\n'
 '};')
PCI_CORE_SHUTDOWN = '''static void pci_device_shutdown(struct device *dev)
{
\tstruct pci_dev *pci_dev = to_pci_dev(dev);
\tstruct pci_driver *drv = pci_dev->driver;

\tpm_runtime_resume(dev);

\tif (drv && drv->shutdown)
\t\tdrv->shutdown(pci_dev);
\tpci_msi_shutdown(pci_dev);
\tpci_msix_shutdown(pci_dev);

#ifdef CONFIG_KEXEC_CORE
\t/*
\t * If this is a kexec reboot, turn off Bus Master bit on the
\t * device to tell it to not continue to do DMA. Don't touch
\t * devices in D3cold or unknown states.
\t * If it is not a kexec reboot, firmware will hit the PCI
\t * devices with big hammer and stop their DMA any way.
\t */
\tif (kexec_in_progress && (pci_dev->current_state <= PCI_D3hot))
\t\tpci_clear_master(pci_dev);
#endif
}'''


def selection_fixture():
    spec = copy.deepcopy(gate.COMPONENTS['pci'])
    values = {'SOURCE_PATHS': spec['paths'], 'FUNCTION_SOURCES': spec['functions'],
              'BODY_ORDER': tuple(spec['functions']), 'PREFIX': '#define DEVEXIT\n/* inert prefix */\n',
              'SUFFIX': '\n/* CASE_ADMISSION */\n',
              'CASE_NAMES': tuple(o['selector'] for _, o in gate.CASES),
              'EXPECTED_ROWS': {o['selector']: gate.EXPECTED[n] for n, o in gate.CASES}}
    inputs = {key: 'inert source ' + key for key in gate.SOURCE_PATHS}
    inputs['harness'] = '\n'.join(k + '=' + repr(v) for k, v in values.items()) + \
        '\ndef generate_source(*args):\n raise AssertionError("Source generator must not execute")\n'
    bodies = '\n'.join('static VOID ' + ('DEVEXIT ' if name == 'rt_pci_remove' else '') +
                       name + '(struct pci_dev *pci_dev) { (void)pci_dev; }' for name in spec['functions'])
    inputs['pci'] = gate.SOURCE_ABI['modern_exit_macros'] + '\n#endif\n' + bodies + '\n' + DRIVER_DECLARATION + '\n'
    inputs['wifi_config'] = '\n'.join(gate.SOURCE_ABI['enabled_config'] + gate.SOURCE_ABI['disabled_config']) + '\n'
    make = ('DRV_NAME = mt_7615e\nifeq ($(CONFIG_CHIP_MT7615E),y)\n'
            'EXTRA_CFLAGS += -DMT7615 -DRTMP_MAC_PCI -DRTMP_PCI_SUPPORT\nendif\n')
    inputs['wifi_makefile'] = inputs['flags'] = make
    inputs['kernel_makefile'] = 'VERSION = 4\nPATCHLEVEL = 4\nKBUILD_CFLAGS += -fno-strict-aliasing\n'
    inputs['pci_core'] = PCI_CORE_SHUTDOWN
    inputs['pci_header'] = gate.SOURCE_ABI['pci_shutdown_declaration']
    spec['model_data_sha256'] = gate.model_data_hash(values)
    return inputs, spec, values


def compiled_fixture(inputs=None):
    if inputs is None:
        inputs, _, _ = selection_fixture()
    names = ('rt_pci_remove', 'rt_pci_shutdown')
    module = module_elf(names)
    relative = gate.COMPILED_OBJECTS['pci'][0]
    aggregate = gate.BUILT_MODULE.removesuffix('.ko') + '.o'
    artifacts = {
        'target-wifi-built.ko': module, 'target-wifi-shipped.ko': module,
        'target-wifi-module.cmd': ('cmd := ld -r -o ' + gate.BUILT_MODULE + ' ' + aggregate).encode(),
        'target-wifi-link.cmd': ('cmd := ld -r -o ' + aggregate + ' ' + relative).encode(),
        'target-pci-lifecycle-pci.o': module_elf(names),
        'target-pci-lifecycle-pci.cmd': ('cmd := gcc ' + ' '.join(gate.REQUIRED_OBJECT_FLAGS) + ' -c ' +
                                         relative.removesuffix('.o') + '.c -o ' + relative).encode(),
    }
    parent = {
        'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4', 'phase': 'final-module-image-reference-bound',
        'source_sha256': {k: gate.sha(inputs[k].encode()) for k in ('wifi_makefile', 'wifi_config')},
        'required_cases': ['factory' + str(i) for i in range(49)], 'checks': [{} for _ in range(49)],
        'kernel_reference': {'image_sha256': 'a' * 64},
        'module_binding': {
            'status': 'PASS', 'exports': {n: gate.sha(artifacts[n]) for n in gate.PARENT_EXPORTS},
            'built_module': {'ELF': {'sha256': gate.sha(module)}},
            'shipped_module': {'ELF': {'sha256': gate.sha(module)}, 'path': gate.SHIPPED_MODULE},
        },
    }
    return inputs, artifacts, parent


class PciLifecycleGateTests(unittest.TestCase):
    def rows(self):
        return [{'case': n, 'inputs': copy.deepcopy(o), 'observed': copy.deepcopy(gate.EXPECTED[n])}
                for n, o in gate.CASES]

    def test_fixed_nine_current_cases_and_two_complete_configured_functions(self):
        gate.validate_contract()
        gate.validate_records(self.rows())
        self.assertEqual((len(gate.CASES), len(gate.SOURCE_PATHS), len(gate.COMPILED_OBJECTS)), (9, 8, 1))
        self.assertEqual(gate.COMPILED_OBJECTS['pci'][2], ('rt_pci_remove', 'rt_pci_shutdown'))
        self.assertEqual(gate.sha(DRIVER_DECLARATION.encode()), gate.SOURCE_ABI['driver_initializer_sha256'])
        self.assertEqual(gate.sha(PCI_CORE_SHUTDOWN.encode()), gate.SOURCE_ABI['pci_core_shutdown_sha256'])
        self.assertTrue(all('current' == o['variant'] for _, o in gate.CASES))

    def test_every_typed_cell_order_schema_and_inventory_is_required(self):
        rows = self.rows()
        for invalid in ([], rows[:-1], rows + rows[:1], list(reversed(rows))):
            with self.assertRaises(ValueError):
                gate.validate_records(invalid)
        for index, row in enumerate(rows):
            for column in range(len(row['observed'])):
                bad = copy.deepcopy(rows)
                bad[index]['observed'][column] = bool(bad[index]['observed'][column])
                with self.subTest(case=row['case'], column=column), self.assertRaises(ValueError):
                    gate.validate_records(bad)
        for fault in ('extra', 'input', 'case'):
            bad = copy.deepcopy(rows)
            if fault == 'extra':
                bad[0]['unknown'] = 0
            elif fault == 'input':
                bad[0]['inputs']['variant'] = 'legacy'
            else:
                bad[0]['case'] = 'unregistered'
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                gate.validate_records(bad)

    def test_literal_data_never_executes_generator_or_top_level_code(self):
        inputs, _, values = selection_fixture()
        self.assertEqual(gate.literal_data(inputs['harness']), values)
        for suffix in ('\nraise RuntimeError("no")\n', '\nX = dangerous()\n',
                       '\nPREFIX = "duplicate"\n', '\nX = unknown_alias\n',
                       '\nimport subprocess\n', '\nX = {"a": 1, "a": 2}\n'):
            with self.subTest(suffix=suffix), self.assertRaises((ValueError, KeyError)):
                gate.literal_data(inputs['harness'] + suffix)

    def test_independent_renderer_keeps_both_whole_bodies_and_honest_manifest(self):
        inputs, spec, values = selection_fixture()
        with patch.dict(gate.COMPONENTS, {'pci': spec}):
            generated, manifest = gate.generate_component(inputs)
            for name in spec['functions']:
                body = gate.function(inputs['pci'], name)
                self.assertEqual(generated.count(body), 1)
                self.assertEqual(manifest[name]['full_body_sha256'], gate.sha(body.encode()))
                self.assertEqual(manifest[name]['executed_fragment_sha256'], gate.sha(body.encode()))
                self.assertEqual(manifest[name]['execution'], 'whole-function')
            self.assertNotIn('CASE_ADMISSION', generated)
            self.assertIn('!strcmp(name,"shutdown-busy")', generated)
            self.assertEqual(values['BODY_ORDER'], ('rt_pci_remove', 'rt_pci_shutdown'))
            with self.assertRaises(ValueError):
                gate.generate_component(inputs, 'pci', 'legacy')

    def test_renderer_resealed_wrong_selectors_observations_paths_and_missing_bodies_fail(self):
        inputs, spec, values = selection_fixture()
        for fault in ('selector', 'observed', 'paths', 'function', 'model', 'admission'):
            local, current, data = copy.deepcopy(inputs), copy.deepcopy(spec), copy.deepcopy(values)
            if fault == 'selector':
                data['CASE_NAMES'] = data['CASE_NAMES'][:-1]
            elif fault == 'observed':
                data['EXPECTED_ROWS']['shutdown-busy'][0] = True
            elif fault == 'paths':
                data['SOURCE_PATHS']['pci'] = 'wrong.c'
            elif fault == 'function':
                local['pci'] = local['pci'].replace('rt_pci_shutdown(struct', 'absent_shutdown(struct')
            elif fault == 'admission':
                data['SUFFIX'] += 'CASE_ADMISSION'
            else:
                data['PREFIX'] += '/* changed */'
            local['harness'] = '\n'.join(k + '=' + repr(v) for k, v in data.items())
            if fault != 'model':
                current['model_data_sha256'] = gate.model_data_hash(data)
            with patch.dict(gate.COMPONENTS, {'pci': current}), self.subTest(fault=fault), self.assertRaises(ValueError):
                gate.generate_component(local)


    def test_current_initializer_matches_init_policy_and_resealed_unsafe_registration_is_rejected(self):
        import re
        import check_target_init_dma_lifecycle as current
        from test_target_init_dma_lifecycle import native_boundary_fixture
        inputs,_,_=selection_fixture();policy=current.SOURCE_ABI['native_boundaries']['pci'];keys=policy['source_keys']
        native=native_boundary_fixture()
        native_initializer=current.native_declaration(native[keys['pci']],r'^static\s+struct\s+pci_driver\s+rt_pci_driver\s*=\s*\{')
        native[keys['pci']]=native[keys['pci']].replace(native_initializer,DRIVER_DECLARATION,1)
        result=gate.source_selection(inputs);other=current.pci_bind_native_boundary(native)
        self.assertIs(result['manual_bind_unbind_suppressed'],True)
        self.assertEqual(result['driver_initializer_sha256'],other['initializer_sha256'])
        self.assertEqual((other['native_case_count'],other['native_test_methods']),(5,7))
        changes=(('.driver = {\n        .suppress_bind_attrs = true,\n    },','.driver = {},\n    .suppress_bind_attrs = true,'),
                 ('.suppress_bind_attrs = true,',''),
                 ('.suppress_bind_attrs = true,','.suppress_bind_attrs = false,'),
                 ('.driver = {','.another_driver = {'),
                 ('probe :\n\trt_pci_probe,','probe :\n\tabsent_probe,'),
                 ('shutdown :\n\trt_pci_shutdown,','shutdown :\n\tabsent_shutdown,'),
                 ('DEVEXIT_P(rt_pci_remove)','DEVEXIT_P(absent_remove)'),
                 ('.suppress_bind_attrs = true,','/* .suppress_bind_attrs = true, */'),
                 ('.suppress_bind_attrs = true,','".suppress_bind_attrs = true,"'))
        for old,new in changes:
            self.assertIn(old,inputs['pci']);bad=dict(inputs);bad['pci']=bad['pci'].replace(old,new,1)
            declaration=re.findall(r'^static struct pci_driver rt_pci_driver = \{[\s\S]*?^\};',bad['pci'],re.M)[0]
            with self.subTest(mutation=new),patch.dict(gate.SOURCE_ABI,driver_initializer_sha256=gate.sha(declaration.encode())),self.assertRaises(ValueError):gate.source_selection(bad)
            if old.startswith('.suppress')or old.startswith('.driver'):
                bad_native=dict(native);bad_native[keys['pci']]=native[keys['pci']].replace(DRIVER_DECLARATION,declaration,1)
                with self.subTest(init_policy_mutation=new),self.assertRaises(ValueError):current.pci_bind_native_boundary(bad_native)
        bad=dict(inputs);bad['pci']+='\n'+DRIVER_DECLARATION
        with self.assertRaises(ValueError):gate.source_selection(bad)

    def test_actual_config_shutdown_registration_and_ordinary_reboot_boundary_are_bound(self):
        inputs, _, _ = selection_fixture()
        result = gate.source_selection(inputs)
        self.assertIs(result['ordinary_reboot_core_clears_master'], False)
        self.assertIs(result['kexec_config_enabled'], False)
        faults = [('pci', 'shutdown :\n\trt_pci_shutdown,', 'shutdown :\n\tabsent,'),
                  ('pci_core', 'kexec_in_progress && ', ''),
                  ('pci_header', gate.SOURCE_ABI['pci_shutdown_declaration'], ''),
                  ('pci', '#define DEVEXIT\n', '#define DEVEXIT __devexit\n'),
                  ('kernel_makefile', '-fno-strict-aliasing', '-fstrict-aliasing'),
                  ('wifi_makefile', '-DRTMP_MAC_PCI', ''),
                  ('flags', '-DMT7615', '-DOTHER'),
                  ('wifi_config', '# CONFIG_PM is not set', 'CONFIG_PM=y'),
                  ('wifi_config', '# CONFIG_PCI_MSI is not set', 'CONFIG_PCI_MSI=y'),
                  ('wifi_config', '# CONFIG_KEXEC is not set', 'CONFIG_KEXEC=y')]
        for key, old, new in faults:
            local = dict(inputs, **{key: inputs[key].replace(old, new)})
            with self.subTest(key=key, old=old), self.assertRaises(ValueError):
                gate.source_selection(local)
        for flag in gate.FORBIDDEN_OBJECT_FLAGS:
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                gate.source_selection(dict(inputs, wifi_makefile=inputs['wifi_makefile'] + '\n' + flag))

    def test_strict_json_and_file_reader_reject_duplicate_nonfinite_alias_fifo_and_size(self):
        for data in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.assertRaises(ValueError):
                gate.decode_json(data)
        with tempfile.TemporaryDirectory(prefix='pci-safe-reader-') as temporary:
            root = Path(temporary)
            file = root / 'file'; file.write_bytes(b'DATA')
            self.assertEqual(gate.read_regular(file, 4), b'DATA')
            link = root / 'symlink'; link.symlink_to(file)
            with self.assertRaises((OSError, ValueError)):
                gate.read_regular(link, 4)
            hard = root / 'hard'; os.link(file, hard)
            with self.assertRaises(ValueError):
                gate.read_regular(file, 4)
            hard.unlink()
            fifo = root / 'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                gate.read_regular(fifo, 4)
            with self.assertRaises(ValueError):
                gate.read_regular(file, 3)

    def test_actual_object_and_same_image_factory_module_parent_are_bound(self):
        inputs, files, parent = compiled_fixture()
        result = gate.compiled_binding_from_bytes(inputs, json.dumps(parent).encode(), files, gate.spi.inspect_elf)
        self.assertEqual(result['factory_cases'], 49)
        self.assertEqual(set(result['objects']), {'pci'})
        self.assertEqual(result['objects']['pci']['required_symbols'], ['rt_pci_remove', 'rt_pci_shutdown'])
        self.assertEqual(set(result['compiled_exports_sha256']), gate.compiled_export_names())
        self.assertEqual(result['image_sha256'], parent['kernel_reference']['image_sha256'])

    def test_resealed_object_symbol_command_profile_and_parent_faults_are_rejected(self):
        inputs, files, parent = compiled_fixture()
        relative = gate.COMPILED_OBJECTS['pci'][0]
        faults = ('object-symbol', 'module-symbol', 'machine', 'command', 'aggregate', 'missing-export',
                  'parent-image', 'parent-source', 'parent-cases', 'parent-phase', 'parent-type',
                  *gate.FORBIDDEN_OBJECT_FLAGS, *gate.REQUIRED_OBJECT_FLAGS)
        for fault in faults:
            current, p = copy.deepcopy(files), copy.deepcopy(parent)
            if fault == 'object-symbol':
                current['target-pci-lifecycle-pci.o'] = module_elf(('rt_pci_remove',))
            elif fault == 'module-symbol':
                current['target-wifi-built.ko'] = module_elf(('rt_pci_remove',))
                p['module_binding']['built_module']['ELF']['sha256'] = gate.sha(current['target-wifi-built.ko'])
            elif fault == 'machine':
                data = bytearray(current['target-pci-lifecycle-pci.o']); data[18:20] = b'\x03\0'
                current['target-pci-lifecycle-pci.o'] = bytes(data)
            elif fault == 'command':
                current['target-pci-lifecycle-pci.cmd'] = current['target-pci-lifecycle-pci.cmd'].replace(relative.encode(), b'wrong.o')
            elif fault == 'aggregate':
                current['target-wifi-link.cmd'] = current['target-wifi-link.cmd'].replace(relative.encode(), b'wrong.o')
            elif fault == 'missing-export':
                current.pop('target-pci-lifecycle-pci.o')
            elif fault == 'parent-image':
                p['kernel_reference']['image_sha256'] = 'bad'
            elif fault == 'parent-source':
                p['source_sha256']['wifi_config'] = '0' * 64
            elif fault == 'parent-cases':
                p['required_cases'][1] = p['required_cases'][0]
            elif fault == 'parent-phase':
                p['phase'] = 'early-source-only'
            elif fault == 'parent-type':
                p['schema_version'] = True
            elif fault in gate.FORBIDDEN_OBJECT_FLAGS:
                current['target-pci-lifecycle-pci.cmd'] += (' ' + fault).encode()
            else:
                current['target-pci-lifecycle-pci.cmd'] = current['target-pci-lifecycle-pci.cmd'].replace(fault.encode(), b'')
            p['module_binding']['exports'] = {n: gate.sha(current[n]) for n in gate.PARENT_EXPORTS}
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                gate.compiled_binding_from_bytes(inputs, json.dumps(p).encode(), current, gate.spi.inspect_elf)

    def test_preflight_and_final_modes_require_unambiguous_parent(self):
        for preflight, parent in ((True, Path('/parent')), (False, None), (1, None)):
            with self.assertRaises(ValueError):
                gate.check(Path('/absent'), Path('/compiler'), Path('/output'), preflight, parent)

    def pipeline(self, fault=None):
        inputs, spec, _ = selection_fixture()
        _, files, parent = compiled_fixture(inputs)
        binary = bytes(static_elf())

        def run(command, **kwargs):
            if command[0] == '/inert/compiler':
                if fault == 'compile':
                    return SimpleNamespace(returncode=1, stdout='', stderr='inert compile rejected')
                Path(command[-1]).write_bytes(binary)
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            observed = copy.deepcopy(gate.EXPECTED['pci:current:' + command[2]])
            if fault == 'typed':
                observed[0] = bool(observed[0])
            return SimpleNamespace(returncode=1 if fault == 'qemu' else 0,
                                   stdout=json.dumps(observed) + '\n', stderr='')

        with tempfile.TemporaryDirectory(prefix='pci-pipeline-') as temporary:
            root = Path(temporary); checkout = root / 'source'; trunk = checkout / 'trunk'; trunk.mkdir(parents=True)
            (trunk / '.config').write_text('CONFIG_LINUXDIR=linux-4.4.x\nCONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')
            for key, path in gate.SOURCE_PATHS.items():
                file = checkout / path; file.parent.mkdir(parents=True, exist_ok=True); file.write_text(inputs[key])
            parent_file = root / 'target-wifi-factory.json'; parent_file.write_text(json.dumps(parent))
            with patch.dict(gate.COMPONENTS, {'pci': spec}), \
                    patch.object(gate.shutil, 'which', return_value='/inert/qemu'), \
                    patch.object(gate.subprocess, 'run', side_effect=run), \
                    patch.object(gate, 'collect_compiled', return_value=files), contextlib.redirect_stdout(io.StringIO()):
                if fault:
                    with self.assertRaises(ValueError):
                        gate.check(trunk, Path('/inert/compiler'), root / 'reject/target-pci-lifecycle.json', True)
                    self.assertFalse((root / 'reject/target-pci-lifecycle.json').exists())
                    return
                early = gate.check(trunk, Path('/inert/compiler'), root / 'early/target-pci-lifecycle.json', True)
                late = gate.check(trunk, Path('/inert/compiler'), root / 'late/target-pci-lifecycle.json', False, parent_file)
                self.assertEqual(early['phase'], 'early-source-only')
                self.assertIsNone(early['compiled_binding'])
                self.assertEqual(late['phase'], 'final-module-reference-bound')
                self.assertEqual(len(late['checks']), 9)
                self.assertEqual(late['source_contract'], gate.source_selection(inputs))
                names = gate.compiled_export_names() | {'target-pci-lifecycle.json', 'target-pci-lifecycle-pci-current',
                                                        'target-pci-lifecycle-pci-current.c', 'target-pci-lifecycle-pci-current.stdout.json'}
                self.assertEqual({p.name for p in (root / 'late').iterdir()}, names)
                self.assertTrue(all(p.is_file() for p in (root / 'late').iterdir()))

    def test_full_preflight_final_pipeline_exports_without_target_execution(self):
        self.pipeline()

    def test_pipeline_compile_qemu_and_typed_failures_never_emit_pass_report(self):
        for fault in ('compile', 'qemu', 'typed'):
            with self.subTest(fault=fault):
                self.pipeline(fault)
