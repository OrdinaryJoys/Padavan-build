"""Fixed data, disabled-oracle and actual backend/kernel binding controls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_target_spi_lifecycle as shared

SPEC=importlib.util.spec_from_file_location('nvram_mtd_gate',Path(__file__).with_name('check_target_nvram_mtd.py'))
gate=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(gate)


class NvramMtdTargetTests(unittest.TestCase):
    def rows(self):return [{'case':name,'inputs':copy.deepcopy(options),'observed':copy.deepcopy(gate.EXPECTED[name])}for name,options in gate.CASES]

    def test_fixed_44_cases_actual_three_old_two_disabled_zero(self):
        gate.validate_contract();gate.validate_records(self.rows())
        self.assertEqual((len(gate.CASES),len(gate.FUNCTION_SOURCES),len(gate.BASELINE_FUNCTION_HASHES)),(44,3,2))
        self.assertEqual([sum(options['mode']==profile for _,options in gate.CASES)for profile in ('current','baseline','disabled')],[32,10,2])
        for row in gate.EXPECTED.values():
            self.assertEqual(len(row),15);self.assertEqual({k for k,v in row.items()if type(v) is str},{'case','trace'})
            self.assertEqual(sum(type(v) is int for v in row.values()),13)

    def test_every_record_effect_and_typed_field_is_fixed(self):
        rows=self.rows()
        for bad in ([],rows[:-1],rows+rows[:1],list(reversed(rows))):
            with self.assertRaises(ValueError):gate.validate_records(bad)
        for index,row in enumerate(rows):
            for field,value in row['observed'].items():
                bad=copy.deepcopy(rows);bad[index]['observed'][field]=bool(value) if type(value) is int else None
                with self.assertRaises(ValueError):gate.validate_records(bad)
        for key,value in (('mode',True),('selector',False),('extra',0)):
            bad=copy.deepcopy(rows);bad[0]['inputs'][key]=value
            with self.assertRaises(ValueError):gate.validate_records(bad)

    def generator_fixture(self):
        current='static int current_function(void){return 1;}'
        old='static int old_function(void){return 0;}'
        stub='static int disabled_function(void){return 0;}'
        selectors={mode:tuple(options['selector']for _,options in gate.CASES if options['mode']==mode)for mode in ('current','baseline','disabled')}
        fixture='''SOURCE_PATHS={'source':'trunk/source.c'}
CASE_NAMES=CURRENT_TOKEN
BASELINE_CASES=BASELINE_TOKEN
DISABLED_CASES=DISABLED_TOKEN
BASELINE_COMMIT=COMMIT_TOKEN
BASELINE_FUNCTIONS={'old_function':OLD_BODY_TOKEN}
BASELINE_FUNCTIONS_SHA256={'old_function':OLD_HASH_TOKEN}
def generate_source(texts,fixture_root=None,owner_uid=0,baseline=False,disabled_oracle=False):
 if baseline:return BASELINE_FUNCTIONS['old_function']
 if disabled_oracle:return STUB_TOKEN
 return texts['source']
'''
        for token,value in (('CURRENT_TOKEN',selectors['current']),('BASELINE_TOKEN',selectors['baseline']),
                            ('DISABLED_TOKEN',selectors['disabled']),('COMMIT_TOKEN',gate.BASELINE_COMMIT),
                            ('OLD_BODY_TOKEN',old),('OLD_HASH_TOKEN',gate.sha(old.encode())),('STUB_TOKEN',stub)):
            fixture=fixture.replace(token,repr(value))
        values=dict(SOURCE_PATHS={'source':'trunk/source.c','harness':'tests/harness.py'},HARNESS_SOURCE_PATHS={'source':'trunk/source.c'},
                    FUNCTION_SOURCES={'current_function':'source'},BASELINE_FUNCTION_HASHES={'old_function':gate.sha(old.encode())},
                    DISABLED_STUBS={'disabled_function':stub},DISABLED_STUB_SHA256=gate.sha(stub.encode()))
        return {'source':current,'harness':fixture},values

    def test_generator_exact_current_baseline_and_disabled_bodies(self):
        inputs,values=self.generator_fixture()
        with patch.multiple(gate,**values):
            for mode in ('current','baseline','disabled'):
                code,bodies=gate.generate_source(inputs,'/tmp/inert',0,mode)
                self.assertTrue(code);self.assertEqual(len(bodies),0 if mode=='disabled'else 1)
            for uid in (True,-1,2**32):
                with self.assertRaises(ValueError):gate.generate_source(inputs,'/tmp/inert',uid)
            with self.assertRaises(ValueError):gate.generate_source(inputs,'/tmp/inert',0,True)
            for key,value in (('source',inputs['source']+'\n'+inputs['source']),
                              ('harness',inputs['harness'].replace(gate.BASELINE_COMMIT,'0'*40))):
                with self.assertRaises(ValueError):gate.generate_source({**inputs,key:value},'/tmp/inert',0)

    def test_disabled_stub_changes_and_actual_execution_relabeling_fail(self):
        inputs,values=self.generator_fixture()
        with patch.multiple(gate,**values):
            bad=inputs['harness'].replace('static int disabled_function(void){return 0;}','static int disabled_function(void){return 1;}')
            with self.assertRaises(ValueError):gate.generate_source({**inputs,'harness':bad},'/tmp/inert',0,'disabled')
            bad=inputs['harness'].replace("if disabled_oracle:return 'static int disabled_function(void){return 0;}'", "if disabled_oracle:return texts['source']")
            with self.assertRaises(ValueError):gate.generate_source({**inputs,'harness':bad},'/tmp/inert',0,'disabled')
        row=copy.deepcopy(self.rows());row[-1]['case']=row[0]['case']
        with self.assertRaises(ValueError):gate.validate_records(row)

    def kernel_fixture(self,temp):
        with patch.object(shared,'gate',gate):return shared.SPILifecycleTargetTests.kernel_fixture(self,temp)

    def test_actual_backend_reference_requires_two_exports_and_all20_sidecars(self):
        with tempfile.TemporaryDirectory() as temp:
            inputs,report,path=self.kernel_fixture(temp);value=gate.kernel_reference(inputs,path)
            self.assertEqual(set(value['required_symbols']),{'mt_mtd_read_nm_wifi','mt_mtd_write_nm_wifi'})
            self.assertEqual(len(value['kernel_exports_sha256']),20)
            self.assertTrue(value['whole_kernel_image_equality'])

    def test_wrong_source_phase_missing_export_or_symbol_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            inputs,report,path=self.kernel_fixture(temp)
            for change in ('source','phase','export','symbol'):
                bad=copy.deepcopy(report)
                if change=='source':bad['source_sha256']['nvram_mtd']='0'*64
                elif change=='phase':bad['phase']='early-source-only'
                elif change=='export':bad['kernel_binding']['exports'].pop('target-spi-wifi-mtd.o')
                else:bad['kernel_binding']['selected_objects']['wifi-mtd']['required_symbols']=[]
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)

    def test_resealed_wrong_implementation_or_source_command_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            inputs,report,path=self.kernel_fixture(temp);root=Path(temp);data=shared.elf(['wrong_backend'],1)
            (root/'target-spi-wifi-mtd.o').write_bytes(data);bad=copy.deepcopy(report)
            bad['kernel_binding']['exports']['target-spi-wifi-mtd.o']=gate.sha(data);bad['kernel_binding']['selected_objects']['wifi-mtd']['ELF']=gate.spi.inspect_elf(data,1);path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)
            inputs,report,path=self.kernel_fixture(temp);data=b'cmd := unrelated.c\n';(root/'target-spi-wifi-mtd.cmd').write_bytes(data)
            report['kernel_binding']['exports']['target-spi-wifi-mtd.cmd']=gate.sha(data);report['kernel_binding']['selected_objects']['wifi-mtd']['command_sha256']=gate.sha(data);path.write_text(json.dumps(report))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)

    def test_bounded_regular_reader_rejects_alias_fifo_and_oversize(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'regular').write_bytes(b'ok');(root/'alias').symlink_to(root/'regular');os.mkfifo(root/'fifo')
            self.assertEqual(gate.read_regular(root/'regular',2),b'ok')
            for file,limit in ((root/'alias',2),(root/'fifo',2),(root/'regular',1)):
                with self.assertRaises(ValueError):gate.read_regular(file,limit)


if __name__=='__main__':unittest.main()
