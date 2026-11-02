"""Fixed typed collector/source/shipped-reference controls; no target execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('collector_gate', Path(__file__).with_name('check_target_collector.py'))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

class CollectorTargetTests(unittest.TestCase):
    def rows(self):
        return [{'case': name, 'inputs': copy.deepcopy(options), 'observed': copy.deepcopy(gate.EXPECTED[name])}
                for name, options in gate.CASES]

    def test_fixed_cases_order_and_record_schema_are_exact(self):
        rows = self.rows()
        gate.validate_records(rows)
        for bad in ([], rows[:-1], rows + rows[:1], list(reversed(rows))):
            with self.assertRaises(ValueError): gate.validate_records(bad)
        for key, value in (('extra', True), ('observed', {}), ('case', True)):
            bad = copy.deepcopy(rows);bad[0][key] = value
            with self.assertRaises(ValueError): gate.validate_records(bad)

    def test_fixed_typed_observations_reject_all_changed_fields(self):
        rows = self.rows();gate.validate_records(rows)
        for index, row in enumerate(rows):
            for field,value in row['observed'].items():
                bad = copy.deepcopy(rows)
                bad[index]['observed'][field] = bool(value) if type(value) is int else None
                with self.subTest(case=row['case'],field=field),self.assertRaises(ValueError):
                    gate.validate_records(bad)
        for field in rows[0]['inputs']:
            bad=copy.deepcopy(rows);bad[0]['inputs'][field]=None
            with self.assertRaises(ValueError):gate.validate_records(bad)

    def test_function_parser_handles_file_pointer_long_long_comments_and_duplicates(self):
        texts = {
            'open_status': 'FILE *open_status(void) { const char *x="}"; /* } */ return 0; }',
            'clock_ms': 'static long long clock_ms(void) { return 1; }',
            'cleanup': 'static int cleanup(int x) { if (x) { return 0; } return 1; }',
        }
        for name,body in texts.items():
            self.assertEqual(gate.function(body,name),body)
            for changed in ('/* '+body+' */',body+'\n'+body,body[:-1]):
                with self.assertRaises(ValueError):gate.function(changed,name)

    def test_generated_body_baseline_and_production_fragments_bound(self):
        current='static int current_function(void) { return LIMIT; }'
        old='static int old_function(void) { return LIMIT - 1; }'
        fragment='#define LIMIT 2\n'
        harness="""SOURCE_PATHS={'collector':'trunk/collector.c','header':'trunk/header.h'}
BASELINE_COMMIT=OLD_COMMIT
BASELINE_FUNCTIONS={'old_function':OLD_BODY}
BASELINE_FUNCTIONS_SHA256={'old_function':OLD_HASH}
CASES=(('normal',{'case':'normal','result':0}),)
BASELINE_CASES=(('old',{'case':'old','result':1}),)
def production_fragments(texts):return FRAGMENT
def generate_source(texts,fixture_root,owner_uid=0,baseline=False):
 return production_fragments(texts)+'\\n'+(BASELINE_FUNCTIONS['old_function'] if baseline else texts['collector'])
""".replace('OLD_COMMIT',repr(gate.BASELINE_COMMIT)).replace('OLD_BODY',repr(old)).replace('OLD_HASH',repr(gate.sha(old.encode()))).replace('FRAGMENT',repr(fragment))
        cases=(('current:normal',{'baseline':False,'selector':'normal'}),('baseline:old',{'baseline':True,'selector':'old'}))
        expected={'current:normal':{'case':'normal','result':0},'baseline:old':{'case':'old','result':1}}
        inputs={'collector':current,'header':fragment,'harness':harness}
        constants=dict(SOURCE_PATHS={'collector':'trunk/collector.c','header':'trunk/header.h','harness':'tests/harness.py'},
            HARNESS_SOURCE_PATHS={'collector':'trunk/collector.c','header':'trunk/header.h'},
            FUNCTION_SOURCES={'current_function':'collector'},BASELINE_FUNCTION_SOURCES={'old_function':'collector'},
            BASELINE_FUNCTION_HASHES={'old_function':gate.sha(old.encode())},PRODUCTION_FRAGMENT_SHA256=gate.sha(fragment.encode()),
            CASES=cases,EXPECTED=expected)
        with mock.patch.multiple(gate,**constants):
            for baseline in (False,True):
                generated,bodies=gate.generate_source(inputs,'/tmp/inert',501,baseline)
                self.assertIn(old if baseline else current,generated)
                self.assertEqual(set(bodies),{'old_function'}if baseline else{'current_function'})
            for altered in (harness.replace('return LIMIT - 1;','return 6;'),harness.replace(gate.BASELINE_COMMIT,'0'*40),
                            harness.replace('#define LIMIT 2','#define LIMIT 3')):
                with self.assertRaises(ValueError):gate.generate_source(dict(inputs,harness=altered),'/tmp/inert',501,True)
            for uid in (True,-1,2**32):
                with self.assertRaises(ValueError):gate.generate_source(inputs,'/tmp/inert',uid)
            with self.assertRaises(ValueError):gate.generate_source(dict(inputs,collector=current+'\n'+current),'/tmp/inert',501)

    def reference_fixture(self,tmp):
        p=Path(tmp);binary=p/'dnsmasq';data=b'harmless target ELF bytes';binary.write_bytes(data)
        inputs={key:'locked source '+key for key in gate.SOURCE_PATHS}
        target={'path':'usr/sbin/dnsmasq','bytes':len(data),'sha256':gate.sha(data),
                'elf':{'class':32,'byte_order':'little','machine':8,'type':2}}
        source={key:gate.sha(inputs[value].encode())for key,value in gate.DNS_SOURCE_KEYS.items()}
        report={'status':'PASS','target':target,'source_sha256':source}
        path=p/'target-dynamic-dns.json';path.write_text(json.dumps(report))
        return inputs,path,binary,report

    def test_shipped_reference_binds_raw_report_source_target_and_required_cases(self):
        with tempfile.TemporaryDirectory()as tmp:
            inputs,path,binary,report=self.reference_fixture(tmp)
            def validate(actual,digest,sources):
                self.assertEqual(actual,report);self.assertEqual(digest,report['target']['sha256'])
                self.assertEqual(sources,report['source_sha256'])
            with mock.patch.object(gate.dns,'validate_report',side_effect=validate),mock.patch.object(gate.dns,'elf',return_value=report['target']['elf']):
                result=gate.dns_reference(inputs,path,binary)
            self.assertEqual(result['report_sha256'],gate.sha(path.read_bytes()))
            self.assertEqual(result['target'],report['target'])
            self.assertTrue(result['separate_image_proof_required'])
            self.assertEqual(result['required_cases'],list(gate.dns.CASE_NAMES))

    def test_reference_rejects_target_splice_and_uses_full_source_map(self):
        with tempfile.TemporaryDirectory()as tmp:
            inputs,path,binary,report=self.reference_fixture(tmp)
            with mock.patch.object(gate.dns,'validate_report'),mock.patch.object(gate.dns,'elf',return_value=report['target']['elf']):
                binary.write_bytes(b'changed')
                with self.assertRaises(ValueError):gate.dns_reference(inputs,path,binary)
            binary.write_bytes(b'harmless target ELF bytes')
            def validate(actual,digest,sources):
                if actual['source_sha256']!=sources:raise ValueError('source mismatch')
            with mock.patch.object(gate.dns,'validate_report',side_effect=validate),mock.patch.object(gate.dns,'elf',return_value=report['target']['elf']):
                for key in gate.DNS_SOURCE_KEYS.values():
                    with self.assertRaises(ValueError):gate.dns_reference(dict(inputs,**{key:'different source'}),path,binary)

    def test_regular_reader_rejects_alias_hardlink_fifo_limits_and_fifo_replacement(self):
        with tempfile.TemporaryDirectory()as tmp:
            p=Path(tmp);f=p/'file';f.write_bytes(b'123')
            self.assertEqual(gate.read_regular(f,3),b'123')
            (p/'alias').symlink_to(f)
            with self.assertRaises(ValueError):gate.read_regular(p/'alias',3)
            os.link(f,p/'hard')
            with self.assertRaises(ValueError):gate.read_regular(f,3)
            (p/'hard').unlink()
            with self.assertRaises(ValueError):gate.read_regular(f,2)
            os.mkfifo(p/'fifo')
            with self.assertRaises(ValueError):gate.read_regular(p/'fifo',3)
            original=gate.os.open
            def swapped(path,flags,*args,**kwargs):
                self.assertTrue(flags&os.O_NONBLOCK)
                f.unlink();os.mkfifo(f)
                return original(path,flags,*args,**kwargs)
            with mock.patch.object(gate.os,'open',side_effect=swapped),self.assertRaises(ValueError):
                gate.read_regular(f,3)

    def test_preflight_final_options_and_profile_fail_closed(self):
        with tempfile.TemporaryDirectory()as tmp:
            p=Path(tmp);(p/'.config').write_text('CONFIG_LINUXDIR=linux-3.4.x\n')
            for preflight,dns_report,rootfs in ((True,p/'r',None),(False,None,None),(False,p/'r',None)):
                with self.assertRaises(ValueError):gate.check(p,p/'gcc',p/'out',preflight,dns_report,rootfs)
            with self.assertRaises(ValueError):gate.check(p,p/'gcc',p/'out',True)

if __name__=='__main__':unittest.main()
