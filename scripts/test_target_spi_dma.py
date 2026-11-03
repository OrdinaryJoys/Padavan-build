"""Fixed DMA source/record and actual-kernel reference corruption controls."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import struct
import unittest
from unittest.mock import patch
from test_target_spi_queue import elf as small_elf

SPEC=importlib.util.spec_from_file_location('spi_dma_gate',Path(__file__).with_name('check_target_spi_dma.py'))
gate=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(gate)

def elf(names,kind):
    # Keep string and symbol tables disjoint for the expanded linked symbol set.
    data=bytearray(small_elf(names,kind));strings=b'\0'+b''.join(n.encode()+b'\0'for n in names)
    symbols=bytes(16)+bytes(data[4816:4800+16*(len(names)+1)])
    data[5500:5500+len(strings)]=strings;data[6500:6500+len(symbols)]=symbols
    struct.pack_into('<I',data,4216+16,6500);struct.pack_into('<I',data,4256+16,5500)
    return bytes(data)


class SpiDmaTargetTests(unittest.TestCase):
    def rows(self):return [{'case':n,'inputs':copy.deepcopy(o),'observed':copy.deepcopy(gate.EXPECTED[n])} for n,o in gate.CASES]

    def test_ten_bodies_forty_five_cases_and_conserved_mapping_contract(self):
        self.assertEqual((len(gate.FUNCTION_SOURCES),len(gate.CASES)),(10,45))
        self.assertEqual(sum(not o['baseline'] for _,o in gate.CASES),36)
        self.assertEqual(set(gate.BASELINE_FUNCTION_HASHES),set(gate.FUNCTION_SOURCES))
        self.assertEqual(len(gate.SOURCE_PATHS),5)
        for label,options in gate.CASES:
            row=gate.EXPECTED[label];self.assertEqual(len(row),27)
            self.assertEqual({k for k,v in row.items()if type(v)is str},{'case','sequence'})
            self.assertEqual(sum(type(v)is int for v in row.values()),25)
            if not options['baseline']:
                self.assertEqual((row['live_maps'],row['live_allocs'],row['bad_sg'],row['mapped_flag']),(0,0,0,0))
                self.assertEqual(row['maps'],row['unmaps']);self.assertEqual(row['allocs'],row['frees'])

    def test_all_fixed_fields_reject_type_changes_and_missing_extra_reordered_records(self):
        rows=self.rows();gate.validate_records(rows)
        for invalid in ([],rows[:-1],rows+rows[:1],list(reversed(rows))):
            with self.assertRaises(ValueError):gate.validate_records(invalid)
        for i,row in enumerate(rows):
            for key,value in row['observed'].items():
                bad=copy.deepcopy(rows);bad[i]['observed'][key]=bool(value) if type(value)is int else None
                with self.subTest(case=row['case'],key=key),self.assertRaises(ValueError):gate.validate_records(bad)
        bad=copy.deepcopy(rows);bad[0]['inputs']['baseline']=0
        with self.assertRaises(ValueError):gate.validate_records(bad)

    def test_old_failures_are_preserved_and_cannot_be_accepted_as_current(self):
        for selector in ('tx-fail-second','rx-fail-third','eligibility-changes'):
            self.assertGreater(gate.EXPECTED['baseline:'+selector]['live_maps'],0)
            self.assertEqual(gate.EXPECTED['current:'+selector]['live_maps'],0)
        self.assertGreater(gate.EXPECTED['baseline:chained-linear']['bad_sg'],0)
        self.assertEqual(gate.EXPECTED['current:zero-length']['result'],0)
        self.assertEqual(gate.EXPECTED['baseline:zero-length']['result'],-22)

    def test_generator_binds_actual_bodies_literal_baseline_and_inert_fragments(self):
        functions={name:'static int '+name+'(void){return '+str(i)+';}' for i,name in enumerate(gate.FUNCTION_SOURCES)}
        old={name:body.replace('return ','return 100+') for name,body in functions.items()}
        core='#ifdef CONFIG_HAS_DMA\n'+'\n'.join(functions[n]for n,k in gate.FUNCTION_SOURCES.items()if k=='core')+'\n#else /* !CONFIG_HAS_DMA */\n\n#endif /* !CONFIG_HAS_DMA */\n'
        texts={'core':core,'scatterlist':'\n'.join(functions[n]for n,k in gate.FUNCTION_SOURCES.items()if k=='scatterlist'),'sg_header':'header','spi_header':'header'}
        prefix='/* INERT MODEL */\n';tail='\n/* FIXED TAIL */'
        current_names=tuple(o['selector']for _,o in gate.CASES if not o['baseline'])
        old_names=tuple(o['selector']for _,o in gate.CASES if o['baseline'])
        values={'SOURCE_PATHS':gate.HARNESS_SOURCE_PATHS,'BASELINE_COMMIT':gate.BASELINE_COMMIT,
                'BASELINE_HASHES':{n:gate.sha(b.encode())for n,b in old.items()},'BASELINE_FUNCTIONS':old,
                'PREFIX':prefix,'TAIL':tail,'CASE_NAMES':current_names,'BASELINE_CASE_NAMES':old_names,
                'EXPECTED':{n:gate.EXPECTED['current:'+n]for n in current_names},
                'BASELINE_EXPECTED':{n:gate.EXPECTED['baseline:'+n]for n in old_names}}
        fixture='\n'.join(n+'='+repr(v)for n,v in values.items())+'''\ndef generate_source(texts,baseline=False):
 return PREFIX+'\\n\\n'.join(BASELINE_FUNCTIONS.values() if baseline else BODY_VALUES)+TAIL
'''
        fixture='BODY_VALUES='+repr(list(functions.values()))+'\n'+fixture
        inputs={**texts,'harness':fixture}
        with patch.object(gate,'BASELINE_FUNCTION_HASHES',values['BASELINE_HASHES']),patch.object(gate,'MODEL_FRAGMENTS_SHA256',gate.sha((prefix+tail).encode())):
            self.assertEqual(gate.generate_source(inputs,'/tmp/k2p-spi-dma-source-fixture/current-fixture',501)[1],functions)
            self.assertEqual(gate.generate_source(inputs,'/tmp/k2p-spi-dma-source-fixture/baseline-fixture',501,True)[1],old)
            for changed in (fixture.replace('INERT MODEL','CHANGED MODEL'),fixture.replace(gate.BASELINE_COMMIT,'0'*40),fixture.replace("return PREFIX+","return ''+")):
                with self.assertRaises(ValueError):gate.generate_source({**inputs,'harness':changed},'/tmp/k2p-spi-dma-source-fixture/current-fixture',501)
            with self.assertRaises(ValueError):gate.generate_source({**inputs,'core':core+functions['spi_map_buf']},'/tmp/k2p-spi-dma-source-fixture/current-fixture',501)
            for uid in (True,-1,2**32):
                with self.assertRaises(ValueError):gate.generate_source(inputs,'/tmp/k2p-spi-dma-source-fixture/current-fixture',uid)

    def fixture(self,root):
        root=Path(root);inputs={k:'inert '+k for k in gate.SPI_SOURCE_KEYS}
        names=tuple(n for _,group in gate.spi.OBJECTS.values()for n in group)
        linked=elf(names,2);(root/'target-spi-kernel-vmlinux.elf').write_bytes(linked)
        selected={}
        for label,(relative,names)in gate.spi.OBJECTS.items():
            name='target-spi-'+label;data=elf(names,1);command=b'cmd := gcc -c '+Path(relative).with_suffix('.c').name.encode()+b'\n'
            (root/(name+'.o')).write_bytes(data);(root/(name+'.cmd')).write_bytes(command)
            selected[label]={'object_file':name+'.o','ELF':gate.spi.inspect_elf(data,1),
                'required_symbols':list(names),'command_file':name+'.cmd','command_sha256':gate.sha(command)}
        for name,data in [('target-spi-kernel-raw.bin',b'RAW'),('target-spi-kernel-vendor.bin',b'RAW'),('target-spi-vmlinux.cmd',b'link vmlinux')]: (root/name).write_bytes(data)
        exports={f.name:gate.sha(f.read_bytes())for f in root.iterdir()}
        report={'schema_version':1,'status':'PASS','profile':'k2p-4.4','phase':'final-kernel-image-bound',
            'required_cases':[n for n,_ in gate.spi.CASES],
            'checks':[{'case':n,'inputs':o,'observed':gate.spi.EXPECTED[n]}for n,o in gate.spi.CASES],
            'source_sha256':{gate.SPI_SOURCE_KEYS[k]:gate.sha(t.encode())for k,t in inputs.items()},
            'kernel_binding':{'whole_byte_equality':True,'exports':exports,'vmlinux':gate.spi.inspect_elf(linked,2),
                'selected_objects':selected,'image':{'image_sha256':'a'*64},'object_to_link_scope':'fixed scope'}}
        path=root/'target-spi-nor.json';path.write_text(json.dumps(report));return inputs,path,report

    def test_kernel_reference_requires_actual_sg_and_spi_symbols_and_all_exports(self):
        with tempfile.TemporaryDirectory(prefix='dma-kernel-control-')as root:
            inputs,path,_=self.fixture(root);value=gate.kernel_reference(inputs,path)
            self.assertEqual(set(value['required_symbols']),{n for names in gate.KERNEL_SYMBOLS.values()for n in names})
            self.assertEqual(len(value['kernel_exports_sha256']),4+2*len(gate.spi.OBJECTS))

    def test_kernel_reference_rejects_missing_sg_corrupt_command_source_and_wrong_phase(self):
        for fault in ('sg-object','sg-command','source','phase','exports','symbol'):
            with tempfile.TemporaryDirectory(prefix='dma-kernel-reject-')as root:
                inputs,path,report=self.fixture(root);root=Path(root)
                if fault=='sg-object':(root/'target-spi-sg-table.o').write_bytes(b'wrong')
                elif fault=='sg-command':(root/'target-spi-sg-table.cmd').write_bytes(b'wrong')
                elif fault=='source':report['source_sha256']['sg_core']='0'*64
                elif fault=='phase':report['phase']='early-source-only'
                elif fault=='exports':report['kernel_binding']['exports'].pop('target-spi-sg-table.o')
                else:report['kernel_binding']['selected_objects']['sg-table']['required_symbols'].remove('sg_free_table')
                path.write_text(json.dumps(report))
                with self.subTest(fault=fault),self.assertRaises(ValueError):gate.kernel_reference(inputs,path)

    def test_dma_branch_selection_ignores_disabled_duplicate(self):
        body='static int __spi_map_msg(void){return 1;}'
        text='#ifdef CONFIG_HAS_DMA\n'+body+'\n#else /* !CONFIG_HAS_DMA */\nstatic int __spi_map_msg(void){return 0;}\n#endif /* !CONFIG_HAS_DMA */\n'
        self.assertEqual(gate.actual_function({'core':text},'core','__spi_map_msg'),body)

    def test_nonregular_and_alias_inputs_fail_without_blocking(self):
        import os
        with tempfile.TemporaryDirectory(prefix='dma-file-control-')as root:
            root=Path(root);file=root/'data';file.write_bytes(b'DATA');alias=root/'alias';alias.symlink_to(file)
            with self.assertRaises(ValueError):gate.read_regular(alias,64)
            fifo=root/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError):gate.read_regular(fifo,64)


if __name__=='__main__':unittest.main()
