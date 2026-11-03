"""Fixed typed, generator-dependency and compiled-resource lifecycle controls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('spi_lifecycle_gate',Path(__file__).with_name('check_target_spi_lifecycle.py'))
gate=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(gate)


def elf(names,kind):
    data=bytearray(16384);data[:7]=b'\x7fELF\x01\x01\x01';start=0x81001000 if kind==2 else 0
    struct.pack_into('<HHIIIIIHHHHHH',data,16,kind,8,1,start,52 if kind==2 else 0,8192,0,52,32 if kind==2 else 0,1 if kind==2 else 0,40,5,1)
    if kind==2:struct.pack_into('<8I',data,52,1,256,start,start,16*len(names),16*len(names),5,4)
    section=b'\0.shstrtab\0.text\0.symtab\0.strtab\0';data[8600:8600+len(section)]=section
    strings=b'\0'+b''.join(name.encode()+b'\0' for name in names);data[9000:9000+len(strings)]=strings
    for offset,name,kind_,flags,address,at,size,link,align,entry in (
        (8232,b'.shstrtab',3,0,0,8600,len(section),0,1,0),
        (8272,b'.text',1,6,start,256,16*len(names),0,4,0),
        (8312,b'.symtab',2,0,0,12000,16*(len(names)+1),4,4,16),
        (8352,b'.strtab',3,0,0,9000,len(strings),0,1,0)):
        struct.pack_into('<10I',data,offset,section.index(name),kind_,flags,address,at,size,link,0,align,entry)
    for index,name in enumerate(names):
        struct.pack_into('<IIIBBH',data,12016+index*16,strings.index(name.encode()),start+index*16,16,18,0,2)
        data[256+index*16:272+index*16]=bytes([index+1])*16
    return bytes(data)


class SPILifecycleTargetTests(unittest.TestCase):
    def rows(self):return [{'case':name,'inputs':copy.deepcopy(options),'observed':copy.deepcopy(gate.EXPECTED[name])}for name,options in gate.CASES]

    def test_frozen_58_typed_cases_27_current_25_baseline_bodies(self):
        gate.validate_contract();gate.validate_records(self.rows())
        self.assertEqual((len(gate.CASES),len(gate.FUNCTION_SOURCES),len(gate.BASELINE_FUNCTION_HASHES)),(58,27,25))
        self.assertEqual(sum(not options['baseline'] for _,options in gate.CASES),29)
        self.assertEqual(set(gate.FUNCTION_SOURCES)-set(gate.BASELINE_FUNCTION_HASHES),{'spi_queue_enter','spi_queue_leave'})
        for row in gate.EXPECTED.values():
            self.assertEqual(len(row),31);self.assertIs(type(row['case']),str)
            self.assertEqual(sum(type(value) is int for value in row.values()),30)

    def test_every_observation_field_and_record_shape_is_strict(self):
        rows=self.rows()
        for bad in ([],rows[:-1],rows+rows[:1],list(reversed(rows))):
            with self.assertRaises(ValueError):gate.validate_records(bad)
        for index,row in enumerate(rows):
            for field,value in row['observed'].items():
                bad=copy.deepcopy(rows);bad[index]['observed'][field]=bool(value) if type(value) is int else None
                with self.subTest(index=index,field=field),self.assertRaises(ValueError):gate.validate_records(bad)
        for key,value in (('baseline',0),('selector',True),('extra',0)):
            bad=copy.deepcopy(rows);bad[0]['inputs'][key]=value
            with self.assertRaises(ValueError):gate.validate_records(bad)

    def generator_fixture(self):
        fields='\tbool\t\t\t\trunning;\n\tbool\t\t\t\tqueue_dead;\n\tunsigned int\t\t\tqueue_users;\n\tunsigned int\t\t\tqueue_callbacks;'
        fragment='#define FIXED_FRAGMENT 1';current='static int current_function(void){return 1;}';old='static int old_function(void){return 0;}'
        cases=(('current:normal',{'baseline':False,'selector':'normal'}),('baseline:old',{'baseline':True,'selector':'old'}))
        expected={'current:normal':{'case':'normal','result':0},'baseline:old':{'case':'old','result':1}}
        dependency='def production_fragments(texts):return '+repr(fragment)+'\ndef generate_source(*args,**kwargs):raise AssertionError("not used")\n'
        fixture='''import spi_queue_harness as queue
SOURCE_PATHS={'source':'trunk/source.c','header':'trunk/header.h'}
CURRENT_CASES=(('normal',{'case':'normal','result':0}),)
BASELINE_CASES=(('old',{'case':'old','result':1}),)
BASELINE_FUNCTIONS={'old_function':OLD_BODY_TOKEN}
BASELINE_HASHES={'old_function':OLD_HASH_TOKEN}
BASELINE_COMMIT=OLD_COMMIT_TOKEN
def generate_source(texts,fixture_root,owner_uid=0,baseline=False):
 return queue.production_fragments(texts)+'\\n'+texts['header']+'\\n'+(BASELINE_FUNCTIONS['old_function'] if baseline else texts['source'])
'''.replace('OLD_BODY_TOKEN',repr(old)).replace('OLD_HASH_TOKEN',repr(gate.sha(old.encode()))).replace('OLD_COMMIT_TOKEN',repr(gate.BASELINE_COMMIT))
        inputs={'source':current,'header':fields,'harness':fixture,'queue_harness':dependency}
        values=dict(SOURCE_PATHS={'source':'trunk/source.c','header':'trunk/header.h','harness':'tests/harness.py','queue_harness':'tests/queue.py'},HARNESS_SOURCE_PATHS={'source':'trunk/source.c','header':'trunk/header.h'},FUNCTION_SOURCES={'current_function':'source'},BASELINE_FUNCTION_HASHES={'old_function':gate.sha(old.encode())},PRODUCTION_FRAGMENT_SHA256=gate.sha(fragment.encode()),OWNERSHIP_FIELDS_SHA256=gate.sha(fields.encode()),CASES=cases,EXPECTED=expected)
        return inputs,values

    def test_generator_binds_bodies_header_fields_baseline_and_exact_dependency(self):
        inputs,values=self.generator_fixture()
        with patch.multiple(gate,**values):
            for profile in (False,True):self.assertTrue(gate.generate_source(inputs,'/tmp/inert',0,profile)[0])
            for uid in (True,-1,2**32):
                with self.assertRaises(ValueError):gate.generate_source(inputs,'/tmp/inert',uid)
            for key,value in (('header',inputs['header'].replace('queue_callbacks','wrong')),
                              ('source',inputs['source']+'\n'+inputs['source']),
                              ('queue_harness',inputs['queue_harness'].replace('FIXED_FRAGMENT 1','FIXED_FRAGMENT 2')),
                              ('harness',inputs['harness'].replace(gate.BASELINE_COMMIT,'0'*40))):
                with self.subTest(key=key),self.assertRaises(ValueError):gate.generate_source({**inputs,key:value},'/tmp/inert',0)

    def test_poisoned_import_cache_cannot_replace_checked_queue_dependency(self):
        inputs,values=self.generator_fixture();poison=types.ModuleType('spi_queue_harness')
        poison.production_fragments=lambda *args:(_ for _ in ()).throw(AssertionError('cached poison ran'))
        previous=sys.modules.get('spi_queue_harness');sys.modules['spi_queue_harness']=poison
        try:
            with patch.multiple(gate,**values):gate.generate_source(inputs,'/tmp/inert',0)
            self.assertIs(sys.modules['spi_queue_harness'],poison)
        finally:
            if previous is None:sys.modules.pop('spi_queue_harness',None)
            else:sys.modules['spi_queue_harness']=previous

    def kernel_fixture(self,directory):
        p=Path(directory);inputs={key:'inert locked '+key for key in gate.SPI_SOURCE_KEYS}
        names=[name for members in gate.KERNEL_SYMBOLS.values()for name in members]
        linked_data=elf(names,2);(p/'target-spi-kernel-vmlinux.elf').write_bytes(linked_data);linked=gate.spi.inspect_elf(linked_data,2);selected={}
        for label in gate.spi.OBJECTS:
            names=list(gate.KERNEL_SYMBOLS.get(label,('unrelated',)));data=elf(names,1);obj='target-spi-'+label+'.o';cmd='target-spi-'+label+'.cmd'
            (p/obj).write_bytes(data);(p/cmd).write_bytes(('cmd := inert '+Path(gate.spi.OBJECTS[label][0]).with_suffix('.c').as_posix()+'\n').encode())
            selected[label]={'object_file':obj,'ELF':gate.spi.inspect_elf(data,1),'required_symbols':names,'command_file':cmd,'command_sha256':gate.sha((p/cmd).read_bytes())}
        for name in ('target-spi-kernel-raw.bin','target-spi-kernel-vendor.bin','target-spi-vmlinux.cmd'):(p/name).write_bytes(b'inert sidecar\n')
        report={'schema_version':1,'status':'PASS','profile':'k2p-4.4','phase':'final-kernel-image-bound','required_cases':[name for name,_ in gate.spi.CASES],
                'checks':[{'case':name,'inputs':options,'observed':gate.spi.EXPECTED[name]}for name,options in gate.spi.CASES],
                'source_sha256':{gate.SPI_SOURCE_KEYS[key]:gate.sha(value.encode())for key,value in inputs.items()},
                'kernel_binding':{'whole_byte_equality':True,'exports':{f.name:gate.sha(f.read_bytes())for f in p.iterdir()},'vmlinux':linked,'selected_objects':selected,'image':{'image_sha256':'1'*64},'object_to_link_scope':'clean locked build attestation'}}
        path=p/'target-spi-nor.json';path.write_text(json.dumps(report));return inputs,report,path

    def test_compact_reference_binds_actual_api_controller_and_driver_core(self):
        with tempfile.TemporaryDirectory() as temp:
            inputs,report,path=self.kernel_fixture(temp);result=gate.kernel_reference(inputs,path)
            self.assertEqual(set(result['required_symbols']),{name for names in gate.KERNEL_SYMBOLS.values()for name in names})
            self.assertEqual(len(result['kernel_exports_sha256']),20)
            self.assertTrue(result['whole_kernel_image_equality'])

    def test_kernel_reference_rejects_outer_source_missing_export_or_symbol_splice(self):
        with tempfile.TemporaryDirectory() as temp:
            inputs,report,path=self.kernel_fixture(temp)
            for key in gate.SPI_SOURCE_KEYS:
                bad=copy.deepcopy(report);bad['source_sha256'][gate.SPI_SOURCE_KEYS[key]]='0'*64;path.write_text(json.dumps(bad))
                with self.subTest(key=key),self.assertRaises(ValueError):gate.kernel_reference(inputs,path)
            bad=copy.deepcopy(report);bad['kernel_binding']['exports'].pop('target-spi-driver-core.o');path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)
            bad=copy.deepcopy(report);bad['kernel_binding']['selected_objects']['driver-core']['required_symbols']=[];path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)

    def test_kernel_reference_rejects_resealed_wrong_object_and_command_source(self):
        with tempfile.TemporaryDirectory() as temp:
            inputs,report,path=self.kernel_fixture(temp);p=Path(temp)
            wrong=elf(['wrong_driver_entry'],1);(p/'target-spi-driver-core.o').write_bytes(wrong)
            bad=copy.deepcopy(report);bad['kernel_binding']['exports']['target-spi-driver-core.o']=gate.sha(wrong);bad['kernel_binding']['selected_objects']['driver-core']['ELF']=gate.spi.inspect_elf(wrong,1);path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)
            inputs,report,path=self.kernel_fixture(temp);wrong=b'cmd := unrelated.c\n';(p/'target-spi-driver-core.cmd').write_bytes(wrong)
            report['kernel_binding']['exports']['target-spi-driver-core.cmd']=gate.sha(wrong);report['kernel_binding']['selected_objects']['driver-core']['command_sha256']=gate.sha(wrong);path.write_text(json.dumps(report))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)

    def test_artifact_reader_refuses_aliases_fifos_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);(p/'regular').write_bytes(b'ok');(p/'alias').symlink_to(p/'regular');os.mkfifo(p/'fifo')
            self.assertEqual(gate.read_regular(p/'regular',2),b'ok')
            for path,limit in ((p/'alias',2),(p/'fifo',2),(p/'regular',1)):
                with self.assertRaises(ValueError):gate.read_regular(path,limit)


if __name__=='__main__':unittest.main()
