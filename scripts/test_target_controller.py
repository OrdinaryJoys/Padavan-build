"""Fixed-contract corruption/source/kernel controls for the controller MIPS gate."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('controller_gate', Path(__file__).with_name('check_target_controller.py'))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

def elf(names, kind):
    """Data-only ELF32LE fixture, with small file-backed named functions."""
    data = bytearray(8192)
    data[:7] = b'\x7fELF\x01\x01\x01'
    start = 0x81001000 if kind == 2 else 0
    struct.pack_into('<HHIIIIIHHHHHH', data, 16, kind, 8, 1, start,
                     52 if kind == 2 else 0, 4096, 0, 52, 32 if kind == 2 else 0,
                     1 if kind == 2 else 0, 40, 5, 1)
    if kind == 2:
        struct.pack_into('<8I', data, 52, 1, 256, start, start, 16 * len(names),
                         16 * len(names), 5, 4)
    section_names = b'\0.shstrtab\0.text\0.symtab\0.strtab\0'
    data[4500:4500 + len(section_names)] = section_names
    strings = b'\0' + b''.join(name.encode() + b'\0' for name in names)
    data[4700:4700 + len(strings)] = strings
    struct.pack_into('<10I', data, 4136, section_names.index(b'.shstrtab'), 3,
                     0, 0, 4500, len(section_names), 0, 0, 1, 0)
    struct.pack_into('<10I', data, 4176, section_names.index(b'.text'), 1,
                     6, start, 256, 16 * len(names), 0, 0, 4, 0)
    struct.pack_into('<10I', data, 4216, section_names.index(b'.symtab'), 2,
                     0, 0, 4800, 16 * (len(names) + 1), 4, 0, 4, 16)
    struct.pack_into('<10I', data, 4256, section_names.index(b'.strtab'), 3,
                     0, 0, 4700, len(strings), 0, 0, 1, 0)
    for i, name in enumerate(names):
        struct.pack_into('<IIIBBH', data, 4816 + i * 16, strings.index(name.encode()),
                         start + i * 16, 16, 18, 0, 2)
        data[256 + i * 16:272 + i * 16] = bytes([i + 1]) * 16
    return bytes(data)


class ControllerTargetTests(unittest.TestCase):
    def rows(self):
        return [{'case': name, 'inputs': copy.deepcopy(inputs),
                 'observed': copy.deepcopy(gate.EXPECTED[name])} for name, inputs in gate.CASES]

    def test_fixed_outcomes_reject_missing_extra_reordered_and_extra_schema(self):
        rows = self.rows()
        gate.validate_records(rows)
        for invalid in ([], rows[:-1], rows + rows[:1], list(reversed(rows))):
            with self.subTest(length=len(invalid)), self.assertRaises(ValueError):
                gate.validate_records(invalid)
        bad = copy.deepcopy(rows);bad[0]['untrusted'] = True
        with self.assertRaises(ValueError):gate.validate_records(bad)

    def test_fixed_typed_outcomes_reject_every_changed_observation(self):
        rows = self.rows();gate.validate_records(rows)
        for index, row in enumerate(rows):
            for field,value in row['observed'].items():
                bad=copy.deepcopy(rows)
                bad[index]['observed'][field] = (not value if type(value) is bool else
                    bool(value) if type(value) is int else None)
                with self.subTest(case=row['case'],field=field),self.assertRaises(ValueError):
                    gate.validate_records(bad)
        for field,value in (('baseline',0),('selector',True)):
            bad=copy.deepcopy(rows);bad[0]['inputs'][field]=value
            with self.assertRaises(ValueError):gate.validate_records(bad)

    def test_body_baseline_and_macro_struct_fragments_cannot_drift(self):
        fragments='#define EXACT_CONST 2\nstruct fixture { int x; };'
        current='static int current_function(void){return EXACT_CONST;}'
        old='static int old_function(void){return EXACT_CONST - 1;}'
        fixture="""SOURCE_PATHS={'source':'trunk/source.c'}
CASES=(('normal',{'case':'normal','result':0}),)
BASELINE_CASES=(('old-negative',{'case':'old-negative','result':1}),)
BASELINE_FUNCTIONS={'old_function':OLD_BODY}
BASELINE_FUNCTIONS_SHA256={'old_function':OLD_HASH}
BASELINE_COMMIT=OLD_COMMIT
def production_fragments(texts):return FRAGMENTS
def generate_source(texts,fixture_root,owner_uid=0,baseline=False):
 return production_fragments(texts)+'\\n'+(BASELINE_FUNCTIONS['old_function'] if baseline else texts['source'])
""".replace('OLD_BODY',repr(old)).replace('OLD_HASH',repr(gate.sha(old.encode()))).replace('OLD_COMMIT',repr(gate.BASELINE_COMMIT)).replace('FRAGMENTS',repr(fragments))
        cases=(('current:normal',{'baseline':False,'selector':'normal'}),
               ('baseline:old-negative',{'baseline':True,'selector':'old-negative'}))
        expected={'current:normal':{'case':'normal','result':0},'baseline:old-negative':{'case':'old-negative','result':1}}
        inputs={'source':current,'harness':fixture}
        with patch.multiple(gate,SOURCE_PATHS={'source':'trunk/source.c','harness':'tests/harness.py'},
            HARNESS_SOURCE_PATHS={'source':'trunk/source.c'},FUNCTION_SOURCES={'current_function':'source'},
            BASELINE_FUNCTION_HASHES={'old_function':gate.sha(old.encode())},
            PRODUCTION_FRAGMENT_SHA256=gate.sha(fragments.encode()),CASES=cases,EXPECTED=expected):
            self.assertEqual(gate.generate_source(inputs,'/tmp/inert',0)[0],fragments+'\n'+current)
            self.assertEqual(gate.generate_source(inputs,'/tmp/inert',0,True)[0],fragments+'\n'+old)
            for replacement in (fixture.replace('return EXACT_CONST - 1;','return 9;'),
                                fixture.replace(gate.BASELINE_COMMIT,'0'*40),
                                fixture.replace('EXACT_CONST 2','EXACT_CONST 3'),
                                fixture.replace("return production_fragments(texts)+'\\n'+", "return ''+")):
                with self.assertRaises(ValueError):gate.generate_source(dict(inputs,harness=replacement),'/tmp/inert',0,True)
            with self.assertRaises(ValueError):gate.generate_source(dict(inputs,source=current+'\n'+current),'/tmp/inert',0)
            for uid in (True,-1,2**32):
                with self.assertRaises(ValueError):gate.generate_source(inputs,'/tmp/inert',uid)

    def kernel_fixture(self,directory):
        p=Path(directory);inputs={'controller':'inert locked controller source'}
        names=[name for members in gate.KERNEL_SYMBOLS.values() for name in members]
        linked_bytes=elf(names,2);(p/'target-spi-kernel-vmlinux.elf').write_bytes(linked_bytes)
        linked=gate.spi.inspect_elf(linked_bytes,2);selected={}
        for label in gate.spi.OBJECTS:
            functions=list(gate.KERNEL_SYMBOLS.get(label,('unrelated',)))
            data=elf(functions,1);object_name='target-spi-'+label+'.o';command_name='target-spi-'+label+'.cmd'
            (p/object_name).write_bytes(data);(p/command_name).write_bytes(('cmd := inert '+Path(gate.spi.OBJECTS[label][0]).with_suffix('.c').as_posix()+'\n').encode())
            selected[label]={'object_file':object_name,'ELF':gate.spi.inspect_elf(data,1),
                'required_symbols':functions,'command_file':command_name,
                'command_sha256':gate.sha((p/command_name).read_bytes())}
        for name in ('target-spi-kernel-raw.bin','target-spi-kernel-vendor.bin','target-spi-vmlinux.cmd'):
            (p/name).write_bytes(b'inert public sidecar\n')
        exports={f.name:gate.sha(f.read_bytes()) for f in p.iterdir()}
        report={'schema_version':1,'status':'PASS','profile':'k2p-4.4','phase':'final-kernel-image-bound',
            'required_cases':[name for name,_ in gate.spi.CASES],
            'checks':[{'case':name,'inputs':options,'observed':gate.spi.EXPECTED[name]} for name,options in gate.spi.CASES],
            'source_sha256':{key:gate.sha(value.encode()) for key,value in inputs.items()},
            'kernel_binding':{'whole_byte_equality':True,'exports':exports,'vmlinux':linked,
                'selected_objects':selected,'image':{'image_sha256':'1'*64},
                'object_to_link_scope':'clean locked build attestation'}}
        path=p/'target-spi-nor.json';path.write_text(json.dumps(report));return inputs,report,path

    def test_compact_reference_binds_controller_and_all_dynamic_kernel_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,report,path=self.kernel_fixture(tmp);result=gate.kernel_reference(inputs,path)
            self.assertTrue(result['whole_kernel_image_equality'])
            self.assertEqual(set(result['required_symbols']),set(gate.KERNEL_SYMBOLS['mt7621']))
            self.assertEqual(len(result['kernel_exports_sha256']),4+2*len(gate.spi.OBJECTS))
            self.assertEqual(result['report_sha256'],gate.sha(path.read_bytes()))

    def test_kernel_reference_rejects_phase_source_export_and_resealed_splices(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,report,path=self.kernel_fixture(tmp)
            for field,value in (('status','FAIL'),('phase','early-source-only'),('schema_version',True)):
                bad=copy.deepcopy(report);bad[field]=value;path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)
            bad=copy.deepcopy(report);bad['source_sha256']['controller']='2'*64;path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)
            bad=copy.deepcopy(report);bad['kernel_binding']['exports']['../outside']='3'*64;path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)
            path.write_text(json.dumps(report));(path.parent/'target-spi-mt7621.cmd').write_bytes(b'changed')
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)
            bad=copy.deepcopy(report);name='target-spi-mt7621.cmd';data=b'resealed command for unrelated.c\n'
            (path.parent/name).write_bytes(data);bad['kernel_binding']['exports'][name]=gate.sha(data)
            bad['kernel_binding']['selected_objects']['mt7621']['command_sha256']=gate.sha(data)
            path.write_text(json.dumps(bad))
            with self.assertRaisesRegex(ValueError,'command/source binding differs'):gate.kernel_reference(inputs,path)

    def test_missing_required_probe_remove_or_transfer_symbol_is_refused_when_resealed(self):
        for removed in gate.KERNEL_SYMBOLS['mt7621']:
            for fault in ('missing','empty'):
                with tempfile.TemporaryDirectory() as tmp:
                    inputs,report,path=self.kernel_fixture(tmp);name='target-spi-mt7621.o'
                    names=[n for n in gate.KERNEL_SYMBOLS['mt7621'] if fault!='missing' or n!=removed]
                    data=bytearray(elf(names,1))
                    if fault=='empty':struct.pack_into('<I',data,4824+16*names.index(removed),0)
                    data=bytes(data);(path.parent/name).write_bytes(data)
                    report['kernel_binding']['exports'][name]=gate.sha(data)
                    report['kernel_binding']['selected_objects']['mt7621']['ELF']=gate.spi.inspect_elf(data,1)
                    path.write_text(json.dumps(report))
                    with self.subTest(symbol=removed,fault=fault),self.assertRaisesRegex(ValueError,'implementation symbol absent'):
                        gate.kernel_reference(inputs,path)

    def test_reference_reader_rejects_alias_directory_fifo_and_size_overflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);source=p/'source';source.write_bytes(b'x'*20);alias=p/'alias';alias.symlink_to(source)
            for path,limit in ((alias,30),(source,19),(p,30)):
                with self.assertRaises(ValueError):gate.read_regular(path,limit)
            fifo=p/'fifo';os.mkfifo(fifo,0o600)
            original=gate.os.open
            def checked_open(path,flags):
                self.assertTrue(flags&os.O_NONBLOCK)
                return original(path,flags)
            with patch.object(gate.os,'open',side_effect=checked_open),self.assertRaises(ValueError):
                gate.read_regular(fifo,30)
            self.assertEqual(gate.read_regular(source,20),b'x'*20)

    def test_invalid_early_final_selection_refused_before_compilation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            for preflight,reference in ((0,None),(True,p/'report'),(False,None)):
                with self.assertRaises(ValueError):gate.check(p,p/'compiler',p/'output',preflight,reference)
            self.assertFalse((p/'output').exists())


if __name__=='__main__':unittest.main()
