import copy,importlib.util,json,os,struct,tempfile,unittest
from pathlib import Path
from unittest import mock
from test_target_controller import elf
CLOCK_CONTROLLER_FIXTURE='#define RS_CLK_SEL_M\t\t\t0xfff\nstatic u32 mt7621_spi_get_clk_div(u32 hclk_freq, u32 freq)\n{\n\tu32 div;\n\n\t/* Avoid overflowing the u32 sum used by DIV_ROUND_UP. */\n\tif (!freq)\n\t\treturn RS_CLK_SEL_M;\n\tdiv = hclk_freq / freq + (hclk_freq % freq != 0);\n\n\tif (div > (RS_CLK_SEL_M + 2))\n\t\treturn RS_CLK_SEL_M;\n\n\tif (div < 2)\n\t\treturn 0;\n\n\treturn div - 2;\n}\n\nstatic void mt7621_spi_prepare(void);\n'
CLOCK_HARNESS_FIXTURE = '#!/usr/bin/env python3\n"""Pure actual divider adapter; no clock, MMIO or device operation."""\nimport hashlib,re\nSOURCE_PATHS={\'controller\':\'trunk/linux-4.4.x/drivers/spi/spi-mt7621.c\'}\nBASELINE_COMMIT=\'6e91276a33d1bd83d416fc8253feb01f30677743\'\nBASELINE_BODY=\'static u32 mt7621_spi_get_clk_div(u32 hclk_freq, u32 freq)\\n{\\n\\tu32 div;\\n\\n\\tdiv = (hclk_freq + freq - 1) / freq;\\n\\n\\tif (div > (RS_CLK_SEL_M + 2))\\n\\t\\treturn RS_CLK_SEL_M;\\n\\n\\tif (div < 2)\\n\\t\\treturn 2;\\n\\n\\treturn div - 2;\\n}\'\nBASELINE_SHA256=\'ffff94290f04b32c9c7baff6f32ba805f408434fefe7c7b2b3002b8274964571\'\nINPUTS=(\n (\'normal-80m\',220000000,80000000,1),\n (\'normal-half\',220000000,110000000,0),\n (\'normal-round-up\',220000000,100000000,1),\n (\'normal-four\',220000000,55000000,2),\n (\'normal-lowest\',220000000,53697,4095),\n (\'too-low\',220000000,1,4095),\n (\'zero-rate\',220000000,0,4095),\n (\'above-half\',220000000,220000000,0),\n (\'above-source\',220000000,4294967295,0),\n (\'overflow-high\',4000000000,900000000,3),\n (\'overflow-max\',4294967295,800000000,4),\n (\'max-encoding\',4097,1,4095),\n (\'before-max\',4096,1,4094),\n (\'clamp-max\',4098,1,4095),\n (\'min-provider\',2,1,0),\n (\'min-above\',2,2,0),\n (\'max-both\',4294967295,4294967295,0),\n (\'max-half\',4294967295,2147483647,1),\n (\'max-small\',4294967295,1048576,4094),\n (\'zero-source\',0,1,0),\n)\nBASELINE_EXPECTED={\'normal-80m\':1,\'normal-half\':0,\'normal-round-up\':1,\'normal-four\':2,\n \'normal-lowest\':4095,\'too-low\':4095,\'above-half\':2,\'above-source\':2,\n \'overflow-high\':2,\'overflow-max\':2,\'max-encoding\':4095,\'before-max\':4094,\n \'clamp-max\':4095,\'min-provider\':0,\'min-above\':2,\'max-both\':2,\'max-half\':2,\n \'max-small\':2,\'zero-source\':2}\nCASES=tuple((name,dict(case=name,hclk=h,rate=f,divider=v)) for name,h,f,v in INPUTS)\nBASELINE_CASES=tuple((name,dict(case=name,hclk=h,rate=f,divider=BASELINE_EXPECTED[name]))\n                     for name,h,f,_ in INPUTS if name in BASELINE_EXPECTED)\nBASELINE_FUNCTIONS={\'mt7621_spi_get_clk_div\':BASELINE_BODY}\nBASELINE_FUNCTIONS_SHA256={\'mt7621_spi_get_clk_div\':BASELINE_SHA256}\ndef function(text):\n if text.count(\'static u32 mt7621_spi_get_clk_div\')!=1:raise ValueError(\'Missing/ambiguous clock divider\')\n start=text.index(\'static u32 mt7621_spi_get_clk_div\')\n end=text.index(\'\\nstatic void mt7621_spi_prepare\',start)\n return text[start:end].rstrip()\ndef production_fragments(texts):\n lines=re.findall(r\'^#define RS_CLK_SEL_M[ \\t]+0xfff$\',texts[\'controller\'],re.M)\n if len(lines)!=1:raise ValueError(\'Changed clock selector constant\')\n return lines[0]\ndef generate_source(texts,fixture_root=None,owner_uid=0,baseline=False):\n if set(texts)!=set(SOURCE_PATHS) or type(baseline)is not bool:raise ValueError(\'Exact clock source/profile required\')\n if hashlib.sha256(BASELINE_BODY.encode()).hexdigest()!=BASELINE_SHA256:raise ValueError(\'Changed clock baseline\')\n body=BASELINE_BODY if baseline else function(texts[\'controller\'])\n prefix=\'#include <stdint.h>\\n#include <stdio.h>\\n#include <string.h>\\n#include <stdlib.h>\\ntypedef uint32_t u32;\\n\'+production_fragments(texts)+\'\\n\'\n cases=\'\'.join(\'if(!strcmp(argv[1],\'+repr(name).replace("\'",\'"\')+\')){h=\'+str(h)+\'U;f=\'+str(f)+\'U;name="\'+name+\'";}\\n\' for name,h,f,_ in INPUTS)\n main=\'int main(int argc,char **argv)\\n{\\n u32 h=0,f=0,d;\\n const char*name=NULL;\\n if(argc!=2)\\n  return 90;\\n\'+cases+\' if(!name)\\n  return 91;\\n d=mt7621_spi_get_clk_div(h,f);\\n printf("{\\\\"case\\\\":\\\\"%s\\\\",\\\\"hclk\\\\":%u,\\\\"rate\\\\":%u,\\\\"divider\\\\":%u}\\\\n",name,h,f,d);\\n return 0;\\n}\'\n return prefix+body+\'\\n\'+main+\'\\n\'\n'
spec=importlib.util.spec_from_file_location('clock_gate',Path(__file__).with_name('check_target_controller_clock.py'))
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
class ControllerClockGateTests(unittest.TestCase):
    def inputs(self):return {'controller':CLOCK_CONTROLLER_FIXTURE,'harness':CLOCK_HARNESS_FIXTURE}
    def rows(self):return [dict(case=n,inputs=copy.deepcopy(i),observed=copy.deepcopy(gate.EXPECTED[n])) for n,i in gate.CASES]
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

    def test_complete_fixed_typed_contract_and_all_field_mutants(self):
        rows=self.rows();gate.validate_records(rows);self.assertEqual(len(rows),39)
        for index,row in enumerate(rows):
            for field,value in row['observed'].items():
                bad=copy.deepcopy(rows);bad[index]['observed'][field]=True if type(value)is int else None
                with self.subTest(case=row['case'],field=field),self.assertRaises(ValueError):gate.validate_records(bad)
        for bad in ([],rows[:-1],list(reversed(rows)),rows+rows[:1]):
            with self.assertRaises(ValueError):gate.validate_records(bad)
    def test_actual_body_and_fixed_old_generation_are_bound(self):
        values=self.inputs()
        for old in (False,True):
            code,bodies=gate.generate_source(values,'/tmp/inert',501,old)
            self.assertEqual(len(bodies),1)
            for body in bodies.values():self.assertEqual(code.count(body),1)
        bad=dict(values);bad['harness']=bad['harness'].replace(gate.BASELINE_COMMIT,'0'*40)
        with self.assertRaises(ValueError):gate.generate_source(bad,'/tmp/inert',501)
        bad=dict(values);bad['controller']=bad['controller'].replace('0xfff','0xffe')
        with self.assertRaises(ValueError):gate.generate_source(bad,'/tmp/inert',501)
    def test_invalid_metadata_and_extra_source_refused(self):
        values=self.inputs()
        for uid in (True,-1,2**32):
            with self.assertRaises(ValueError):gate.generate_source(values,'/tmp/inert',uid)
        with self.assertRaises(ValueError):gate.generate_source(dict(values,extra=''),'/tmp/inert',501)
        with self.assertRaises(ValueError):gate.generate_source(values,'/tmp/inert',501,1)
    def test_kernel_reference_binds_same_actual_controller_and_all_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,report,path=self.kernel_fixture(tmp);value=gate.kernel_reference(inputs,path)
            self.assertEqual(len(value['kernel_exports_sha256']),20)
            self.assertTrue(value['whole_kernel_image_equality'])
            bad=copy.deepcopy(report);bad['source_sha256']['controller']='0'*64;path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)
    def test_resealed_unrelated_controller_command_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,report,path=self.kernel_fixture(tmp);name='target-spi-mt7621.cmd';data=b'inert wrong.c'
            (Path(tmp)/name).write_bytes(data);report['kernel_binding']['exports'][name]=gate.sha(data)
            report['kernel_binding']['selected_objects']['mt7621']['command_sha256']=gate.sha(data);path.write_text(json.dumps(report))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)
    def test_special_file_reader_is_nonblocking_and_refuses_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'x').write_bytes(b'xx');(d/'alias').symlink_to(d/'x');os.mkfifo(d/'fifo')
            for name in ('alias','fifo'):
                with self.assertRaises(ValueError):gate.read_regular(d/name,10)
            with self.assertRaises(ValueError):gate.read_regular(d/'x',1)
