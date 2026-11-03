"""Self-contained configured WiFi startup/module corruption controls, no source clone or target execution."""
import copy,importlib.util,json,os,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from test_target_spi_dma import elf

SPEC=importlib.util.spec_from_file_location('wifi_factory_gate',Path(__file__).with_name('check_target_wifi_factory.py'))
gate=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(gate)

def module_elf(names,imports=(),relocation=False):
    data=bytearray(elf(tuple(names)+tuple(imports),1))
    for index,name in enumerate(tuple(names)+tuple(imports)):
        if name in imports:
            struct.pack_into('<I',data,6500+16*(index+1)+4,0)
            struct.pack_into('<I',data,6500+16*(index+1)+8,0)
            struct.pack_into('<B',data,6500+16*(index+1)+12,16)
            struct.pack_into('<H',data,6500+16*(index+1)+14,0)
    if relocation:
        section_names=b'\0.shstrtab\0.text\0.symtab\0.strtab\0.rel.text\0'
        data[4500:4500+len(section_names)]=section_names
        struct.pack_into('<I',data,4136+20,len(section_names))
        struct.pack_into('<H',data,48,6)
        struct.pack_into('<10I',data,4296,section_names.index(b'.rel.text'),9,0,0,7400,8,3,2,4,8)
        struct.pack_into('<II',data,7400,0,((len(names)+1)<<8)|2)
    return bytes(data)

def selection_inputs():
    text='DRV_NAME = mt_7615e\nSRC_DIR = ../mt7615\nSRC_EMBEDDED_DIR = ../mt7615/embedded\n-DCONFIG_WIFI_MTD\n'
    for relative,key,symbol in gate.OBJECTS.values():
        leaf=relative.split('/mt7615/',1)[1]
        text+=('$(SRC_EMBEDDED_DIR)/'+leaf.removeprefix('embedded/')if leaf.startswith('embedded/')else'$(SRC_DIR)/'+leaf)+'\n'
    return {'wifi_makefile':text,'wifi_config':'CONFIG_RTMP_FLASH_SUPPORT=y\nCONFIG_ATE_SUPPORT=y\nCONFIG_MT_AP_SUPPORT=m\n',
            **{k:'inert-source '+k for _,k,_ in gate.OBJECTS.values()}}

def module_fixture():
    inputs=selection_inputs();names=tuple(row[2]for row in gate.OBJECTS.values())
    module=module_elf(names,('mt_mtd_read_nm_wifi','mt_mtd_write_nm_wifi'),True)
    files={'target-wifi-built.ko':module,'target-wifi-shipped.ko':module,
           'target-wifi-module.cmd':('cmd := ld -r -o '+gate.BUILT_MODULE+' '+gate.BUILT_MODULE.removesuffix('.ko')+'.o\n').encode(),
           'target-wifi-link.cmd':('cmd := ld -r -o '+gate.BUILT_MODULE.removesuffix('.ko')+'.o '+' '.join(row[0]for row in gate.OBJECTS.values())+'\n').encode()}
    for label,(relative,key,symbol)in gate.OBJECTS.items():
        files['target-wifi-'+label+'.o']=module_elf((symbol,))
        files['target-wifi-'+label+'.cmd']=('cmd := gcc -DCONFIG_WIFI_MTD -c '+relative.removesuffix('.o')+'.c -o '+relative+'\n').encode()
    return inputs,files

class WifiFactoryTargetTests(unittest.TestCase):
    def rows(self):return [{'case':n,'inputs':copy.deepcopy(o),'observed':copy.deepcopy(gate.EXPECTED[n])}for n,o in gate.CASES]

    def test_frozen_thirteen_bodies_honest_sections_and_forty_nine_typed_cases(self):
        self.assertEqual((len(gate.FUNCTION_SOURCES),len(gate.PROJECTIONS),len(gate.CASES)),(13,3,49))
        self.assertEqual([sum(o['profile']==p for _,o in gate.CASES)for p in('current','baseline','disabled')],[29,18,2])
        for row in gate.EXPECTED.values():
            self.assertEqual(len(row),21)
            self.assertEqual({k for k,v in row.items()if type(v)is str},{'case','trace'})
            self.assertEqual(sum(type(v)is int for v in row.values()),19)
        for name in ('boot-read-error','direct-read-short','direct-default-file-error','direct-default-invalid-id-error'):
            self.assertEqual(gate.EXPECTED['current:'+name]['factorywrites'],0)
            self.assertEqual(gate.EXPECTED['current:'+name]['fsdepth'],0)
        self.assertEqual(gate.EXPECTED['baseline:boot-read-error']['factorywrites'],1)
        self.assertGreater(gate.EXPECTED['baseline:direct-default-missing-error']['fsdepth'],0)

    def test_every_observed_type_and_missing_extra_ordered_case_is_enforced(self):
        rows=self.rows();gate.validate_records(rows)
        for invalid in([],rows[:-1],rows+rows[:1],list(reversed(rows))):
            with self.assertRaises(ValueError):gate.validate_records(invalid)
        for i,row in enumerate(rows):
            for key,value in row['observed'].items():
                bad=copy.deepcopy(rows);bad[i]['observed'][key]=bool(value)if type(value)is int else None
                with self.subTest(case=row['case'],field=key),self.assertRaises(ValueError):gate.validate_records(bad)

    def test_generator_uses_only_literal_fragments_and_actual_source_sections(self):
        functions={'rtmp_nv_init':'wifi_flash','NICReadEEPROMParameters':'wifi_eeprom'}
        bodies={'rtmp_nv_init':'NDIS_STATUS rtmp_nv_init(RTMP_ADAPTER*p){return 7;}',
                'NICReadEEPROMParameters':'INT NICReadEEPROMParameters(RTMP_ADAPTER*p){\n/*start*/return 3;/*end*/\n}'}
        projection={'NICReadEEPROMParameters':{'start':'/*start*/','end':'/*end*/','include_end':True,'prefix':'INT NICReadEEPROMParameters(RTMP_ADAPTER*p){','suffix':'\n}'}}
        old={n:b.replace('return ','return 100+')for n,b in bodies.items()}
        values={'SOURCE_PATHS':gate.HARNESS_SOURCE_PATHS,'FUNCTION_SOURCES':functions,'BASELINE_COMMIT':gate.BASELINE_COMMIT,
                'BASELINE_FUNCTIONS_SHA256':{n:gate.sha(b.encode())for n,b in old.items()},'BASELINE_FUNCTIONS':old,
                'BODY_ORDER':tuple(functions),'PROJECTIONS':projection,'PREFIX':'/*literal model*/\n',
                'MAIN':'\n/*CASE_ADMISSION*/\n','CASE_NAMES':tuple(o['selector']for _,o in gate.CASES if o['profile']=='current'),
                'BASELINE_CASES':tuple(o['selector']for _,o in gate.CASES if o['profile']=='baseline'),
                'DISABLED_CASES':tuple(o['selector']for _,o in gate.CASES if o['profile']=='disabled')}
        source='\n'.join(n+'='+repr(v)for n,v in values.items())+'\ndef generate_source(*a,**k):\n raise AssertionError("must never execute")\n'
        inputs={k:'inert'for k in gate.SOURCE_PATHS};inputs.update(wifi_flash=bodies['rtmp_nv_init'],wifi_eeprom=bodies['NICReadEEPROMParameters'],harness=source)
        with patch.object(gate,'FUNCTION_SOURCES',functions),patch.object(gate,'BASELINE_FUNCTION_HASHES',values['BASELINE_FUNCTIONS_SHA256']),patch.object(gate,'BODY_ORDER',tuple(functions)),patch.object(gate,'PROJECTIONS',projection),patch.object(gate,'MODEL_FRAGMENTS_SHA256',gate.fragment_hash(values)):
            for profile in('current','baseline','disabled'):
                generated,manifest=gate.generate_source(inputs,'/tmp/k2p-wifi-factory-source-control/'+profile+'-fixture',501,profile,old)
                self.assertEqual(manifest['NICReadEEPROMParameters']['execution'],'early-section')
                self.assertIn('/*start*/',generated)
                self.assertEqual(manifest['rtmp_nv_init']['execution'],'disabled-control'if profile=='disabled'else'whole-function')
            for mutation in(source.replace('literal model','changed model'),source+'\nraise RuntimeError("no")\n'):
                with self.assertRaises(ValueError):gate.generate_source({**inputs,'harness':mutation},'/tmp/k2p-wifi-factory-source-control/current-fixture',501)
            for uid in(True,-1,2**32):
                with self.assertRaises(ValueError):gate.generate_source(inputs,'/tmp/k2p-wifi-factory-source-control/current-fixture',uid)

    def test_configured_module_selection_and_five_object_binding(self):
        inputs,files=module_fixture();value=gate.module_binding_from_bytes(inputs,files,gate.spi.inspect_elf,gate.parse_module_elf)
        self.assertEqual(value['status'],'PASS');self.assertEqual(len(value['objects']),5);self.assertEqual(len(value['exports']),14)
        self.assertIs(value['runtime_strip_equivalence']['all_allocated_bytes_equal'],True)
        for fault in('module-name','config','ate-object','object-missing'):
            bad=copy.deepcopy(inputs)
            if fault=='module-name':bad['wifi_makefile']=bad['wifi_makefile'].replace('mt_7615e','mt_wifi')
            elif fault=='config':bad['wifi_config']=bad['wifi_config'].replace('CONFIG_MT_AP_SUPPORT=m','CONFIG_MT_AP_SUPPORT=y')
            elif fault=='ate-object':bad['wifi_makefile']+='$(SRC_DIR)/ate/mt_mac/mt_ate.o\n'
            else:bad['wifi_makefile']=bad['wifi_makefile'].replace('$(SRC_EMBEDDED_DIR)/common/ee_flash.o','')
            with self.subTest(fault=fault),self.assertRaises(ValueError):gate.module_binding_from_bytes(bad,files,gate.spi.inspect_elf,gate.parse_module_elf)

    def test_whole_runtime_bytes_and_relocation_targets_cannot_be_masked(self):
        inputs,files=module_fixture()
        for fault in('code','relocation','object','object-cmd','aggregate','module-cmd','backend'):
            bad=copy.deepcopy(files)
            if fault in('code','relocation','backend'):
                data=bytearray(bad['target-wifi-shipped.ko'])
                if fault=='code':data[256]^=1
                elif fault=='relocation':struct.pack_into('<II',data,7400,0,((len(gate.OBJECTS)+2)<<8)|2)
                else:struct.pack_into('<H',data,6500+16*(len(gate.OBJECTS)+1)+14,2)
                bad['target-wifi-shipped.ko']=bytes(data)
            elif fault=='object':bad['target-wifi-ee-flash.o']=module_elf(('wrong_function',))
            elif fault=='object-cmd':bad['target-wifi-ee-flash.cmd']=b'cmd := gcc unrelated.c'
            elif fault=='aggregate':bad['target-wifi-link.cmd']=bad['target-wifi-link.cmd'].replace(b'embedded/common/ee_flash.o',b'wrong.o')
            else:bad['target-wifi-module.cmd']=b'cmd := ld -o mt_wifi.ko mt_wifi.o'
            with self.subTest(fault=fault),self.assertRaises(ValueError):gate.module_binding_from_bytes(inputs,bad,gate.spi.inspect_elf,gate.parse_module_elf)

    def test_strip_symbol_index_change_is_semantically_compared_without_code_normalization(self):
        inputs,files=module_fixture();data=bytearray(files['target-wifi-shipped.ko'])
        a,b=6500+16*(len(gate.OBJECTS)+1),6500+16*(len(gate.OBJECTS)+2)
        first,second=bytes(data[a:a+16]),bytes(data[b:b+16]);data[a:a+16],data[b:b+16]=second,first
        struct.pack_into('<II',data,7400,0,((len(gate.OBJECTS)+2)<<8)|2);files['target-wifi-shipped.ko']=bytes(data)
        value=gate.module_binding_from_bytes(inputs,files,gate.spi.inspect_elf,gate.parse_module_elf)
        self.assertIs(value['runtime_strip_equivalence']['semantic_runtime_relocations_equal'],True)

    def test_backend_reference_requires_actual_kernel_backend_and_export_bytes(self):
        from test_target_spi_dma import SpiDmaTargetTests
        with tempfile.TemporaryDirectory(prefix='wifi-spi-control-')as root:
            helper=SpiDmaTargetTests()
            # Helper uses its own source aliases, replace only source identities for WiFi policy.
            _,path,report=helper.fixture(root);inputs={'nvram_mtd':'inert backend source'}
            report['source_sha256']={'nvram_mtd':gate.sha(inputs['nvram_mtd'].encode())};path.write_text(json.dumps(report))
            value=gate.kernel_reference(inputs,path);self.assertEqual(len(value['kernel_exports_sha256']),20)
            self.assertEqual(set(value['required_symbols']),{'mt_mtd_read_nm_wifi','mt_mtd_write_nm_wifi'})
            report['kernel_binding']['selected_objects']['wifi-mtd']['required_symbols'].remove('mt_mtd_read_nm_wifi')
            path.write_text(json.dumps(report))
            with self.assertRaises(ValueError):gate.kernel_reference(inputs,path)

    def test_nonregular_and_alias_artifacts_fail_without_blocking(self):
        with tempfile.TemporaryDirectory(prefix='wifi-file-control-')as root:
            root=Path(root);file=root/'regular';file.write_bytes(b'DATA');alias=root/'alias';alias.symlink_to(file)
            with self.assertRaises(ValueError):gate.read_regular(alias,64)
            fifo=root/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError):gate.read_regular(fifo,64)

if __name__=='__main__':unittest.main()
