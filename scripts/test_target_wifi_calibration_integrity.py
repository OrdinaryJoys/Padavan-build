"""Offline typed-data/source/ELF corruption controls for MCU/Flash target gate."""
import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from test_target_wifi_factory import module_elf
import check_target_wifi_file_io as old_gate
SPEC=importlib.util.spec_from_file_location('wifi_calibration_integrity_gate',Path(__file__).with_name('check_target_wifi_calibration_integrity.py'))
gate=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(gate)


def compiled_fixture():
    inputs={key:'inert source '+key for key in gate.SOURCE_PATHS}
    inputs['kernel_makefile']='KBUILD_CFLAGS += -fno-strict-aliasing\n'
    inputs['wifi_config']='CONFIG_RTMP_FLASH_SUPPORT=y\nCONFIG_ATE_SUPPORT=y\n';inputs['wifi_makefile']='DRV_NAME = mt_7615e\n'
    objects={}
    for label,(relative,key,symbol)in gate.FACTORY_OBJECTS.items():objects[label]=(relative,(symbol,),'factory')
    for label in gate.PARENT_IO_EXTRA_OBJECTS:
        relative,key,symbols,origin=old_gate.COMPILED_OBJECTS[label];objects[label]=(relative,symbols,origin)
    for label,(relative,key,symbols,origin)in gate.COMPILED_OBJECTS.items():
        objects[label]=(relative,tuple(dict.fromkeys((*objects[label][1],*symbols))),origin)
    names=tuple(dict.fromkeys(n for _,symbols,_ in objects.values()for n in symbols));module=module_elf(names)
    artifacts={'target-wifi-built.ko':module,'target-wifi-shipped.ko':module,
      'target-wifi-module.cmd':('cmd := ld -r -o '+gate.BUILT_MODULE+' '+gate.BUILT_MODULE.removesuffix('.ko')+'.o').encode(),
      'target-wifi-link.cmd':('cmd := ld -r -o '+gate.BUILT_MODULE.removesuffix('.ko')+'.o '+' '.join(o[0]for o in objects.values())).encode()}
    for label,(relative,symbols,origin)in objects.items():
        stem='target-wifi-'+label if origin=='factory'else'target-wifi-io-'+label
        artifacts[stem+'.o']=module_elf(symbols);artifacts[stem+'.cmd']=('cmd := gcc -c '+relative.removesuffix('.o')+'.c -o '+relative).encode()
    hashes={n:gate.sha(b)for n,b in artifacts.items()};built=gate.sha(module)
    factory={'schema_version':1,'status':'PASS','profile':'k2p-4.4','phase':'final-module-image-reference-bound',
      'required_cases':['factory'+str(i)for i in range(49)],'checks':[{}for _ in range(49)],
      'source_sha256':{dest:gate.sha(inputs[key].encode())for key,dest in gate.FACTORY_SOURCE_KEYS.items()},
      'kernel_reference':{'image_sha256':'a'*64,'source_sha256':{'nvram_mtd':gate.sha(inputs['nvram_mtd'].encode())},'required_symbols':{'mt_mtd_read_nm_wifi':{},'mt_mtd_write_nm_wifi':{}}},
      'module_binding':{'status':'PASS','exports':{n:hashes[n]for n in gate.factory_export_names()},'built_module':{'ELF':{'sha256':built}},'shipped_module':{'ELF':{'sha256':built},'path':gate.SHIPPED_MODULE}}}
    io={'schema_version':1,'status':'PASS','profile':'k2p-4.4','phase':'final-module-reference-bound',
      'required_cases':['io'+str(i)for i in range(246)],'checks':[{}for _ in range(246)],
      'source_files':gate.PARENT_IO_SOURCE_PATHS,'source_sha256':{key:gate.sha(inputs[key].encode())for key in gate.PARENT_IO_SOURCE_PATHS},
      'module_reference':{'status':'PASS','report_sha256':gate.sha(json.dumps(factory).encode()),'image_sha256':'a'*64,'built_module_sha256':built,'shipped_module_sha256':built,'module_exports_sha256':factory['module_binding']['exports']},
      'compiled_binding':{'status':'PASS','built_module_sha256':built,'extra_exports':{n:hashes[n]for n in gate.io_export_names()}}}
    return inputs,artifacts,factory,io


def model_fixture(component):
    inputs={key:'inert '+key for key in gate.SOURCE_PATHS};spec=copy.deepcopy(gate.COMPONENTS[component])
    source='mcu'if component=='mcu'else'eeprom';name='toy_'+component;bodies={name:'INT '+name+'(void){return 7;}'}
    spec['functions']={name:next(k for k,v in spec['source_keys'].items()if v==source)};spec['source_literals']={}
    old={n:b.replace('return 7','return 100')for n,b in bodies.items()};spec['baseline_hashes']={n:gate.sha(b.encode())for n,b in old.items()}
    values={'SOURCE_PATHS':spec['paths'],'FUNCTION_SOURCES':spec['functions'],'BASELINE_COMMIT':gate.BASELINE_COMMIT,
      'BASELINE_FUNCTIONS_SHA256':spec['baseline_hashes'],'BASELINE_FUNCTIONS':old,'NEW_FUNCTIONS':(),
      'CASE_NAMES':tuple(o['selector']for _,o in gate.CASES if o['component']==component and o['profile']=='current'),
      'BASELINE_CASES':tuple(o['selector']for _,o in gate.CASES if o['component']==component and o['profile']=='baseline'),
      'DISABLED_CASES':tuple(o['selector']for _,o in gate.CASES if o['component']==component and o['profile']=='disabled'),
      'PREFIX':'/* inert literal prefix */\n'+('SOURCE_DECLARATIONS'if component=='mcu'else'SOURCE_MACROS\nSOURCE_HQA_FRAME'),
      'MAIN':'\n/* CASE_ADMISSION */\n','BODY_ORDER':(name,),
      'DISABLED_STUBS':{n:b.replace('return 7','return 0')for n,b in bodies.items()}}
    values['DISABLED_STUBS_SHA256'if component=='mcu'else'DISABLED_STUB_SHA256']={n:gate.sha(b.encode())for n,b in values['DISABLED_STUBS'].items()}
    if component=='mcu':
        values.update(RLM_MACROS=('A',),EVENT_TYPES=('EV',),CHIP_MACROS=('C',))
        local={'adapter':'UINT16 PreCalWriteOffSet;\nUINT16 ChGrpMap;', 'rlm':'#define A 1\ntypedef struct _EV {int x;} EV, *P_EV;',
          'cmd':'typedef enum _PRE_CAL_TYPE {P=1} PRE_CAL_TYPE;\n'+''.join('typedef union _'+n+' {int x;} '+n+';\n'*1+'typedef union _'+n+' {int y;} '+n+';\n'for n in('FW_RXD_0','FW_RXD_1','FW_RXD_2'))+'typedef struct GNU_PACKED _EVENT_RXD_ {int x;} EVENT_RXD;\n#define RXDCOC_SIZE 1\n#define TXDPD_SIZE 1',
          'andes':'#define GET_EVENT_FW_RXD_LENGTH(x) 1\n#define GET_EVENT_HDR_ADD_PAYLOAD_TOTAL_LEN(x) 1',
          'tables':'UINT16 K_AllFreq[] = {1};\nUINT16 K_ALL_SIZE = (sizeof(K_AllFreq) / sizeof(UINT16));\nUINT16 DPD_AllFreq[] = {1};\nUINT16 DPD_ALL_SIZE = (sizeof(DPD_AllFreq) / sizeof(UINT16));',
          'chip':'#define DCOC_FLASH_OFFSET\t\t1024\n#define C 1'}
    else:
        values.update(ABI_PROTOTYPES={'os_header':('INT checked(void);',)},BASE_PROTOTYPES={'eeprom_header':('INT legacy(void);',)},BASELINE_LEGACY_MACRO='#define RT28xx_EEPROM_WRITE16(p,o,v) 1',HQA_FRAME_DECLARATION='struct frame {int x;};',NETWORK_MACROS=('#define NETWORK_ORDER(x) (x)',))
        values['BASELINE_MACRO_SHA256']=gate.sha(values['BASELINE_LEGACY_MACRO'].encode())
        local={'os_header':'INT checked(void);','eeprom_header':'INT legacy(void);','chip_header':'#define RT28xx_EEPROM_WRITE16(p,o,v) 1\n#define RT28xx_EEPROM_WRITE16_CHECKED(p,o,v) 2','hqa_header':values['HQA_FRAME_DECLARATION']+'\n'+values['NETWORK_MACROS'][0],'ate_header':'#define IOCTLBUFF 2048'}
    inputs.update({spec['source_keys'][k]:v for k,v in local.items()});inputs[source]='\n'.join(bodies.values())
    spec['model_data_sha256']=gate.model_data_hash(values)
    inputs[spec['harness_key']]='\n'.join(n+'='+repr(v)for n,v in values.items())+'\ndef generate_source(*a,**k):\n raise AssertionError("Source generator must never run")\n'
    return inputs,spec,values,old

class WifiCalibrationIntegrityTests(unittest.TestCase):
    def rows(self):return [{'case':n,'inputs':copy.deepcopy(o),'observed':copy.deepcopy(gate.EXPECTED[n])}for n,o in gate.CASES]

    def test_fixed_two_components_real_geometry_and_reused_compiled_scope(self):
        gate.validate_contract()
        self.assertEqual(set(gate.COMPONENTS),{'mcu','flash'})
        self.assertEqual((len(gate.CASES),len(gate.SOURCE_PATHS)),(277,32))
        self.assertEqual({c:sum(o['component']==c for _,o in gate.CASES)for c in gate.COMPONENTS},{'mcu':137,'flash':140})
        self.assertEqual({c:(len(v['functions']),len(v['baseline_hashes']))for c,v in gate.COMPONENTS.items()},{'mcu':(15,12),'flash':(19,15)})
        self.assertEqual({c:[sum(o['component']==c and o['profile']==p for _,o in gate.CASES)for p in('current','baseline','disabled')]for c in gate.COMPONENTS},{'mcu':[115,17,5],'flash':[106,30,4]})
        self.assertEqual((len(gate.COMPILED_OBJECTS),len(gate.parent_export_names())),(5,26))
        self.assertEqual(len(gate.PARENT_IO_SOURCE_PATHS),20)
        self.assertEqual(gate.BASELINE_COMMIT,'3ba292933a5cdbcaac3d5187d2454b387fbfbcc1')
        self.assertIn('AndesMTRxEventHandler',gate.COMPILED_OBJECTS['mcu'][2])
        self.assertIn('HQA_WriteBulkEEPROM',gate.COMPILED_OBJECTS['hqa'][2])
        self.assertIn('RtmpFlashWriteChecked',gate.COMPILED_OBJECTS['ee-flash'][2])
        self.assertTrue(any('partial write'in text for text in gate.LIMITS))

    def test_every_typed_observation_and_fixed_selection_is_required(self):
        rows=self.rows();gate.validate_records(rows)
        for invalid in([],rows[:-1],rows+rows[:1],list(reversed(rows))):
            with self.assertRaises(ValueError):gate.validate_records(invalid)
        for i,row in enumerate(rows):
            for key,value in row['observed'].items():
                saved=rows[i]['observed'][key];rows[i]['observed'][key]=bool(value)if type(value)is int else None
                with self.subTest(case=row['case'],field=key),self.assertRaises(ValueError):gate.validate_records(rows)
                rows[i]['observed'][key]=saved
        bad=copy.deepcopy(rows);bad[0]['inputs']['profile']='disabled'
        with self.assertRaises(ValueError):gate.validate_records(bad)

    def test_all_six_profiles_reconstruct_from_literals_and_actual_bodies(self):
        for component in gate.COMPONENTS:
            inputs,spec,values,old=model_fixture(component)
            with patch.dict(gate.COMPONENTS,{component:spec}),patch.object(gate,'exec',side_effect=AssertionError('Forbidden execution'),create=True):
                for profile in('current','baseline','disabled'):
                    root='/tmp/k2p-wifi-calibration-integrity-source-control/'+component+'-'+profile+'-fixture'
                    generated,manifest=gate.generate_source(inputs,root,501,component,profile,old)
                    self.assertTrue(generated);item=next(iter(manifest.values()))
                    self.assertEqual(item['execution'],'disabled-stub'if profile=='disabled'else'whole-function')
                damaged=inputs[spec['harness_key']].replace('inert literal prefix','changed literal prefix')
                self.assertNotEqual(damaged,inputs[spec['harness_key']])
                with self.assertRaises(ValueError):gate.generate_component({**inputs,spec['harness_key']:damaged},component,'current')
                for uid in(True,-1,2**32):
                    with self.assertRaises(ValueError):gate.generate_source(inputs,root,uid,component,'current')

    def test_execution_ast_source_abi_geometry_and_old_body_substitution_rejected(self):
        for component in gate.COMPONENTS:
            inputs,spec,values,old=model_fixture(component)
            with patch.dict(gate.COMPONENTS,{component:spec}):
                for suffix in('\nimport os\n','\nraise RuntimeError("no")\n','\nDYNAMIC=unknown()\n'):
                    with self.assertRaises(ValueError):gate.generate_component({**inputs,spec['harness_key']:inputs[spec['harness_key']]+suffix},component,'current')
                bad=copy.deepcopy(old);bad[next(iter(bad))]+=' '
                with self.assertRaises(ValueError):gate.generate_component(inputs,component,'baseline',bad)
                bad=dict(inputs);bad['mcu'if component=='mcu'else'eeprom']='INT absent(void){return 0;}'
                with self.assertRaises(ValueError):gate.generate_component(bad,component,'current')
                for local in(('rlm','cmd','andes','tables','chip','adapter')if component=='mcu'else('chip_header','os_header','hqa_header','ate_header')):
                    flat=spec['source_keys'][local]
                    with self.subTest(component=component,source=local),self.assertRaises(ValueError):gate.generate_component({**inputs,flat:''},component,'current')

    def test_both_parent_proofs_same_image_sources_backend_and_actual26_exports(self):
        inputs,files,factory,io=compiled_fixture()
        def verify(f=factory,i=io,t=inputs,a=files):return gate.parent_reference_from_bytes(t,json.dumps(f).encode(),json.dumps(i).encode(),a)
        result=verify();self.assertEqual((result['factory_cases'],result['io_cases']),(49,246));self.assertEqual(len(result['parent_exports_sha256']),26)
        for fault in('missing','factory-phase','io-phase','image','shipped','source','backend','kernel-symbol','export','factory-hash','io-cases','io-sourcepaths'):
            f=copy.deepcopy(factory);i=copy.deepcopy(io);t=copy.deepcopy(inputs);a=copy.deepcopy(files)
            if fault=='missing':a.pop('target-wifi-built.ko')
            elif fault=='factory-phase':f['phase']='early-source-only'
            elif fault=='io-phase':i['phase']='early-source-only'
            elif fault=='image':i['module_reference']['image_sha256']='0'*64
            elif fault=='shipped':f['module_binding']['shipped_module']['path']='wrong.ko'
            elif fault=='source':t['mcu']+='changed'
            elif fault=='backend':t['nvram_mtd']+='changed'
            elif fault=='kernel-symbol':f['kernel_reference']['required_symbols'].pop('mt_mtd_write_nm_wifi')
            elif fault=='export':f['module_binding']['exports']['target-wifi-eeprom.o']='0'*64
            elif fault=='factory-hash':i['module_reference']['report_sha256']='0'*64
            elif fault=='io-cases':i['required_cases'][1]=i['required_cases'][0]
            else:i['source_files'].pop('mcu')
            if fault not in('factory-hash',):i['module_reference']['report_sha256']=gate.sha(json.dumps(f).encode())
            with self.subTest(fault=fault),self.assertRaises(ValueError):verify(f,i,t,a)

    def test_resealed_valid_elf_missing_symbols_commands_and_aggregate_are_rejected(self):
        inputs,files,factory,io=compiled_fixture();result=gate.compiled_binding_from_bytes(inputs,files,gate.spi.inspect_elf)
        self.assertEqual(len(result['objects']),5);self.assertEqual(len(result['reused_exports_sha256']),26)
        for fault in('checked-api','andes-entry','qa-bulk','machine','command','token-suffix','aggregate','module','missing'):
            a=copy.deepcopy(files)
            if fault=='checked-api':a['target-wifi-ee-flash.o']=module_elf(('wrong_checked_api',))
            elif fault=='andes-entry':a['target-wifi-io-mcu.o']=module_elf(tuple(n for n in gate.COMPILED_OBJECTS['mcu'][2]if n!='AndesMTRxEventHandler'))
            elif fault=='qa-bulk':a['target-wifi-io-hqa.o']=module_elf(('HQA_WriteBufferDone',))
            elif fault=='machine':
                data=bytearray(a['target-wifi-eeprom.o']);data[18:20]=b'\x03\0';a['target-wifi-eeprom.o']=bytes(data)
            elif fault=='command':a['target-wifi-ee-flash.cmd']=b'wrong.c'
            elif fault=='token-suffix':a['target-wifi-ee-flash.cmd']=a['target-wifi-ee-flash.cmd'].replace(b'ee_flash.o',b'ee_flash.o.missing')
            elif fault=='aggregate':a['target-wifi-link.cmd']=a['target-wifi-link.cmd'].replace(b'andes_mt.o',b'absent.o')
            elif fault=='module':a['target-wifi-built.ko']=module_elf(('wrong_module',))
            else:a.pop('target-wifi-io-hqa.o')
            # Reseal enclosing parent hashes so failure reaches symbol/command validation.
            f=copy.deepcopy(factory);i=copy.deepcopy(io)
            f['module_binding']['exports']={n:gate.sha(a[n])for n in gate.factory_export_names()if n in a}
            i['compiled_binding']['extra_exports']={n:gate.sha(a[n])for n in gate.io_export_names()if n in a}
            with self.subTest(fault=fault),self.assertRaises(ValueError):gate.compiled_binding_from_bytes(inputs,a,gate.spi.inspect_elf)

    def test_strict_json_and_readers_reject_aliases_nonfinite_and_oversize(self):
        for data in('{"a":1,"a":2}','{"a":NaN}','{"a":Infinity}'):
            with self.assertRaises(ValueError):gate.decode_json(data)
        with tempfile.TemporaryDirectory(prefix='wifi-calibration-reader-')as root:
            root=Path(root);file=root/'regular';file.write_bytes(b'DATA')
            self.assertEqual(gate.read_regular(file,4),b'DATA');alias=root/'alias';alias.symlink_to(file)
            with self.assertRaises(ValueError):gate.read_regular(alias,8)
            hard=root/'hard';os.link(file,hard)
            with self.assertRaises(ValueError):gate.read_regular(hard,8)
            hard.unlink();fifo=root/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError):gate.read_regular(fifo,8)
            with self.assertRaises(ValueError):gate.read_regular(file,3)

    def test_source_selection_and_exclusive_early_late_modes_fail_before_execution(self):
        for early,factory,io in((False,None,None),(False,Path('/factory'),None),(False,None,Path('/io')),(True,Path('/factory'),Path('/io')),(True,None,Path('/io')),(1,None,None)):
            with self.assertRaises(ValueError):gate.check(Path('/missing'),Path('/compiler'),Path('/output'),early,factory,io)
        inputs,files,factory,io=compiled_fixture();gate.source_selection(inputs)
        for key,value in(('kernel_makefile','KBUILD_CFLAGS += -fstrict-aliasing'),('wifi_config','CONFIG_RTMP_FLASH_SUPPORT=y\n'),('wifi_makefile','DRV_NAME = mt_7615e\nmeta_agent.o')):
            with self.assertRaises(ValueError):gate.source_selection({**inputs,key:value})

    def test_full_preflight_late_loop_exports_and_failure_publication_are_separate(self):
        """Control-flow test uses inert generated C and synthetic MIPS bytes, no compiler/target."""
        from test_target_resident_upgrade import elf as static_elf
        from types import SimpleNamespace
        inputs,files,factory,io=compiled_fixture();binary=bytes(static_elf())
        self.assertEqual(gate.resident.validate_static_helper(binary)['machine'],8)
        def generate(texts,root,uid,component,profile):return '/* inert control C '+component+profile+' */',{}
        def run(command,**kwargs):
            if command[0]=='/inert/compiler':Path(command[-1]).write_bytes(binary);return SimpleNamespace(returncode=0,stdout='',stderr='')
            stem=Path(command[1]).name;component,profile=stem.removeprefix('target-wifi-calibration-integrity-').rsplit('-',1)
            return SimpleNamespace(returncode=0,stdout=json.dumps(gate.EXPECTED[component+':'+profile+':'+command[2]]),stderr='')
        with tempfile.TemporaryDirectory(prefix='wifi-calibration-pipeline-')as directory:
            directory=Path(directory);checkout=directory/'source';trunk=checkout/'trunk';trunk.mkdir(parents=True)
            (trunk/'.config').write_text('CONFIG_LINUXDIR=linux-4.4.x\nCONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')
            for key,path in gate.SOURCE_PATHS.items():
                file=checkout/path;file.parent.mkdir(parents=True,exist_ok=True);file.write_text(inputs[key])
            parents=directory/'parents';parents.mkdir()
            for name,data in files.items():(parents/name).write_bytes(data)
            (parents/'target-wifi-factory.json').write_text(json.dumps(factory));(parents/'target-wifi-file-io.json').write_text(json.dumps(io))
            with patch.object(gate,'generate_source',side_effect=generate),patch.object(gate.shutil,'which',return_value='/inert/qemu'),patch.object(gate.subprocess,'run',side_effect=run):
                early=gate.check(trunk,Path('/inert/compiler'),directory/'early/target-wifi-calibration-integrity.json',True)
                late=gate.check(trunk,Path('/inert/compiler'),directory/'late/target-wifi-calibration-integrity.json',False,parents/'target-wifi-factory.json',parents/'target-wifi-file-io.json')
                self.assertEqual(early['phase'],'early-source-only');self.assertIsNone(early['module_reference']);self.assertIsNone(early['compiled_binding'])
                self.assertEqual(late['phase'],'final-module-reference-bound');self.assertEqual(len(late['compiled_binding']['objects']),5)
                self.assertEqual(len(list((directory/'early').iterdir())),13);self.assertEqual(len(list((directory/'late').iterdir())),13)
            def failed(command,**kwargs):
                value=run(command,**kwargs)
                if command[0]=='/inert/qemu':return SimpleNamespace(returncode=1,stdout='',stderr='inert failure')
                return value
            with patch.object(gate,'generate_source',side_effect=generate),patch.object(gate.shutil,'which',return_value='/inert/qemu'),patch.object(gate.subprocess,'run',side_effect=failed),self.assertRaises(ValueError):
                gate.check(trunk,Path('/inert/compiler'),directory/'failed/target-wifi-calibration-integrity.json',True)
            self.assertFalse((directory/'failed').exists())


if __name__=='__main__':unittest.main()
