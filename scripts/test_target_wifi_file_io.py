"""Self-contained data/source-corruption controls; no source clone or target runs."""
import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from test_target_wifi_factory import module_elf
SPEC=importlib.util.spec_from_file_location('wifi_file_io_gate',Path(__file__).with_name('check_target_wifi_file_io.py'))
gate=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(gate)


def compiled_fixture():
    """Wide MIPS object/module/command bundle, never executed."""
    inputs={key:'inert source '+key for key in gate.SOURCE_PATHS}
    inputs['wifi_config']='CONFIG_RTMP_FLASH_SUPPORT=y\nCONFIG_ATE_SUPPORT=y\n'
    inputs['wifi_makefile']='DRV_NAME = mt_7615e\n'
    names=[]
    for _,_,symbol in gate.FACTORY_OBJECTS.values():
        if symbol not in names:names.append(symbol)
    for _,_,symbols,_ in gate.COMPILED_OBJECTS.values():
        for symbol in symbols:
            if symbol not in names:names.append(symbol)
    module=module_elf(tuple(names))
    aggregate='cmd := ld -r -o '+gate.BUILT_MODULE.removesuffix('.ko')+'.o '
    aggregate+=' '.join(v[0]for v in gate.FACTORY_OBJECTS.values())+' '
    aggregate+=' '.join(v[0]for v in gate.COMPILED_OBJECTS.values())
    parent={'target-wifi-built.ko':module,'target-wifi-shipped.ko':module,
      'target-wifi-module.cmd':('cmd := ld -r -o '+gate.BUILT_MODULE+' '+gate.BUILT_MODULE.removesuffix('.ko')+'.o').encode(),
      'target-wifi-link.cmd':aggregate.encode()}
    for label,(relative,key,symbol)in gate.FACTORY_OBJECTS.items():
        required=gate.COMPILED_OBJECTS[label][2]if label in gate.COMPILED_OBJECTS else(symbol,)
        parent['target-wifi-'+label+'.o']=module_elf(required)
        parent['target-wifi-'+label+'.cmd']=('cmd := gcc -c '+relative.removesuffix('.o')+'.c -o '+relative).encode()
    extra={}
    for label in gate.EXTRA_OBJECTS:
        relative,key,symbols,origin=gate.COMPILED_OBJECTS[label]
        extra['target-wifi-io-'+label+'.o']=module_elf(symbols)
        extra['target-wifi-io-'+label+'.cmd']=('cmd := gcc -c '+relative.removesuffix('.o')+'.c -o '+relative).encode()
    report={'schema_version':1,'status':'PASS','profile':'k2p-4.4','phase':'final-module-image-reference-bound',
      'source_sha256':{dest:gate.sha(inputs[key].encode())for key,dest in gate.FACTORY_SOURCE_KEYS.items()},
      'kernel_reference':{'image_sha256':'a'*64},
      'module_binding':{'status':'PASS','exports':{n:gate.sha(b)for n,b in parent.items()},
          'built_module':{'ELF':{'sha256':gate.sha(module)}},
          'shipped_module':{'ELF':{'sha256':gate.sha(module)},'path':gate.SHIPPED_MODULE}}}
    return inputs,parent,extra,report


def model_fixture(component):
    """Minimal independent source/model literals exercise regeneration rules."""
    inputs={key:'inert '+key for key in gate.SOURCE_PATHS}
    spec=copy.deepcopy(gate.COMPONENTS[component]);spec['paths']={'source':'inert/'+component+'.c'}
    flat='meta'if component=='meta'else'eeprom';spec['source_keys']={'source':flat};spec['source_literals']={}
    if component=='bin':
        functions={'toy_bin':'source'};bodies={'toy_bin':'int toy_bin(void){return 7;}'}
    elif component=='cal':
        functions={'RtmpOSFileClose':'source','NICReadEEPROMParameters':'source'}
        bodies={'RtmpOSFileClose':'int RtmpOSFileClose(void){return 7;}',
          'NICReadEEPROMParameters':'INT NICReadEEPROMParameters(void){\n\tPreCalSize = PRE_CAL_SIZE_ONE_CARD;\nreturn 7;\n#endif /* PRE_CAL_TRX_SET2_SUPPORT */\n}'}
    else:
        functions={n:'source'for n in('resp_to_meta','oid_nvram_rw','do_meta_cmd')}
        bodies={n:'INT32 '+n+'(void){return 7;}'for n in functions}
    old={n:b.replace('return 7','return 100')for n,b in bodies.items()}
    spec['functions']=functions;spec['baseline_hashes']={n:gate.sha(b.encode())for n,b in old.items()}
    values={'SOURCE_PATHS':spec['paths'],'FUNCTION_SOURCES':functions,'BASELINE_COMMIT':gate.BASELINE_COMMIT,
      'BASELINE_FUNCTIONS_SHA256':spec['baseline_hashes'],'BASELINE_FUNCTIONS':old,
      'CASE_NAMES':tuple(o['selector']for _,o in gate.CASES if o['component']==component and o['profile']=='current'),
      'BASELINE_CASES':tuple(o['selector']for _,o in gate.CASES if o['component']==component and o['profile']=='baseline'),
      'DISABLED_CASES':tuple(o['selector']for _,o in gate.CASES if o['component']==component and o['profile']=='disabled'),
      'PREFIX':'/* inert literal prefix */\n','MAIN':'\n/* CASE_ADMISSION */\nMODE_CALL\n',
      'BODY_ORDER':tuple(functions),'CALL':'CHECKED_CALL',
      'HEADER_CURRENT':'int RtmpOSFileClose(RTMP_OS_FD osfd);\nint RtmpOSFileCloseChecked(RTMP_OS_FD osfd);',
      'HEADER_BASELINE':'int RtmpOSFileClose(RTMP_OS_FD osfd);',
      'DISABLED_STUBS':{n:b.replace('return 7','return 0')for n,b in bodies.items()},
      'DISPATCH':'\n/* inert dispatch */\n','TAIL':'\n/* inert tail */\n'}
    values['DISABLED_STUB_SHA256']={n:gate.sha(b.encode())for n,b in values['DISABLED_STUBS'].items()}
    spec['model_data_sha256']=gate.model_data_hash(values)
    source='\n'.join(n+'='+repr(v)for n,v in values.items())+'\ndef generate_source(*a,**k):\n raise AssertionError("Source generator must never run")\n'
    inputs.update({flat:'\n'.join(bodies.values()),spec['harness_key']:source,'os_header':values['HEADER_CURRENT'],
      'meta_header':'struct GNU_PACKED _META_CMD_HDR {int code;};\nstruct GNU_PACKED _PARAM_CUSTOM_EEPROM_RW {int word;};'})
    return inputs,spec,values,old


class WifiFileIOTargetTests(unittest.TestCase):
    def rows(self):
        return [{'case':n,'inputs':copy.deepcopy(o),'observed':copy.deepcopy(gate.EXPECTED[n])}for n,o in gate.CASES]

    def test_fixed_three_components218_cases_honest_variant_and_object_scope(self):
        gate.validate_contract()
        self.assertEqual((len(gate.CASES),len(gate.SOURCE_PATHS),len(gate.COMPILED_OBJECTS),len(gate.EXTRA_OBJECTS)),(218,19,8,5))
        self.assertEqual({c:sum(o['component']==c for _,o in gate.CASES)for c in gate.COMPONENTS},{'bin':125,'cal':69,'meta':24})
        self.assertEqual((len(gate.parent_export_names()),len(gate.io_export_names())),(14,10))
        self.assertEqual(len(gate.COMPONENTS['cal']['functions']),9)
        self.assertIn('rtmp_ee_bin_read_with_range',gate.CONDITIONAL_FUNCTIONS[0]['functions'])
        self.assertIs(gate.CONDITIONAL_FUNCTIONS[1]['configured_object_claimed'],False)

    def test_every_typed_observation_and_exact_selection_is_required(self):
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

    def test_all_nine_profile_regenerations_use_literals_and_exact_source_fragments(self):
        for component in gate.COMPONENTS:
            inputs,spec,values,old=model_fixture(component)
            with patch.dict(gate.COMPONENTS,{component:spec}),patch.object(gate,'exec',side_effect=AssertionError('Execution forbidden'),create=True):
                for profile in('current','baseline','disabled'):
                    root='/tmp/k2p-wifi-file-io-source-control/'+component+'-'+profile+'-fixture'
                    generated,manifest=gate.generate_source(inputs,root,501,component,profile,old)
                    self.assertTrue(generated)
                    expected='omitted-control'if component=='cal'and profile=='disabled'else'disabled-stub'if profile=='disabled'else'precal-section'if component=='cal'else'whole-function'
                    name='NICReadEEPROMParameters'if component=='cal'else next(iter(spec['functions']))
                    self.assertEqual(manifest[name]['execution'],expected)
                    if component=='cal'and profile!='disabled':self.assertIn(gate.CAL_PROJECTION['prefix'],generated)
                for mutation in(values['PREFIX'].replace('inert','altered'),):
                    damaged=inputs[spec['harness_key']].replace(repr(values['PREFIX']),repr(mutation))
                    self.assertNotEqual(damaged,inputs[spec['harness_key']])
                    with self.assertRaises(ValueError):gate.generate_component({**inputs,spec['harness_key']:damaged},component,'current')
                for uid in(True,-1,2**32):
                    with self.assertRaises(ValueError):gate.generate_source(inputs,root,uid,component,'current')

    def test_ast_execution_protocol_and_baseline_substitution_are_rejected(self):
        for component in gate.COMPONENTS:
            inputs,spec,values,old=model_fixture(component)
            with patch.dict(gate.COMPONENTS,{component:spec}):
                for suffix in('\nimport os\n','\nraise RuntimeError("no")\n','\nDYNAMIC=unknown()\n'):
                    with self.assertRaises(ValueError):gate.generate_component({**inputs,spec['harness_key']:inputs[spec['harness_key']]+suffix},component,'current')
                bad=copy.deepcopy(old);name=next(iter(bad));bad[name]+=' '
                with self.assertRaises(ValueError):gate.generate_component(inputs,component,'baseline',bad)
                if component=='meta':
                    with self.assertRaises(ValueError):gate.generate_component({**inputs,'meta_header':''},component,'current')
                if component=='cal':
                    with self.assertRaises(ValueError):gate.generate_component({**inputs,'os_header':''},component,'current')

    def test_same_module_parent_reference_and_compiled_implementations_are_bound(self):
        inputs,parent,extra,report=compiled_fixture()
        reference=gate.module_reference_from_bytes(inputs,json.dumps(report).encode(),parent)
        self.assertEqual(reference['image_sha256'],'a'*64)
        result=gate.compiled_binding_from_bytes(inputs,parent,extra,gate.spi.inspect_elf)
        self.assertEqual((len(result['objects']),len(result['extra_exports'])),(8,10))
        self.assertEqual(set(result['reused_factory_objects']),{'eeprom','ee-flash','testmode'})
        self.assertIs(result['unconfigured_meta_object_claimed'],False)
        for fault in('missing','source','report-hash','module','meta-selected'):
            r=copy.deepcopy(report);p=copy.deepcopy(parent);t=copy.deepcopy(inputs)
            if fault=='missing':p.pop('target-wifi-built.ko')
            elif fault=='source':r['source_sha256']['wifi_eeprom']='0'*64
            elif fault=='report-hash':r['module_binding']['exports']['target-wifi-built.ko']='0'*64
            elif fault=='module':r['module_binding']['shipped_module']['path']='mt_wifi.ko'
            else:t['wifi_makefile']+='meta_agent.o'
            with self.subTest(fault=fault),self.assertRaises(ValueError):gate.module_reference_from_bytes(t,json.dumps(r).encode(),p)

    def test_resealed_object_source_command_and_module_symbol_corruption_fails(self):
        inputs,parent,extra,report=compiled_fixture()
        for fault in('object','machine','command','suffix-token','aggregate','module-symbol','missing'):
            p=copy.deepcopy(parent);e=copy.deepcopy(extra)
            if fault=='object':e['target-wifi-io-os.o']=module_elf(('wrong_api',))
            elif fault=='machine':
                data=bytearray(e['target-wifi-io-os.o']);data[18:20]=b'\x03\0';e['target-wifi-io-os.o']=bytes(data)
            elif fault in('command','suffix-token'):
                e['target-wifi-io-os.cmd']=b'wrong.c'if fault=='command'else e['target-wifi-io-os.cmd'].replace(b'rt_linux.o',b'rt_linux.o.missing')
            elif fault=='aggregate':p['target-wifi-link.cmd']=p['target-wifi-link.cmd'].replace(b'rtmp_init_inf.o',b'absent.o')
            elif fault=='module-symbol':p['target-wifi-built.ko']=module_elf(('wrong_module',))
            else:e.pop('target-wifi-io-teardown.o')
            with self.subTest(fault=fault),self.assertRaises(ValueError):gate.compiled_binding_from_bytes(inputs,p,e,gate.spi.inspect_elf)

    def test_strict_json_reader_rejects_aliases_fifo_hardlinks_and_nonfinite(self):
        for data in('{"a":1,"a":2}','{"a":NaN}'):
            with self.assertRaises(ValueError):gate.decode_json(data)
        with tempfile.TemporaryDirectory(prefix='wifi-file-io-reader-')as root:
            root=Path(root);file=root/'regular';file.write_bytes(b'DATA')
            self.assertEqual(gate.read_regular(file,4),b'DATA')
            alias=root/'alias';alias.symlink_to(file)
            with self.assertRaises(ValueError):gate.read_regular(alias,8)
            hard=root/'hard';os.link(file,hard)
            with self.assertRaises(ValueError):gate.read_regular(hard,8)
            hard.unlink();fifo=root/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError):gate.read_regular(fifo,8)
            with self.assertRaises(ValueError):gate.read_regular(file,3)

    def test_preflight_and_late_modes_are_exclusive_before_any_source_or_target(self):
        for preflight,report in ((False,None),(True,Path('/missing')),(1,None)):
            with self.assertRaises(ValueError):gate.check(Path('/missing'),Path('/compiler'),Path('/output'),preflight,report)


if __name__=='__main__':unittest.main()
