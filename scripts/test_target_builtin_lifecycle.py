"""Built-in failure-gate contract and protected rendering regressions."""
import copy
import gzip
import unittest
from pathlib import Path
from unittest.mock import patch
import check_target_builtin_lifecycle as g

def rows():
    return [dict(case=n,inputs=copy.deepcopy(o),observed=copy.deepcopy(g.EXPECTED[n]))for n,o in g.CASES]

def profile_inputs():
    return {'raeth_raeth':'.suppress_bind_attrs = true,','raeth_device_header':'bool suppress_bind_attrs;',
        'raeth_bus':'int bus_add_driver(void) { if (!drv->suppress_bind_attrs) { error = add_bind_files(drv); } return 0; }',
        'raeth_header':'#define MAX_RX_RING_NUM 4\n',
        'nor_nor':'#define DEFAULT_READY_WAIT_JIFFIES (40UL * HZ)\n',
        'proc_harness':'SOURCE_MACROS={\'PROCREG_DIR\':\'"mt7621"\'}\nSOURCE_FEATURE_MACROS={\'FE_HW_LRO\':\'BIT(1)\'}\n',
        'proc_reg':'#define PROCREG_DIR "mt7621"\n','proc_config':'#define FE_HW_LRO BIT(1)\n',
        'kernel_config':'CONFIG_RAETH=y\nCONFIG_MTD_SPI_NOR=y\nCONFIG_CPU_LITTLE_ENDIAN=y\nCONFIG_SOC_MT7621=y\n',
        'nor_header':'enum spi_nor_ops { SPI_NOR_OPS_READ=0,SPI_NOR_OPS_WRITE,SPI_NOR_OPS_ERASE,SPI_NOR_OPS_LOCK,SPI_NOR_OPS_UNLOCK,};\nenum spi_nor_option_flags {SNOR_F_USE_FSR=BIT(0),};\n'+'\n'.join('#define '+n+' '+v for n,v in {'SPINOR_OP_RDSR':'0x05','SPINOR_OP_RDFSR':'0x70',
            'SPINOR_OP_WREN':'0x06','SPINOR_OP_WRDI':'0x04','SPINOR_OP_CHIP_ERASE':'0xc7','SR_WIP':'BIT(0)','FSR_READY':'BIT(7)'}.items())+'\n'}

def mini():
    data=dict(SOURCE_PATHS={'raeth':'c.c'},FUNCTION_SOURCES={'work':'raeth'},SOURCE_ONLY_FUNCTION_SOURCES={'never':'raeth'},
        BODY_ORDER=('work',),CASE_NAMES=('one',),EXPECTED_ROWS={'one':{'ret':0}},PREFIX='FUNCTION_DECLARATIONS\n',
        SUFFIX='\nvoid test(void) { const char *name="one"; int handled=0; /* CASE_ADMISSION */ if(!handled)return; }',CASE_ADMISSION='/* CASE_ADMISSION */')
    source='\n'.join(k+'='+repr(v)for k,v in data.items())+'\ndef generate_source():\n raise AssertionError("generator must not execute")\n'
    inputs={'harness':source,'driver':'static int work(void) { char *x="}"; /* { */ return x[0]; }\nint never(void) {return 9;}\n'}
    spec=dict(paths=data['SOURCE_PATHS'],functions=data['FUNCTION_SOURCES'],source_only_functions=data['SOURCE_ONLY_FUNCTION_SOURCES'],
              source_keys={'raeth':'driver'},harness_key='harness',model_data_sha256=g.model.model_data_hash(data))
    return inputs,data,spec

class BuiltinGateTests(unittest.TestCase):
    def test_fixed_disjoint_case_function_and_actual_object_scopes(self):
        self.assertEqual({c:sum(o['component']==c for _,o in g.CASES)for c in g.COMPONENTS},{'raeth': 45, 'nor': 31, 'proc': 29, 'runtime': 49, 'qtx': 30, 'ioctl': 74})
        self.assertEqual((len(g.CASES),len(g.SOURCE_PATHS),len(g.OBJECTS)),(258, 34, 9))
        self.assertEqual((sum(len(c['functions'])for c in g.COMPONENTS.values()),sum(len(c['source_only_functions'])for c in g.COMPONENTS.values())),(65, 9))
        self.assertIn('ei_init',g.OBJECTS['raeth_driver'][2]);self.assertIn('proc_remove',g.OBJECTS['proc_generic'][2])

    def test_exact_typed_case_observations_reject_bool_aliases(self):
        g.validate_rows(rows())
        for i,row in enumerate(rows()):
            for key,value in row['observed'].items():
                if type(value)is not int:continue
                bad=rows();bad[i]['observed'][key]=bool(value)
                with self.subTest(case=row['case'],field=key),self.assertRaises(ValueError):g.validate_rows(bad)

    def test_case_order_and_duplicate_missing_extra_rows_fail(self):
        r=rows()
        for bad in (r[:-1],r+r[:1],list(reversed(r))):
            with self.assertRaises(ValueError):g.validate_rows(bad)
        r[0]['extra']=0
        with self.assertRaises(ValueError):g.validate_rows(r)

    def test_declared_mips_probes_are_static_strict_and_inert(self):
        self.assertEqual(g.FLAGS,('-static','-std=gnu99','-Wall','-Wextra','-Werror','-pthread'))
        self.assertIn('physical DMA',' '.join(g.LIMITS));self.assertEqual(len(g.exports()),37)

    def test_kernel_board_and_ring_constants_are_required(self):
        g.source_profile(profile_inputs())
        for key,old,new in (('raeth_header','NUM 4','NUM 2'),('kernel_config','RAETH=y','RAETH=m'),
                           ('kernel_config','SPI_NOR=y','SPI_NOR=m'),('kernel_config','SOC_MT7621=y','SOC_MT7621=m'),('nor_header','BIT(0)','BIT(1)'),('nor_nor','40UL','50UL'),('proc_reg','mt7621','changed'),('proc_config','BIT(1)','BIT(2)'),('nor_header','READ=0','READ=1')):
            bad=profile_inputs();bad[key]=bad[key].replace(old,new)
            with self.subTest(key=key),self.assertRaises(ValueError):g.source_profile(bad)

    def test_manual_unbind_guard_requires_actual_flag_and_driver_core_consumer(self):
        for key in ('raeth_raeth','raeth_device_header','raeth_bus'):
            bad=profile_inputs();bad[key]=''
            with self.subTest(key=key),self.assertRaises(ValueError):g.source_profile(bad)

    def test_model_render_reads_data_without_calling_generator(self):
        i,d,s=mini()
        with patch.object(g,'SOURCE_PATHS',{'harness':'h.py','driver':'c.c'}),patch.object(g,'COMPONENTS',{'raeth':s}),\
             patch.object(g,'CASES',(('raeth:one',{'component':'raeth','selector':'one'}),)),patch.object(g,'EXPECTED',{'raeth:one':d['EXPECTED_ROWS']['one']}):
            code,m,o=g.generate(i,'raeth')
        self.assertIn('static int work(void);',code);self.assertIn('handled=1;',code)
        self.assertEqual(code.count('static int work(void) {'),1);self.assertNotIn('int never(void)',code)
        self.assertEqual(o['never']['execution'],'source-only-not-run');self.assertEqual(m['work']['execution'],'whole-function')

    def test_fragment_profile_requires_complete_unique_lines_without_generator_execution(self):
        inputs,data,spec=mini()
        data['SOURCE_FRAGMENTS']={'raeth':('#define REQUIRED_K2P_MODEL 1',)}
        spec['model_data_sha256']=g.model.model_data_hash(data)
        inputs['harness']='\n'.join(k+'='+repr(v)for k,v in data.items())+'\ndef generate_source():\n raise AssertionError("No source execution")\n'
        original=inputs['driver'];inputs['driver']='#define REQUIRED_K2P_MODEL 1\n'+original
        with patch.object(g,'SOURCE_PATHS',{'harness':'h.py','driver':'c.c'}),patch.object(g,'COMPONENTS',{'raeth':spec}),\
             patch.object(g,'CASES',(('raeth:one',{'component':'raeth','selector':'one'}),)),patch.object(g,'EXPECTED',{'raeth:one':data['EXPECTED_ROWS']['one']}):
            g.generate(inputs,'raeth')
            for prefix in ('','#define REQUIRED_K2P_MODEL 1 //changed\n','#define REQUIRED_K2P_MODEL 1\n'*2):
                inputs['driver']=prefix+original
                with self.subTest(prefix=prefix),self.assertRaises(ValueError): g.generate(inputs,'raeth')

    def test_function_lexer_rejects_ambiguous_source(self):
        for typename in ('int','bool','unsigned int','unsigned long'):
            text='static inline '+typename+' work(void) { return 0; }\n'
            self.assertEqual(g.model.function(text,'work'),text.strip())
            with self.assertRaises(ValueError):g.model.function(text+text,'work')

    def test_model_data_changes_and_source_execution_fail_closed(self):
        for source in ('x=dict(a=1)','x=1\nraise RuntimeError()','import os\nx=1'):
            with self.assertRaises((ValueError,SyntaxError)):g.model.literal_data(source)

    def test_embedded_config_is_bounded_complete_and_unique(self):
        import zlib
        config=b'CONFIG_RAETH=y\n';good=b'prefixIKCFG_ST'+gzip.compress(config,mtime=0)+b'IKCFG_EDsuffix'
        self.assertEqual(g.embedded_config(good),config)
        for bad in (b'',good+b'IKCFG_ST',good.replace(b'IKCFG_ED',b'broken'),b'IKCFG_STbadIKCFG_ED'):
            with self.assertRaises((ValueError,zlib.error)):g.embedded_config(bad)
        with patch.object(g,'MAX_SOURCE',4),self.assertRaises(ValueError):g.embedded_config(good)

    def test_commands_require_bounded_plain_bytes(self):
        self.assertEqual(g.command(b'cc -c a.c -o a.o'),'cc -c a.c -o a.o')
        for bad in ('cc',b'',b'cc\0',b'x'*(g.MAX_COMMAND+1)):
            with self.assertRaises(ValueError):g.command(bad)

    def test_build_requires_preflight_final_parent_and_all_exports(self):
        source=Path(__file__).with_name('build_k2p.sh').read_text();self.assertEqual(source.count('check_target_builtin_lifecycle.py'),2)
        self.assertIn('builtin-lifecycle-preflight/target-builtin-lifecycle.json',source)
        self.assertIn('--spi-report "$diagnostics/target-spi-nor.json" --output "$diagnostics/target-builtin-lifecycle.json"',source)
        self.assertIn('cp "$diagnostics/target-builtin-lifecycle"* "$dist/"',source)
