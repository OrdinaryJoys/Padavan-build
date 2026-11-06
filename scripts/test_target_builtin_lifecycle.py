"""Built-in failure-gate contract and protected rendering regressions."""
import copy
import gzip
import unittest
from pathlib import Path
from unittest.mock import patch
import check_target_builtin_lifecycle as g

def integer_paths(value, path=()):
    if type(value) is int: yield path
    elif type(value) is list:
        for key,item in enumerate(value): yield from integer_paths(item,path+(key,))
    elif type(value) is dict:
        for key,item in value.items(): yield from integer_paths(item,path+(key,))

def set_path(value,path,replacement):
    for key in path[:-1]:value=value[key]
    value[path[-1]]=replacement

def rows():
    return [dict(case=n,inputs=copy.deepcopy(o),observed=copy.deepcopy(g.EXPECTED[n]))for n,o in g.CASES]

def profile_inputs():
    result = {'raeth_raeth':'.suppress_bind_attrs = true,','raeth_device_header':'bool suppress_bind_attrs;',
        'raeth_bus':'int bus_add_driver(void) { if (!drv->suppress_bind_attrs) { error = add_bind_files(drv); } return 0; }',
        'raeth_header':'#define MAX_RX_RING_NUM 4\n',
        'nor_nor':'#define DEFAULT_READY_WAIT_JIFFIES (40UL * HZ)\n',
        'proc_harness':'SOURCE_MACROS={\'PROCREG_DIR\':\'"mt7621"\'}\nSOURCE_FEATURE_MACROS={\'FE_HW_LRO\':\'BIT(1)\'}\n',
        'proc_reg':'#define PROCREG_DIR "mt7621"\n','proc_config':'#define FE_HW_LRO BIT(1)\n',
        'kernel_config':'CONFIG_RAETH=y\nCONFIG_MTD_SPI_NOR=y\nCONFIG_CPU_LITTLE_ENDIAN=y\nCONFIG_SOC_MT7621=y\nCONFIG_RESET_CONTROLLER=y\nCONFIG_RAETH_ESW_CONTROL=y\n# CONFIG_RAETH_ETHTOOL is not set\n',
        'nor_header':'enum spi_nor_ops { SPI_NOR_OPS_READ=0,SPI_NOR_OPS_WRITE,SPI_NOR_OPS_ERASE,SPI_NOR_OPS_LOCK,SPI_NOR_OPS_UNLOCK,};\nenum spi_nor_option_flags {SNOR_F_USE_FSR=BIT(0),};\n'+'\n'.join('#define '+n+' '+v for n,v in {'SPINOR_OP_RDSR':'0x05','SPINOR_OP_RDFSR':'0x70',
            'SPINOR_OP_WREN':'0x06','SPINOR_OP_WRDI':'0x04','SPINOR_OP_CHIP_ERASE':'0xc7','SR_WIP':'BIT(0)','FSR_READY':'BIT(7)'}.items())+'\n'}
    result['runtime_raeth'] = 'static inline void ei_receive(void) { return; }\nstatic void ei_receive_tasklet(unsigned long unused) { ei_receive(); }\nstatic int fe_int_enable(struct net_device *dev) { if (ei_local->features & FE_INT_TASKLET) { tasklet_init(&ei_local->rx_tasklet, ei_receive_tasklet, 0); } return 0; }\nint ei_open(struct net_device *dev) { err = fe_int_enable(dev); if (err) goto fail_dma; ei_start_dma(dev); return 0; fail_dma: return err; }\nstatic int rather_probe(struct platform_device *pdev) { fe_features_config(ei_local); fe_architecture_config(ei_local); return 0; }\n'
    result['runtime_config'] = '#if defined(CONFIG_SOC_MT7621)\n#define CONFIG_GE1_RGMII_FORCE_1000\n//#define CONFIG_GE1_RGMII_FORCE_1200\n#define CONFIG_RA_NETWORK_TASKLET_BH\n#endif\n#ifdef\tCONFIG_RA_NETWORK_TASKLET_BH\n#define FE_INT_TASKLET\tBIT(7)\n#else\n#define FE_INT_TASKLET\t(0)\n#endif\n#define fe_features_config(end_device)\t\\\n{\\\nend_device->features = 0;\\\nend_device->features |= FE_INT_TASKLET;\\\n}\n'
    result['esw_ioctl'] = 'static long mtk_esw_ioctl(struct file *file, unsigned int req, unsigned long arg) { return 0; }\nstatic const struct file_operations mtk_esw_fops = { .owner = THIS_MODULE, .unlocked_ioctl = mtk_esw_ioctl, .open = mtk_esw_open, .release = mtk_esw_release, };\nint esw_ioctl_init(void) { r = register_chrdev(MTK_ESW_DEVMAJOR, MTK_ESW_DEVNAME, &mtk_esw_fops); if (r < 0) { return r; } return 0; }\n'
    result['esw_esw'] = '#include "ioctl.c"\n'
    result['raeth_makefile'] = 'ifeq ($(CONFIG_RAETH_ESW_CONTROL),y)\nraeth-objs += mtk_esw/ioctl_mt762x.o\nendif\n'
    return result

def optimizer_symbols():
    # A compiler-owned inline body may disappear while its escaped callback stays.
    import subprocess, tempfile, shutil
    compiler = shutil.which('cc'); nm = shutil.which('nm')
    if not compiler or not nm: raise AssertionError('Native strict compiler/nm required')
    source = ('static volatile unsigned long observed;\n'
              'static inline void ei_receive(void) { observed++; }\n'
              'static void ei_receive_tasklet(unsigned long unused) { (void)unused; ei_receive(); }\n'
              'void (*owner)(unsigned long) = ei_receive_tasklet;\n')
    with tempfile.TemporaryDirectory(prefix='builtin-inline-owner-') as temp:
        unit = Path(temp)/'owner.c'; obj = Path(temp)/'owner.o'; unit.write_text(source)
        subprocess.run([compiler,'-O2','-Wall','-Wextra','-Werror','-c',str(unit),'-o',str(obj)],check=True,capture_output=True)
        return {line.split()[-1].removeprefix('_') for line in subprocess.check_output([nm,str(obj)],text=True).splitlines() if line.split()}


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
        self.assertEqual({c:sum(o['component']==c for _,o in g.CASES)for c in g.COMPONENTS},{'raeth': 45, 'nor': 31, 'proc': 29, 'runtime': 51, 'qtx': 31, 'ioctl': 78, 'reset_core': 17, 'mdio': 34, 'remove': 20, 'esw': 32, 'reset_lifecycle': 48, 'esw_vlan': 42})
        self.assertEqual((len(g.CASES),len(g.SOURCE_PATHS),len(g.OBJECTS)),(458, 72, 13))
        self.assertEqual((sum(len(c['functions'])for c in g.COMPONENTS.values()),sum(len(c['source_only_functions'])for c in g.COMPONENTS.values())),(169, 18))
        self.assertIn('ei_init',g.OBJECTS['raeth_driver'][2]);self.assertIn('proc_remove',g.OBJECTS['proc_generic'][2])
        for label in ('raeth_driver','raeth_aggregate','raeth_builtin'):
            self.assertIn('ei_receive_tasklet',g.OBJECTS[label][2]);self.assertNotIn('ei_receive',g.OBJECTS[label][2])
        self.assertIn('ei_receive',g.COMPONENTS['runtime']['functions'])
        self.assertNotIn('ei_receive_tasklet',g.COMPONENTS['runtime']['source_only_functions'])
        symbols=optimizer_symbols();self.assertIn('ei_receive_tasklet',symbols);self.assertNotIn('ei_receive',symbols)


    def test_new_reset_scenarios_are_fixed_typed_and_bounded(self):
        data={'CASE_NAMES':('one','two'),'SCENARIO_DATA':(('one',0,1,0,0,0,0,1,-1,0),('two',1,1,1,0,0,0,1,-1,0))}
        suffix='before\nSCENARIOS\nafter'
        rendered=g.reset_lifecycle_scenarios(data,suffix)
        self.assertIn('{"one",0,1,0,0,0,0,1,-1,0}',rendered)
        self.assertIn('{"two",1,1,1,0,0,0,1,-1,0}',rendered)
        for value in (True,2**31,-2**31-1,'1'):
            wrong=copy.deepcopy(data);rows=list(wrong['SCENARIO_DATA']);row=list(rows[0]);row[1]=value;rows[0]=tuple(row);wrong['SCENARIO_DATA']=tuple(rows)
            with self.subTest(value=value),self.assertRaises(ValueError):g.reset_lifecycle_scenarios(wrong,suffix)
        for rows in (data['SCENARIO_DATA'][:-1],tuple(reversed(data['SCENARIO_DATA'])),data['SCENARIO_DATA']+(data['SCENARIO_DATA'][0],)):
            with self.subTest(rows=rows),self.assertRaises(ValueError):g.reset_lifecycle_scenarios(dict(data,SCENARIO_DATA=rows),suffix)
        for altered in ('before','SCENARIOS SCENARIOS'):
            with self.assertRaises(ValueError):g.reset_lifecycle_scenarios(data,altered)

    def test_esw_actual_header_port_and_capability_source_insertions_are_checked(self):
        names=('CONFIG_RAETH_ESW_PORT_WAN','CONFIG_RAETH_ESW_PORT_LAN1','CONFIG_RAETH_ESW_PORT_LAN2','CONFIG_RAETH_ESW_PORT_LAN3','CONFIG_RAETH_ESW_PORT_LAN4')
        data=dict(HEADER_KEYS=('common','header','mt762x'),CONFIG_NAMES=names,SOURCE_DECLARATIONS={r'^#define CAP_NET_ADMIN [^\n]+$':'capheader'})
        spec={'source_keys':{k:k for k in ('config','common','header','mt762x','capheader')}}
        inputs=dict(config='CONFIG_MULTIUSER=y\n'+'\n'.join(n+'='+str(i)for i,n in enumerate(names)),common='/* actual common */',header='#include "esw_common.h"\n/* actual ioctl */',mt762x='/* actual MT762x */',capheader='#define CAP_NET_ADMIN 12\n')
        value=g.esw_vlan_definitions(inputs,spec,data,'HEADERS_AND_DEFINITIONS\n')
        self.assertIn('#define '+names[0]+' 0',value);self.assertIn('#define CAP_NET_ADMIN 12',value)
        self.assertNotIn('#include "esw_common.h"',value)
        for key,old,new in (('config','CONFIG_MULTIUSER=y','CONFIG_MULTIUSER=n'),('config',names[0]+'=0',names[0]+'=32'),('config',names[0]+'=0',names[0]+'=0\n'+names[0]+'=0'),('capheader','#define CAP_NET_ADMIN 12',''),('capheader','#define CAP_NET_ADMIN 12','#define CAP_NET_ADMIN 12\n#define CAP_NET_ADMIN 12')):
            wrong=dict(inputs);wrong[key]=wrong[key].replace(old,new)
            with self.subTest(key=key,new=new),self.assertRaises(ValueError):g.esw_vlan_definitions(wrong,spec,data,'HEADERS_AND_DEFINITIONS')
        for wrong in (dict(data,HEADER_KEYS=tuple(reversed(data['HEADER_KEYS']))),dict(data,CONFIG_NAMES=names[:-1])):
            with self.assertRaises(ValueError):g.esw_vlan_definitions(inputs,spec,wrong,'HEADERS_AND_DEFINITIONS')

    def test_esw_static_callback_table_registration_and_actual_translation_unit_are_bound(self):
        original=profile_inputs();proof=g.esw_ioctl_callback_binding(original)
        self.assertEqual(proof['actual_object_label'],'esw');self.assertEqual(proof['callback_linkage'],'static')
        self.assertTrue(proof['linked_vmlinux_symbol_required']);self.assertFalse(proof['relocated_callback_machine_code_equivalence_replayed'])
        for key,old,new in (('esw_ioctl','static long mtk_esw_ioctl','long mtk_esw_ioctl'),('esw_ioctl','.unlocked_ioctl = mtk_esw_ioctl','.unlocked_ioctl = other_ioctl'),('esw_ioctl','&mtk_esw_fops','&other_fops'),('esw_ioctl','if (r < 0)','if (r > 0)'),('esw_esw','#include "ioctl.c"','#include "other.c"'),('raeth_makefile','mtk_esw/ioctl_mt762x.o','mtk_esw/ioctl.o')):
            wrong=dict(original);wrong[key]=wrong[key].replace(old,new)
            with self.subTest(key=key,new=new),self.assertRaises(ValueError):g.esw_ioctl_callback_binding(wrong)
        wrong=dict(original);wrong['esw_esw']*=2
        with self.assertRaises(ValueError):g.esw_ioctl_callback_binding(wrong)
        for label,names in (('esw',('mtk_esw_ioctl','esw_ioctl_init')),('reset_core',('reset_control_assert','reset_control_deassert','reset_control_put','__devm_reset_control_get'))):
            for name in names:self.assertIn(name,g.OBJECTS[label][2])
        self.assertEqual(len(g.OBJECTS),13)

    def test_reset_pointer_complete_body_parser_rejects_ambiguity_and_prototypes(self):
        reader=g.model.function
        body='static struct reset_control *__reset_control_get(void) { char *s="}"; /* { */ if (s) { return s; } return 0; }'
        self.assertEqual(reader(body,'__reset_control_get'),body)
        for text in (body+'\n'+body,'static struct reset_control *__reset_control_get(void);'):
            with self.assertRaises(ValueError):reader(text,'__reset_control_get')

    def test_exact_typed_case_observations_reject_bool_aliases(self):
        g.validate_rows(rows())
        for i,row in enumerate(rows()):
            for path in integer_paths(row['observed']):
                bad=rows();set_path(bad[i]['observed'],path,True)
                with self.subTest(case=row['case'],field=path),self.assertRaises(ValueError):g.validate_rows(bad)
        # Full MDIO command values and order are fixed, including nested arrays.
        index=next(i for i,r in enumerate(rows()) if r['inputs']['component']=='mdio' and len(r['observed']['controller_writes'])>=4)
        commands=rows()[index]['observed']['controller_writes']
        variants=([True]+commands[1:],[-1]+commands[1:],[2**32]+commands[1:],commands+commands[:1],commands[:-1],list(reversed(commands)),[commands[0]^1]+commands[1:])
        for altered in variants:
            bad=rows();bad[index]['observed']['controller_writes']=altered
            with self.subTest(commands=altered),self.assertRaises(ValueError):g.validate_rows(bad)

    def test_case_order_and_duplicate_missing_extra_rows_fail(self):
        r=rows()
        for bad in (r[:-1],r+r[:1],list(reversed(r))):
            with self.assertRaises(ValueError):g.validate_rows(bad)
        r[0]['extra']=0
        with self.assertRaises(ValueError):g.validate_rows(r)

    def test_declared_mips_probes_are_static_strict_and_inert(self):
        self.assertEqual(g.FLAGS,('-static','-std=gnu99','-Wall','-Wextra','-Werror','-pthread'))
        self.assertEqual(set(g.COMPONENT_FLAGS),set(g.COMPONENTS))
        for old in ('raeth','nor','proc','runtime','qtx','ioctl'):
            self.assertEqual(g.COMPONENT_FLAGS[old],())
        self.assertEqual(g.COMPONENT_FLAGS['mdio'],('-Wno-unused-parameter',))
        self.assertEqual(g.COMPONENT_FLAGS['esw'],('-Wno-unused-variable','-Wno-unused-parameter','-Wno-unused-but-set-variable'))
        self.assertEqual(g.COMPONENT_FLAGS['esw_vlan'],g.COMPONENT_FLAGS['esw'])
        self.assertEqual(g.COMPONENT_FLAGS['reset_lifecycle'],('-Wno-unused-parameter',))
        self.assertIn('physical DMA',' '.join(g.LIMITS));self.assertEqual(len(g.exports()),63)

    def test_kernel_board_and_ring_constants_are_required(self):
        g.source_profile(profile_inputs())
        for key,old,new in (('raeth_header','NUM 4','NUM 2'),('kernel_config','RAETH=y','RAETH=m'),
                           ('kernel_config','RESET_CONTROLLER=y','RESET_CONTROLLER=n'),('kernel_config','ESW_CONTROL=y','ESW_CONTROL=n'),('kernel_config','# CONFIG_RAETH_ETHTOOL is not set','CONFIG_RAETH_ETHTOOL=y'),('kernel_config','SPI_NOR=y','SPI_NOR=m'),('kernel_config','SOC_MT7621=y','SOC_MT7621=m'),('nor_header','BIT(0)','BIT(1)'),('nor_nor','40UL','50UL'),('proc_reg','mt7621','changed'),('proc_config','BIT(1)','BIT(2)'),('nor_header','READ=0','READ=1')):
            bad=profile_inputs();bad[key]=bad[key].replace(old,new)
            with self.subTest(key=key),self.assertRaises(ValueError):g.source_profile(bad)

        proof=g.source_profile(profile_inputs())
        self.assertEqual(proof['reference_functions'],3)
        owner=proof['receive_callback_binding']
        self.assertEqual(owner['execution'],'source-only-not-run')
        self.assertFalse(owner['inline_callee_standalone_symbol_required'])
        for key,old,new in (
            ('runtime_raeth','{ ei_receive(); }','{ other_receive(); }'),
            ('runtime_raeth','unsigned long unused','unsigned int unused'),
            ('runtime_raeth','static void ei_receive_tasklet','static void removed_callback'),
            ('runtime_raeth','ei_receive_tasklet, 0','ei_receive_workq, 0'),
            ('runtime_raeth','features & FE_INT_TASKLET','features & FE_INT_WORKQ'),
            ('runtime_raeth','if (err) goto fail_dma;','if (err) return 0;'),
            ('runtime_raeth','fe_features_config(ei_local);','other_features(ei_local);'),
            ('runtime_config','#define CONFIG_RA_NETWORK_TASKLET_BH','#define DISABLED_TASKLET'),
            ('runtime_config','FE_INT_TASKLET\tBIT(7)','FE_INT_TASKLET\tBIT(6)'),
            ('runtime_config','features |= FE_INT_TASKLET','features |= FE_INT_WORKQ')):
            bad=profile_inputs();assert old in bad[key];bad[key]=bad[key].replace(old,new)
            with self.subTest(callback_owner=(key,old)),self.assertRaises(ValueError):g.source_profile(bad)
        for extra in ('\nstatic void ei_receive_tasklet(unsigned long unused) { ei_receive(); }\n',):
            bad=profile_inputs();bad['runtime_raeth']+=extra
            with self.assertRaises(ValueError):g.source_profile(bad)

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

        # Selected source declarations are rendered exactly once before helpers.
        inputs,data,spec=mini()
        data['SOURCE_DECLARATIONS']={r'^(#define MODEL_STATUS 17)$':'raeth'}
        data['PREFIX']='SOURCE_DEFINITIONS\n'+data['PREFIX']
        spec['model_data_sha256']=g.model.model_data_hash(data)
        inputs['harness']='\n'.join(k+'='+repr(v)for k,v in data.items())
        original=inputs['driver']
        with patch.object(g,'SOURCE_PATHS',{'harness':'h.py','driver':'c.c'}),patch.object(g,'COMPONENTS',{'raeth':spec}),\
             patch.object(g,'CASES',(('raeth:one',{'component':'raeth','selector':'one'}),)),patch.object(g,'EXPECTED',{'raeth:one':data['EXPECTED_ROWS']['one']}):
            inputs['driver']='#define MODEL_STATUS 17\n'+original
            code,*_=g.generate(inputs,'raeth')
            self.assertEqual(code.count('#define MODEL_STATUS 17'),1)
            self.assertLess(code.index('#define MODEL_STATUS 17'),code.index('work(void)'))
            for declaration in ('','#define MODEL_STATUS 18\n','#define MODEL_STATUS 17\n'*2):
                inputs['driver']=declaration+original
                with self.subTest(declaration=declaration),self.assertRaises(ValueError):g.generate(inputs,'raeth')

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
