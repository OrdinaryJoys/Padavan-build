"""Inert initialization/DMA gate interfaces; no target, clone or device."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import check_target_init_dma_lifecycle as g
from test_target_resident_upgrade import elf as static_elf


def module_elf(names):
    """Data-only ET_REL with disjoint dynamic sections and complete name offsets."""
    names=tuple(names)
    labels=b'\0.text\0.shstrtab\0.strtab\0.symtab\0'
    strings=b'\0';offsets={}
    for name in names:
        offsets[name]=len(strings);strings+=name.encode()+b'\0'
    text=b''.join(struct.pack('<I',0x24020000|i)for i in range(len(names)))
    symbols=bytes(16)+b''.join(struct.pack('<IIIBBH',offsets[name],i*4,4,0x12,0,1)
                              for i,name in enumerate(names))
    raw=bytearray(0x100);parts=[]
    for payload in(text,labels,strings,symbols):
        raw.extend(bytes((-len(raw))%16));parts.append((len(raw),len(payload)));raw.extend(payload)
    raw.extend(bytes((-len(raw))%16));shoff=len(raw)
    rows=[(0,0,0,0,0,0,0,0,0,0),
          (labels.index(b'.text'),1,6,0,*parts[0],0,0,4,0),
          (labels.index(b'.shstrtab'),3,0,0,*parts[1],0,0,1,0),
          (labels.index(b'.strtab'),3,0,0,*parts[2],0,0,1,0),
          (labels.index(b'.symtab'),2,0,0,*parts[3],3,1,4,16)]
    for row in rows:raw.extend(struct.pack('<10I',*row))
    raw[:16]=b'\x7fELF\x01\x01\x01'+bytes(9)
    struct.pack_into('<HHIIIIIHHHHHH',raw,16,1,8,1,0,0,shoff,0x50001001,52,0,0,40,len(rows),2)
    return bytes(raw)


KERNEL_REFERENCE_BODIES = {'try_module_get': 'bool try_module_get(struct module *module)\n'
                   '{\n'
                   '\tbool ret = true;\n'
                   '\n'
                   '\tif (module) {\n'
                   '\t\tpreempt_disable();\n'
                   '\t\t/* Note: here, we can fail to get a reference */\n'
                   '\t\tif (likely(module_is_live(module) &&\n'
                   '\t\t\t   atomic_inc_not_zero(&module->refcnt) != 0))\n'
                   '\t\t\ttrace_module_get(module, _RET_IP_);\n'
                   '\t\telse\n'
                   '\t\t\tret = false;\n'
                   '\n'
                   '\t\tpreempt_enable();\n'
                   '\t}\n'
                   '\treturn ret;\n'
                   '}',
 'module_put': 'void module_put(struct module *module)\n'
               '{\n'
               '\tint ret;\n'
               '\n'
               '\tif (module) {\n'
               '\t\tpreempt_disable();\n'
               '\t\tret = atomic_dec_if_positive(&module->refcnt);\n'
               '\t\tWARN_ON(ret < 0);\t/* Failed to put refcount */\n'
               '\t\ttrace_module_put(module, _RET_IP_);\n'
               '\t\tpreempt_enable();\n'
               '\t}\n'
               '}',
 'try_release_module_ref': 'static int try_release_module_ref(struct module *mod)\n'
                           '{\n'
                           '\tint ret;\n'
                           '\n'
                           '\t/* Try to decrement refcnt which we set at loading */\n'
                           '\tret = atomic_sub_return(MODULE_REF_BASE, &mod->refcnt);\n'
                           '\tBUG_ON(ret < 0);\n'
                           '\tif (ret)\n'
                           '\t\t/* Someone can put this right now, recover with checking */\n'
                           '\t\tret = atomic_add_unless(&mod->refcnt, MODULE_REF_BASE, 0);\n'
                           '\n'
                           '\treturn ret;\n'
                           '}',
 'try_stop_module': 'static int try_stop_module(struct module *mod, int flags, int *forced)\n'
                    '{\n'
                    "\t/* If it's not unused, quit unless we're forcing. */\n"
                    '\tif (try_release_module_ref(mod) != 0) {\n'
                    '\t\t*forced = try_force_unload(flags);\n'
                    '\t\tif (!(*forced))\n'
                    '\t\t\treturn -EWOULDBLOCK;\n'
                    '\t}\n'
                    '\n'
                    '\t/* Mark it as dying. */\n'
                    '\tmod->state = MODULE_STATE_GOING;\n'
                    '\n'
                    '\treturn 0;\n'
                    '}',
 'module_is_live': 'static inline int module_is_live(struct module *mod)\n'
                   '{\n'
                   '\treturn mod->state != MODULE_STATE_GOING;\n'
                   '}'}


def fixture():
    inputs={k:'inert '+k for k in g.SOURCE_PATHS};specs=copy.deepcopy(g.COMPONENTS);models={}
    for c,s in specs.items():
        opts=[o for _,o in g.CASES if o['component']==c]
        d={'SOURCE_PATHS':s['paths'],'FUNCTION_SOURCES':s['functions'],'BODY_ORDER':tuple(s['functions']),
           'CASE_NAMES':tuple(o['selector']for o in opts),
           'EXPECTED_ROWS':{o['selector']:g.EXPECTED[c+':current:'+o['selector']]for o in opts},
           'PREFIX':'/* inert model */\n','SUFFIX':'\n/* CASE_ADMISSION */\n'}
        d['SOURCE_ONLY_FUNCTION_SOURCES']=s.get('source_only_functions',{})
        if c in g.SOURCE_ABI.get('model_variants',{}):d['MODEL_VARIANT']=copy.deepcopy(g.SOURCE_ABI['model_variants'][c])
        models[c]=d;s['model_data_sha256']=g.model_data_hash(d)
        inputs[s['harness_key']]='\n'.join(k+'='+repr(v)for k,v in d.items())+'\ndef generate_source():\n raise AssertionError("Do not execute generator")\n'
        for name,local in {**s['functions'],**s.get('source_only_functions',{})}.items():
            key=s['source_keys'][local]
            if inputs[key].startswith('inert '):inputs[key]=''
            body='NDIS_STATUS '+name+'(void) { return 0; }\n'
            if name=='rt_pci_probe':body='static int DEVINIT rt_pci_probe(struct pci_dev *pdev) {\n'+g.SOURCE_ABI['probe_rejection_fragment']+'\nreturn pci_enable_device(pdev);\n}\n'
            if name=='tm_init':body='NDIS_STATUS tm_init(void) {\n'+'\n'.join(g.SOURCE_ABI['cmwq_runtime_selector_fragments'])+'\nreturn 0;\n}\n'
            if name in g.SOURCE_ABI['beacon_lifecycle_fragments']:
                direct=''if name=='RTMPFreeAdapter'else'struct _PCI_HIF_T *hif = &pAd->PciHif;\n'
                body='NDIS_STATUS '+name+'(void) {\n'+direct+'\n'.join(g.SOURCE_ABI['beacon_lifecycle_fragments'][name])+'\nreturn 0;\n}\n'
            if name in g.SOURCE_ABI.get('wdev_retirement_fragments',{}):
                fragments='\n'.join(g.SOURCE_ABI['wdev_retirement_fragments'][name])
                # Fragment-order fixtures are parsed, never compiled/executed.
                # Supply any closing loop braces omitted by the selected fragments.
                closing='}\n'*(fragments.count('{')-fragments.count('}'))
                body='NDIS_STATUS '+name+'(void) {\n'+fragments+'\n'+closing+'return 0;\n}\n'
            if body not in inputs[key]:inputs[key]+=body
    inputs[specs['probe']['source_keys']['header']]+='\nBOOLEAN BcnContentLockInitialized;\n'
    inputs['os_header']='#define NDIS_STATUS_SUCCESS 0x00\n#define NDIS_STATUS_FAILURE 0x01\n#define NDIS_STATUS_INVALID_DATA 0x02\n#define NDIS_STATUS_RESOURCES 0x03\n#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)\n#define KTHREAD_SUPPORT 1\n#endif\n'
    inputs['wifi_config']='\n'.join(g.SOURCE_ABI['enabled_config']+g.SOURCE_ABI['disabled_config'])+'\n'
    make='DRV_NAME = mt_7615e\nifeq ($(CONFIG_CHIP_MT7615E),y)\nEXTRA_CFLAGS += -DMT7615 -DRTMP_MAC_PCI -DRTMP_PCI_SUPPORT -DLINUX\nendif\n'
    inputs['flags']=inputs['wifi_makefile']=make
    inputs['kernel_makefile']='VERSION = 4\nPATCHLEVEL = 4\nKBUILD_CFLAGS += -fno-strict-aliasing\n'
    inputs['driver_config']='HAS_RESOURCE_PRE_ALLOC=y\nHAS_RX_CUT_THROUGH=n\nHAS_CUT_THROUGH_DBG=n\nWFLAGS += -DERR_RECOVERY -DLINUX\n'
    inputs['chip']='MT7615_ChipCap.qm = FAST_PATH_QM;\nMT7615_ChipCap.qm_tm = TASKLET_METHOD;\nMT7615_ChipCap.hif_tm = TASKLET_METHOD;\n'+g.SOURCE_ABI['chip_hif_type_fragment']+'\n'
    inputs['irq_shim']=g.SOURCE_ABI['irq_quarantine_fragment']+'\n'
    inputs['module_core']='#define MODULE_REF_BASE\t1\n'+'\n'.join(v for n,v in KERNEL_REFERENCE_BODIES.items()if n!='module_is_live')+'\n'+g.SOURCE_ABI['no_force_unload_fragment']+'\n'
    inputs['module_header']=KERNEL_REFERENCE_BODIES['module_is_live']+'\n'+'\n'.join(g.SOURCE_ABI['module_reference_declarations'])+'\n'
    inputs[specs['dma']['source_keys']['chip_header']]='NDIS_STATUS (*FwInit)(struct _RTMP_ADAPTER *pAd);\nBOOLEAN (*hif_wait_dma_idle)(struct _RTMP_ADAPTER *pAd, INT round, INT wait_us);\n'
    by_path={}
    for key,path in g.SOURCE_PATHS.items():by_path.setdefault(path,[]).append(key)
    for keys in by_path.values():
        if len(keys)==1:continue
        bodies={};other=[]
        names={name for spec in specs.values() for name in
               (*spec['functions'],*spec.get('source_only_functions',{}))
               if any(spec['paths'][spec.get('functions',{}).get(name,spec.get('source_only_functions',{}).get(name))]
                      ==g.SOURCE_PATHS[key]for key in keys)}
        for key in keys:
            remainder=inputs[key]
            for name in names:
                try:body=g.function(remainder,name)
                except ValueError:continue
                if name in bodies:assert bodies[name]==body
                bodies[name]=body;remainder=remainder.replace(body,'')
            other.extend(remainder.splitlines())
        text='\n'.join(dict.fromkeys(other))+'\n'+'\n'.join(bodies.values())+'\n'
        for key in keys:inputs[key]=text
    return inputs,specs,models


def compiled_fixture():
    inputs,_,_=fixture();allnames=tuple(dict.fromkeys(n for _,_,names in g.COMPILED_OBJECTS.values()for n in names))
    mod=module_elf(allnames);agg=g.BUILT_MODULE.removesuffix('.ko')+'.o'
    files={'target-wifi-built.ko':mod,'target-wifi-shipped.ko':mod,
      'target-wifi-module.cmd':('ld -r -o '+g.BUILT_MODULE+' '+agg).encode(),
      'target-wifi-link.cmd':('ld -r -o '+agg+' '+' '.join(v[0]for v in g.COMPILED_OBJECTS.values())).encode()}
    for label,(path,_,names)in g.COMPILED_OBJECTS.items():
        stem='target-init-dma-lifecycle-'+label;files[stem+'.o']=module_elf(names)
        files[stem+'.cmd']=('gcc '+' '.join(g.REQUIRED_OBJECT_FLAGS)+' -c '+path[:-2]+'.c -o '+path).encode()
    parent={'schema_version':1,'status':'PASS','profile':'k2p-4.4','phase':'final-module-image-reference-bound',
      'source_sha256':{k:g.sha(inputs[k].encode())for k in ('wifi_makefile','wifi_config')},
      'required_cases':['factory'+str(i)for i in range(49)],'checks':[{}for _ in range(49)],
      'kernel_reference':{'image_sha256':'a'*64},'module_binding':{'status':'PASS',
      'exports':{n:g.sha(files[n])for n in g.PARENT_EXPORTS},'built_module':{'ELF':{'sha256':g.sha(mod)}},
      'shipped_module':{'ELF':{'sha256':g.sha(mod)},'path':g.SHIPPED_MODULE}}}
    return inputs,files,parent


class InitDmaGateTests(unittest.TestCase):
    def rows(self):return [{'case':n,'inputs':copy.deepcopy(o),'observed':copy.deepcopy(g.EXPECTED[n])}for n,o in g.CASES]

    def test_complete_pci_callback_qualifiers_and_braces_in_literals(self):
        for qualifier in ('DEVINIT','DEVEXIT'):
            body='static int '+qualifier+' lifecycle(void) { char close=\'}\'; const char *s="{"; /* } */ return close+s[0]; }'
            text='/* lifecycle() { } */\n'+body+'\nint unrelated(void) { return 0; }\n'
            self.assertEqual(g.function(text,'lifecycle'),body)
            with self.assertRaises(ValueError):g.function(text+'\n'+body,'lifecycle')

    def test_exact_current_ten_component_source_and_object_contract(self):
        g.validate_contract();g.validate_records(self.rows())
        self.assertEqual((len(g.CASES),len(g.SOURCE_PATHS),len(g.COMPILED_OBJECTS)),(489,150,39))
        self.assertEqual((len(g.compiled_export_names()),sum(len(row[2])for row in g.COMPILED_OBJECTS.values())),(78,144))
        self.assertEqual(set(g.COMPONENTS),{'init','dma','unwind','quarantine','command','vif','probe','cmwq','resource','wdev'})
        self.assertNotIn('-DCONFIG_PROPRIETARY_DRIVER',g.REQUIRED_OBJECT_FLAGS)
        relative,key,names=g.COMPILED_OBJECTS['probe_hdev']
        self.assertIn('hc_get_os_cookie',names)
        altered=tuple('other_accessor'if name=='hc_get_os_cookie'else name for name in names)
        with patch.dict(g.COMPILED_OBJECTS,{'probe_hdev':(relative,key,altered)}),self.assertRaises(ValueError):
            g.validate_contract()

    def test_every_typed_cell_schema_order_and_inventory_is_required(self):
        rows=self.rows()
        for bad in (rows[:-1],rows+rows[:1],list(reversed(rows))):
            with self.assertRaises(ValueError):g.validate_records(bad)
        for i,row in enumerate(rows):
            for j in range(len(row['observed'])):
                bad=copy.deepcopy(rows);bad[i]['observed'][j]=bool(bad[i]['observed'][j])
                with self.subTest(case=row['case'],column=j),self.assertRaises(ValueError):g.validate_records(bad)
        bad=copy.deepcopy(rows);bad[0]['extra']=0
        with self.assertRaises(ValueError):g.validate_records(bad)

    def test_literal_parser_never_runs_source_generator_or_top_level_code(self):
        inputs,specs,models=fixture()
        for c,s in specs.items():self.assertEqual(g.literal_data(inputs[s['harness_key']]),models[c])
        for tail in ('\nX=dangerous()','\nraise RuntimeError()','\nimport subprocess','\nX={"a":1,"a":2}'):
            with self.assertRaises((ValueError,KeyError)):g.literal_data(inputs[specs['init']['harness_key']]+tail)

    def test_three_renderers_keep_every_complete_function(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):
            for c,s in specs.items():
                code,manifest=g.generate_component(inputs,c)
                for n,key in s['functions'].items():
                    body=g.function(inputs[s['source_keys'][key]],n);self.assertEqual(code.count(body),1)
                    self.assertEqual(manifest[n]['full_body_sha256'],g.sha(body.encode()));self.assertEqual(manifest[n]['execution'],'whole-function')
                self.assertNotIn('CASE_ADMISSION',code)

    def test_reviewed_actual_prototype_marker_is_replaced_once_and_still_pinned(self):
        inputs,specs,models=fixture()
        component='init';spec=specs[component];data=copy.deepcopy(models[component])
        data['PREFIX']+='FUNCTION_DECLARATIONS\n'
        inputs[spec['harness_key']]='\n'.join(k+'='+repr(v)for k,v in data.items())
        spec['model_data_sha256']=g.model_data_hash(data)
        with patch.dict(g.COMPONENTS,specs):code,_=g.generate_component(inputs,component)
        self.assertNotIn('FUNCTION_DECLARATIONS',code)
        for name,key in spec['functions'].items():
            signature=g.function(inputs[spec['source_keys'][key]],name).split('{',1)[0].rstrip()+';'
            self.assertEqual(code.count(signature),1)
        data['PREFIX']+='FUNCTION_DECLARATIONS'
        inputs[spec['harness_key']]='\n'.join(k+'='+repr(v)for k,v in data.items())
        spec['model_data_sha256']=g.model_data_hash(data)
        with patch.dict(g.COMPONENTS,specs),self.assertRaises(ValueError):g.generate_component(inputs,component)

    def test_resealed_wrong_path_rows_admission_and_model_pin_fail(self):
        inputs,specs,models=fixture()
        for fault in ('path','rows','admission','model'):
            local=copy.deepcopy(inputs);current=copy.deepcopy(specs);d=copy.deepcopy(models['init'])
            if fault=='path':d['SOURCE_PATHS'][next(iter(d['SOURCE_PATHS']))]='wrong.c'
            elif fault=='rows':d['EXPECTED_ROWS'][next(iter(d['EXPECTED_ROWS']))][0]=True
            elif fault=='admission':d['SUFFIX']+='CASE_ADMISSION'
            else:d['PREFIX']+='changed'
            local[current['init']['harness_key']]='\n'.join(k+'='+repr(v)for k,v in d.items())
            if fault!='model':current['init']['model_data_sha256']=g.model_data_hash(d)
            with patch.dict(g.COMPONENTS,current),self.subTest(fault=fault),self.assertRaises(ValueError):g.generate_component(local,'init')

    def test_source_profile_close_reopen_and_kernel_stop_order(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):self.assertTrue(g.source_selection(inputs)['current_K2P_profile'])
        for key,old,new in [('chip','TASKLET_METHOD','CMWQ_METHOD'),('kernel_makefile','-fno-strict-aliasing','-fstrict-aliasing'),('driver_config','HAS_RESOURCE_PRE_ALLOC=y','HAS_RESOURCE_PRE_ALLOC=n'),('os_header','NDIS_STATUS_SUCCESS 0x00','NDIS_STATUS_SUCCESS 0x01'),('quarantine_pci',g.SOURCE_ABI['probe_rejection_fragment'],''),('irq_shim',g.SOURCE_ABI['irq_quarantine_fragment'],'if (pAd == NULL) {')]:
            with patch.dict(g.COMPONENTS,specs),self.subTest(key=key),self.assertRaises(ValueError):g.source_selection(dict(inputs,**{key:inputs[key].replace(old,new)}))
        bad=dict(inputs);bad['chip']=inputs['chip'].replace(g.SOURCE_ABI['chip_hif_type_fragment'],'')
        with patch.dict(g.COMPONENTS,specs),self.assertRaises(ValueError):g.source_selection(bad)
        probe=specs['probe']
        for name,fragments in g.SOURCE_ABI['beacon_lifecycle_fragments'].items():
            key=probe['source_keys'][probe['functions'][name]]
            for fragment in fragments:
                bad=dict(inputs);bad[key]=inputs[key].replace(fragment,'')
                with patch.dict(g.COMPONENTS,specs),self.subTest(function=name,fragment=fragment),self.assertRaises(ValueError):
                    g.source_selection(bad)
            bad=dict(inputs);bad[key]=inputs[key].replace('&pAd->PciHif','hc_get_hif_ctrl(pAd->hdev_ctrl)')
            with patch.dict(g.COMPONENTS,specs),self.subTest(function=name,direct_hif=False),self.assertRaises(ValueError):
                g.source_selection(bad)
            a,b=fragments[-2:];bad=dict(inputs)
            bad[key]=inputs[key].replace(a,'BEACON_ORDER_MARKER').replace(b,a).replace('BEACON_ORDER_MARKER',b)
            with patch.dict(g.COMPONENTS,specs),self.subTest(function=name,owner_order=False),self.assertRaises(ValueError):
                g.source_selection(bad)
        key=probe['source_keys']['header'];bad=dict(inputs)
        bad[key]=inputs[key].replace('BOOLEAN BcnContentLockInitialized;','')
        with patch.dict(g.COMPONENTS,specs),self.assertRaises(ValueError):g.source_selection(bad)
        key=probe['source_keys'][probe['functions']['RTMPFreeAdapter']];bad=dict(inputs)
        bad[key]=inputs[key].replace('hif = &pAd->PciHif;','NdisFreeSpinLock(&pAd->early_lock);\nhif = &pAd->PciHif;')
        with patch.dict(g.COMPONENTS,specs),self.assertRaisesRegex(ValueError,'every adapter lock'):g.source_selection(bad)

    def test_optional_cmwq_is_compiled_but_not_current_runtime_or_real_workqueue_execution(self):
        inputs,specs,models=fixture()
        with patch.dict(g.COMPONENTS,specs):proof=g.source_selection(inputs)
        cmwq=proof['cmwq_variant_contract']
        self.assertIs(cmwq['CMWQ_present_in_nonproprietary_compilation'],True)
        self.assertIs(cmwq['current_K2P_runtime_selects_CMWQ'],False)
        self.assertIs(cmwq['inert_CMWQ_model_execution_required'],True)
        self.assertIs(cmwq['real_Linux_workqueue_execution_performed'],False)
        self.assertIs(cmwq['FQ_SCH_SUPPORT_forbidden_in_actual_objects'],True)
        self.assertEqual(cmwq['current_K2P_qm_method'],cmwq['current_K2P_hif_method'])
        self.assertEqual(cmwq['current_K2P_qm_method'],'TASKLET_METHOD')
        key=specs['init']['source_keys']['tm']
        for fragment in g.SOURCE_ABI['cmwq_runtime_selector_fragments']:
            bad=dict(inputs);bad[key]=inputs[key].replace(fragment,'')
            with patch.dict(g.COMPONENTS,specs),self.subTest(fragment=fragment),self.assertRaises(ValueError):g.source_selection(bad)
        for component in ('probe','cmwq','resource','wdev'):
            current=copy.deepcopy(specs);bad=dict(inputs);data=copy.deepcopy(models[component])
            data['MODEL_VARIANT'][next(iter(data['MODEL_VARIANT']))]='changed'
            bad[current[component]['harness_key']]='\n'.join(k+'='+repr(v)for k,v in data.items())
            current[component]['model_data_sha256']=g.model_data_hash(data)
            with patch.dict(g.COMPONENTS,current),self.subTest(component=component),self.assertRaises(ValueError):g.source_selection(bad)

    def test_probe_and_cmwq_components_keep_full_current_functions_and_source_owners(self):
        probe=g.COMPONENTS['probe'];cmwq=g.COMPONENTS['cmwq']
        for name,suffix in [('rt_pci_probe','os/linux/pci_main_dev.c'),('RTMPAllocAdapterBlock','embedded/common/rtmp_init.c')]:
            self.assertIn(name,probe['functions'])
            self.assertTrue(probe['paths'][probe['functions'][name]].endswith(suffix))
        self.assertTrue({'tm_init','tm_exit','tm_quiesce','tm_wq_prepare','tm_wq_abort','tm_wq_publish','tm_wq_destroy'}<=set(cmwq['functions']))
        self.assertTrue(set(g.SOURCE_ABI['cmwq_compiled_entrypoints'])<=set(g.COMPILED_OBJECTS['tm'][2]))
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):variant=g.source_selection(inputs)['probe_variant_contract']
        self.assertIs(variant['model_uses_current_source_not_exact_current_preprocessor_profile'],True)
        self.assertIs(variant['inert_model_forces_MULTI_INF_SUPPORT'],True)
        self.assertIs(variant['actual_K2P_MULTI_INF_SUPPORT_enabled'],False)
        self.assertIs(variant['default_MIPS_model_MSI_enabled'],False)
        self.assertIs(variant['actual_K2P_kernel_MSI_enabled'],False)
        self.assertEqual(variant['actual_K2P_hif_type'],'HIF_MT')
        self.assertIs(variant['inert_beacon_model_HIF_MT'],True)
        self.assertIs(variant['beacon_content_lock_has_explicit_owner_flag'],True)
        self.assertIs(variant['beacon_destructor_precedes_all_adapter_lock_and_hdev_retirement'],True)
        self.assertIs(variant['beacon_fixture_is_real_kernel_ABI'],False)
        self.assertIs(variant['beacon_packet_and_lock_operations_are_inert_seams'],True)
        self.assertEqual(tuple(g.COMPILED_OBJECTS['probe_bcn'][2]),('bcn_buf_init','bcn_buf_deinit'))
        for name in g.COMPILED_OBJECTS['probe_bcn'][2]:
            self.assertEqual(probe['functions'][name],'bcn')
        for row in (
                ('drivers/net/wireless/mediatek/mt7615/embedded/common/other.o','probe_bcn',('bcn_buf_init','bcn_buf_deinit')),
                ('drivers/net/wireless/mediatek/mt7615/embedded/common/bcn.o','probe_free',('bcn_buf_init','bcn_buf_deinit')),
                ('drivers/net/wireless/mediatek/mt7615/embedded/common/bcn.o','probe_bcn',('other_beacon_init','bcn_buf_deinit'))):
            with patch.dict(g.COMPILED_OBJECTS,{'probe_bcn':row}),self.subTest(beacon_object=row),self.assertRaises(ValueError):
                g.validate_contract()
        self.assertNotIn('-DHIF_MT',g.REQUIRED_OBJECT_FLAGS)
        self.assertIn('-DMULTI_INF_SUPPORT',g.FORBIDDEN_OBJECT_FLAGS)
        self.assertEqual(len(g.COMPONENTS['resource']['functions']),17)
        for name in ('WcInit','WcExit','HdevHwResourceInit','hdev_resource_init','alloc_chip_cap_dep_data',
                     'alloc_chip_cap_dep_data_cmm','alloc_chip_cap_dep_data_pci','RtmpRaDevCtrlInit','RTMPInitPCIeDevice'):
            self.assertIn(name,g.COMPONENTS['resource']['functions'])
        with patch.dict(g.COMPONENTS,specs):resource=g.source_selection(inputs)['resource_variant_contract']
        self.assertIs(resource['current_IP_ASSEMBLY_enabled'],True)
        self.assertEqual(resource['inert_model_ring_counts'],[2,2])
        self.assertEqual(resource['NDIS_success_status'],0)
        self.assertIs(resource['real_driver_kernel_or_device_execution_performed'],False)
        self.assertIs(resource['hc_get_os_cookie_fixture_seam'],True)
        self.assertIs(resource['opaque_consumer_public_accessor_required'],True)

    def test_wdev_retirement_interface_order_and_actual_active_callers_are_required(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):claim=g.source_selection(inputs)['wdev_variant_contract']
        self.assertEqual(claim['complete_current_source_functions'],15)
        self.assertEqual(claim['inert_model_MBSS_slots'],3)
        for name in ('current_K2P_MBSS_enabled','current_K2P_APCLI_enabled',
                     'all_interface_close_precedes_wdev_and_config_retirement',
                     'published_main_wdev_retired_after_detach_before_config',
                     'failed_retirement_preserves_wdev_config_and_netdev',
                     'beacon_owners_retained_until_final_adapter_release'):
            self.assertIs(claim[name],True)
        for name in ('current_K2P_WDS_enabled','current_K2P_SNIFFER_enabled',
                     'real_netdev_kernel_or_device_execution_performed',
                     'fixture_struct_layout_is_real_kernel_ABI'):
            self.assertIs(claim[name],False)
        for name,fragments in g.SOURCE_ABI['wdev_retirement_fragments'].items():
            local=specs['wdev']['functions'][name];alias=specs['wdev']['source_keys'][local]
            for fragment in fragments:
                bad=dict(inputs);bad[alias]=inputs[alias].replace(fragment,'')
                with patch.dict(g.COMPONENTS,specs),self.subTest(function=name,fragment=fragment),self.assertRaises(ValueError):
                    g.source_selection(bad)
            a,b=fragments[-2:];bad=dict(inputs)
            bad[alias]=inputs[alias].replace(a,'WDEV_STAGE_MARKER').replace(b,a).replace('WDEV_STAGE_MARKER',b)
            with patch.dict(g.COMPONENTS,specs),self.subTest(function=name,order=False),self.assertRaises(ValueError):g.source_selection(bad)
        self.assertIn('-DAPCLI_SUPPORT',g.REQUIRED_OBJECT_FLAGS)
        self.assertIn('-DMBSS_SUPPORT',g.REQUIRED_OBJECT_FLAGS)
        self.assertTrue({'-DWDS_SUPPORT','-DCONFIG_SNIFFER_SUPPORT','-DSNIFFER_SUPPORT'}<=set(g.FORBIDDEN_OBJECT_FLAGS))
        for label,names in [('wdev_mbss',('MBSS_Init','MBSS_Remove')),('wdev_apcli',('APCli_Init',)),
                            ('wdev_vendor',('init_vie_ctrl','deinit_vie_ctrl','add_vie','find_oui_oitype'))]:
            self.assertEqual(tuple(g.COMPILED_OBJECTS[label][2]),names)
        body='PNET_DEV RtmpPhyNetDevInit(void *pAd, void *ops) { return NULL; }'
        self.assertEqual(g.function(body,'RtmpPhyNetDevInit'),body)

    def test_every_compiled_optional_workqueue_callback_is_required_by_actual_object_binding(self):
        inputs,files,parent=compiled_fixture()
        for label,required in [('tm',g.SOURCE_ABI['cmwq_compiled_entrypoints']),('probe_bcn',('bcn_buf_init','bcn_buf_deinit')),('wdev_mbss',('MBSS_Init','MBSS_Remove')),('wdev_apcli',('APCli_Init',)),('wdev_vendor',('init_vie_ctrl','deinit_vie_ctrl','add_vie','find_oui_oitype'))]:
            _,_,names=g.COMPILED_OBJECTS[label]
            for name in required:
                bad=dict(files);bad['target-init-dma-lifecycle-'+label+'.o']=module_elf(tuple(n for n in names if n!=name))
                with self.subTest(callback=name,location='object'),self.assertRaisesRegex(ValueError,'symbol'):
                    g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),bad,g.spi.inspect_elf)
                allnames=tuple(dict.fromkeys(n for _,_,ns in g.COMPILED_OBJECTS.values()for n in ns if n!=name))
                bad=dict(files);p=copy.deepcopy(parent);mod=module_elf(allnames)
                for member,field in [('target-wifi-built.ko','built_module'),('target-wifi-shipped.ko','shipped_module')]:
                    bad[member]=mod;p['module_binding'][field]['ELF']['sha256']=g.sha(mod)
                p['module_binding']['exports']={n:g.sha(bad[n])for n in g.PARENT_EXPORTS}
                with self.subTest(callback=name,location='module'),self.assertRaisesRegex(ValueError,'symbol'):
                    g.compiled_binding_from_bytes(inputs,json.dumps(p).encode(),bad,g.spi.inspect_elf)

    def test_actual_kernel_module_reference_sources_and_selected_unload_branch(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):proof=g.source_selection(inputs)
        self.assertIs(proof['module_unload_configured'],True)
        self.assertIs(proof['forced_module_unload_configured'],False)
        self.assertIs(proof['kernel_reference_functions_executed'],False)
        self.assertEqual(set(proof['kernel_module_reference_manifest']),set(KERNEL_REFERENCE_BODIES))
        for row in proof['kernel_module_reference_manifest'].values():
            self.assertEqual(row['execution'],'source-only-not-run')
        for key,old,new in (
            ('wifi_config','CONFIG_MODULE_UNLOAD=y','# CONFIG_MODULE_UNLOAD is not set'),
            ('wifi_config','# CONFIG_MODULE_FORCE_UNLOAD is not set','CONFIG_MODULE_FORCE_UNLOAD=y'),
            ('module_core','return -EWOULDBLOCK;','return 0;'),
            ('module_core','module_is_live(module) &&','true &&'),
            ('module_core','atomic_sub_return(MODULE_REF_BASE,','atomic_sub_return(0,'),
            ('module_core','return 0;\n}\n#endif /* CONFIG_MODULE_FORCE_UNLOAD */','return 1;\n}\n#endif /* CONFIG_MODULE_FORCE_UNLOAD */'),
            ('module_header','extern bool try_module_get(','extern int try_module_get(')):
            self.assertIn(old,inputs[key])
            with patch.dict(g.COMPONENTS,specs),self.subTest(key=key,old=old),self.assertRaises(ValueError):
                g.source_selection(dict(inputs,**{key:inputs[key].replace(old,new)}))

    def test_exact_sixteen_actual_exports_and_module_parent_binding(self):
        inputs,files,parent=compiled_fixture();expected={'target-init-dma-lifecycle-'+n+e for n in g.COMPILED_OBJECTS for e in ('.o','.cmd')}
        self.assertEqual(g.compiled_export_names(),expected);self.assertEqual(len(expected),2*len(g.COMPILED_OBJECTS))
        p=g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),files,g.spi.inspect_elf)
        self.assertEqual(set(p['objects']),set(g.COMPILED_OBJECTS));self.assertEqual(set(p['compiled_exports_sha256']),expected)
        for name in expected:
            bad=dict(files);bad.pop(name)
            with self.subTest(missing=name),self.assertRaises(ValueError):g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),bad,g.spi.inspect_elf)
        with self.assertRaises(ValueError):g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),dict(files,**{'target-init-dma-lifecycle-pci.o':b'old'}),g.spi.inspect_elf)

    def test_resealed_symbol_command_flags_and_parent_corruption_fail(self):
        inputs,files,parent=compiled_fixture()
        for fault in ('symbol','aggregate','parent-source','parent-cases','parent-phase',*g.FORBIDDEN_OBJECT_FLAGS,*g.REQUIRED_OBJECT_FLAGS):
            current,p=copy.deepcopy(files),copy.deepcopy(parent);path,_,names=g.COMPILED_OBJECTS[next(iter(g.COMPILED_OBJECTS))];stem='target-init-dma-lifecycle-'+next(iter(g.COMPILED_OBJECTS))
            if fault=='symbol':current[stem+'.o']=module_elf(names[:-1])
            elif fault=='aggregate':current['target-wifi-link.cmd']=current['target-wifi-link.cmd'].replace(path.encode(),b'wrong.o')
            elif fault=='parent-source':p['source_sha256']['wifi_config']='b'*64
            elif fault=='parent-cases':p['required_cases']=p['required_cases'][:-1]
            elif fault=='parent-phase':p['phase']='early-source-only'
            elif fault in g.FORBIDDEN_OBJECT_FLAGS:current[stem+'.cmd']+=(' '+fault).encode()
            else:current[stem+'.cmd']=current[stem+'.cmd'].replace(fault.encode(),b'')
            p['module_binding']['exports']={n:g.sha(current[n])for n in g.PARENT_EXPORTS}
            with self.subTest(fault=fault),self.assertRaises(ValueError):g.compiled_binding_from_bytes(inputs,json.dumps(p).encode(),current,g.spi.inspect_elf)

    def test_json_and_reader_reject_duplicates_nonfinite_alias_fifo_and_limit(self):
        for text in ('{"a":1,"a":2}','{"a":NaN}'):
            with self.assertRaises(ValueError):g.decode_json(text)
        with tempfile.TemporaryDirectory(prefix='init-dma-gate-reader-')as t:
            root=Path(t);f=root/'f';f.write_bytes(b'DATA');self.assertEqual(g.read_regular(f,4),b'DATA')
            alias=root/'alias';alias.symlink_to(f)
            with self.assertRaises((OSError,ValueError)):g.read_regular(alias,4)
            fifo=root/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError):g.read_regular(fifo,4)
            with self.assertRaises(ValueError):g.read_regular(f,3)

    def check_mode(self,final):
        inputs,specs,_=fixture();_,files,parent=compiled_fixture()
        with tempfile.TemporaryDirectory(prefix='init-dma-gate-private-mode-')as t:
            root=Path(t);trunk=root/'trunk';trunk.mkdir();(trunk/'.config').write_text('CONFIG_LINUXDIR=linux-4.4.x\nCONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')
            for key,relative in g.SOURCE_PATHS.items():
                p=root/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(inputs[key])
            output=root/'out/target-init-dma-lifecycle.json';output.parent.mkdir()
            parent_path=output.parent/'target-wifi-factory.json'
            if final:
                parent_path.write_text(json.dumps(parent))
                for name in g.PARENT_EXPORTS:(output.parent/name).write_bytes(files[name])
                for label,(relative,_,_)in g.COMPILED_OBJECTS.items():
                    obj=trunk/'linux-4.4.x'/relative;obj.parent.mkdir(parents=True,exist_ok=True)
                    stem='target-init-dma-lifecycle-'+label
                    obj.write_bytes(files[stem+'.o']);obj.with_name('.'+obj.name+'.cmd').write_bytes(files[stem+'.cmd'])
            selectors={(o['component'],o['selector']):g.EXPECTED[n]for n,o in g.CASES}
            commands=[]
            def run(argv,**kwargs):
                commands.append(argv)
                if argv[0]=='/inert/compiler':
                    Path(argv[argv.index('-o')+1]).write_bytes(bytes(static_elf()))
                    return SimpleNamespace(returncode=0,stdout='',stderr='')
                self.assertEqual(argv[0],'/inert/qemu');self.assertEqual(len(argv),3)
                return SimpleNamespace(returncode=0,stdout=json.dumps(selectors[(Path(argv[1]).name.removeprefix('target-init-dma-lifecycle-').removesuffix('-current'),argv[2])])+'\n',stderr='')
            with patch.dict(g.COMPONENTS,specs),patch.object(g.shutil,'which',return_value='/inert/qemu'),patch.object(g.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO()):
                # Snapshot before patch.dict restores the shared contract map.
                report=json.loads(json.dumps(g.check(trunk,Path('/inert/compiler'),output,not final,parent_path if final else None)))
            self.assertEqual(len(commands),len(g.CASES)+len(g.COMPONENTS));self.assertEqual(sum(c[0]=='/inert/compiler'for c in commands),len(g.COMPONENTS))
            self.assertEqual(len(report['checks']),len(g.CASES));g.validate_records(report['checks'])
            self.assertEqual(set(report['probes']),set(g.COMPONENTS))
            self.assertEqual(report['phase'],'final-module-reference-bound'if final else'early-source-only')
            self.assertEqual(json.loads(output.read_text()),report)
            for comp,probe in report['probes'].items():
                item=probe['current'];self.assertEqual(g.sha((output.parent/item['source_file']).read_bytes()),item['source_sha256'])
                stdout=json.loads((output.parent/item['stdout_file']).read_text());self.assertEqual(len(stdout),sum(o['component']==comp for _,o in g.CASES))
            if final:
                self.assertEqual(set(report['compiled_binding']['compiled_exports_sha256']),g.compiled_export_names())
                self.assertTrue(all((output.parent/name).is_file()for name in g.compiled_export_names()))
            else:
                self.assertIsNone(report['compiled_binding']);self.assertFalse(any((output.parent/name).exists()for name in g.compiled_export_names()))
            return report

    def test_preflight_emits_every_static_component_source_and_full_stdout(self):
        self.check_mode(False)
        with self.assertRaises(ValueError):g.check(Path('/unused'),Path('/unused'),Path('/unused'),False,None)

    def test_final_collects_all_sixteen_actual_object_exports_and_parent(self):
        self.check_mode(True)
        with self.assertRaises(ValueError):g.check(Path('/unused'),Path('/unused'),Path('/unused'),True,Path('/unused'))


    def test_source_only_outer_functions_and_known_busy_gap_are_explicit(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):proof=g.source_selection(inputs)
        self.assertIs(proof['known_busy_teardown_release_gap'],False)
        self.assertIs(proof['failed_idle_complete_owner_graph_retained_in_models'],True)
        self.assertIs(proof['terminal_reenable_rejected_in_models'],True)
        self.assertIs(proof['hardware_DMA_or_reset_executed'],False)
        self.assertTrue(any(proof['outer_function_manifest'].values()))
        for functions in proof['outer_function_manifest'].values():
            for row in functions.values():self.assertEqual(row['execution'],'source-only-not-run')


    def test_header_declarations_require_unique_complete_locked_source_matches(self):
        spec={'source_keys':{'header':'source'}}
        data={'SOURCE_DECLARATIONS':{r'^#define VALUE [^\n]+':'header'}}
        prefix='before\nSOURCE_DEFINITIONS\nafter'
        self.assertEqual(g.source_definitions({'source':'/* header */\n#define VALUE 7\n'},spec,data,prefix),
                         'before\n#define VALUE 7\nafter')
        for source,contract,template in (
                ('#define VALUE 7\n#define VALUE 8\n',data,prefix),
                ('#define OTHER 7\n',data,prefix),
                ('#define VALUE 7\n',data,prefix+'SOURCE_DEFINITIONS'),
                ('#define VALUE 7\n',{'SOURCE_DECLARATIONS':{r'(#define) (VALUE)':'header'}},prefix),
                ('#define VALUE 7\n',{'SOURCE_DECLARATIONS':{r'#define VALUE 7':'other'}},prefix)):
            with self.assertRaises(ValueError):g.source_definitions({'source':source},spec,contract,template)
        field={'SOURCE_FIELD_CONSTRAINTS':{r'UINT8 state;':'header'}}
        template='struct model { STATE_FIELDS };'
        self.assertEqual(g.source_definitions({'source':'UINT8 state;'},spec,field,template),
                         'struct model { UINT8 state; };')
        for source,contract,target in (
                ('UINT8 state; UINT8 state;',field,template),
                ('UINT16 state;',field,template),
                ('UINT8 state;',field,template+' STATE_FIELDS'),
                ('UINT8 state;',{},template),
                ('UINT8 state;',{'SOURCE_FIELD_CONSTRAINTS':[]},template)):
            with self.assertRaises(ValueError):g.source_definitions({'source':source},spec,contract,target)


if __name__=='__main__':unittest.main()
