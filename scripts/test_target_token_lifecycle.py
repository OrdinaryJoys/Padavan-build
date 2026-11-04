"""Self-contained inert token gate interfaces; no target, clone or device."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import check_target_token_lifecycle as g
from test_target_wifi_factory import module_elf
from test_target_resident_upgrade import elf as static_elf


def fixture():
    inputs={k:'inert '+k for k in g.SOURCE_PATHS};specs=copy.deepcopy(g.COMPONENTS);models={}
    for c,s in specs.items():
        opts=[o for _,o in g.CASES if o['component']==c]
        d={'SOURCE_PATHS':s['paths'],'FUNCTION_SOURCES':s['functions'],'BODY_ORDER':tuple(s['functions']),
           'CASE_NAMES':tuple(o['selector']for o in opts),
           'EXPECTED_ROWS':{o['selector']:g.EXPECTED[c+':current:'+o['selector']]for o in opts},
           'PREFIX':'struct lock {int inert;};\nstatic int __RtmpOSTaskKill(OS_TASK *p);\n','SUFFIX':'\n/* CASE_ADMISSION */\n'}
        models[c]=d;s['model_data_sha256']=g.model_data_hash(d)
        inputs[s['harness_key']]='\n'.join(k+'='+repr(v)for k,v in d.items())+'\ndef generate_source():\n raise AssertionError("Do not execute generator")\n'
        for name,local in s['functions'].items():
            key=s['source_keys'][local]
            if inputs[key].startswith('inert '):inputs[key]=''
            body='NDIS_STATUS '+name+'(void) { return 0; }\n'
            if body not in inputs[key]:inputs[key]+=body
    t=specs['token']['source_keys'];s=specs['ser']['source_keys']
    inputs[t['header']]='\n'.join('typedef struct _PKT_TOKEN_'+n+' { int inert; } PKT_TOKEN_'+n+';'for n in ('ENTRY','LIST','QUEUE','CB'))+'\n#define DEFAUT_PKT_TX_TOKEN_ID_MAX 4095\n'
    inputs[t['os_header']]='#define NDIS_STATUS_SUCCESS 0x00\n#define NDIS_STATUS_FAILURE 0x01\n#define NDIS_STATUS_INVALID_DATA 0x02\n#define NDIS_STATUS_RESOURCES 0x03\n#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)\n#define KTHREAD_SUPPORT 1\n#endif\n'
    inputs[s['header']]='typedef enum _ERR_RECOVERY_STATE { X } ERR_RECOVERY_STATE, *P_ERR_RECOVERY_STATE;\ntypedef struct _ERR_RECOVERY_CTRL_T { int inert; } ERR_RECOVERY_CTRL_T;\n'
    inputs[s['task_header']]='typedef enum _RTMP_TASK_STATUS_ { Z } RTMP_TASK_STATUS;\n#define RTMP_OS_TASK_NAME_LEN 16\n'
    inputs[s['flag_header']]='#define fRTMP_ADAPTER_HALT_IN_PROGRESS 0x40\n'
    names=('ERROR_DETECT_STOP_PDMA_WITH_FW_RELOAD','ERROR_DETECT_STOP_PDMA','ERROR_DETECT_RESET_DONE','ERROR_DETECT_RECOVERY_DONE','ERROR_DETECT_N9_NORMAL_STATE','ERROR_DETECT_LMAC_ERROR','ERROR_DETECT_PSE_ERROR','ERROR_DETECT_PLE_ERROR','ERROR_DETECT_PDMA_ERROR','ERROR_DETECT_PCIE_ERROR','ERROR_DETECT_MASK','MCU_INT_PDMA0_STOP_DONE','MCU_INT_PDMA0_INIT_DONE','MCU_INT_PDMA0_RECOVERY_DONE')
    inputs[s['wire_header']]='\n'.join('#define '+n+' BIT(1)'for n in names)+'\n'
    inputs[s['close']]='''VOID RTMPDrvClose(void) {
RTMP_OS_IRQ_RELEASE(pAd,net_dev);
HwCtrlSerExit(pAd);
tr_ctl_exit(pAd);
if (!pAd->ErrRecoveryCtl.queues_retired) {
tm_exit(pAd);
qm_exit(pAd);
pAd->ErrRecoveryCtl.queues_retired = TRUE;
}
}
INT rtmp_sys_init(void) { HwCtrlInit(pAd); qm_init(pAd); tm_init(pAd); return 0; }
'''
    inputs[s['basic']]+='VOID HwCtrlExit(void) { HwCtrlSerExit(pAd); HwCtrlCmdHandler(pAd); ser_exit(pAd); }\n'
    inputs['kernel_kthread']='int kthread_stop(void) { get_task_struct(k); wait_for_completion(&kthread->exited); ret = k->exit_code; put_task_struct(k); return ret; }\n'
    inputs['wifi_config']='\n'.join(g.SOURCE_ABI['enabled_config']+g.SOURCE_ABI['disabled_config'])+'\n'
    make='DRV_NAME = mt_7615e\nifeq ($(CONFIG_CHIP_MT7615E),y)\nEXTRA_CFLAGS += -DMT7615 -DRTMP_MAC_PCI -DRTMP_PCI_SUPPORT\nendif\n'
    inputs['flags']=inputs['wifi_makefile']=make
    inputs['kernel_makefile']='VERSION = 4\nPATCHLEVEL = 4\nKBUILD_CFLAGS += -fno-strict-aliasing\n'
    inputs['driver_config']='HAS_RESOURCE_PRE_ALLOC=y\nHAS_RX_CUT_THROUGH=n\nHAS_CUT_THROUGH_DBG=n\nWFLAGS += -DERR_RECOVERY\n'
    inputs['chip']='MT7615_ChipCap.qm_tm = TASKLET_METHOD;\nMT7615_ChipCap.hif_tm = TASKLET_METHOD;\n'
    return inputs,specs,models


def compiled_fixture():
    inputs,_,_=fixture();allnames=tuple(n for _,_,names in g.COMPILED_OBJECTS.values()for n in names)
    mod=module_elf(allnames);agg=g.BUILT_MODULE.removesuffix('.ko')+'.o'
    files={'target-wifi-built.ko':mod,'target-wifi-shipped.ko':mod,
      'target-wifi-module.cmd':('ld -r -o '+g.BUILT_MODULE+' '+agg).encode(),
      'target-wifi-link.cmd':('ld -r -o '+agg+' '+' '.join(v[0]for v in g.COMPILED_OBJECTS.values())).encode()}
    for label,(path,_,names)in g.COMPILED_OBJECTS.items():
        stem='target-token-lifecycle-'+label;files[stem+'.o']=module_elf(names)
        files[stem+'.cmd']=('gcc '+' '.join(g.REQUIRED_OBJECT_FLAGS)+' -c '+path[:-2]+'.c -o '+path).encode()
    parent={'schema_version':1,'status':'PASS','profile':'k2p-4.4','phase':'final-module-image-reference-bound',
      'source_sha256':{k:g.sha(inputs[k].encode())for k in ('wifi_makefile','wifi_config')},
      'required_cases':['factory'+str(i)for i in range(49)],'checks':[{}for _ in range(49)],
      'kernel_reference':{'image_sha256':'a'*64},'module_binding':{'status':'PASS',
      'exports':{n:g.sha(files[n])for n in g.PARENT_EXPORTS},'built_module':{'ELF':{'sha256':g.sha(mod)}},
      'shipped_module':{'ELF':{'sha256':g.sha(mod)},'path':g.SHIPPED_MODULE}}}
    return inputs,files,parent


class TokenLifecycleGateTests(unittest.TestCase):
    def rows(self):return [{'case':n,'inputs':copy.deepcopy(o),'observed':copy.deepcopy(g.EXPECTED[n])}for n,o in g.CASES]

    def test_fixed_forty_cases_three_components_and_eight_objects(self):
        g.validate_contract();g.validate_records(self.rows())
        self.assertEqual((len(g.CASES),len(g.SOURCE_PATHS),len(g.COMPILED_OBJECTS)),(47,24,8))
        self.assertEqual({k:len(v['functions'])for k,v in g.COMPONENTS.items()},{'token':6,'ser':7,'task':3})
        self.assertNotIn('-DCONFIG_PROPRIETARY_DRIVER',g.REQUIRED_OBJECT_FLAGS)

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
            with self.assertRaises((ValueError,KeyError)):g.literal_data(inputs[specs['token']['harness_key']]+tail)

    def test_three_renderers_keep_every_complete_function(self):
        inputs,specs,_=fixture()
        with patch.dict(g.COMPONENTS,specs):
            for c,s in specs.items():
                code,manifest=g.generate_component(inputs,c)
                for n,key in s['functions'].items():
                    body=g.function(inputs[s['source_keys'][key]],n);self.assertEqual(code.count(body),1)
                    self.assertEqual(manifest[n]['full_body_sha256'],g.sha(body.encode()));self.assertEqual(manifest[n]['execution'],'whole-function')
                self.assertNotIn('CASE_ADMISSION',code)

    def test_resealed_wrong_path_rows_admission_and_model_pin_fail(self):
        inputs,specs,models=fixture()
        for fault in ('path','rows','admission','model'):
            local=copy.deepcopy(inputs);current=copy.deepcopy(specs);d=copy.deepcopy(models['token'])
            if fault=='path':d['SOURCE_PATHS']['token']='wrong.c'
            elif fault=='rows':d['EXPECTED_ROWS']['token-normal'][0]=True
            elif fault=='admission':d['SUFFIX']+='CASE_ADMISSION'
            else:d['PREFIX']+='changed'
            local[current['token']['harness_key']]='\n'.join(k+'='+repr(v)for k,v in d.items())
            if fault!='model':current['token']['model_data_sha256']=g.model_data_hash(d)
            with patch.dict(g.COMPONENTS,current),self.subTest(fault=fault),self.assertRaises(ValueError):g.generate_component(local,'token')

    def test_source_profile_close_reopen_and_kernel_stop_order(self):
        inputs,_,_=fixture();self.assertTrue(g.source_selection(inputs)['KTHREAD_current_profile'])
        for key,old,new in [('chip','TASKLET_METHOD','CMWQ_METHOD'),('kernel_makefile','-fno-strict-aliasing','-fstrict-aliasing'),('driver_config','HAS_RESOURCE_PRE_ALLOC=y','HAS_RESOURCE_PRE_ALLOC=n'),(g.COMPONENTS['ser']['source_keys']['close'],'HwCtrlSerExit(pAd);','late_ser(pAd);'),('kernel_kthread','ret = k->exit_code;','ret = 0;')]:
            with self.subTest(key=key),self.assertRaises(ValueError):g.source_selection(dict(inputs,**{key:inputs[key].replace(old,new)}))

    def test_exact_sixteen_actual_exports_and_module_parent_binding(self):
        inputs,files,parent=compiled_fixture();expected={'target-token-lifecycle-'+n+e for n in ('token','hif','hardware','recovery','basic','command','os','close')for e in ('.o','.cmd')}
        self.assertEqual(g.compiled_export_names(),expected);self.assertEqual(len(expected),16)
        p=g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),files,g.spi.inspect_elf)
        self.assertEqual(set(p['objects']),set(g.COMPILED_OBJECTS));self.assertEqual(set(p['compiled_exports_sha256']),expected)
        for name in expected:
            bad=dict(files);bad.pop(name)
            with self.subTest(missing=name),self.assertRaises(ValueError):g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),bad,g.spi.inspect_elf)
        with self.assertRaises(ValueError):g.compiled_binding_from_bytes(inputs,json.dumps(parent).encode(),dict(files,**{'target-token-lifecycle-pci.o':b'old'}),g.spi.inspect_elf)

    def test_resealed_symbol_command_flags_and_parent_corruption_fail(self):
        inputs,files,parent=compiled_fixture()
        for fault in ('symbol','aggregate','parent-source','parent-cases','parent-phase',*g.FORBIDDEN_OBJECT_FLAGS,*g.REQUIRED_OBJECT_FLAGS):
            current,p=copy.deepcopy(files),copy.deepcopy(parent);path,_,names=g.COMPILED_OBJECTS['os'];stem='target-token-lifecycle-os'
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
        with tempfile.TemporaryDirectory(prefix='token-gate-reader-')as t:
            root=Path(t);f=root/'f';f.write_bytes(b'DATA');self.assertEqual(g.read_regular(f,4),b'DATA')
            alias=root/'alias';alias.symlink_to(f)
            with self.assertRaises((OSError,ValueError)):g.read_regular(alias,4)
            fifo=root/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError):g.read_regular(fifo,4)
            with self.assertRaises(ValueError):g.read_regular(f,3)

    def check_mode(self,final):
        inputs,specs,_=fixture();_,files,parent=compiled_fixture()
        with tempfile.TemporaryDirectory(prefix='token-gate-private-mode-')as t:
            root=Path(t);trunk=root/'trunk';trunk.mkdir();(trunk/'.config').write_text('CONFIG_LINUXDIR=linux-4.4.x\nCONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')
            for key,relative in g.SOURCE_PATHS.items():
                p=root/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(inputs[key])
            output=root/'out/target-token-lifecycle.json';output.parent.mkdir()
            parent_path=output.parent/'target-wifi-factory.json'
            if final:
                parent_path.write_text(json.dumps(parent))
                for name in g.PARENT_EXPORTS:(output.parent/name).write_bytes(files[name])
                for label,(relative,_,_)in g.COMPILED_OBJECTS.items():
                    obj=trunk/'linux-4.4.x'/relative;obj.parent.mkdir(parents=True,exist_ok=True)
                    stem='target-token-lifecycle-'+label
                    obj.write_bytes(files[stem+'.o']);obj.with_name('.'+obj.name+'.cmd').write_bytes(files[stem+'.cmd'])
            selectors={o['selector']:g.EXPECTED[n]for n,o in g.CASES}
            commands=[]
            def run(argv,**kwargs):
                commands.append(argv)
                if argv[0]=='/inert/compiler':
                    Path(argv[argv.index('-o')+1]).write_bytes(bytes(static_elf()))
                    return SimpleNamespace(returncode=0,stdout='',stderr='')
                self.assertEqual(argv[0],'/inert/qemu');self.assertEqual(len(argv),3)
                return SimpleNamespace(returncode=0,stdout=json.dumps(selectors[argv[2]])+'\n',stderr='')
            with patch.dict(g.COMPONENTS,specs),patch.object(g.shutil,'which',return_value='/inert/qemu'),patch.object(g.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO()):
                # Snapshot before patch.dict restores the shared contract map.
                report=json.loads(json.dumps(g.check(trunk,Path('/inert/compiler'),output,not final,parent_path if final else None)))
            self.assertEqual(len(commands),50);self.assertEqual(sum(c[0]=='/inert/compiler'for c in commands),3)
            self.assertEqual(len(report['checks']),47);g.validate_records(report['checks'])
            self.assertEqual(set(report['probes']),{'token','ser','task'})
            self.assertEqual(report['phase'],'final-module-reference-bound'if final else'early-source-only')
            self.assertEqual(json.loads(output.read_text()),report)
            for comp,probe in report['probes'].items():
                item=probe['current'];self.assertEqual(g.sha((output.parent/item['source_file']).read_bytes()),item['source_sha256'])
                stdout=json.loads((output.parent/item['stdout_file']).read_text());self.assertEqual(len(stdout),{'token':18,'ser':22,'task':7}[comp])
            if final:
                self.assertEqual(set(report['compiled_binding']['compiled_exports_sha256']),g.compiled_export_names())
                self.assertTrue(all((output.parent/name).is_file()for name in g.compiled_export_names()))
            else:
                self.assertIsNone(report['compiled_binding']);self.assertFalse(any((output.parent/name).exists()for name in g.compiled_export_names()))
            return report

    def test_preflight_emits_all_three_static_probe_sources_and_full_stdout(self):
        self.check_mode(False)
        with self.assertRaises(ValueError):g.check(Path('/unused'),Path('/unused'),Path('/unused'),False,None)

    def test_final_collects_all_sixteen_actual_object_exports_and_parent(self):
        self.check_mode(True)
        with self.assertRaises(ValueError):g.check(Path('/unused'),Path('/unused'),Path('/unused'),True,Path('/unused'))


if __name__=='__main__':unittest.main()
