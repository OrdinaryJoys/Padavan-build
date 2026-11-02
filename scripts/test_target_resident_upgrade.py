#!/usr/bin/env python3
"""Independent failure controls for the resident source and shipped-ELF gate."""
import copy
import importlib.util
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).with_name('check_target_resident_upgrade.py')
spec=importlib.util.spec_from_file_location('resident_gate_tests',PATH)
gate=importlib.util.module_from_spec(spec)
exec(compile(PATH.read_text(),str(PATH),'exec'),gate.__dict__)


def elf(symbol=None,label='external',info=16,value=0,size=0,other=0,table_kind=2):
    data=bytearray(1024)
    data[:7]=b'\x7fELF\x01\x01\x01'
    struct.pack_into('<HHIIIIIHHHHHH',data,16,2,8,1,0x400080,52,0,0,52,32,1,0,0,0)
    struct.pack_into('<8I',data,52,1,0,0x400000,0,512,512,5,4096)
    if symbol is not None:
        struct.pack_into('<I',data,32,512)
        struct.pack_into('<HH',data,46,40,3)
        strings=b'\0'+label.encode()+b'\0'
        struct.pack_into('<10I',data,552,0,3,0,0,800,len(strings),0,0,1,0)
        struct.pack_into('<10I',data,592,0,table_kind,0,0,832,32,1,0,4,16)
        data[800:800+len(strings)]=strings
        struct.pack_into('<IIIBBH',data,848,1,value,size,info,other,symbol)
    return data


def records():
    return [{'case':name,'inputs':copy.deepcopy(options),'observed':copy.deepcopy(gate.EXPECTED[name])}
            for name,options in gate.CASES]


def inputs_for(adapter):
    values={key:'/* '+key+' */\n' for key in gate.SOURCE_PATHS}
    for name,key in gate.ADAPTERS[adapter]['functions'].items():
        values[key]+=('int ' if name=='main' else 'static int ')+name+'(void){return 0;}\n'
    if adapter in ('parent','consumer'):
        values[gate.ADAPTERS[adapter]['source_keys']['rc']] += '#define FW_UPGRADE_NOT_STARTED (-2)\n'
    return values


def module_for(adapter):
    adapter_spec=gate.ADAPTERS[adapter]
    cases=tuple((options['selector'],gate.EXPECTED[name]) for name,options in gate.CASES
                if options['adapter']==adapter)
    text='SOURCE_PATHS='+repr(adapter_spec['source_paths'])+'\nCASES='+repr(cases)+'\n'
    if 'case_args' in adapter_spec:text+='CASE_ARGS='+repr(adapter_spec['case_args'])+'\n'
    text+='def generate_source(texts, fixture_root, owner_uid=0, **options):\n'
    if 'enabled' in adapter_spec:text+=' assert options["enabled"] is '+repr(adapter_spec['enabled'])+'\n'
    text+=' result="\\n".join(texts.values())\n'
    for name,new in adapter_spec.get('renames',{}).items():
        text+=' result=result.replace('+repr('int '+name+'(')+','+repr('int '+new+'(')+',1)\n'
    return text+' return result\n'


class ResidentTargetTests(unittest.TestCase):
    def test_independent_fixed_case_counts(self):
        self.assertEqual(len(gate.CASES),111)
        self.assertEqual({name:sum(options['adapter']==name for _,options in gate.CASES)
                          for name in gate.ADAPTERS},
                         {'helper':35,'legacy':44,'legacy-disabled':1,'parent':20,'consumer':11})
        self.assertEqual(len(gate.SHIPPED_CASES),5)
        gate.validate_records(records())

    def test_missing_extra_duplicate_and_reordered_records_fail(self):
        rows=records()
        for invalid in ([],rows[:-1],rows+[rows[0]],rows[:1]+rows[:-1],list(reversed(rows))):
            with self.subTest(rows=len(invalid)),self.assertRaises(ValueError):gate.validate_records(invalid)

    def test_wrong_result_reset_mask_and_effect_trace_fail(self):
        mutations=(('helper:verified-reset-zero','trace',['writer-calls:1','writer-result:0','reboot-calls:1','exit:0','fd-balance:1','canonical-exclusion:1']),
                   ('legacy:reboot-storage-read','trace','raw-reboot'),
                   (next(name for name,_ in gate.CASES if name.startswith('parent:')),'parent_mask_restored',0),
                   ('consumer:consumer-unknown','post',[0,0,1,0,0,0]))
        for name,key,value in mutations:
            rows=records();row=next(row for row in rows if row['case']==name)
            row['observed'][key]=value
            with self.subTest(case=name),self.assertRaises(ValueError):gate.validate_records(rows)

    def test_json_integer_boolean_and_row_schema_are_distinct(self):
        rows=records();rows[-1]['observed']['active']=True
        with self.assertRaises(ValueError):gate.validate_records(rows)
        rows=records();rows[0]['extra']=1
        with self.assertRaises(ValueError):gate.validate_records(rows)
        rows=records();rows[0]['inputs']['selector']='different'
        with self.assertRaises(ValueError):gate.validate_records(rows)

    def test_static_elf_no_loader_or_named_import(self):
        row=gate.validate_static_helper(elf())
        self.assertTrue(row['static_no_runtime_loader'])
        self.assertIsNone(row['PT_INTERP'])
        self.assertEqual(row['named_undefined_imports'],[])
        self.assertEqual(row['source_only_mips_linker_pseudo_symbols'],[])
        with self.assertRaisesRegex(ValueError,'undefined'):gate.validate_static_helper(elf(0))
        with self.assertRaisesRegex(ValueError,'undefined'):gate.validate_static_helper(elf(0),source_weak_symbols=True)
        weak=elf(0);weak[848+12]=32
        with self.assertRaisesRegex(ValueError,'undefined'):gate.validate_static_helper(weak)
        self.assertEqual(gate.validate_static_helper(weak,source_weak_symbols=True)
                         ['source_only_weak_undefined_symbols'],['external'])
        self.assertEqual(gate.validate_static_helper(elf(0xfff1))['symbol_tables'][0]['symbols'],2)
        for name in ('__gnu_local_gp','_gp_disp'):
            for symbol_type in (0,1):
                data=elf(0,label=name,info=16|symbol_type)
                for options in ({},{'source_weak_symbols':True}):
                    with self.assertRaisesRegex(ValueError,'undefined'):
                        gate.validate_static_helper(data,**options)
                observed=gate.validate_static_helper(data,source_mips_pseudo_symbols=True)
                self.assertEqual(observed['source_only_mips_linker_pseudo_symbols'],[
                    {'name':name,'table':'SYMTAB','binding':1,'type':symbol_type,
                     'value':0,'size':0,'other':0,'shndx':0}])
            for changes in ({'label':'_gp_disp_extra'},{'label':'real_import'},{'info':18},
                            {'info':32},{'info':0},{'value':1},{'size':1},{'other':2},{'table_kind':11}):
                options={'label':name};options.update(changes)
                data=elf(0,**options)
                with self.subTest(name=name,changes=changes),self.assertRaisesRegex(ValueError,'undefined'):
                    gate.validate_static_helper(data,source_weak_symbols=True,source_mips_pseudo_symbols=True)
        with self.assertRaisesRegex(ValueError,'MIPS-pseudo'):
            gate.validate_static_helper(elf(),source_mips_pseudo_symbols=1)

    def test_loader_dynamic_wrong_arch_bounds_and_nonexec_rejected(self):
        variants=[]
        for kind in (2,3):
            data=elf();struct.pack_into('<I',data,52,kind);variants.append(data)
        data=elf();struct.pack_into('<H',data,18,62);variants.append(data)
        data=elf();data[5]=2;variants.append(data)
        data=elf();struct.pack_into('<I',data,28,1020);variants.append(data)
        data=elf();struct.pack_into('<I',data,24,0x500000);variants.append(data)
        data=elf();struct.pack_into('<I',data,76,4);variants.append(data)
        data=elf();struct.pack_into('<I',data,68,2048);variants.append(data)
        data=elf();struct.pack_into('<I',data,80,3);variants.append(data)
        for data in variants:
            with self.subTest(data=data[:84].hex()),self.assertRaises(ValueError):gate.validate_static_helper(data)

    def test_symbol_table_bounds_fail(self):
        for offset,value in ((592+24,9),(592+36,8),(848,11),(552+20,10000)):
            data=elf(0xfff1);struct.pack_into('<I',data,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):gate.validate_static_helper(data)

    def test_all_actual_source_bodies_and_embedded_headers_required_once(self):
        for adapter in gate.ADAPTERS:
            values=inputs_for(adapter);values[gate.ADAPTERS[adapter]['harness']]=module_for(adapter)
            generated,actual=gate.generate_source(values,'/tmp/inert-fixture',0,adapter)
            self.assertEqual(set(actual),set(gate.ADAPTERS[adapter]['functions']))
            for key in gate.ADAPTERS[adapter].get('embedded_headers',[]):
                self.assertEqual(generated.count(values[key]),1)

    def test_omitted_or_duplicated_actual_function_rejected(self):
        for transform in ('return result.replace("return 0;","")','return result+result'):
            values=inputs_for('parent');values['parent_harness']=module_for('parent').replace('return result',transform)
            with self.assertRaisesRegex(ValueError,'omitted/duplicated'):
                gate.generate_source(values,'/tmp/inert-fixture',0,'parent')

    def test_source_contract_case_contract_and_legacy_argv_drift_fail(self):
        for adapter,old,new in (('parent','trunk/user/rc/rc.c','trunk/user/rc/other.c'),
                                ('parent','parent_mask_restored','mask_forgotten'),
                                ('legacy','--upgrade-write','--uncontrolled-write')):
            values=inputs_for(adapter);key=gate.ADAPTERS[adapter]['harness']
            values[key]=module_for(adapter).replace(old,new)
            with self.subTest(adapter=adapter),self.assertRaises(ValueError):
                gate.generate_source(values,'/tmp/inert-fixture',0,adapter)

    def test_ambiguous_body_mapping_owner_type_and_missing_input_fail(self):
        values=inputs_for('parent');values['parent_harness']=module_for('parent')
        with self.assertRaises(ValueError):gate.generate_source(values,'/tmp/inert-fixture',True,'parent')
        invalid=dict(values);invalid.pop('parent_rc')
        with self.assertRaises(ValueError):gate.generate_source(invalid,'/tmp/inert-fixture',0,'parent')
        values['parent_rc']+=values['parent_rc']
        with self.assertRaises(ValueError):gate.generate_source(values,'/tmp/inert-fixture',0,'parent')

    def test_no_child_sentinel_is_bound_to_actual_rc_macro(self):
        for adapter in ('parent','consumer'):
            values=inputs_for(adapter);values[gate.ADAPTERS[adapter]['harness']]=module_for(adapter)
            key=gate.ADAPTERS[adapter]['source_keys']['rc']
            for changed in ('#define FW_UPGRADE_NOT_STARTED (-1)',
                            '#define FW_UPGRADE_NOT_STARTED (-2)\n#define FW_UPGRADE_NOT_STARTED (-1)', ''):
                invalid=dict(values);invalid[key]=invalid[key].replace('#define FW_UPGRADE_NOT_STARTED (-2)',changed)
                with self.subTest(adapter=adapter,changed=changed),self.assertRaisesRegex(ValueError,'sentinel'):
                    gate.generate_source(invalid,'/tmp/inert-fixture',0,adapter)
        for name,key,value in (('parent:fork-failure','status',-1),
                               ('parent:fork-restore-failure','status',-2),
                               ('parent:parent-mask-failure','status',-2),
                               ('parent:parent-mask-copy-failure','status',-2),
                               ('parent:exec-failure','status',-2)):
            rows=records();next(row for row in rows if row['case']==name)['observed'][key]=value
            with self.subTest(case=name),self.assertRaises(ValueError):gate.validate_records(rows)

    def test_source_module_never_uses_stale_cached_import(self):
        first=gate.checked_module('def generate_source(*a): return 1\n','fresh')
        second=gate.checked_module('def generate_source(*a): return 2\n','fresh')
        self.assertEqual((first.generate_source(),second.generate_source()),(1,2))

    def test_probe_source_binary_export_are_exact_and_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);gate.export_probe(root/'report.json','parent',b'actual source',b'actual binary')
            self.assertEqual((root/'target-resident-upgrade-parent.c').read_bytes(),b'actual source')
            binary=root/'target-resident-upgrade-parent'
            self.assertEqual(binary.read_bytes(),b'actual binary')
            self.assertEqual(binary.stat().st_mode & 0o777,0o755)

    def test_guard_specific_refusal_required_not_only_failure_status(self):
        spec=gate.SHIPPED_CASES[-1]
        with tempfile.TemporaryDirectory() as tmp:
            status=Path(tmp)/'status'
            good=subprocess.CompletedProcess([],21,'',spec['stderr'])
            self.assertFalse(gate.validate_refusal(spec,good,status)['status_file_created'])
            for run in (subprocess.CompletedProcess([],1,'','Could not open mtd device\n'),
                        subprocess.CompletedProcess([],21,'','Could not open mtd device\n'),
                        subprocess.CompletedProcess([],21,'',spec['stderr']+'late side effect\n'),
                        subprocess.CompletedProcess([],21,'output',spec['stderr']),
                        subprocess.CompletedProcess([],0,'',spec['stderr'])):
                with self.subTest(result=run),self.assertRaises(ValueError):gate.validate_refusal(spec,run,status)
            status.symlink_to(Path(tmp)/'absent')
            with self.assertRaises(ValueError):gate.validate_refusal(spec,good,status)
            status.unlink()
            trace='123 write(2,0x1000,105)'+spec['stderr']+' = 105\n123 exit_group(21)\n'
            traced=subprocess.CompletedProcess([],21,'',trace)
            self.assertEqual(gate.validate_refusal_trace(spec,traced,status)['forbidden_attempts'],[])
            for effect in ('sync() = -1 EPERM','open("/dev/mtd3",O_RDONLY) = -1 EPERM',
                           'open("/tmp/status",O_WRONLY|O_CREAT) = -1 EPERM',
                           'openat(AT_FDCWD,"/tmp/status",0x101) = -1 EPERM',
                           'reboot(1,2,3) = -1 EPERM','ioctl(4,0x4d01,0) = -1 EPERM',
                           'write(1,0x1000,1) = -1 EPERM','Unknown syscall 9999'):
                invalid=subprocess.CompletedProcess([],21,'',trace+'123 '+effect+'\n')
                with self.subTest(effect=effect),self.assertRaises(ValueError):
                    gate.validate_refusal_trace(spec,invalid,status)

    def test_refusal_exec_uses_empty_env_sandbox_and_no_static_loader_prefix(self):
        fake=subprocess.CompletedProcess([],21,'','')
        traced=subprocess.CompletedProcess([],21,'','123 exit_group(21)\n')
        with patch.object(gate,'refusal_environment',return_value={}),\
             patch.object(gate,'refusal_preexec',return_value='sandbox'),\
             patch.object(gate.subprocess,'run',side_effect=[fake,traced]) as run:
            row=gate.run_refusals({'bin/fw_upgrade':Path('/inert-helper')},'/qemu',gate.SHIPPED_CASES[:1])
            args,kwargs=run.call_args_list[0]
            self.assertEqual(args[0],['/qemu','/inert-helper'])
            self.assertEqual(kwargs['env'],{})
            self.assertEqual(kwargs['preexec_fn'],'sandbox')
            self.assertTrue(kwargs['close_fds'])
            self.assertEqual(len(row['checks']),1)
            self.assertEqual(row['runs_per_case'],2)
            self.assertEqual(run.call_args_list[1].args[0],['/qemu','-strace','/inert-helper'])

    def test_complete_helper_compiles_exact_source_and_static_flags(self):
        values={key:'/* exact '+key+' */\n' for key in gate.SOURCE_PATHS}
        values['helper_main']='int main(int argc,char **argv,char **environment){_exit(fwup_resident_run(argc,argv,environment));}\n'
        values['helper_makefile']='fw_upgrade: fw_upgrade.c crc32.c\n\t$(CC) $(CFLAGS) -static -o $@ fw_upgrade.c crc32.c\n'
        def compile_fake(command,**options):
            Path(command[command.index('-o')+1]).write_bytes(elf(0,label='_gp_disp',info=17))
            return subprocess.CompletedProcess(command,0,'','')
        with tempfile.TemporaryDirectory() as tmp,\
             patch.object(gate.subprocess,'run',side_effect=compile_fake) as compiler,\
             patch.object(gate,'run_refusals',return_value={'checks':[]}) as refusals:
            info,sources,binary=gate.compile_full_helper(values,'/mips-cc',Path(tmp),'/qemu')
            self.assertIn('-static',compiler.call_args.args[0])
            self.assertNotIn('-s',compiler.call_args.args[0])
            self.assertEqual(sources['fw_upgrade.c'],values['helper_main'].encode())
            self.assertEqual(info['source_sha256']['fw_upgrade.c'],gate.sha(sources['fw_upgrade.c']))
            self.assertEqual(info['binary_sha256'],gate.sha(binary))
            self.assertEqual(info['ELF']['source_only_mips_linker_pseudo_symbols'][0]['name'],'_gp_disp')
            self.assertEqual(refusals.call_args.args[2],gate.SHIPPED_CASES[:2])

    def test_complete_helper_rejects_crt_return_or_dynamic_link_rule(self):
        values={key:'' for key in gate.SOURCE_PATHS}
        values['helper_main']='int main(int argc,char **argv,char **environment){return fwup_resident_run(argc,argv,environment);}'
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'_exit'):
                gate.compile_full_helper(values,'/never-run',Path(tmp),'/never-run')
            values['helper_main']='int main(int argc,char **argv,char **environment){_exit(fwup_resident_run(argc,argv,environment));}'
            values['helper_makefile']='fw_upgrade: fw_upgrade.c crc32.c\n\t$(CC) -o $@ fw_upgrade.c crc32.c\n'
            with self.assertRaisesRegex(ValueError,'static'):
                gate.compile_full_helper(values,'/never-run',Path(tmp),'/never-run')

    def test_source_to_shipped_binding_requires_whole_file_equality(self):
        inputs={'romfs_install':'${STRIPTOOL} ${dstfile} 2>/dev/null\n'
                '${STRIPTOOL} -R .comment -R .note --strip-debug --strip-unneeded ${dstfile} 2>/dev/null\n'
                '${SSTRIP_TOOL} ${dstfile}',
                'trunk_makefile':'SSTRIP_TOOL    = $(if $(CONFIG_FIRMWARE_PERFORM_SSTRIP),$(ROOTDIR)/tools/sstrip/sstrip)',
                'sstrip_source':'/* reviewed sstrip source */'}
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);trunk=base/'trunk';rootfs=base/'rootfs'
            (trunk/'user/mtd_write').mkdir(parents=True);(rootfs/'bin').mkdir(parents=True)
            built=trunk/'user/mtd_write/fw_upgrade';built.write_bytes(elf());built.chmod(0o755)
            (rootfs/'bin/fw_upgrade').write_bytes(elf());(trunk/'.config').write_text('')
            compiler=base/'mips-gcc';strip=base/'mips-strip';strip.write_bytes(b'inert strip fixture');strip.chmod(0o755)
            with patch.object(gate.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
                binding,original,transformed=gate.bind_shipped_helper(trunk,rootfs,compiler,inputs)
                self.assertEqual(original,transformed)
                self.assertTrue(binding['whole_file_equal'])
                self.assertEqual([call.args[0][1:-1] for call in run.call_args_list],
                                 [[],['-R','.comment','-R','.note','--strip-debug','--strip-unneeded']])
            def altered_install(command,**options):
                target=Path(command[-1]);data=bytearray(target.read_bytes());data[300]=123;target.write_bytes(data)
                return subprocess.CompletedProcess(command,0,'','')
            with patch.object(gate.subprocess,'run',side_effect=altered_install),\
                 self.assertRaisesRegex(ValueError,'differs'):
                gate.bind_shipped_helper(trunk,rootfs,compiler,inputs)
            (trunk/'.config').write_text('CONFIG_FIRMWARE_PERFORM_SSTRIP=y\n')
            with self.assertRaisesRegex(ValueError,'sstrip tool is missing'):
                gate.bind_shipped_helper(trunk,rootfs,compiler,inputs)

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine()=='x86_64',
                         'Linux x86_64 seccomp host only')
    def test_real_refusal_sandbox_denies_invalid_reboot_and_ioctl(self):
        # All arguments are deliberately invalid. No valid reboot magic/device
        # is supplied, even if a broken filter accidentally allows the calls.
        code='import ctypes,errno; c=ctypes.CDLL(None,use_errno=True); '\
             'assert c.syscall(169,0,0,0,0)==-1 and ctypes.get_errno()==errno.EPERM; '\
             'assert c.syscall(16,-1,0,0)==-1 and ctypes.get_errno()==errno.EPERM'
        run=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,
                           preexec_fn=gate.refusal_preexec(),timeout=10)
        self.assertEqual(run.returncode,0,run.stderr)


if __name__=='__main__':unittest.main()
