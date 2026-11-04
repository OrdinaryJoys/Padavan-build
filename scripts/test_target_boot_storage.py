"""Private synthetic contract controls; these do not execute target binaries."""
import copy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_target_ntp import dynamic_elf

SPEC = importlib.util.spec_from_file_location('boot_storage', Path(__file__).with_name('check_target_boot_storage.py'))
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)


def synthetic_sources():
    functions = {name: name+'()\n{\n :\n}' for name in boot.SHELL_FUNCTIONS}
    functions['func_load'] = 'func_load()\n{\n func_record_hash &&\n\t   rm -f "$slk" && func_ready_publish\n}'
    functions['func_tarb'] = 'func_tarb()\n{\n (ulimit -f 16384 && cd "$dir_storage" && tar fixture)\n}'
    functions['func_save'] = '''func_save()
{
 blocks=$((mtd_part_size / 512))
 (ulimit -f "$blocks" && bzip2 -c -9 "$tmp" > "$archive")
 [ "$fsz" -gt "$mtd_part_size" ]
 func_invalidate_hash || return 1
 mtd_write write "$archive" "$mtd_part_name"
}'''
    functions['func_invalidate_hash'] = '''func_invalidate_hash()
{
	if ! rm -f "$hsh" || [ -e "$hsh" ] || [ -L "$hsh" ]; then
		return 1
	fi
}'''
    functions['func_fill'] = '''func_fill()
{
 cat > "$fixture" <<EOF || return 1
}
EOF
 chmod 755 "$fixture" || return 1
 reset_ss.sh -a || return 1
}'''
    functions['func_erase'] = '''func_erase()
{
	if ! func_invalidate_hash; then
		result=1
		return 1
	fi
	mtd_write erase "$mtd_part_name"
}'''
    functions['func_restore'] = 'func_restore()\n{\n func_ready_clear || return 1\n func_stop_apps\n}'
    functions['func_reset'] = 'func_reset()\n{\n\trm -f "$slk" &&\n\t\trm -rf "$dir_storage" &&\n\t\tmkdir -p -m 755 "$dir_storage"\n}'
    storage = '\n'.join(functions.values())+'''
case "$1" in load|erase|reset) func_ready_clear || exit 1;; esac
func_begin || exit 1
save)
	func_ready || exit 1
	if [ -e "$slk" ] || [ -L "$slk" ]; then exit 1; fi
if func_reset && func_fill && func_tarb && func_ready_publish; then :; fi
fill)
'''+boot.FILL_GUARD+'\n\t;;\n'
    return {key: value.encode() for key, value in {
        'storage': storage,
        'dev_init': '''storage_load_status=0
mtd_storage.sh load || storage_load_status=$?
storage_fill_status=0
mtd_storage.sh fill || storage_fill_status=$?
if [ "$storage_load_status" -eq 0 ]; then
	storage_load_status=$storage_fill_status
fi
exit "$storage_load_status"
''',
        'reset_ss': '''#!/bin/sh
script_start="/etc/storage/start_script.sh"
cat > "$script_start" <<EOF || exit 1
#!/bin/sh
# private synthetic default, never executed
EOF
chmod 755 "$script_start" || exit 1
if [ -z "$1" ] ; then
	$script_start
	mtd_storage.sh save
fi
''',
        'rc': '''void run_startup_script(void){
 access(SCRIPT_STARTUP, X_OK);
 shutdown_hook_run(SCRIPT_STARTUP, HOOK_RUNNER_NO_ARGUMENT, 30000, 2000, 1000);
}''',
        'init': '''void init_main_loop(void){
 system("dev_init.sh");system("dev_init.sh -l");
 if (early_status != 0) warning();run_startup_script();init_nodes();
}''',
        'rc_header': '#define SCRIPT_STARTUP\t\t\t"/etc/storage/start_script.sh"\n',
        'runner': '''#define HOOK_RUNNER_NO_ARGUMENT (-1)
static int shutdown_hook_run(void){
 if(level < HOOK_RUNNER_NO_ARGUMENT || level > 2)return -1;
 const char *command = level == -1 ? "exec \\"$0\\"" : "exec \\"$0\\" \\"$1\\"";
 return 0;
}'''.replace('\\\\', '\\'),
        'shell_common': "{ RLIMIT_FSIZE, 9, 'f', \"file size (blocks)\" },\n",
        'busybox_template': '\n'.join(boot.REQUIRED_CONFIG)+'\n',
    }.items()}


class TargetBootStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='k2p-boot-contract-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def source_check(self, inputs):
        with mock.patch.object(boot, 'EXPECTED_SOURCE_SHA256', {key: boot.sha(value) for key, value in inputs.items()}):
            return boot.source_contract(inputs)

    def runtime(self):
        rootfs, sysroot = self.root/'rootfs', self.root/'sysroot'
        for root in (rootfs, sysroot):
            for name in ('bin', 'usr/lib', 'lib'):
                (root/name).mkdir(parents=True, exist_ok=True)
        busybox = bytes(dynamic_elf())
        (rootfs/'bin/busybox').write_bytes(busybox);(rootfs/'bin/busybox').chmod(0o755)
        library = bytes(dynamic_elf(needed=(), interpreter=None, kind=3))
        for root in (rootfs, sysroot):
            for name in ('lib/libc.so.0', 'lib/ld-uClibc.so.0'):
                (root/name).write_bytes(library);(root/name).chmod(0o644)
        staging = self.root/'staging';staging.mkdir()
        runtime, hashes = boot.prepare_uid_runtime(rootfs, sysroot, staging)
        return rootfs, sysroot, runtime, hashes, busybox

    def test_four_complete_fixed_typed_rows_are_exact_and_recomputable(self):
        self.assertEqual(len(boot.CASE_NAMES),4)
        self.assertEqual(len(set(boot.CASE_NAMES)),4)
        rows=boot.expected_rows();boot.validate_records(rows)
        self.assertEqual([row['raw_exit'] for row in rows],[0,73,73,73])
        self.assertEqual([row['actual_bytes'] for row in rows],[1024,1024,524288,8388608])
        self.assertEqual([row['requested_bytes'] for row in rows],[1024,1025,524289,8388609])

    def test_missing_duplicate_reordered_extra_or_boolean_typed_rows_reject(self):
        rows=boot.expected_rows()
        variants=[rows[:-1],rows+rows[:1],list(reversed(rows))]
        for key,value in [('raw_exit',False),('actual_bytes',1024.0),('limit_blocks',True),
                          ('eof',1),('requested_bytes','1024'),('sha256','0'*64),('case','unknown')]:
            wrong=copy.deepcopy(rows);wrong[0][key]=value;variants.append(wrong)
        wrong=copy.deepcopy(rows);wrong[0]['extra']=0;variants.append(wrong)
        wrong=copy.deepcopy(rows);wrong[1]=copy.deepcopy(wrong[0]);variants.append(wrong)
        for value in variants:
            with self.assertRaises(ValueError):boot.validate_records(value)

    def test_private_source_contract_records_real_function_hashes(self):
        proof=self.source_check(synthetic_sources())
        self.assertEqual(len(proof['actual_functions_sha256']),15)
        self.assertEqual(len(proof['source_sha256']),9)
        self.assertIs(proof['semantics']['whole_boot_executed'],False)
        self.assertIs(proof['semantics']['custom_script_executed'],False)
        self.assertEqual(set(proof['source_sha256']),set(boot.SOURCE_PATHS))

    def test_unreviewed_source_hash_and_missing_file_cannot_be_silently_admitted(self):
        inputs=synthetic_sources()
        with self.assertRaises(ValueError):boot.source_contract(inputs)
        del inputs['dev_init']
        with self.assertRaises(ValueError):self.source_check(inputs)

    def test_boot_revoke_authorize_quota_and_hook_semantic_mutants_reject(self):
        changes=[
            ('storage','case "$1" in load|erase|reset) func_ready_clear || exit 1;; esac','late-revoke'),
            ('storage','func_ready || exit 1','true'),
            ('storage','[ -e "$slk" ] || [ -L "$slk" ]','[ -f "$slk" ]'),
            ('storage','func_record_hash &&','true &&'),
            ('storage','func_ready_clear || return 1','true'),
            ('storage','func_fill && func_tarb && func_ready_publish','func_fill && func_ready_publish'),
            ('storage','if func_reset && func_fill','if func_fill'),
            ('storage','rm -f "$slk" &&\n\t\trm -rf','rm -f "$slk";\n\t\trm -rf'),
            ('storage','rm -rf "$dir_storage" &&','rm -rf "$dir_storage";'),
            ('storage','mkdir -p -m 755 "$dir_storage"','mkdir -p -m 777 "$dir_storage"'),
            ('storage','ulimit -f 16384','ulimit -f 32768'),
            ('storage','mtd_part_size / 512','mtd_part_size / 1024'),
            ('dev_init','exit "$storage_load_status"','exit 0'),
            ('init','run_startup_script();init_nodes();','init_nodes();run_startup_script();'),
            ('rc','HOOK_RUNNER_NO_ARGUMENT,','0,'),
            ('runner','level > 2','level > 3'),
            ('shell_common','RLIMIT_FSIZE, 9','RLIMIT_FSIZE, 10'),
        ]
        for key,old,new in changes:
            with self.subTest(change=old):
                inputs=synthetic_sources();self.assertIn(old.encode(),inputs[key])
                inputs[key]=inputs[key].replace(old.encode(),new.encode(),1)
                with self.assertRaises(ValueError):self.source_check(inputs)

    def test_fill_cache_and_default_creation_failures_cannot_mint_authority(self):
        changes=[
            ('storage','func_invalidate_hash || return 1','true'),
            ('storage',' || [ -e "$hsh" ]',''),
            ('storage',' || [ -L "$hsh" ]',''),
            ('storage','result=1\n\t\treturn 1','result=0\n\t\treturn 1'),
            ('storage','reset_ss.sh -a || return 1','reset_ss.sh -a'),
            ('storage','<<EOF || return 1','<<EOF'),
            ('storage','fill_was_ready=0','fill_was_ready=1'),
            ('storage','if func_ready; then fill_was_ready=1; fi','fill_was_ready=1'),
            ('storage','if func_ready_clear && func_mdir && func_fill; then','if func_mdir && func_fill; then'),
            ('storage','if [ "$fill_was_ready" = 1 ]; then','if true; then'),
            ('storage','func_tarb && func_ready_publish || result=1','func_ready_publish || result=1'),
            ('dev_init','mtd_storage.sh fill || storage_fill_status=$?','mtd_storage.sh fill'),
            ('dev_init','if [ "$storage_load_status" -eq 0 ]; then','if true; then'),
            ('dev_init','storage_load_status=$storage_fill_status','storage_load_status=0'),
            ('reset_ss','<<EOF || exit 1','<<EOF'),
            ('reset_ss','chmod 755 "$script_start" || exit 1','chmod 755 "$script_start"'),
        ]
        for key,old,new in changes:
            with self.subTest(change=old):
                inputs=synthetic_sources();self.assertIn(old.encode(),inputs[key])
                inputs[key]=inputs[key].replace(old.encode(),new.encode(),1)
                with self.assertRaises(ValueError):self.source_check(inputs)

    def test_shell_extraction_keeps_column_zero_braces_and_multiple_heredocs(self):
        bodies=[
            'func_fixture()\n{\n cat <<FIRST\n}\nFIRST\n printf complete\n}',
            "func_fixture()\n{\n cat <<'FIRST'\n}\nFIRST\n cat <<-SECOND\n\t}\n\tSECOND\n printf complete\n}",
            "func_fixture()\n{\n cat <<FIRST <<'SECOND'\n}\nFIRST\n}\nSECOND\n printf complete\n}",
        ]
        for body in bodies:
            with self.subTest(body=body):
                text=body+'\nfunc_next()\n{\n :\n}\n'
                self.assertEqual(boot.shell_function(text,'func_fixture'),body)
                self.assertNotIn('func_next',boot.shell_function(text,'func_fixture'))

    def test_shell_extraction_rejects_ambiguous_or_unterminated_heredoc_functions(self):
        body='func_fixture()\n{\n cat <<FIRST\n}\nFIRST\n printf complete\n}'
        for text in (body+'\n'+body,body.replace('\nFIRST\n','\nMISSING\n'),
                     body.replace('func_fixture()','func_other()')):
            with self.subTest(text=text),self.assertRaises(ValueError):
                boot.shell_function(text,'func_fixture')

    def test_ash_printf_test_rmdir_and_stat_configuration_must_be_explicit(self):
        for line in boot.REQUIRED_CONFIG:
            with self.subTest(line=line):
                raw=('\n'.join(item for item in boot.REQUIRED_CONFIG if item!=line)+'\n').encode()
                with self.assertRaises(ValueError):boot.config_contract(raw)
        with self.assertRaises(ValueError):boot.config_contract(('\n'.join(boot.REQUIRED_CONFIG)+'\nCONFIG_ASH=y\n').encode())

    def test_c_extraction_handles_escaped_newline_and_does_not_consume_next_function(self):
        text='int one(void){const char*s="before\\\n} after";return 0;}\nint two(void){return 2;}'
        body=boot.c_function(text,'one')
        self.assertNotIn('two(',body)
        self.assertTrue(body.endswith('return 0;}'))
        with self.assertRaises(ValueError):boot.c_function(text+text,'one')
        with self.assertRaises(ValueError):boot.shell_function('func_x()\n{\n :\n}\n'*2,'func_x')

    def test_public_runtime_copy_has_complete_matching_rootfs_sysroot_closure(self):
        rootfs,sysroot,runtime,hashes,binary=self.runtime()
        boot.inventory_runtime(sysroot)
        closure=boot.runtime_closure(rootfs,sysroot,runtime,binary)
        self.assertEqual(set(closure['libraries']),{'lib/libc.so.0','lib/ld-uClibc.so.0'})
        self.assertEqual(closure['busybox_dynamic']['needed'],['libc.so.0'])
        boot.verify_runtime_copy(runtime,rootfs,sysroot,hashes)
        self.assertFalse((runtime/'dev').exists());self.assertFalse((runtime/'proc').exists())

    def test_rootfs_sysroot_copied_library_corruption_or_missing_dependency_rejects(self):
        rootfs,sysroot,runtime,hashes,binary=self.runtime()
        path=runtime/'lib/libc.so.0';original=path.read_bytes();path.write_bytes(original[:-1]+b'X')
        with self.assertRaises(ValueError):boot.runtime_closure(rootfs,sysroot,runtime,binary)
        with self.assertRaises(ValueError):boot.verify_runtime_copy(runtime,rootfs,sysroot,hashes)
        path.write_bytes(original);(rootfs/'lib/libc.so.0').unlink()
        with self.assertRaises(ValueError):boot.runtime_closure(rootfs,sysroot,runtime,binary)

    def test_runtime_inventory_rejects_special_files_and_explicit_budgets(self):
        rootfs,sysroot,runtime,hashes,binary=self.runtime()
        os.mkfifo(sysroot/'lib/forbidden')
        with self.assertRaises(ValueError):boot.inventory_runtime(sysroot)
        (sysroot/'lib/forbidden').unlink()
        with mock.patch.object(boot,'MAX_RUNTIME_FILES',1):
            with self.assertRaises(ValueError):boot.inventory_runtime(sysroot)
        with mock.patch.object(boot,'MAX_RUNTIME_BYTES',1):
            with self.assertRaises(ValueError):boot.inventory_runtime(sysroot)

    def test_runtime_leaf_aliases_are_rebased_but_directory_escape_is_never_followed(self):
        rootfs,sysroot,runtime,hashes,binary=self.runtime()
        path=rootfs/'lib/libc.so.0';path.rename(rootfs/'lib/libc-runtime.so')
        path.symlink_to('/lib/libc-runtime.so')
        identity,_=boot.runtime_library(rootfs,'lib/libc.so.0')
        self.assertEqual(identity['resolved'],'lib/libc-runtime.so')
        outside=self.root/'outside';outside.mkdir();(outside/'secret').write_bytes(b'never parse this')
        (rootfs/'lib/pivot').symlink_to(outside,target_is_directory=True)
        path.unlink();path.symlink_to('pivot/secret')
        with self.assertRaisesRegex(ValueError,'directory alias'):boot.runtime_library(rootfs,'lib/libc.so.0')

    def fake_target(self, command, **options):
        self.assertEqual(command[1],'-L');self.assertEqual(command[4:6],['sh','-c'])
        self.assertEqual(command[6],boot.QUOTA_SCRIPT)
        self.assertEqual(options['env']['PATH'],'')
        self.assertEqual(options['stdin'],subprocess.DEVNULL)
        self.assertEqual(options['timeout'],30)
        blocks,chunks,tail=map(int,command[8:11])
        requested=chunks*1024+tail;size=min(requested,blocks*512)
        Path(command[-1]).write_bytes(b'0'*size)
        over=requested>size
        return SimpleNamespace(returncode=73 if over else 0,
                               stdout=b'ARMED\n' if over else b'ARMED\nCOMPLETE\n',stderr=b'')

    def test_observer_runs_only_explicit_copied_busybox_and_checks_real_file_eof(self):
        base=self.root/'cases';base.mkdir()
        with mock.patch.object(boot.subprocess,'run',side_effect=self.fake_target) as run:
            rows=[]
            for rule in boot.CASES:
                row,diagnostic=boot.observe_case(Path('/inert/qemu'),self.root/'runtime',base,rule)
                rows.append(row);self.assertEqual(diagnostic['stderr_bytes'],0)
            boot.validate_records(rows);self.assertEqual(run.call_count,4)
        self.assertNotIn('/proc',boot.QUOTA_SCRIPT)
        self.assertNotIn('/dev',boot.QUOTA_SCRIPT)
        self.assertNotIn('dd ',boot.QUOTA_SCRIPT)
        for literal in ('set -e','ulimit -c 0',"trap '' XFSZ",'ulimit -f "$1"',"printf '%01024d' 0 || exit 73"):
            self.assertIn(literal,boot.QUOTA_SCRIPT)

    def test_observer_rejects_exit_stage_size_alias_and_diagnostic_faults(self):
        for fault in ('exit','stage','size','alias','diagnostic'):
            with self.subTest(fault=fault):
                base=self.root/fault;base.mkdir()
                def wrong(command,**options):
                    result=self.fake_target(command,**options)
                    path=Path(command[-1])
                    if fault=='exit':result.returncode=0
                    elif fault=='stage':result.stdout=b'COMPLETE\n'
                    elif fault=='size':path.write_bytes(b'0'*1000)
                    elif fault=='alias':
                        victim=base/'victim';victim.write_bytes(path.read_bytes());path.unlink();path.symlink_to(victim)
                    else:result.stderr=b'X'*4097
                    return result
                with mock.patch.object(boot.subprocess,'run',side_effect=wrong):
                    with self.assertRaises(ValueError):boot.observe_case(Path('/inert/qemu'),self.root/'runtime',base,boot.CASES[1])

    def test_regular_inputs_and_exports_reject_fifo_symlink_hardlink_without_truncation(self):
        original=self.root/'original';original.write_bytes(b'keep')
        link=self.root/'link';link.symlink_to(original)
        with self.assertRaises((OSError,ValueError)):boot.read_regular(link)
        with self.assertRaises((OSError,ValueError)):boot.write_export(link,b'bad')
        hard=self.root/'hard';os.link(original,hard)
        with self.assertRaises(ValueError):boot.write_export(hard,b'bad')
        os.mkfifo(self.root/'fifo')
        with self.assertRaises(ValueError):boot.read_regular(self.root/'fifo')
        self.assertEqual(original.read_bytes(),b'keep')

    def test_final_checker_binds_three_shipped_scripts_and_exports_only_declared_proof(self):
        rootfs,sysroot,runtime,hashes,binary=self.runtime()
        trunk=self.root/'trunk';trunk.mkdir();inputs=synthetic_sources()
        for key,path in boot.SOURCE_PATHS.items():
            destination=trunk/path;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(inputs[key])
        (trunk/'.config').write_text('CONFIG_LINUXDIR=linux-4.4.x\nCONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')
        (trunk/'user/busybox/busybox-1.24.x/.config').write_bytes(inputs['busybox_template'])
        (rootfs/'sbin').mkdir()
        for key,path in boot.ROOTFS_SCRIPTS.items():
            (rootfs/path).write_bytes(inputs[key]);(rootfs/path).chmod(0o755)
        qemu=self.root/'inert-qemu';qemu.write_bytes(b'unit fixture, never executed');qemu.chmod(0o755)
        report=self.root/'out/target-boot-storage.json'
        with mock.patch.object(boot,'EXPECTED_SOURCE_SHA256',{key:boot.sha(value) for key,value in inputs.items()}), \
             mock.patch.object(boot.shutil,'which',return_value=str(qemu)), \
             mock.patch.object(boot.subprocess,'run',side_effect=self.fake_target) as execute, \
             contextlib.redirect_stdout(io.StringIO()):
            value=boot.check(trunk,rootfs,sysroot,report)
            self.assertEqual(execute.call_count,4)
            self.assertEqual(value['status'],'PASS');self.assertEqual(json.loads(report.read_text()),value)
            boot.validate_records(value['checks'])
            self.assertEqual((report.parent/boot.SCRIPT_FILE).read_text(),boot.QUOTA_SCRIPT)
            self.assertEqual((report.parent/boot.CONFIG_FILE).read_bytes(),inputs['busybox_template'])
            self.assertEqual(set(value['rootfs_scripts']),{'storage','dev_init','reset_ss'})
            for key,path in boot.ROOTFS_SCRIPTS.items():
                with self.subTest(shipped=key):
                    (rootfs/path).write_bytes(b'wrong shipped script')
                    execute.reset_mock()
                    with self.assertRaisesRegex(ValueError,'differs from reviewed source'):
                        boot.check(trunk,rootfs,sysroot,report)
                    execute.assert_not_called()
                    (rootfs/path).write_bytes(inputs[key])

    def test_cli_is_final_only_and_requires_all_four_explicit_inputs(self):
        script=Path(boot.__file__)
        result=subprocess.run([sys.executable,str(script),'--help'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        for option in ('--trunk','--rootfs','--sysroot','--output'):self.assertIn(option,result.stdout)
        self.assertNotIn('--preflight',result.stdout)
        for omitted in ('--trunk','--rootfs','--sysroot','--output'):
            args=[sys.executable,str(script)]
            for option in ('--trunk','--rootfs','--sysroot','--output'):
                if option!=omitted:args.extend((option,str(self.root/'absent')))
            result=subprocess.run(args,capture_output=True,text=True)
            self.assertEqual(result.returncode,2,result.stderr)


if __name__=='__main__':unittest.main()
