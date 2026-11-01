"""Strict target proof/generator tests; native wait controls are not MIPS claims."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('upgrade', Path(__file__).with_name('check_target_upgrade.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def inputs():
    void_helpers = ('firmware_upgrade_stop_watchdog', 'notify_watchdog_time', 'firmware_upgrade_signal_fault')
    functions = {name: ('void' if name in void_helpers else 'int') +
                 ' ' + name + '(void) { ' + ('return;' if name in void_helpers else 'return 0;') + ' }'
                 for name in upgrade.REQUIRED_HELPERS}
    functions['flash_firmware'] = 'int flash_firmware(void) { shutdown_hook_run(script_name, 0, HOOK_RUNNER_TIMEOUT_MS, HOOK_RUNNER_TERM_MS, HOOK_RUNNER_KILL_MS); return 0; }'
    markers = '\n'.join(('#define open fixture_open', '#define ioctl fixture_ioctl', '#define reboot fake_reboot',
                         '#define sync fake_sync', '#define mlockall fixture_mlockall', '#define munlockall fixture_munlockall',
                         '#define daemon fixture_daemon', 'static int _eval(', 'static int doSystem('))
    adapter = 'FUNCTIONS = ' + repr(upgrade.RC_HELPERS) + '\n'
    adapter += 'def generate(root):\n    return ' + repr(markers + '\n') + " + '\\n'.join(function(source('trunk/user/rc/rc.c'), n) for n in FUNCTIONS) + '\\n' + '\\n'.join(function(source('trunk/user/rc/watchdog.c'), n) for n in " + repr(upgrade.WD_HELPERS) + ')\n'
    return {'rc.c': '#include "hook_runner.h"\n' + '\n'.join(functions[n] for n in upgrade.RC_HELPERS),
            'rc.h': 'int write_storage_to_mtd(void);\nint firmware_upgrade_inhibited(void);\n',
            'watchdog.c': '\n'.join(functions[n] for n in upgrade.WD_HELPERS),
            'upgrade_gate_harness.py': adapter,
            'upgrade_guard.h': '/* Synthetic generator-only input; actual shared header is bound by the transaction proof. */',
            'hook_runner.h': '\n'.join(('#define HOOK_RUNNER_TIMEOUT_MS 30000U', '#define HOOK_RUNNER_TERM_MS 2000U',
                                         '#define HOOK_RUNNER_KILL_MS 1000U', '#define HOOK_RUNNER_STREAM_LIMIT (128U * 1024U)',
                                         '#define HOOK_RUNNER_PROC_LIMIT 8192U'))}


RUN = r'''
static int firmware_upgrade_run(const char *writer,const char *record,pid_t *child)
{
 char *args[]={(char*)writer,"--upgrade-write",FW_IMG_NAME,FW_MTD_NAME,(char*)record,NULL};
 sigset_t block,previous;pid_t waited;int status=-1;*child=-1;
 sigemptyset(&block);sigaddset(&block,SIGCHLD);
 if(sigprocmask(SIG_BLOCK,&block,&previous)!=0)return -1;
 if(_eval(args,NULL,0,child)==0){do waited=waitpid(*child,&status,0);while(waited<0&&errno==EINTR);if(waited!=*child)status=-1;}
 if(sigprocmask(SIG_SETMASK,&previous,NULL)!=0)status=-1;
 return status;
}
'''


class TargetUpgradeProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='test-upgrade-proof-')
        cls.root = Path(cls.temp.name)
        code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#define FW_IMG_NAME "/synthetic/image"
#define FW_MTD_NAME "firmware"
static int mode;
static int _eval(char *const args[],char *path,int timeout,int *child){
 pid_t pid;assert(!path&&!timeout&&!strcmp(args[1],"--upgrade-write"));
 if(mode<0){errno=EAGAIN;return EAGAIN;}pid=fork();assert(pid>=0);
 if(pid){*child=pid;return 0;}if(mode==999){kill(getpid(),SIGKILL);_exit(99);}_exit(mode);
}
'''
        code = code.replace('#include <stdlib.h>', '#include <stdlib.h>\n#include <string.h>')
        code += upgrade.extract_function(RUN, 'firmware_upgrade_run')
        code += '\nint main(int argc,char**argv){pid_t child;sigset_t current;assert(argc==2);mode=atoi(argv[1]);int raw=firmware_upgrade_run("/synthetic/writer","/synthetic/status",&child);sigprocmask(SIG_SETMASK,NULL,&current);printf("%d %d\\n",raw,sigismember(&current,SIGCHLD));return 0;}\n'
        path = cls.root / 'wait.c'; path.write_text(code)
        cls.binary = cls.root / 'wait'
        subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                        str(path), '-o', str(cls.binary)], check=True, capture_output=True)
        cls.records = [{'case': name, 'inputs': options.copy(), 'observed': upgrade.expected_trace(options)}
                       for name, options in upgrade.CASES]

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_required_cases_and_helpers_have_independent_fixed_identity(self):
        self.assertEqual(len(upgrade.CASE_NAMES), 59)
        self.assertEqual(hashlib.sha256('\n'.join(upgrade.CASE_NAMES).encode()).hexdigest(),
                         '73188c31c0156327af07b8071bcf6819263ec1341f4301b29f46b5dedb13d388')
        self.assertEqual(len(upgrade.REQUIRED_HELPERS), 18)
        self.assertIn('firmware_upgrade_disable_watchdog', upgrade.REQUIRED_HELPERS)
        self.assertIn('watchdog_main', upgrade.REQUIRED_HELPERS)
        upgrade.validate_records(self.records)

    def test_missing_duplicate_or_reordered_case_is_rejected(self):
        for records in (self.records[:-1], [self.records[0], *self.records], list(reversed(self.records))):
            with self.assertRaisesRegex(ValueError, 'case set/order'):
                upgrade.validate_records(records)

    def test_wrong_safe_unknown_reboot_phase_trace_and_types_are_rejected(self):
        for name, key, value in [('unknown-signal-with-prewrite', 'phase', 0),
                                 ('verified-direct-reboot-return', 'reboots', 0),
                                 ('resident-request-failure', 'stops', [1] * 7),
                                 ('no-hook-safe-prewrite', 'trace', ['writer', 'reboot']),
                                 ('no-hook-safe-prewrite', 'phase', False),
                                 ('no-hook-safe-prewrite', 'mlocks', 1.0)]:
            records = copy.deepcopy(self.records)
            records[upgrade.CASE_NAMES.index(name)]['observed'][key] = value
            with self.subTest(name=name, key=key), self.assertRaisesRegex(ValueError, 'mismatch'):
                upgrade.validate_records(records)

    def test_old_missing_ambiguous_helpers_and_header_fail_closed(self):
        for mutation in ('old', 'missing', 'ambiguous', 'header'):
            data = inputs()
            if mutation == 'old': data['rc.c'] = data['rc.c'].replace('int write_storage_to_mtd', 'void write_storage_to_mtd')
            if mutation == 'missing': data['watchdog.c'] = ''
            if mutation == 'ambiguous': data['rc.c'] += '\n' + data['rc.c']
            if mutation == 'header': data['rc.h'] = 'void write_storage_to_mtd(void);'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                upgrade.generate_source(data, Path('/tmp/synthetic'))

    def test_complete_helper_group_is_embedded_once_in_generated_source(self):
        generated, functions = upgrade.generate_source(inputs(), Path('/tmp/synthetic'))
        self.assertEqual(tuple(functions), upgrade.REQUIRED_HELPERS)
        self.assertTrue(generated.startswith('#define USE_STORAGE 1\n#define USE_USB_SUPPORT 1\n'))
        for body in functions.values():
            self.assertEqual(generated.count(body), 1)

    def test_comments_strings_and_braces_do_not_forge_or_truncate_functions(self):
        function = 'static int flash_firmware(void) { const char *text="}"; /* { */ return 0; }'
        text = '/* int flash_firmware(void) { return 0; } */\n' + function
        self.assertEqual(upgrade.extract_function(text, 'flash_firmware'), function)

    def test_new_unstubbed_effect_callback_is_rejected(self):
        data = inputs(); data['rc.c'] = data['rc.c'].replace('return 0;', 'system("must never run"); return 0;', 1)
        with self.assertRaisesRegex(ValueError, 'Unstubbed.*system'):
            upgrade.generate_source(data, Path('/tmp/synthetic'))

    def test_unbounded_or_missing_hook_supervisor_cannot_use_recovery_proof(self):
        for mutation in ('missing', 'budget', 'unbounded'):
            data = inputs()
            if mutation == 'missing': data.pop('hook_runner.h')
            if mutation == 'budget': data['hook_runner.h'] = data['hook_runner.h'].replace('30000U', '300000U')
            if mutation == 'unbounded': data['rc.c'] = data['rc.c'].replace('shutdown_hook_run(script_name, 0, HOOK_RUNNER_TIMEOUT_MS, HOOK_RUNNER_TERM_MS, HOOK_RUNNER_KILL_MS)', 'doSystem("%s %d", script_name, 0)')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                upgrade.generate_source(data, Path('/tmp/synthetic'))

    def test_adapter_cannot_omit_functions_or_inert_boundaries(self):
        for mutation in ('helpers', 'omitted', 'reboot'):
            data = inputs()
            if mutation == 'helpers': data['upgrade_gate_harness.py'] = data['upgrade_gate_harness.py'].replace(repr(upgrade.RC_HELPERS), '()', 1)
            if mutation == 'omitted': data['upgrade_gate_harness.py'] = data['upgrade_gate_harness.py'].replace('for n in FUNCTIONS', 'for n in FUNCTIONS[:-1]')
            if mutation == 'reboot': data['upgrade_gate_harness.py'] = data['upgrade_gate_harness.py'].replace('#define reboot fake_reboot', '')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                upgrade.generate_source(data, Path('/tmp/synthetic'))

    def test_native_wait_contract_retains_normal_exit_signal_and_launch_failure(self):
        for argument, expected in [('20', 20 << 8), ('0', 0), ('999', 9), ('-1', -1)]:
            result = subprocess.run([str(self.binary), argument], check=True, text=True, capture_output=True)
            self.assertEqual(result.stdout.strip(), f'{expected} 0')

    def test_mips_gate_rejects_native_binary_and_wrong_endianness(self):
        with self.assertRaisesRegex(ValueError, 'ELF32 MIPS'):
            upgrade.validate_mips_elf(self.binary.read_bytes())
        header = bytearray(52); header[:7] = b'\x7fELF\x01\x01\x01'; struct.pack_into('<H', header, 18, 8)
        upgrade.validate_mips_elf(header); header[5] = 2
        with self.assertRaisesRegex(ValueError, 'ELF32 MIPS'):
            upgrade.validate_mips_elf(header)

    def test_export_preserves_exact_compiled_and_generated_diagnostic_bytes(self):
        generated = (self.root / 'wait.c').read_bytes(); binary = self.binary.read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'report.json'
            upgrade.export_probe(output, generated, binary)
            for name, expected in [('target-upgrade-probe.c', generated), ('target-upgrade-probe', binary)]:
                exported = (output.parent / name).read_bytes()
                self.assertEqual(exported, expected)
                self.assertEqual(hashlib.sha256(exported).digest(), hashlib.sha256(expected).digest())
            self.assertEqual((output.parent / 'target-upgrade-probe').stat().st_mode & 0o777, 0o755)

    def test_susu_never_silently_uses_new_upgrade_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            trunk = Path(temp); (trunk / '.config').write_text('CONFIG_LINUXDIR=linux-3.4.x\nCONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')
            with self.assertRaisesRegex(ValueError, 'no legacy/SUSU fallback'):
                upgrade.check(trunk, Path('/missing'), trunk, trunk / 'result.json')


if __name__ == '__main__':
    unittest.main()
