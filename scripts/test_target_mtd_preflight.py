"""Typed preflight producer tests; compiler, QEMU, MTD and reset stay inert."""
import contextlib
import copy
import io
import json
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest import mock
import check_target_mtd_preflight as gate

MODEL_FIXTURE = {'SOURCE_PATHS': {'mtd': 'trunk/user/mtd_write/mtd.c'},
 'FUNCTIONS': ('mtd_check', 'image_check', 'mtd_write', 'main'),
 'MAIN_CASES': ('configured-k2p',
                'small-large',
                'large-small',
                'resume-larger',
                'scratch-refused',
                'existing-scratch-growth-refused',
                'first-open-error',
                'second-open-error',
                'first-close-error',
                'second-close-error',
                'zero-erase',
                'negative-erase',
                'name-allocation-refused',
                'writer-geometry-growth',
                'resume-offset-refused'),
 'DIRECT_CASES': ('null-target',
                  'overlong-target',
                  'writer-null-buffer',
                  'writer-short-capacity',
                  'writer-negative-length',
                  'writer-carried-length',
                  'writer-zero-erase'),
 'PREFIX': '\n'
           '#define _GNU_SOURCE\n'
           '#include <stdio.h>\n'
           '#include <stdint.h>\n'
           '#include <stdlib.h>\n'
           '#include <string.h>\n'
           '#include <errno.h>\n'
           '#include <limits.h>\n'
           '#include <unistd.h>\n'
           '#include <fcntl.h>\n'
           '#include <sys/types.h>\n'
           '#include <sys/stat.h>\n'
           '#include <setjmp.h>\n'
           '#define MAX_ARGS 8\n'
           '#define JFFS2_EOF "\\xde\\xad\\xc0\\xde"\n'
           '#define TRX_MAGIC 0x48445230\n'
           '#define SEAMA_MAGIC 0x5ea3a417\n'
           '#define WRGG03_MAGIC 0x20080321\n'
           '#define be32_to_cpu(x) __builtin_bswap32(x)\n'
           '#define le32_to_cpu(x) (x)\n'
           '/* Admission has its own gate; this adapter never discovers proc/device nodes. */\n'
           '#define MTD_K2P_LEGACY_GUARD 0\n'
           'enum mtd_image_format { MTD_IMAGE_FORMAT_UNKNOWN, MTD_IMAGE_FORMAT_TRX, MTD_IMAGE_FORMAT_SEAMA, '
           'MTD_IMAGE_FORMAT_WRGG03 };\n'
           'static char *buf,*imagefile,*jffs2file,*jffs2dir="";\n'
           'static size_t buf_capacity,physical_bytes;\n'
           'static enum mtd_image_format imageformat;\n'
           'static int buflen,quiet=2,no_erase,jffs2_skip_bytes,erasesize;\n'
           'static const char *case_name;\n'
           'static int opens,closes,allocs,name_allocs,late_allocs,unlocks,erases,writes,reads;\n'
           'static int mutation_started,main_exit,bad_range,write_started,block_erases;\n'
           'static size_t requested,written_bytes;\n'
           'static int live_fds[32],live_count;\n'
           'static char trace[4096];\n'
           'static size_t trace_used;\n'
           'static jmp_buf escape;\n'
           'static int is_case(const char *name){return !strcmp(case_name,name);}\n'
           'static void event(const char *name){\n'
           ' int n=snprintf(trace+trace_used,sizeof(trace)-trace_used,"%s%s",trace_used?",":"",name);\n'
           ' if(n<0||(size_t)n>=sizeof(trace)-trace_used)abort();\n'
           ' trace_used+=(size_t)n;\n'
           '}\n'
           'static int fixture_fd(const char *path,int flags){\n'
           ' struct stat st;int fd=open(path,flags|O_NOFOLLOW|O_CLOEXEC);\n'
           ' if(fd<0||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_nlink!=1)abort();\n'
           ' return fd;\n'
           '}\n'
           'static int geometry(const char *name){\n'
           ' if(is_case("resume-offset-refused"))return '
           '!strcmp(name,"Nvram")?128:!strcmp(name,"Storage")?64:16;\n'
           ' if(is_case("configured-k2p"))return 65536;\n'
           ' if(is_case("zero-erase"))return 0;\n'
           ' if(is_case("negative-erase"))return -16;\n'
           ' if(is_case("writer-geometry-growth")&&mutation_started)return 32;\n'
           ' if(is_case("writer-zero-erase"))return 0;\n'
           ' if(is_case("large-small"))return !strcmp(name,"Storage")?64:16;\n'
           ' return !strcmp(name,"Config")?64:16;\n'
           '}\n'
           'static int mtd_check_open(const char *name){\n'
           ' int fd;\n'
           ' if(strcmp(name,"Storage")&&strcmp(name,"Config")&&strcmp(name,"Nvram"))abort();\n'
           ' opens++;event("metadata-open");erasesize=geometry(name);\n'
           ' if((is_case("first-open-error")&&opens==1)||(is_case("second-open-error")&&opens==2)){\n'
           '  errno=EACCES;return -1;\n'
           ' }\n'
           ' fd=fixture_fd(FIXTURE_DEVICE,O_RDWR);\n'
           ' if(live_count==32)abort();\n'
           ' live_fds[live_count++]=fd;return fd;\n'
           '}\n'
           'static int seam_close(int fd){\n'
           ' int i,result;\n'
           ' for(i=0;i<live_count&&live_fds[i]!=fd;i++);\n'
           ' if(i==live_count)abort();\n'
           ' live_fds[i]=live_fds[--live_count];\n'
           ' result=close(fd);closes++;event("metadata-close");\n'
           ' if((is_case("first-close-error")&&closes==1)||(is_case("second-close-error")&&closes==2)){\n'
           '  errno=EIO;return -1;\n'
           ' }\n'
           ' return result;\n'
           '}\n'
           'static void *seam_realloc(void *old,size_t length){\n'
           ' void *result;\n'
           ' allocs++;requested=length;event("scratch-allocation");\n'
           ' if(mutation_started){late_allocs++;event("late-allocation");}\n'
           ' if(is_case("scratch-refused")||is_case("existing-scratch-growth-refused")){errno=ENOMEM;return '
           'NULL;}\n'
           ' result=realloc(old,length);if(result)physical_bytes=length;\n'
           ' return result;\n'
           '}\n'
           'static void *seam_malloc(size_t length){return seam_realloc(NULL,length);}\n'
           'static char *seam_strdup(const char *text){\n'
           ' size_t length=strlen(text)+1;char *copy;\n'
           ' name_allocs++;event("name-allocation");\n'
           ' if(mutation_started){late_allocs++;event("late-allocation");}\n'
           ' if(is_case("name-allocation-refused")){errno=ENOMEM;return NULL;}\n'
           ' copy=malloc(length);if(copy)memcpy(copy,text,length);return copy;\n'
           '}\n'
           'static int seam_open(const char *path,int flags,...){\n'
           ' if(strcmp(path,FIXTURE_IMAGE)||flags!=O_RDONLY)abort();\n'
           ' return fixture_fd(path,flags);\n'
           '}\n'
           'static int range_ok(const void *address,size_t length){\n'
           ' uintptr_t start=(uintptr_t)address,base=(uintptr_t)buf;\n'
           ' return buf&&start>=base&&start-base<=physical_bytes&&length<=physical_bytes-(start-base);\n'
           '}\n'
           'static ssize_t seam_read(int fd,void *address,size_t length){\n'
           ' reads++;event("image-read");\n'
           ' if(!range_ok(address,length)){bad_range++;errno=EFAULT;return -1;}\n'
           ' return read(fd,address,length);\n'
           '}\n'
           'static ssize_t seam_write(int fd,const void *address,size_t length){\n'
           ' (void)fd;writes++;event("write");\n'
           ' if(!range_ok(address,length)){bad_range++;errno=EFAULT;return -1;}\n'
           ' written_bytes+=length;return (ssize_t)length;\n'
           '}\n'
           'static int mtd_block_is_bad(int fd,int offset){(void)fd;(void)offset;return 0;}\n'
           'static int mtd_erase_block(int fd,int offset){\n'
           ' (void)fd;(void)offset;erases++;block_erases++;event("erase");\n'
           ' if((is_case("resume-larger")&&block_erases==1)||\n'
           '    (is_case("resume-offset-refused")&&(block_erases==1||block_erases==3))){errno=EIO;return '
           '-1;}\n'
           ' return 0;\n'
           '}\n'
           'static void indicate_writing(const char '
           '*name){(void)name;write_started++;event("writer-ready");}\n'
           'static int mtd_replace_jffs2(const char*a,int b,int c,const '
           'char*d){(void)a;(void)b;(void)c;(void)d;abort();}\n'
           'static void mtd_parse_jffs2data(const char*a,const char*b){(void)a;(void)b;abort();}\n'
           'static int (*trx_check)(int,const char*,char*,int*)=NULL;\n'
           'static int (*trx_fixup)(int,const char*)=NULL;\n'
           'static int (*mtd_fixtrx)(const char*,size_t,size_t)=NULL;\n'
           'static int (*mtd_fixseama)(const char*,size_t,size_t)=NULL;\n'
           'static int (*mtd_fixwrgg)(const char*,size_t,size_t)=NULL;\n'
           'static int (*mtd_resetbc)(const char*)=NULL;\n'
           'static int mtd_unlock(const char '
           '*name){(void)name;unlocks++;mutation_started=1;event("unlock");return 0;}\n'
           'static int mtd_erase(const char '
           '*name){(void)name;erases++;mutation_started=1;event("pre-erase");return 0;}\n'
           'static int mtd_dump(const char*a,size_t b,size_t c){(void)a;(void)b;(void)c;abort();}\n'
           'static int mtd_write_jffs2(const char*a,const char*b,const '
           'char*c){(void)a;(void)b;(void)c;abort();}\n'
           'static void do_reboot(void){event("forbidden-reboot");abort();}\n'
           'static void usage(void){main_exit=98;longjmp(escape,1);}\n'
           'static void seam_exit(int code){main_exit=code;longjmp(escape,1);}\n'
           'static void seam_sync(void){mutation_started=1;event("sync");}\n',
 'SUFFIX': '\n'
           'int main(int argc,char **argv){\n'
           ' char '
           '*args[]={"probe","-q","-q","-f","-e","Config","write",FIXTURE_IMAGE,"Storage:Config",NULL};\n'
           ' char overlong[PATH_MAX+1];char *volatile old=NULL;int result,image_fd;\n'
           ' if(argc!=2)return 99;\n'
           ' case_name=argv[1];\n'
           ' if(is_case("existing-scratch-growth-refused")){\n'
           '  old=malloc(8);if(!old)abort();memset(old,0x5a,8);buf=old;buf_capacity=physical_bytes=8;\n'
           ' }\n'
           ' if(is_case("null-target"))result=mtd_check(NULL)?0:1;\n'
           ' else if(is_case("overlong-target")){\n'
           "  memset(overlong,'a',PATH_MAX);overlong[PATH_MAX]=0;result=mtd_check(overlong)?0:1;\n"
           ' }else if(!strncmp(case_name,"writer-",7)&&!is_case("writer-geometry-growth")){\n'
           '  buf=malloc(16);if(!buf)abort();buf_capacity=physical_bytes=16;\n'
           '  if(is_case("writer-null-buffer")){free(buf);buf=NULL;buf_capacity=physical_bytes=0;}\n'
           '  if(is_case("writer-short-capacity"))buf_capacity=8;\n'
           '  if(is_case("writer-negative-length"))buflen=-1;\n'
           '  if(is_case("writer-carried-length"))buflen=17;\n'
           '  image_fd=fixture_fd(FIXTURE_IMAGE,O_RDONLY);\n'
           '  result=mtd_write(image_fd,"Storage",NULL,0)!=0;\n'
           '  if(close(image_fd))abort();\n'
           ' }else{\n'
           '  if(is_case("configured-k2p")||is_case("writer-geometry-growth"))args[8]="Storage";\n'
           '  if(is_case("resume-offset-refused"))args[8]="Storage:Config:Storage:Nvram";\n'
           '  if(!setjmp(escape))result=preflight_main(9,args);else result=main_exit;\n'
           ' }\n'
           ' '
           'printf("{\\"case\\":\\"%s\\",\\"returncode\\":%d,\\"trace\\":\\"%s\\",\\"opens\\":%d,\\"closes\\":%d,\\"live_fds\\":%d,\\"allocations\\":%d,\\"allocation_bytes\\":%lu,\\"capacity\\":%lu,\\"name_allocations\\":%d,\\"late_allocations\\":%d,\\"unlocks\\":%d,\\"erases\\":%d,\\"writes\\":%d,\\"image_reads\\":%d,\\"written_bytes\\":%lu,\\"bad_range\\":%d,\\"writer_ready\\":%d,\\"old_allocation_preserved\\":%s}\\n",\n'
           ' case_name,result,trace,opens,closes,live_count,allocs,(unsigned long)requested,(unsigned '
           'long)buf_capacity,\n'
           ' name_allocs,late_allocs,unlocks,erases,writes,reads,(unsigned '
           'long)written_bytes,bad_range,write_started,\n'
           ' old&&buf==old&&physical_bytes==8&&buf[0]==0x5a?"true":"false");\n'
           ' while(live_count)if(close(live_fds[--live_count]))abort();\n'
           ' free(buf);return 0;\n'
           '}\n'}


def shipped_elf():
    data = bytearray(52)
    data[:7] = b'\x7fELF\x01\x01\x01'
    struct.pack_into('<HH', data, 16, 2, 8)
    return bytes(data)


class MtdPreflightTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = {
            'mtd': 'static size_t buf_capacity;\n' +\
                'static int mtd_check(const char *p) { return p != 0; }\n' +\
                'static int image_check(int f, const char *p) { return f && p; }\n' +\
                'static int mtd_write(int f, const char *p, char *l, size_t o) { return f && p && !l && !o; }\n' +\
                'int main(int n, char **v) { return n && v ? 0 : 1; }\n',
            'harness': '\n'.join(name + ' = ' + repr(value) for name, value in MODEL_FIXTURE.items()),
            'legacy_guard': '/* inert source identity fixture */\n',
            'makefile': 'CFLAGS += -DMTD_K2P_LEGACY_GUARD=1\n',
        }

    def rows(self):
        return [{'case': name, 'inputs': copy.deepcopy(options), 'observed': copy.deepcopy(gate.EXPECTED[name])}
                for name, options in gate.CASES]

    def parent(self):
        data = shipped_elf()
        shared = {key: gate.sha(self.inputs[key].encode()) for key in ('mtd', 'legacy_guard', 'makefile')}
        rows = [{'case': name, 'inputs': copy.deepcopy(options),
                 'observed': dict(copy.deepcopy(gate.backup.EXPECTED[name]), flags=0)}
                for name, options in gate.backup.CASES]
        return {'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4',
                'phase': 'final-shipped-image-reference-bound',
                'required_cases': [name for name, _ in gate.backup.CASES], 'checks': rows,
                'source_files': {key: gate.SOURCE_PATHS[key] for key in shared}, 'source_sha256': shared,
                'shipped_legacy': {'path': 'bin/mtd_write', 'bytes': len(data), 'sha256': gate.sha(data),
                    'ELF': gate.dns.elf(data, True), 'source_sha256': shared['mtd'],
                    'guard_sha256': shared['legacy_guard'], 'image_byte_binding_required': True,
                    'execution_performed': False}}

    def test_fixed22_records_schema_order_and_case_inputs(self):
        rows = self.rows()
        gate.validate_records(rows)
        self.assertEqual(len(rows), 22)
        for value in ([], rows[:-1], rows + rows[:1], list(reversed(rows))):
            with self.assertRaises(ValueError):
                gate.validate_records(value)
        for key, value in (('case', False), ('inputs', {}), ('extra', 1)):
            changed = copy.deepcopy(rows)
            changed[0][key] = value
            with self.assertRaises(ValueError):
                gate.validate_records(changed)

    def test_every_observed_field_is_fixed_and_typed(self):
        rows = self.rows()
        for index, row in enumerate(rows):
            for key, value in row['observed'].items():
                changed = copy.deepcopy(rows)
                changed[index]['observed'][key] = bool(value) if type(value) is int else None
                with self.subTest(case=row['case'], field=key), self.assertRaises(ValueError):
                    gate.validate_records(changed)
        for key in ('mode', 'selector'):
            changed = copy.deepcopy(rows)
            changed[0]['inputs'][key] = False
            with self.assertRaises(ValueError):
                gate.validate_records(changed)

    def test_full_stdout_is_one_exact_json_line_without_duplicate_keys_or_nonfinite_numbers(self):
        name = gate.CASES[0][0]
        raw = json.dumps(gate.EXPECTED[name]) + '\n'
        self.assertEqual(gate.stdout_observation(raw, name), gate.EXPECTED[name])
        for changed in ('noise\n' + raw, raw + '\n', raw + raw, raw.rstrip(),
                        raw.replace('{', '{"case":"duplicate",', 1), raw.replace('65536', 'NaN', 1)):
            with self.subTest(raw=changed[:40]), self.assertRaises(ValueError):
                gate.stdout_observation(changed, name)
        changed = copy.deepcopy(gate.EXPECTED[name]);changed['opens'] = float(changed['opens'])
        with self.assertRaises(ValueError):
            gate.stdout_observation(json.dumps(changed) + '\n', name)

    def test_literal_reconstruction_uses_four_current_whole_functions_without_S_execution(self):
        fixture = '/tmp/k2p-mtd-preflight-unit/fixture'
        code, manifest = gate.regenerate(self.inputs, fixture, 501)
        self.assertEqual(set(manifest), set(gate.FUNCTION_SOURCES))
        for name in manifest:
            body = gate.backup.function(self.inputs['mtd'], name)
            self.assertEqual(code.count(body), 1)
            self.assertEqual(manifest[name]['full_body_sha256'], gate.sha(body.encode()))
        inputs = dict(self.inputs, harness=self.inputs['harness'] + '\nraise AssertionError("S MUST NOT EXECUTE")\n')
        self.assertEqual(gate.regenerate(inputs, fixture, 501), (code, manifest))

    def test_model_pin_nonliteral_duplicate_paths_and_owner_fail_closed(self):
        changed = dict(self.inputs)
        values = copy.deepcopy(MODEL_FIXTURE);values['PREFIX'] += 'changed'
        changed['harness'] = '\n'.join(name + ' = ' + repr(value) for name, value in values.items())
        with self.assertRaises(ValueError):
            gate.regenerate(changed, '/tmp/k2p-mtd-preflight-unit/fixture', 501)
        changed['harness'] = self.inputs['harness'].replace('PREFIX = ', 'PREFIX = str(', 1)
        with self.assertRaises((ValueError, SyntaxError)):
            gate.regenerate(changed, '/tmp/k2p-mtd-preflight-unit/fixture', 501)
        changed = dict(self.inputs, harness=self.inputs['harness'] + '\nPREFIX = "duplicate"\n')
        with self.assertRaises(ValueError):
            gate.regenerate(changed, '/tmp/k2p-mtd-preflight-unit/fixture', 501)
        for root in ('relative', '/dev/fixture', '/tmp/k2p-mtd-preflight-unit/../fixture',
                     '/tmp/k2p-mtd-preflight-unit/fixture\n'):
            with self.subTest(root=root), self.assertRaises(ValueError):
                gate.regenerate(self.inputs, root, 501)
        for uid in (True, -1, 2**32):
            with self.assertRaises(ValueError):
                gate.regenerate(self.inputs, '/tmp/k2p-mtd-preflight-unit/fixture', uid)

    def test_final_parent_binds71_typed_cases_same_source_actual_mtd_and_image(self):
        parent = self.parent();raw = json.dumps(parent).encode();image = b'I' * 64
        ref = gate.parent_reference_from_bytes(self.inputs, raw, shipped_elf(), image)
        self.assertEqual((ref['parent_cases'], ref['image_sha256'], ref['report_sha256']),
                         (71, gate.sha(image), gate.sha(raw)))
        self.assertTrue(ref['independent_image_extraction_required'])
        for field, value in (('schema_version', True), ('status', 'FAIL'), ('profile', 'other'),
                             ('phase', 'early-source-only'), ('required_cases', []), ('checks', [])):
            changed = copy.deepcopy(parent);changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.parent_reference_from_bytes(self.inputs, json.dumps(changed).encode(), shipped_elf(), image)
        for field in ('mtd', 'legacy_guard', 'makefile'):
            changed = copy.deepcopy(parent);changed['source_sha256'][field] = '0' * 64
            with self.subTest(source=field), self.assertRaises(ValueError):
                gate.parent_reference_from_bytes(self.inputs, json.dumps(changed).encode(), shipped_elf(), image)
        for field, value in (('sha256', '0' * 64), ('bytes', True), ('execution_performed', True)):
            changed = copy.deepcopy(parent);changed['shipped_legacy'][field] = value
            with self.subTest(shipped=field), self.assertRaises(ValueError):
                gate.parent_reference_from_bytes(self.inputs, json.dumps(changed).encode(), shipped_elf(), image)
        for image in (b'', b'I' * 63, bytearray(64)):
            with self.assertRaises(ValueError):
                gate.parent_reference_from_bytes(self.inputs, raw, shipped_elf(), image)

    def test_preflight_and_final_output_schema_with_inert_compiler_and_qemu(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trunk = root / 'trunk';trunk.mkdir()
            (trunk / '.config').write_text('CONFIG_LINUXDIR=linux-4.4.x\nCONFIG_FIRMWARE_PRODUCT_ID="K2P"\n')
            for key, relative in gate.SOURCE_PATHS.items():
                path = root / relative;path.parent.mkdir(parents=True, exist_ok=True);path.write_text(self.inputs[key])
            rootfs = root / 'rootfs';(rootfs / 'bin').mkdir(parents=True)
            (rootfs / 'bin/mtd_write').write_bytes(shipped_elf())
            image = root / 'synthetic.trx';image.write_bytes(b'I' * 64)
            parent = root / 'target-mtd-backup.json';parent.write_text(json.dumps(self.parent()))
            compiler = root / 'inert-gcc';output = root / 'out/target-mtd-preflight.json'
            def run(command, **kwargs):
                if command[0] == str(compiler):
                    self.assertEqual(tuple(command[1:1 + len(gate.FLAGS)]), gate.FLAGS)
                    Path(command[-1]).write_bytes(shipped_elf())
                    return types.SimpleNamespace(returncode=0, stdout='', stderr='')
                self.assertEqual(command[0], '/inert/qemu-mipsel')
                self.assertEqual(Path(command[1]).name, 'current')
                return types.SimpleNamespace(returncode=0, stdout=json.dumps(gate.EXPECTED[command[2]]) + '\n', stderr='')
            captured = io.StringIO()
            with mock.patch.object(gate.shutil, 'which', return_value='/inert/qemu-mipsel'), \
                 mock.patch.object(gate.subprocess, 'run', side_effect=run), \
                 mock.patch.object(gate.resident, 'validate_static_helper', return_value={'inert_test_metadata': True}), \
                 contextlib.redirect_stdout(captured):
                early = gate.check(trunk, compiler, output, True)
                self.assertEqual(early['phase'], 'early-source-only');self.assertIsNone(early['parent_reference'])
                final = gate.check(trunk, compiler, output, False, rootfs, image, parent)
            self.assertEqual(captured.getvalue(), 'MTD preflight:22 inert current-source MIPS cases PASS\n' * 2)
            self.assertEqual(final['phase'], 'final-parent-image-reference-bound')
            self.assertEqual(final['parent_reference']['report_sha256'], gate.sha(parent.read_bytes()))
            self.assertEqual(set(output.parent.iterdir()), {output, output.parent / 'target-mtd-preflight.c',
                output.parent / 'target-mtd-preflight', output.parent / 'target-mtd-preflight.stdout.json'})
            raw = (output.parent / 'target-mtd-preflight.stdout.json').read_bytes()
            self.assertEqual(final['stdout']['sha256'], gate.sha(raw))
            for row in gate.strict_json(raw):
                gate.stdout_observation(row['stdout'], row['case'])

    def test_profile_and_early_late_arguments_fail_closed_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);(root / '.config').write_text('CONFIG_LINUXDIR=linux-3.4.x\n')
            for args in ((True, root, None, None), (False, None, None, None),
                         (False, root, None, root), (True, None, None, None)):
                with self.assertRaises(ValueError):
                    gate.check(root, root / 'gcc', root / 'out', *args)


if __name__ == '__main__':
    unittest.main()
