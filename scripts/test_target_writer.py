import copy
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('writer', Path(__file__).with_name('check_target_writer.py'))
writer = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(writer)

# Reviewed independently of expected_events: SAFE frees its snapshot; no
# possible-write/verified result may enter allocator cleanup.
MLOCK_ALL = ['open-device', 'device-sync', 'memory-lock']
DEVICE_PREP = MLOCK_ALL + ['snapshot-lock', 'readback-lock']
ERASE_THREE = ['unlock', 'erase', 'unlock', 'erase', 'unlock', 'erase']
COMPLETE = DEVICE_PREP + ERASE_THREE + ['write', 'device-sync', 'writer-close', 'readback', 'reader-close']
FIXED_EVENTS = {
    'success-supported-sync': COMPLETE,
    'success-mtdchar-unsupported-sync': COMPLETE,
    'success-short-writes': DEVICE_PREP + ERASE_THREE + ['write'] * 723 + ['device-sync', 'writer-close', 'readback', 'reader-close'],
    'success-write-eintr': DEVICE_PREP + ERASE_THREE + ['write', 'write', 'device-sync', 'writer-close', 'readback', 'reader-close'],
    'memory-lock-prewrite': MLOCK_ALL + ['memory-free', 'memory-unlock'],
    'image-read-prewrite': ['open-device', 'memory-free'],
    'invalid-crc-prewrite': ['open-device', 'memory-free'],
    'readback-interface-prewrite': ['open-device', 'memory-free'],
    'state-maybe-write-unknown': DEVICE_PREP,
    'state-maybe-sync-unknown': DEVICE_PREP,
    'unlock-unknown': DEVICE_PREP + ['unlock'],
    'erase-unknown': DEVICE_PREP + ['unlock', 'erase'],
    'write-partial-unknown': DEVICE_PREP + ERASE_THREE + ['write', 'write'],
    'sync-unknown': DEVICE_PREP + ERASE_THREE + ['write', 'device-sync'],
    'writer-close-unknown': DEVICE_PREP + ERASE_THREE + ['write', 'device-sync', 'writer-close'],
    'readback-mismatch-unknown': DEVICE_PREP + ERASE_THREE + ['write', 'device-sync', 'writer-close', 'readback'],
    'reader-close-unknown': COMPLETE,
    'state-verified-write-unknown': COMPLETE,
    'state-verified-sync-unknown': COMPLETE,
    'global-lock-busy-unknown': [],
    'success-large-chunked': DEVICE_PREP + ['unlock','erase'] * 37 + ['write'] * 3 +
        ['device-sync','writer-close'] + ['readback'] * 10 + ['reader-close'],
    'second-block-error-unknown': DEVICE_PREP + ['unlock','erase'] * 37 + ['write','write'],
    'allocation-prewrite': ['open-device','memory-free'],
    'snapshot-lock-prewrite': MLOCK_ALL + ['snapshot-lock','memory-free','memory-unlock'],
    'readback-lock-prewrite': MLOCK_ALL + ['snapshot-lock','readback-lock','memory-free','memory-unlock'],
}
# The actual OOM guard runs through low-level private-file seams, never host proc.
OOM_GUARD = ['oom-open','oom-write','oom-read','oom-read','oom-close']
FIXED_EVENTS = {name:OOM_GUARD+events if name!='global-lock-busy-unknown' else events
                for name,events in FIXED_EVENTS.items()}
FIXED_EVENTS.update({
    'oom-open-prewrite':['oom-open','memory-free'],
    'oom-fstat-prewrite':['oom-open','oom-close','memory-free'],
    'oom-owner-prewrite':['oom-open','oom-close','memory-free'],
    'oom-statfs-prewrite':['oom-open','oom-close','memory-free'],
    'oom-not-proc-prewrite':['oom-open','oom-close','memory-free'],
    'oom-write-prewrite':['oom-open','oom-write','oom-close','memory-free'],
    'oom-write-zero-prewrite':['oom-open','oom-write','oom-close','memory-free'],
    'oom-write-over-prewrite':['oom-open','oom-write','oom-close','memory-free'],
    'oom-write-short-prewrite':['oom-open','oom-write','oom-close','memory-free'],
    'oom-mismatch-prewrite':OOM_GUARD+['memory-free'],
    'oom-seek-prewrite':['oom-open','oom-write','oom-close','memory-free'],
    'oom-read-prewrite':['oom-open','oom-write','oom-read','oom-close','memory-free'],
    'oom-read-over-prewrite':['oom-open','oom-write','oom-read','oom-close','memory-free'],
    'oom-read-eof-prewrite':['oom-open','oom-write','oom-read','oom-close','memory-free'],
    'oom-read-extra-prewrite':['oom-open','oom-write','oom-read','oom-close','memory-free'],
    'oom-close-prewrite':OOM_GUARD+['memory-free'],
    'success-oom-write-eintr':['oom-open','oom-write','oom-write','oom-read','oom-read','oom-close']+COMPLETE,
    'success-oom-read-eintr':['oom-open','oom-write','oom-read','oom-read','oom-read','oom-close']+COMPLETE,
    'success-oom-read-short':['oom-open','oom-write','oom-read','oom-read','oom-read','oom-read','oom-close']+COMPLETE,
})
OOM_FIXTURE = {name:'-1000\n' for name in FIXED_EVENTS}
for name in ('global-lock-busy-unknown','oom-open-prewrite','oom-fstat-prewrite','oom-owner-prewrite',
             'oom-statfs-prewrite','oom-not-proc-prewrite','oom-write-prewrite',
             'oom-write-zero-prewrite','oom-write-over-prewrite'):
    OOM_FIXTURE[name]='0\n'
OOM_FIXTURE['oom-write-short-prewrite']='-100'
OOM_FIXTURE['oom-mismatch-prewrite']='-0999\n'
FIXED_REQUESTS = {name:([12288] if 'write' in events else []) for name,events in FIXED_EVENTS.items()}
FIXED_REQUESTS.update({'success-short-writes':list(range(12288,0,-17)),
                       'success-write-eintr':[12288,12288],
                       'write-partial-unknown':[12288,12281],
                       'success-large-chunked':[65536,65536,20480],
                       'second-block-error-unknown':[65536,65536]})

def records():
    rows = []
    for index, (name, fault, code, state, matches) in enumerate([
            ('shipped-legacy-protocol-refused', None, 21, None, None), *writer.CASES]):
        pid = 123 + index
        shipped = name == 'shipped-legacy-protocol-refused'
        image_bytes = 150064 if name in ('success-large-chunked','second-block-error-unknown') else 9064
        rows.append({'case': name, 'backend': 'actual-shipped-writer' if shipped else 'inert-production-source-MIPS-probe',
                     'fault': fault, 'exit_code': code, 'child_pid': pid,
                     'record': None if shipped else {'state': state, 'pid': pid, 'target': 'firmware',
                                'image_bytes': 0 if state == 'PREWRITE' else image_bytes,
                                'verified_bytes': image_bytes if state == 'VERIFIED' else 0},
                     'events': [] if shipped else list(FIXED_EVENTS[name]),
                     'device_write_requests':None if shipped else list(FIXED_REQUESTS[name]),
                     'oom_score_fixture':None if shipped else OOM_FIXTURE[name],
                     'payload_matches_snapshot': matches, 'record_metadata': None if shipped else {'uid': 0, 'mode': 0o600, 'nlink': 1}})
    return rows


def elf(tags=(), dynamic=True):
    data = bytearray(256)
    data[:7] = b'\x7fELF\x01\x01\x01'
    struct.pack_into('<H', data, 18, 8)
    struct.pack_into('<I', data, 28, 52)
    struct.pack_into('<HH', data, 42, 32, 1)
    struct.pack_into('<8I', data, 52, 2 if dynamic else 1, 128, 0, 0, (len(tags) + 1) * 8, 0, 0, 0)
    for index, pair in enumerate(tags): struct.pack_into('<II', data, 128 + index * 8, *pair)
    return bytes(data)


def sources():
    branch = '\tif (argc > 1 && !strcmp(argv[1], "--upgrade-write")) {\n\t\treturn 21;\n\t}'
    body = ('#include "mtd-abi.h"\n#include "upgrade_write.h"\n'
            'int main(int argc,char**argv){if(argc!=4)return 99;_exit(firmware_upgrade_write(argv[1],argv[2],argv[3]));}')
    fixture = ('class FirmwareWriterProtocolTests:\n @classmethod\n def setUpClass(cls):\n  harness.write_text('
               + repr(body) + ')\n')
    return {'mtd.c': 'int main(int argc,char**argv){\n' + branch + '\nwhile ((ch = getopt',
            'legacy_guard.h': '/* locked guard */',
            'upgrade_write.h': '#include "crc32.h"\n/* production header */', 'crc32.h': '/* CRC declarations */',
            'crc32.c': '/* CRC table */', 'mtd-abi.h': '/* MTD ABI */', 'fixture': fixture,
            'Makefile': 'LDFLAGS += -Wl,-z,now\n'}


class TargetWriterTests(unittest.TestCase):
    def test_controller_output_reservation_rejects_existing_files_and_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            original = writer.prepare_output(path)
            self.assertEqual(original.st_uid, os.geteuid())
            self.assertEqual(original.st_mode & 0o7777, 0o600)
            with self.assertRaises(FileExistsError): writer.prepare_output(path)
            alias = Path(directory) / 'alias'; alias.symlink_to(path)
            with self.assertRaises(FileExistsError): writer.prepare_output(alias)

    def test_same_uid_worker_truncate_preserves_owner_inode_and_controller_rewrite(self):
        # Portable subprocess control only; this does not claim a UID transition.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'; before = writer.prepare_output(path)
            subprocess.run([sys.executable, '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("worker")', str(path)], check=True)
            after = path.stat(); self.assertEqual((before.st_uid, before.st_ino), (after.st_uid, after.st_ino))
            path.write_text('controller final report'); self.assertEqual(path.read_text(), 'controller final report')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Real root worker transition requires Linux/sudo CI')
    def test_linux_root_worker_preserves_controller_inode_and_parent_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'; before = writer.prepare_output(path)
            command = (['sudo', '-n'] if os.geteuid() else []) + [
                sys.executable, '-c',
                'import os,pathlib,sys;assert os.geteuid()==0;p=pathlib.Path(sys.argv[1]);p.write_text("root worker");p.chmod(0o644);print(os.geteuid())', str(path)]
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertEqual(result.stdout, '0\n')
            after = path.stat(); self.assertEqual((before.st_uid, before.st_ino), (after.st_uid, after.st_ino))
            path.write_text('controller final report'); self.assertEqual(path.read_text(), 'controller final report')
    def test_exact_forty_five_records_are_accepted(self):
        self.assertEqual(len(records()), 45)
        self.assertEqual(set(FIXED_EVENTS),{row[0] for row in writer.CASES})
        self.assertEqual(set(FIXED_REQUESTS),set(FIXED_EVENTS))
        writer.validate_records(records())

    def test_source_only_preflight_requires_exact_forty_four_cases_and_preserves_roles(self):
        source = records()[1:]
        self.assertEqual(len(source), 44)
        writer.validate_records(source, include_shipped=False)
        other_owner = copy.deepcopy(source)
        for row in other_owner: row['record_metadata']['uid'] = 99
        writer.validate_records(other_owner, expected_owner=99, include_shipped=False)
        with self.assertRaises(ValueError): writer.validate_records(source)
        with self.assertRaises(ValueError): writer.validate_records(records(), include_shipped=False)
        for selection in (0, 1, 'false', None):
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                writer.validate_records(source, include_shipped=selection)
        bad_role = copy.deepcopy(source); bad_role[0]['backend'] = 'actual-shipped-writer'
        bad_events = copy.deepcopy(source); bad_events[0]['events'] = []
        for rows in (source[:-1], source + source[:1], list(reversed(source)), bad_role, bad_events):
            with self.subTest(cases=len(rows)), self.assertRaises(ValueError):
                writer.validate_records(rows, include_shipped=False)

    def test_missing_duplicate_and_reordered_cases_are_rejected(self):
        for rows in (records()[:-1], records() + records()[:1], list(reversed(records()))):
            with self.assertRaises(ValueError): writer.validate_records(rows)
        for value in ([65537,65536,20480],[65536,20480],[65536,True,20480],
                      [65536,65536,20480.0],None):
            rows=records();next(row for row in rows if row['case']=='success-large-chunked')['device_write_requests']=value
            with self.subTest(requests=value),self.assertRaises(ValueError):writer.validate_records(rows)
        rows=records();rows[-1]['events'].append('readback')
        with self.assertRaises(ValueError):writer.validate_records(rows)

    def test_extra_keys_and_wrong_backend_roles_are_rejected(self):
        for change in ('extra', 'backend'):
            rows = records()
            if change == 'extra': rows[1]['unexpected'] = True
            else: rows[0]['backend'] = 'inert-production-source-MIPS-probe'
            with self.assertRaises(ValueError): writer.validate_records(rows)

    def test_unknown_exit_and_prewrite_pair_cannot_be_swapped(self):
        rows = records(); next(row for row in rows if row['case']=='second-block-error-unknown')['exit_code'] = 20
        with self.assertRaises(ValueError): writer.validate_records(rows)
        rows = records(); rows[4]['record']['state'] = 'PREWRITE'
        with self.assertRaises(ValueError): writer.validate_records(rows)

    def test_status_pid_and_target_bindings_are_required(self):
        for key, value in (('pid', 999), ('target', 'Firmware'), ('image_bytes', 1), ('verified_bytes', 1)):
            rows = records(); rows[1]['record'][key] = value
            with self.assertRaises(ValueError): writer.validate_records(rows)

    def test_boolean_numeric_fields_and_public_status_modes_are_rejected(self):
        for location in ('exit', 'pid', 'uid', 'nlink', 'mode'):
            rows = records()
            if location == 'exit': rows[1]['exit_code'] = False
            elif location == 'pid': rows[1]['record']['pid'] = True
            else: rows[1]['record_metadata'][location] = True if location == 'nlink' else False if location == 'uid' else 0o644
            with self.assertRaises(ValueError): writer.validate_records(rows)

    def test_memlock_and_write_order_and_unknown_no_unlock_are_required(self):
        for change in ('remove-lock', 'reorder', 'unlock'):
            rows = records()
            if change == 'remove-lock': rows[1]['events'].remove('memory-lock')
            elif change == 'reorder':
                events=rows[1]['events'];a=events.index('memory-lock');b=events.index('snapshot-lock')
                events[a],events[b]=events[b],events[a]
            else: rows[11]['events'].append('memory-unlock')
            with self.assertRaises(ValueError): writer.validate_records(rows)
        for name in ('memory-lock-prewrite','image-read-prewrite','invalid-crc-prewrite','readback-interface-prewrite',
                     'allocation-prewrite','snapshot-lock-prewrite','readback-lock-prewrite'):
            rows=records();row=next(row for row in rows if row['case']==name)
            row['events'].remove('memory-free')
            with self.subTest(case=name),self.assertRaises(ValueError):writer.validate_records(rows)
        for name in ('success-supported-sync','state-maybe-write-unknown','readback-mismatch-unknown','global-lock-busy-unknown'):
            rows=records();row=next(row for row in rows if row['case']==name)
            row['events'].append('memory-free')
            with self.subTest(case=name),self.assertRaises(ValueError):writer.validate_records(rows)

    def test_both_checked_ranges_precede_write_and_failure_stays_prewrite(self):
        for name in ('success-supported-sync','success-large-chunked'):
            for step in ('snapshot-lock','readback-lock'):
                rows=records();row=next(row for row in rows if row['case']==name)
                row['events'].remove(step)
                with self.subTest(case=name,removed=step),self.assertRaises(ValueError):writer.validate_records(rows)
        for name in ('allocation-prewrite','snapshot-lock-prewrite','readback-lock-prewrite'):
            for key,value in (('exit_code',21),('device_write_requests',[12288])):
                rows=records();next(row for row in rows if row['case']==name)[key]=value
                with self.subTest(case=name,key=key),self.assertRaises(ValueError):writer.validate_records(rows)
            rows=records();row=next(row for row in rows if row['case']==name)
            row['record']['state']='MAYBE_WRITTEN'
            with self.subTest(case=name),self.assertRaises(ValueError):writer.validate_records(rows)

    def test_actual_oom_guard_outcome_and_syscall_trace_are_mandatory(self):
        for name in ('oom-open-prewrite','oom-write-short-prewrite','oom-mismatch-prewrite',
                     'oom-read-extra-prewrite','oom-close-prewrite'):
            rows=records();row=next(row for row in rows if row['case']==name)
            self.assertEqual(row['exit_code'],20)
            self.assertNotIn('open-device',row['events'])
            row['exit_code']=0
            with self.subTest(case=name),self.assertRaises(ValueError):writer.validate_records(rows)
        for value in ('0\n','-1000','-1000\nX',-1000,None,False):
            rows=records();rows[1]['oom_score_fixture']=value
            with self.subTest(value=value),self.assertRaises(ValueError):writer.validate_records(rows)
        for name in ('success-supported-sync','success-oom-write-eintr','success-oom-read-eintr','success-oom-read-short'):
            rows=records();row=next(row for row in rows if row['case']==name);row['events'].remove('oom-read')
            with self.subTest(case=name),self.assertRaises(ValueError):writer.validate_records(rows)
        rows=records();rows[0]['oom_score_fixture']='-1000\n'
        with self.assertRaises(ValueError):writer.validate_records(rows)
        rows=records();row=next(row for row in rows if row['case']=='oom-write-short-prewrite')
        row['events'].insert(2,'oom-write')
        with self.assertRaises(ValueError):writer.validate_records(rows)

    def test_payload_and_state_preservation_are_not_only_exit_checks(self):
        rows = records(); rows[1]['payload_matches_snapshot'] = False
        with self.assertRaises(ValueError): writer.validate_records(rows)
        rows = records(); next(row for row in rows if row['case']=='success-large-chunked')['record']['verified_bytes'] = 0
        with self.assertRaises(ValueError): writer.validate_records(rows)

    def test_all_three_dynamic_now_forms_and_static_are_accepted(self):
        for tags in (((24, 0),), ((30, 8),), ((0x6ffffffb, 1),)):
            self.assertEqual(writer.validate_elf_binding(elf(tags)), 'eager-dynamic-binding')
        self.assertEqual(writer.validate_elf_binding(elf(dynamic=False)), 'static-no-dynamic-segment')

    def test_missing_now_wrong_arch_and_truncated_dynamic_are_rejected(self):
        controls = [elf(), b'bad', elf(((30, 0),))]
        wrong = bytearray(elf(((24, 0),))); struct.pack_into('<H', wrong, 18, 62); controls.append(bytes(wrong))
        wrong = bytearray(elf(((24, 0),))); struct.pack_into('<I', wrong, 52 + 16, 65536); controls.append(bytes(wrong))
        for data in controls:
            with self.assertRaises(ValueError): writer.validate_elf_binding(data)

    def test_generator_inlines_locked_header_crc_abi_and_main_dispatch(self):
        text = writer.generate_source(sources())
        for phrase in ('production header', 'CRC declarations', 'CRC table', 'MTD ABI', 'if(argc!=5', 'WRITER_OPERATION'):
            self.assertIn(phrase, text)
        self.assertNotIn('#include "upgrade_write.h"', text)
        self.assertEqual(text, writer.generate_source(sources()))

    def test_generator_rejects_missing_sources_dispatch_binding_or_fixture(self):
        for mode in ('source', 'dispatch', 'binding', 'fixture'):
            values = sources()
            if mode == 'source': values.pop('crc32.c')
            elif mode == 'dispatch': values['mtd.c'] = 'missing'
            elif mode == 'binding': values['Makefile'] = ''
            else: values['fixture'] = 'class Other: pass'
            with self.assertRaises(ValueError): writer.generate_source(values)

    def test_safe_record_parser_rejects_alias_and_embedded_nul(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'status'
            data = b'K2P_FWUP_V1\nstate=PREWRITE\npid=123\ntarget=firmware\nimage_bytes=0\nverified_bytes=0\n'
            path.write_bytes(data); path.chmod(0o600)
            record, meta = writer.parse_record(path, 123)
            self.assertEqual(record['state'], 'PREWRITE'); self.assertEqual(meta['mode'], 0o600)
            with self.assertRaises(ValueError): writer.parse_record(path, 124)
            path.write_bytes(data + b'\0')
            with self.assertRaises(ValueError): writer.parse_record(path, 123)
            alias = Path(temp) / 'alias'; alias.symlink_to(path)
            with self.assertRaises(OSError): writer.parse_record(alias, 123)

    def test_synthetic_image_has_fixed_crc_product_and_structural_size(self):
        import zlib
        data = writer.synthetic_image(); self.assertEqual(len(data), writer.IMAGE_BYTES)
        header = bytearray(data[:64]); header[4:8] = bytes(4)
        self.assertEqual(zlib.crc32(header) & 0xffffffff, struct.unpack_from('>I', data, 4)[0])
        self.assertEqual(data[36:40], b'K2P\0'); self.assertEqual(data[4096:4100], b'hsqs')


if __name__ == '__main__': unittest.main()
