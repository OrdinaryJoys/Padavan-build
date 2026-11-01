"""Independent failure controls for inert SPI MIPS and kernel-image proofs."""
import copy
import importlib.util
import lzma
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zlib

SPEC=importlib.util.spec_from_file_location('spi_gate',Path(__file__).with_name('check_target_spi_nor.py'))
gate=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(gate)


def elf(kind=2,text=None):
    text=text or bytes(range(16));data=bytearray(8192)
    data[:7]=b'\x7fELF\x01\x01\x01'
    struct.pack_into('<HHIIIIIHHHHHH',data,16,kind,8,1,0x81001000 if kind==2 else 0,
                     52 if kind==2 else 0,4096,0,52,32 if kind==2 else 0,1 if kind==2 else 0,40,5,1)
    if kind==2:struct.pack_into('<8I',data,52,1,256,0x81001000,0x81001000,len(text),len(text),5,4)
    names=b'\0.shstrtab\0.text\0.symtab\0.strtab\0';data[4500:4500+len(names)]=names
    strings=b'\0test_function\0';data[4700:4700+len(strings)]=strings
    struct.pack_into('<10I',data,4136,names.index(b'.shstrtab'),3,0,0,4500,len(names),0,0,1,0)
    struct.pack_into('<10I',data,4176,names.index(b'.text'),1,6,0x81001000 if kind==2 else 0,256,len(text),0,0,4,0)
    struct.pack_into('<10I',data,4216,names.index(b'.symtab'),2,0,0,4800,32,4,0,4,16)
    struct.pack_into('<10I',data,4256,names.index(b'.strtab'),3,0,0,4700,len(strings),0,0,1,0)
    struct.pack_into('<IIIBBH',data,4816,1,0x81001000 if kind==2 else 0,len(text),18,0,2)
    data[256:256+len(text)]=text
    return data


def image(raw=None):
    raw=raw or bytes(n%251 for n in range(2048))
    compressed=lzma.compress(raw,format=lzma.FORMAT_ALONE)
    compressed+=b'\xff'*((-(64+len(compressed)))%16)
    boundary=64+len(compressed);data=bytearray(64)+compressed+b'hsqs'+b'fixture'
    struct.pack_into('>7I',data,0,0x27051956,0,0,len(data)-64,0x81001000,0x81001000,zlib.crc32(data[64:])&0xffffffff)
    data[28:34]=bytes((5,5,2,3,4,4));data[36:40]=b'K2P\0';struct.pack_into('>I',data,60,boundary)
    struct.pack_into('>I',data,4,zlib.crc32(data[:64])&0xffffffff)
    return bytes(data),raw


def reseal(data):
    data=bytearray(data);struct.pack_into('>I',data,24,zlib.crc32(data[64:])&0xffffffff)
    data[4:8]=bytes(4);struct.pack_into('>I',data,4,zlib.crc32(data[:64])&0xffffffff)
    return bytes(data)


class SpiTargetTests(unittest.TestCase):
    def test_frozen_current_and_old_controls_reject_missing_wrong_or_untyped_results(self):
        self.assertEqual(len(gate.CASES),51)
        self.assertEqual(sum(not options['baseline'] for _,options in gate.CASES),42)
        self.assertEqual(sum(options['baseline'] for _,options in gate.CASES),9)
        self.assertEqual(len(gate.SOURCE_PATHS),10)
        self.assertEqual(len(gate.FUNCTION_SOURCES),10)
        self.assertEqual(len(gate.BASELINE_FUNCTION_HASHES),9)
        rows=[{'case':name,'inputs':copy.deepcopy(options),'observed':copy.deepcopy(gate.EXPECTED[name])}
              for name,options in gate.CASES]
        gate.validate_records(rows)
        self.assertEqual(gate.EXPECTED['current:write-second-page-error']['sequence'],'AWPTWPU')
        self.assertEqual(gate.EXPECTED['baseline:char-write-zero']['lower_calls'],3)
        self.assertEqual(gate.EXPECTED['current:char-write-zero']['lower_calls'],1)
        for name,key,value in (('current:write-final-ready-error','result',0),
                               ('current:read-fast-command-error','retlen',4294967291),
                               ('current:write-single','allocations',1),
                               ('current:char-read-raw-zero','raw_zeroed',1),
                               ('baseline:write-command-error','retlen',0)):
            invalid=copy.deepcopy(rows);row=next(row for row in invalid if row['case']==name)
            row['observed'][key]=value
            with self.subTest(case=name),self.assertRaises(ValueError):gate.validate_records(invalid)
        for invalid in ([],rows[:-1],rows+rows[:1],list(reversed(rows))):
            with self.assertRaises(ValueError):gate.validate_records(invalid)

    def test_elf_object_and_kernel_symbol_metadata(self):
        for kind in (1,2):
            data=elf(kind);row=gate.inspect_elf(data,kind)
            symbol=row['function_symbols']['test_function'][0]
            self.assertEqual(symbol['bytes'],16)
            self.assertEqual(symbol['sha256'],gate.sha(bytes(range(16))))
            self.assertEqual(row['machine'],8)
            self.assertEqual(row['type'],'ET_REL' if kind==1 else 'ET_EXEC')

    def test_elf_wrong_arch_endian_bounds_and_dynamic_loader_fail(self):
        rows=[]
        data=elf();data[5]=2;rows.append(data)
        data=elf();struct.pack_into('<H',data,18,62);rows.append(data)
        data=elf();struct.pack_into('<I',data,32,8180);rows.append(data)
        data=elf();struct.pack_into('<I',data,52,3);rows.append(data)
        data=elf();struct.pack_into('<I',data,52,2);rows.append(data)
        for data in rows:
            with self.subTest(data=data[:84].hex()),self.assertRaises(ValueError):gate.inspect_elf(data,2)
        with self.assertRaises(ValueError):gate.inspect_elf(elf(1),2)

    def test_elf_function_and_string_table_corruption_fail(self):
        rows=[]
        data=elf();struct.pack_into('<I',data,4824,1000000);rows.append(data)
        data=elf();struct.pack_into('<H',data,4830,1000);rows.append(data)
        data=elf();struct.pack_into('<I',data,4816,1000);rows.append(data)
        data=elf();struct.pack_into('<I',data,4216+24,2);rows.append(data)
        data=elf();struct.pack_into('<I',data,4176+16,8191);rows.append(data)
        for data in rows:
            with self.assertRaises(ValueError):gate.inspect_elf(data,2)

    def test_image_lzma_boundary_crc_and_decoded_bytes(self):
        packed,raw=image();decoded,info=gate.decoded_image_kernel(packed)
        self.assertEqual(decoded,raw);self.assertEqual(info['decoded_sha256'],gate.sha(raw))
        self.assertLessEqual(info['padding_bytes'],15)
        self.assertEqual(info['entry'],0x81001000)

    def test_image_rejects_wrong_metadata_crc_and_rootfs_boundary(self):
        packed,_=image()
        rows=[packed[:-1],bytes(32)]
        for offset,value in ((0,1),(16,1),(31,0),(32,3),(36,88)):
            data=bytearray(packed);data[offset]=value;rows.append(reseal(data))
        data=bytearray(packed);data[4]^=1;rows.append(bytes(data))
        data=bytearray(packed);struct.pack_into('>I',data,60,64);rows.append(reseal(data))
        for data in rows:
            with self.assertRaises(ValueError):gate.decoded_image_kernel(data)

    def test_image_rejects_oversized_declared_output_and_non_ff_tail(self):
        packed,_=image();data=bytearray(packed);data[69:77]=(gate.MAX_KERNEL+1).to_bytes(8,'little')
        with self.assertRaises(ValueError):gate.decoded_image_kernel(reseal(data))
        boundary=struct.unpack_from('>I',packed,60)[0];data=bytearray(packed)
        data[boundary-1]=0
        with self.assertRaises((ValueError,lzma.LZMAError)):gate.decoded_image_kernel(reseal(data))

    def test_vendor_replay_binds_whole_bytes_and_exports_actual_artifacts(self):
        packed,raw=image()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);trunk=root/'trunk';kernel=trunk/'linux-4.4.x';out=root/'out';out.mkdir()
            (trunk/'vendors/Ralink').mkdir(parents=True);(kernel/'drivers/mtd').mkdir(parents=True)
            (trunk/'vendors/Ralink/Makefile').write_text('$(CROSS_COMPILE)objcopy -O binary -R .note -R .comment -S $(ROOTDIR)/$(LINUXDIR)/vmlinux $(KERNELZ)\n')
            (kernel/'vmlinux').write_bytes(elf(2,raw));(kernel/'drivers/mtd/mtdchar.o').write_bytes(elf(1,raw))
            (kernel/'drivers/mtd/.mtdchar.o.cmd').write_text('cmd := fake drivers/mtd/mtdchar.c\n')
            (kernel/'.vmlinux.cmd').write_text('cmd_vmlinux := fake\n')
            compiler=root/'mips-gcc';objcopy=root/'mips-objcopy';objcopy.write_bytes(b'inert tool');objcopy.chmod(0o755)
            firmware=root/'firmware.trx';firmware.write_bytes(packed);vendor=root/'zImage';vendor.write_bytes(raw)
            def replay(command,**options):
                self.assertEqual(command[1:-2],['-O','binary','-R','.note','-R','.comment','-S'])
                Path(command[-1]).write_bytes(raw)
                return subprocess.CompletedProcess(command,0,'','')
            objects={'mtdchar':('drivers/mtd/mtdchar.o',('test_function',))}
            with patch.object(gate,'OBJECTS',objects),patch.object(gate.subprocess,'run',side_effect=replay):
                result=gate.kernel_binding(trunk,compiler,firmware,vendor,out/'report.json')
                self.assertTrue(result['whole_byte_equality'])
                self.assertEqual((out/'target-spi-kernel-raw.bin').read_bytes(),raw)
                self.assertEqual((out/'target-spi-kernel-vendor.bin').read_bytes(),raw)
                vendor.write_bytes(raw[:-1]+bytes((raw[-1]^1,)))
                with self.assertRaisesRegex(ValueError,'byte-for-byte'):
                    gate.kernel_binding(trunk,compiler,firmware,vendor,out/'report.json')

    def test_public_old_source_and_current_body_are_independently_bound(self):
        current='static int current_function(void){return 1;}'
        old='static int old_function(void){return 0;}'
        module='''SOURCE_PATHS={'source':'trunk/source.c'}
CASES=(('normal',{'case':'normal','result':0}),)
BASELINE_CASES=(('old-negative',{'case':'old-negative','result':1}),)
BASELINE_FUNCTIONS={'old_function':OLD_BODY}
BASELINE_FUNCTIONS_SHA256={'old_function':OLD_HASH}
def generate_source(texts,fixture_root,owner_uid=0,baseline=False):
 return BASELINE_FUNCTIONS['old_function'] if baseline else texts['source']
'''.replace('OLD_BODY',repr(old)).replace('OLD_HASH',repr(gate.sha(old.encode())))
        cases=(('current:normal',{'baseline':False,'selector':'normal'}),
               ('baseline:old-negative',{'baseline':True,'selector':'old-negative'}))
        expected={'current:normal':{'case':'normal','result':0},'baseline:old-negative':{'case':'old-negative','result':1}}
        values={'source':current,'harness':module}
        with patch.multiple(gate,SOURCE_PATHS={'source':'trunk/source.c','harness':'tests/harness.py'},
             HARNESS_SOURCE_PATHS={'source':'trunk/source.c'},FUNCTION_SOURCES={'current_function':'source'},
             BASELINE_FUNCTION_HASHES={'old_function':gate.sha(old.encode())},CASES=cases,EXPECTED=expected):
            self.assertEqual(gate.generate_source(values,'/tmp/inert',0)[0],current)
            self.assertEqual(gate.generate_source(values,'/tmp/inert',0,True)[0],old)
            invalid=dict(values);invalid['harness']=module.replace('return 0;','return 9;')
            with self.assertRaises(ValueError):gate.generate_source(invalid,'/tmp/inert',0,True)
            invalid=dict(values);invalid['harness']=module.replace('return texts[\'source\']','return \'omitted\'')
            invalid['source']=current+'\n'+current
            with self.assertRaises(ValueError):gate.generate_source(invalid,'/tmp/inert',0)
            rows=[{'case':name,'inputs':options,'observed':expected[name]} for name,options in cases]
            gate.validate_records(rows)
            bad=copy.deepcopy(rows);bad[0]['observed']['result']=False
            with self.assertRaises(ValueError):gate.validate_records(bad)
            for bad in ([],rows[:-1],list(reversed(rows)),rows+rows[:1]):
                with self.assertRaises(ValueError):gate.validate_records(bad)


if __name__=='__main__':unittest.main()
