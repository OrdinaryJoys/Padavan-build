"""Fail closed on target profile and lifetime object/command mismatches."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import check_device_lifetime as gate

class LifetimeGateTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.config='\n'.join(gate.REQUIRED_CONFIG).encode()
  self.metadata={'sha256':'a'*64,'function_symbols':{n:[{'bytes':16,'value':0}] for _,names in gate.OBJECTS.values() for n in names}}
  (self.root/'target-spi-kernel-raw.bin').write_bytes(b'kernel')
  (self.root/'target-spi-kernel-vmlinux.elf').write_bytes(b'elf')
  for label,(relative,_) in gate.OBJECTS.items():
   stem=self.root/(gate.PREFIX+'-'+label);stem.with_suffix('.o').write_bytes(b'object');stem.with_suffix('.cmd').write_text('cmd_test := mipsel-linux-uclibc-gcc -c -o '+relative+' test.c\n')
 def inspect(self,config=None,metadata=None):
  with patch.object(gate,'embedded_config',return_value=self.config if config is None else config),patch.object(gate,'inspect_elf',return_value=self.metadata if metadata is None else metadata):
   return gate.inspect(self.root)
 def test_profile_and_missing_objects_or_symbols_are_rejected(self):
  self.assertEqual(self.inspect()['status'],'PASS')
  for line in gate.REQUIRED_CONFIG:
   with self.subTest(line=line),self.assertRaises(ValueError):self.inspect(self.config.replace(line.encode(),b''))
  broken=copy.deepcopy(self.metadata);del broken['function_symbols']['device_lifetime_remove_begin']
  with self.assertRaises(ValueError):self.inspect(metadata=broken)
  (self.root/(gate.PREFIX+'-lifetime.o')).unlink()
  with self.assertRaises(FileNotFoundError):self.inspect()
 def test_split_release_entry_and_body_are_both_required(self):
  self.assertEqual(self.inspect()['status'],'PASS')
  for name in ('device_release_driver', '__device_release_driver.part.6', 'driver_detach'):
   broken=copy.deepcopy(self.metadata);del broken['function_symbols'][name]
   with self.subTest(name=name),self.assertRaises(ValueError):self.inspect(metadata=broken)
 def test_compile_command_cannot_point_to_unrelated_object(self):
  self.assertEqual(self.inspect()['status'],'PASS')
  path=self.root/(gate.PREFIX+'-lifetime.cmd');path.write_text('cmd_test := gcc -c -o other.o test.c\n')
  with self.assertRaises(ValueError):self.inspect()
if __name__=='__main__':unittest.main()
