#!/usr/bin/env python3
"""Bind fixed-board lifetime protection to the actual K2P MIPS image."""
import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess
from check_k2p_reset_guard import bind, require, sha
from check_target_builtin_lifecycle import embedded_config
from check_target_spi_nor import inspect_elf, MAX_ELF
from check_target_init_dma_lifecycle import canonical_command, command_member

PREFIX = 'target-device-lifetime'
OBJECTS = {
 'lifetime': ('drivers/base/device_lifetime.o', ('device_lifetime_probe_begin', 'device_lifetime_depend', 'device_lifetime_remove_begin', 'device_lifetime_detach_begin', 'device_lifetime_driver_remove', 'device_lifetime_devres_allowed')),
 'dd': ('drivers/base/dd.o', ('really_probe', 'device_bind_driver', '__device_release_driver', 'driver_detach')),
 'core': ('drivers/base/core.o', ('device_add', 'device_del', 'device_unregister', 'device_move')),
 'bus': ('drivers/base/bus.o', ('bus_add_driver', 'bus_remove_driver', 'bus_remove_device')),
 'driver': ('drivers/base/driver.o', ('driver_register', 'driver_unregister')),
 'devres': ('drivers/base/devres.o', ('devres_release_all',)),
 'platform': ('drivers/base/platform.o', ('platform_device_del', 'platform_device_unregister')),
 'pci': ('drivers/pci/pci-driver.o', ('pci_device_probe', 'pci_unregister_driver')),
 'pci_remove': ('drivers/pci/remove.o', ('pci_stop_and_remove_bus_device', 'pci_remove_bus', 'pci_stop_root_bus', 'pci_remove_root_bus')),
 'pci_sysfs': ('drivers/pci/pci-sysfs.o', ('remove_store',)),
 'spi': ('drivers/spi/spi.o', ('spi_unregister_master',)),
}
REQUIRED_CONFIG = ('CONFIG_K2P_RESET_GUARD=y', 'CONFIG_MT7615_AP=m', 'CONFIG_SPI_MT7621=y', '# CONFIG_MODULE_FORCE_UNLOAD is not set', '# CONFIG_HOTPLUG_PCI is not set', '# CONFIG_PM is not set', '# CONFIG_PCI_MSI is not set')
LAYOUT = '''#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/spi/spi.h>
const unsigned int layout_driver_flag = offsetof(struct device_driver, no_forced_unbind);
const unsigned int layout_platform_driver = offsetof(struct platform_driver, driver);
const unsigned int layout_pci_driver = offsetof(struct pci_driver, driver);
const unsigned int layout_spi_driver = offsetof(struct spi_driver, driver);
'''

def compile_layout(trunk, artifacts):
 kernel=(trunk/'linux-4.4.x').resolve();artifacts=artifacts.resolve()
 original=(kernel/'drivers/base/.device_lifetime.o.cmd').read_text().splitlines()[0].split(':=',1)[1].strip()
 argv=[arg.replace('$(pound)','#')for arg in shlex.split(original)if not arg.startswith('-Wp,-MD,')]
 require(argv.count('-o')==argv.count('-c')==1 and argv[-1]=='drivers/base/device_lifetime.c','Unexpected lifetime compiler command')
 source=artifacts/'target-device-lifetime-layout.c';obj=source.with_suffix('.o')
 source.write_text(LAYOUT);argv[argv.index('-o')+1]=str(obj);argv[-1]=str(source)
 result=subprocess.run(argv,cwd=kernel,capture_output=True,text=True,timeout=90)
 require(result.returncode==0 and not result.stderr,'Lifetime layout compilation failed: '+result.stdout+result.stderr)
 source.with_suffix('.command.json').write_text(json.dumps({'original_command':original,'argv':argv,'cwd':str(kernel),'source':source.name,'object':obj.name},indent=2)+'\n')

def inspect(directory):
 config=embedded_config((directory/'target-spi-kernel-raw.bin').read_bytes()).decode().splitlines()
 for line in REQUIRED_CONFIG:
  require(config.count(line)==1, 'Lifetime guard target profile differs: '+line)
 kernel=directory/'target-spi-kernel-vmlinux.elf'
 linked=inspect_elf(kernel.read_bytes(),2)
 objects={}
 for label,(relative,names) in OBJECTS.items():
  stem=directory/(PREFIX+'-'+label);obj,cmd=stem.with_suffix('.o'),stem.with_suffix('.cmd')
  require(obj.stat().st_size<=MAX_ELF,'Lifetime object too large')
  require(command_member(canonical_command(cmd.read_bytes()),relative),'Wrong lifetime object command: '+label)
  meta=inspect_elf(obj.read_bytes(),1)
  objects[label]={'sha256':meta['sha256'],'command_sha256':sha(cmd),'functions':bind(meta,linked,names)}
 return {'status':'PASS','config':list(REQUIRED_CONFIG),'kernel_sha256':sha(kernel),'objects':objects}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--trunk',type=Path);p.add_argument('--artifacts',required=True,type=Path);a=p.parse_args()
 if a.trunk:
  for label,(relative,_) in OBJECTS.items():
   obj=a.trunk/'linux-4.4.x'/relative;stem=a.artifacts/(PREFIX+'-'+label)
   shutil.copyfile(obj,stem.with_suffix('.o'));shutil.copyfile(obj.with_name('.'+obj.name+'.cmd'),stem.with_suffix('.cmd'))
  compile_layout(a.trunk,a.artifacts)
 report=inspect(a.artifacts);output=a.artifacts/(PREFIX+'.json')
 if a.trunk:output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 else:require(json.loads(output.read_text())==report,'Lifetime report differs from actual ELF evidence')
 print(json.dumps({'status':'PASS','objects':len(report['objects'])}))
if __name__=='__main__':main()
