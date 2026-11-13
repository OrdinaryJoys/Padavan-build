#!/usr/bin/env python3
"""Check the K2P configuration and production ELF members for reset ownership."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil

from check_target_builtin_lifecycle import embedded_config
from check_target_spi_nor import inspect_elf, MAX_ELF
from check_target_init_dma_lifecycle import canonical_command, command_member

PREFIX = "target-k2p-reset-guard"
MT = "drivers/net/wireless/mediatek/mt7615"
CONFIG = "CONFIG_K2P_RESET_GUARD=y"
OBJECTS = {
    "core": ("kernel/reboot_guard.o", ("reboot_guard_begin", "reboot_guard_fail",
                                      "reboot_guard_finish", "reboot_guard_seal", "reboot_guard_consume")),
    "reboot": ("kernel/reboot.o", ("kernel_restart", "emergency_restart")),
    "board": ("arch/mips/ralink/reset.o", ("ralink_restart", "ralink_reset_update")),
    "raeth": ("drivers/net/ethernet/raeth/raether.o", ("ei_open", "ei_close", "raether_shutdown")),
    "flash": ("drivers/mtd/spi-nor/spi-nor.o", ("spi_nor_restore", "spi_nor_scan")),
    "m25p": ("drivers/mtd/devices/m25p80.o", ("m25p_probe", "m25p_shutdown")),
    "spi": ("drivers/spi/spi-mt7621.o", ("mt7621_spi_shutdown",)),
    "watchdog": ("drivers/watchdog/mt7621_wdt.o", ("mt762x_wdt_shutdown",)),
    "wifi": (MT + "/os/linux/rt_main_dev.o", ("RtmpDmaShutdown", "RtmpDmaLifecycleGet")),
    "pci": (MT + "/os/linux/pci_main_dev.o", ("RtmpPciDrain", "rt_pci_probe", "rt_pci_shutdown")),
    "wpdma": (MT + "/chips/mt7615.o", ("hif_set_WPDMA",)),
}


def require(condition, error):
    if not condition:
        raise ValueError(error)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bind(obj, linked, names):
    result = {}
    for name in names:
        a = obj["function_symbols"].get(name, [])
        b = linked["function_symbols"].get(name, [])
        require(len(a) == len(b) == 1 and a[0]["bytes"] > 0 and b[0]["bytes"] == a[0]["bytes"],
                "Missing or inconsistent guard function " + name)
        result[name] = {"object": a[0], "linked": b[0]}
    return result


def inspect(directory):
    image_kernel = directory / "target-spi-kernel-raw.bin"
    config = embedded_config(image_kernel.read_bytes()).decode().splitlines()
    require(config.count(CONFIG) == 1, "Guard is not enabled in the image kernel")
    kernel = directory / "target-spi-kernel-vmlinux.elf"
    module = directory / "target-wifi-built.ko"
    linked_kernel = inspect_elf(kernel.read_bytes(), 2)
    linked_wifi = inspect_elf(module.read_bytes(), 1)
    objects = {}
    for label, (relative, names) in OBJECTS.items():
        stem = directory / (PREFIX + "-" + label)
        obj, cmd = stem.with_suffix(".o"), stem.with_suffix(".cmd")
        require(obj.stat().st_size <= MAX_ELF, "Guard object too large")
        require(command_member(canonical_command(cmd.read_bytes()), relative),
                "Wrong compile command for " + label)
        meta = inspect_elf(obj.read_bytes(), 1)
        linked = linked_wifi if relative.startswith(MT + "/") else linked_kernel
        objects[label] = {"sha256": meta["sha256"], "command_sha256": sha(cmd),
                          "functions": bind(meta, linked, names)}
    return {"status": "PASS", "config": CONFIG, "kernel_sha256": sha(kernel),
            "module_sha256": sha(module), "objects": objects}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trunk", type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    args = parser.parse_args()
    if args.trunk:
        for label, (relative, _) in OBJECTS.items():
            obj = args.trunk / "linux-4.4.x" / relative
            stem = args.artifacts / (PREFIX + "-" + label)
            shutil.copyfile(obj, stem.with_suffix(".o"))
            shutil.copyfile(obj.with_name("." + obj.name + ".cmd"), stem.with_suffix(".cmd"))
    report = inspect(args.artifacts)
    output = args.artifacts / (PREFIX + ".json")
    if args.trunk:
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    else:
        require(json.loads(output.read_text()) == report, "Guard report differs from copied ELF evidence")
    print(json.dumps({"status": "PASS", "objects": len(report["objects"])}))


if __name__ == "__main__":
    main()
