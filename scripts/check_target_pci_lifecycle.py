#!/usr/bin/env python3
"""Current PCI lifecycle source adapters and same-image module evidence.

Only an inert static userspace recorder runs under QEMU.  No PCI, DMA, module,
router, flash or reset operation is executed by the adapter.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

import check_target_resident_upgrade as resident
import check_target_spi_nor as spi

SOURCE_PATHS = {
    'pci': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/pci_main_dev.c',
    'harness': 'tests/pci_lifecycle_harness.py',
    'wifi_config': 'trunk/configs/boards/K2P/kernel-4.4.x.config',
    'flags': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/Makefile.mt_wifi_ap',
    'wifi_makefile': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615_ap/Makefile',
    'kernel_makefile': 'trunk/linux-4.4.x/Makefile',
    'pci_core': 'trunk/linux-4.4.x/drivers/pci/pci-driver.c',
    'pci_header': 'trunk/linux-4.4.x/include/linux/pci.h',
}
COMPONENTS = {'pci': {
    'paths': {
        'pci': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/pci_main_dev.c',
        'config': 'trunk/configs/boards/K2P/kernel-4.4.x.config',
        'flags': 'trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/os/linux/Makefile.mt_wifi_ap',
    },
    'source_keys': {'pci': 'pci', 'config': 'wifi_config', 'flags': 'flags'},
    'functions': {'rt_pci_remove': 'pci', 'rt_pci_shutdown': 'pci'},
    'harness_key': 'harness',
    'model_data_sha256': 'cab3fb384e561ba7d597facd007f15bcf736473a95af5eda317b5ad14004895b',
    'variants': ('current',),
}}
CASES = (
    ('pci:current:remove-adapter', {'component': 'pci', 'variant': 'current', 'selector': 'remove-adapter'}),
    ('pci:current:remove-no-adapter', {'component': 'pci', 'variant': 'current', 'selector': 'remove-no-adapter'}),
    ('pci:current:remove-repeat', {'component': 'pci', 'variant': 'current', 'selector': 'remove-repeat'}),
    ('pci:current:remove-disabled', {'component': 'pci', 'variant': 'current', 'selector': 'remove-disabled'}),
    ('pci:current:remove-no-netdev', {'component': 'pci', 'variant': 'current', 'selector': 'remove-no-netdev'}),
    ('pci:current:remove-no-netdev-repeat', {'component': 'pci', 'variant': 'current', 'selector': 'remove-no-netdev-repeat'}),
    ('pci:current:shutdown-busy', {'component': 'pci', 'variant': 'current', 'selector': 'shutdown-busy'}),
    ('pci:current:shutdown-busy-repeat', {'component': 'pci', 'variant': 'current', 'selector': 'shutdown-busy-repeat'}),
    ('pci:current:shutdown-no-netdev', {'component': 'pci', 'variant': 'current', 'selector': 'shutdown-no-netdev'}),
)
EXPECTED = {
    'pci:current:remove-adapter': [0, 0, 0, 0, 0, 0, 0, 8, 2, 3, 1, 4, 5, 6, 7, 8],
    'pci:current:remove-no-adapter': [0, 0, 0, 0, 0, 0, 0, 7, 9, 1, 4, 5, 6, 7, 8],
    'pci:current:remove-repeat': [0, 0, 0, 0, 0, 0, 0, 9, 2, 3, 1, 4, 5, 6, 7, 8, 1],
    'pci:current:remove-disabled': [0, 0, 0, 0, 0, 0, 0, 7, 2, 3, 1, 4, 5, 6, 7],
    'pci:current:remove-no-netdev': [0, 0, 0, 0, 0, 0, 0, 2, 1, 8],
    'pci:current:remove-no-netdev-repeat': [0, 0, 0, 0, 0, 0, 0, 3, 1, 8, 1],
    'pci:current:shutdown-busy': [1, 0, 1, 1, 1, 1, 0, 1, 1],
    'pci:current:shutdown-busy-repeat': [1, 0, 1, 1, 1, 1, 0, 2, 1, 1],
    'pci:current:shutdown-no-netdev': [1, 0, 0, 0, 0, 1, 0, 1, 1],
}
COMPILED_OBJECTS = {'pci': ('drivers/net/wireless/mediatek/mt7615/os/linux/pci_main_dev.o',
                           'pci', ('rt_pci_remove', 'rt_pci_shutdown'))}
PARENT_EXPORTS = ('target-wifi-built.ko', 'target-wifi-shipped.ko',
                  'target-wifi-module.cmd', 'target-wifi-link.cmd')
BUILT_MODULE = 'drivers/net/wireless/mediatek/mt7615_ap/mt_7615e.ko'
SHIPPED_MODULE = 'lib/modules/4.4.198/kernel/' + BUILT_MODULE
FLAGS = ('-std=gnu99', '-Os', '-static', '-s', '-Wall', '-Wextra', '-Werror', '-fno-strict-aliasing')
REQUIRED_OBJECT_FLAGS = ('-DMT7615', '-DRTMP_MAC_PCI', '-DRTMP_PCI_SUPPORT', '-fno-strict-aliasing')
FORBIDDEN_OBJECT_FLAGS = ('-DINTELP6_SUPPORT', '-DWIFI_DIAG', '-DMEM_ALLOC_INFO_SUPPORT',
                          '-DCONFIG_WIFI_MSI_SUPPORT', '-DCONFIG_PM', '-fstrict-aliasing')
SOURCE_ABI = {
    'driver_initializer_sha256': 'ebb42fb57c892bdcee35873fb2e6734465ce8a5d1d5d8c4a21be759b32bf7e12',
    'pci_core_shutdown_sha256': 'b42c687071cf3d3fc063e8db2b51efe1a008a9cbd6f71d384d444d731c79d522',
    'pci_shutdown_declaration': 'void (*shutdown) (struct pci_dev *dev);',
    'modern_exit_macros': '#if (KERNEL_VERSION(3, 8, 0) <= LINUX_VERSION_CODE)\n#define DEVEXIT\n#define DEVEXIT_P\n#define DEVINIT\n#define DEVINITDATA',
    'enabled_config': ('CONFIG_RALINK_MT7621=y', 'CONFIG_PCI=y', 'CONFIG_CHIP_MT7615E=y', 'CONFIG_MT7615_AP=m'),
    'disabled_config': ('# CONFIG_KEXEC is not set', '# CONFIG_PCI_MSI is not set', '# CONFIG_PM is not set'),
}
ROLE = 'Two complete current PCI lifecycle functions in inert static MIPS userspace'
LIMITS = (
    'PCI API operations, netdev/adapter frees, DMA ownership and DMA busy are inert recorders, not kernel or hardware execution.',
    'The adapter represents the actual K2P Linux4.4 non-MSI/non-PM/non-IntelP6/non-diagnostic preprocessor branch; reduced fixture structures are not the kernel ABI.',
    'Shutdown only suppresses new bus mastering and retains all modeled ownership; it does not prove in-flight DMA drained or that physical reset/boot succeeds.',
    'The real driver close, DMA stop-before-free, first-arm error propagation and complete callback/quarantine graph remain unverified and unrepaired by this gate.',
    'The PCI core ordinary-reboot versus kexec boundary is a fixed source-declaration proof, not execution of either kernel path.',
    'Actual object commands and function symbols are bound to the same built/shipped module and Factory49 image parent; clean locked compilation/relocation attestations are not independently replayed.',
    'No kernel module, PCI configuration, device, networking, MTD, flash, reset or historical unsafe code is executed.',
)
MAX_SOURCE = 4 * 1024 * 1024
MAX_REPORT = 16 * 1024 * 1024
MAX_ELF = 32 * 1024 * 1024
MAX_COMMAND = 2 * 1024 * 1024
MAX_STDOUT = 64 * 1024
MAX_CASE_SECONDS = 20


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact(left, right, message):
    require(json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) ==
            json.dumps(right, sort_keys=True, separators=(',', ':'), allow_nan=False), message)


def decode_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'Duplicate PCI JSON key')
            out[key] = value
        return out

    def nonfinite(value):
        raise ValueError('Non-finite PCI JSON value: ' + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
                'Ordinary bounded single-link PCI input required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
                'PCI input changed during read')
        return data
    finally:
        os.close(fd)


def literal_data(source):
    """Parse source data declarations only; never import/execute its generator."""
    values = {}

    def value(node):
        if isinstance(node, ast.Name):
            require(node.id in values, 'Unknown PCI literal alias')
            return values[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = value(node.left), value(node.right)
            require(type(left) is str and type(right) is str, 'Only PCI literal strings concatenate')
            return left + right
        if isinstance(node, ast.Dict):
            require(all(k is not None for k in node.keys), 'PCI dictionary expansion is not literal')
            items = [(value(k), value(v)) for k, v in zip(node.keys, node.values)]
            require(len(dict(items)) == len(items), 'Duplicate PCI literal dictionary key')
            return dict(items)
        if isinstance(node, (ast.Tuple, ast.List)):
            items = [value(n) for n in node.elts]
            return tuple(items) if isinstance(node, ast.Tuple) else items
        return ast.literal_eval(node)

    for node in ast.parse(source).body:
        require(isinstance(node, (ast.Import, ast.Assign, ast.FunctionDef)) or
                isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and
                type(node.value.value) is str, 'Unsupported PCI source top-level execution')
        if isinstance(node, ast.Import):
            require(all(n.name in ('hashlib', 're') for n in node.names), 'Unexpected PCI source import')
        if isinstance(node, ast.Assign):
            require(len(node.targets) == 1 and isinstance(node.targets[0], ast.Name), 'PCI literal assignment required')
            name = node.targets[0].id
            require(name not in values, 'Duplicate PCI literal assignment')
            values[name] = value(node.value)
    return values


def model_data_hash(values):
    return sha(json.dumps(values, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())


def function(source, name):
    token = r'"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*'
    masked = re.sub(token, lambda m: ' ' * len(m.group()), source)
    pattern = r'(?m)^[ \t]*(?:(?:static|inline)\s+)*(?:[A-Za-z_]\w*\s+|\*\s*)+\b' + re.escape(name) + r'\s*\([^;{}]*\)\s*\{'
    matches = list(re.finditer(pattern, masked))
    require(len(matches) == 1, 'Missing/ambiguous actual PCI function: ' + name)
    start = matches[0].start()
    while source[start] in ' \t':
        start += 1
    opening = masked.index('{', start)
    depth = 0
    for match in re.finditer(token + r'|[{}]', source[opening:]):
        if match.group() == '{':
            depth += 1
        elif match.group() == '}':
            depth -= 1
            if depth == 0:
                return source[start:opening + match.end()]
    raise ValueError('Unterminated actual PCI function: ' + name)


def command_member(text, path):
    return re.search(r'(?<![A-Za-z0-9_./+-])' + re.escape(path) + r'(?![A-Za-z0-9_./+-])', text) is not None


def canonical_command(data):
    require(type(data) is bytes and 0 < len(data) <= MAX_COMMAND and b'\0' not in data,
            'Bounded ordinary PCI command required')
    return data.decode().replace('mt7615_ap/../mt7615/', 'mt7615/')


def validate_contract():
    require(set(COMPONENTS) == {'pci'} and len(SOURCE_PATHS) == 8 and len(CASES) == 9 and
            len({n for n, _ in CASES}) == 9 and set(EXPECTED) == {n for n, _ in CASES},
            'Fixed PCI nine-case source contract required')
    for name, options in CASES:
        require(type(name) is str and type(options) is dict and set(options) == {'component', 'variant', 'selector'} and
                options['component'] == 'pci' and options['variant'] == 'current' and
                type(options['selector']) is str and re.fullmatch('[a-z0-9-]{1,100}', options['selector']) and
                name == 'pci:current:' + options['selector'], 'Fixed PCI case declaration differs')
    spec = COMPONENTS['pci']
    require(spec['variants'] == ('current',) and set(spec['functions']) == {'rt_pci_remove', 'rt_pci_shutdown'} and
            all(SOURCE_PATHS[spec['source_keys'][key]] == path for key, path in spec['paths'].items()) and
            spec['harness_key'] in SOURCE_PATHS and re.fullmatch('[0-9a-f]{64}', spec['model_data_sha256']),
            'Fixed PCI model/function declaration differs')
    require(COMPILED_OBJECTS == {'pci': ('drivers/net/wireless/mediatek/mt7615/os/linux/pci_main_dev.o',
                                        'pci', ('rt_pci_remove', 'rt_pci_shutdown'))},
            'PCI actual object/symbol contract differs')


def source_selection(inputs):
    require(set(inputs) == set(SOURCE_PATHS), 'PCI exact source inventory differs')
    config = inputs['wifi_config']
    for line in SOURCE_ABI['enabled_config'] + SOURCE_ABI['disabled_config']:
        require(len(re.findall('^' + re.escape(line) + '$', config, re.M)) == 1, 'PCI configured board differs: ' + line)
    require(not re.search(r'^CONFIG_(?:KEXEC_CORE|PCI_MSI|PM)=y$', config, re.M), 'PCI excluded kernel profile enabled')
    require('DRV_NAME = mt_7615e' in inputs['wifi_makefile'] and
            command_member(inputs['kernel_makefile'], '-fno-strict-aliasing') and
            re.search(r'^VERSION\s*=\s*4$', inputs['kernel_makefile'], re.M) and
            re.search(r'^PATCHLEVEL\s*=\s*4$', inputs['kernel_makefile'], re.M), 'PCI Linux4.4 module/compiler source differs')
    for key in ('flags', 'wifi_makefile'):
        selected = re.findall(r'ifeq \(\$\(CONFIG_CHIP_MT7615E\),y\)\n([\s\S]*?)\nendif', inputs[key])
        require(len(selected) == 1 and all(command_member(selected[0], flag) for flag in
                ('-DMT7615', '-DRTMP_MAC_PCI', '-DRTMP_PCI_SUPPORT')), 'PCI actual MT7615 make selection differs')
        require(not any(command_member(inputs[key], flag) for flag in FORBIDDEN_OBJECT_FLAGS),
                'PCI source enables an unmodeled preprocessor profile')
    require(SOURCE_ABI['modern_exit_macros'] in inputs['pci'] and
            '#define DEVEXIT\n' in literal_data(inputs['harness'])['PREFIX'], 'PCI Linux4.4 exit macro differs')
    require(SOURCE_ABI['pci_shutdown_declaration'] in inputs['pci_header'], 'PCI real shutdown callback declaration differs')
    found = re.findall(r'^static struct pci_driver rt_pci_driver = \{[\s\S]*?^\};', inputs['pci'], re.M)
    require(len(found) == 1 and sha(found[0].encode()) == SOURCE_ABI['driver_initializer_sha256'] and
            len(re.findall(r'\bshutdown\s*:\s*rt_pci_shutdown\s*,', found[0])) == 1,
            'PCI actual driver shutdown registration differs')
    core = function(inputs['pci_core'], 'pci_device_shutdown')
    require(sha(core.encode()) == SOURCE_ABI['pci_core_shutdown_sha256'] and
            '#ifdef CONFIG_KEXEC_CORE' in core and
            'if (kexec_in_progress && (pci_dev->current_state <= PCI_D3hot))\n\t\tpci_clear_master(pci_dev);' in core and
            core.count('pci_clear_master(pci_dev);') == 1, 'PCI real ordinary-reboot/kexec boundary differs')
    return {'status': 'PASS', 'driver_initializer_sha256': sha(found[0].encode()),
            'shutdown_callback': 'rt_pci_shutdown', 'pci_core_shutdown_sha256': sha(core.encode()),
            'ordinary_reboot_core_clears_master': False, 'kexec_config_enabled': False,
            'selected_profile': 'K2P Linux4.4 MT7615 PCI non-PM/non-MSI/non-IntelP6/non-diagnostic'}


def generate_component(inputs, component='pci', variant='current'):
    require(component == 'pci' and variant == 'current', 'Only fixed current PCI source variant is allowed')
    spec = COMPONENTS[component]
    values = literal_data(inputs[spec['harness_key']])
    exact(values.get('SOURCE_PATHS'), spec['paths'], 'PCI literal source paths differ')
    exact(values.get('FUNCTION_SOURCES'), spec['functions'], 'PCI literal whole-function set differs')
    require(model_data_hash(values) == spec['model_data_sha256'], 'PCI literal model differs')
    exact(values['CASE_NAMES'], [o['selector'] for _, o in CASES], 'PCI literal selector set differs')
    exact(values['EXPECTED_ROWS'], {o['selector']: EXPECTED[n] for n, o in CASES}, 'PCI literal typed outcomes differ')
    require(set(values['BODY_ORDER']) == set(spec['functions']) and len(values['BODY_ORDER']) == 2,
            'PCI complete body order differs')
    bodies = {name: function(inputs[spec['source_keys'][key]], name) for name, key in spec['functions'].items()}
    require(values['SUFFIX'].count('CASE_ADMISSION') == 1, 'PCI fixed admission template differs')
    admission = 'if(!(' + '||'.join('!strcmp(name,' + json.dumps(o['selector']) + ')' for _, o in CASES) + '))return 91;'
    code = values['PREFIX'] + '\n'.join(bodies[n] for n in values['BODY_ORDER']) + values['SUFFIX'].replace('CASE_ADMISSION', admission)
    require(0 < len(code.encode()) <= MAX_SOURCE and all(code.count(body) == 1 for body in bodies.values()),
            'PCI exact complete source body rendering differs')
    manifest = {name: {'source': spec['source_keys'][spec['functions'][name]], 'execution': 'whole-function',
                       'full_body_sha256': sha(body.encode()), 'executed_fragment_sha256': sha(body.encode())}
                for name, body in bodies.items()}
    return code, manifest


def validate_records(rows):
    require(type(rows) is list and len(rows) == len(CASES), 'PCI fixed case count differs')
    for row, (name, options) in zip(rows, CASES):
        require(type(row) is dict and set(row) == {'case', 'inputs', 'observed'} and row['case'] == name,
                'PCI fixed row order/schema differs')
        exact(row['inputs'], options, 'PCI typed case inputs differ: ' + name)
        exact(row['observed'], EXPECTED[name], 'PCI fixed typed outcome differs: ' + name)


def compiled_export_names():
    return {'target-pci-lifecycle-pci.o', 'target-pci-lifecycle-pci.cmd'}


def compiled_binding_from_bytes(inputs, parent_raw, artifacts, metadata):
    require(set(artifacts) == set(PARENT_EXPORTS) | compiled_export_names(), 'PCI exact compiled export inventory differs')
    parent = decode_json(parent_raw)
    require(type(parent) is dict and type(parent.get('schema_version')) is int and parent['schema_version'] == 1 and
            parent.get('status') == 'PASS' and parent.get('profile') == 'k2p-4.4' and
            parent.get('phase') == 'final-module-image-reference-bound', 'PCI requires completed Factory49 parent')
    binding = parent.get('module_binding', {})
    require(type(binding) is dict and binding.get('status') == 'PASS', 'PCI parent module binding absent')
    for name in PARENT_EXPORTS:
        require(binding.get('exports', {}).get(name) == sha(artifacts[name]), 'PCI actual Factory export differs: ' + name)
    built, shipped = metadata(artifacts['target-wifi-built.ko'], 1), metadata(artifacts['target-wifi-shipped.ko'], 1)
    require(binding.get('built_module', {}).get('ELF', {}).get('sha256') == built['sha256'] and
            binding.get('shipped_module', {}).get('ELF', {}).get('sha256') == shipped['sha256'] and
            binding.get('shipped_module', {}).get('path') == SHIPPED_MODULE, 'PCI parent actual module identity differs')
    image = parent.get('kernel_reference', {}).get('image_sha256')
    require(type(image) is str and re.fullmatch('[0-9a-f]{64}', image), 'PCI parent image identity absent')
    for key in ('wifi_makefile', 'wifi_config'):
        require(parent.get('source_sha256', {}).get(key) == sha(inputs[key].encode()), 'PCI parent configured source differs')
    require(type(parent.get('required_cases')) is list and len(parent['required_cases']) == 49 and
            len(set(parent['required_cases'])) == 49 and type(parent.get('checks')) is list and len(parent['checks']) == 49,
            'PCI completed parent49 cases absent')
    module_cmd = canonical_command(artifacts['target-wifi-module.cmd'])
    aggregate = canonical_command(artifacts['target-wifi-link.cmd'])
    aggpath = BUILT_MODULE.removesuffix('.ko') + '.o'
    require(command_member(module_cmd, BUILT_MODULE) and command_member(module_cmd, aggpath) and
            command_member(aggregate, aggpath), 'PCI module/aggregate command differs')
    objects = {}
    for label, (relative, source_key, names) in COMPILED_OBJECTS.items():
        stem = 'target-pci-lifecycle-' + label
        data, cmd = artifacts[stem + '.o'], artifacts[stem + '.cmd']
        text = canonical_command(cmd)
        require(command_member(text, relative) and command_member(text, relative.removesuffix('.o') + '.c') and
                command_member(aggregate, relative), 'PCI object/source/module command membership differs')
        require(all(command_member(text, flag) for flag in REQUIRED_OBJECT_FLAGS) and
                all(not command_member(text, '-U' + flag[2:]) for flag in REQUIRED_OBJECT_FLAGS if flag.startswith('-D')) and
                not any(command_member(text, flag) for flag in FORBIDDEN_OBJECT_FLAGS),
                'PCI configured object preprocessor/aliasing selection differs')
        obj = metadata(data, 1)
        symbols = {}
        for name in names:
            a, b = obj['function_symbols'].get(name, []), built['function_symbols'].get(name, [])
            require(len(a) == len(b) == 1 and a[0]['bytes'] > 0 and b[0]['bytes'] > 0,
                    'PCI implementation symbol absent/ambiguous: ' + name)
            symbols[name] = {'object_symbol': a[0], 'module_symbol': b[0]}
        objects[label] = {'object_file': stem + '.o', 'command_file': stem + '.cmd', 'source_key': source_key,
                          'source_sha256': sha(inputs[source_key].encode()), 'command_sha256': sha(cmd),
                          'ELF': obj, 'required_symbols': list(names), 'symbol_bindings': symbols}
    return {'status': 'PASS', 'factory_report_file': 'target-wifi-factory.json', 'factory_report_sha256': sha(parent_raw),
            'factory_cases': 49, 'image_sha256': image, 'built_module_sha256': built['sha256'],
            'shipped_module_sha256': shipped['sha256'],
            'parent_exports_sha256': {n: sha(artifacts[n]) for n in PARENT_EXPORTS},
            'compiled_exports_sha256': {n: sha(artifacts[n]) for n in sorted(compiled_export_names())}, 'objects': objects,
            'source_to_compiled_scope': 'Clean locked full-build compilation and object-to-module relocation attestations; no independent replay.'}


def collect_compiled(trunk, wifi_report):
    artifacts = {n: read_regular(wifi_report.parent / n, MAX_COMMAND if n.endswith('.cmd') else MAX_ELF) for n in PARENT_EXPORTS}
    for label, (relative, _, _) in COMPILED_OBJECTS.items():
        obj = trunk / 'linux-4.4.x' / relative
        artifacts['target-pci-lifecycle-' + label + '.o'] = read_regular(obj, MAX_ELF)
        artifacts['target-pci-lifecycle-' + label + '.cmd'] = read_regular(obj.with_name('.' + obj.name + '.cmd'), MAX_COMMAND)
    return artifacts


def check(trunk, compiler, output, preflight=False, wifi_report=None):
    validate_contract()
    require(type(preflight) is bool and ((preflight and wifi_report is None) or
            (not preflight and wifi_report is not None)), 'PCI requires preflight alone or completed Factory report')
    config = read_regular(trunk / '.config', MAX_SOURCE).decode()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M), 'PCI gate requires configured K2P4.4')
    inputs = {k: read_regular(trunk.parent / p, MAX_SOURCE).decode() for k, p in SOURCE_PATHS.items()}
    source_contract = source_selection(inputs)
    generated, manifest = generate_component(inputs)
    qemu = shutil.which('qemu-mipsel')
    require(qemu is not None, 'qemu-mipsel required')
    rows, stdout_rows, exports = [], [], {}
    stem = 'target-pci-lifecycle-pci-current'
    with tempfile.TemporaryDirectory(prefix='k2p-pci-lifecycle-source-', dir='/tmp') as temporary:
        base = Path(temporary)
        source, binary = base / (stem + '.c'), base / stem
        source.write_text(generated)
        run = subprocess.run([str(compiler), *FLAGS, str(source), '-o', str(binary)],
                             capture_output=True, text=True, timeout=90)
        require(run.returncode == 0, 'PCI static MIPS compile failed: ' + run.stdout + run.stderr)
        data = read_regular(binary, MAX_ELF)
        elf = resident.validate_static_helper(data)
        for name, options in CASES:
            run = subprocess.run([qemu, str(binary), options['selector']], capture_output=True, text=True,
                                 timeout=MAX_CASE_SECONDS)
            require(run.returncode == 0 and not run.stderr and 0 < len(run.stdout.encode()) <= MAX_STDOUT,
                    'PCI inert MIPS case failed ' + name + ': ' + run.stdout + run.stderr)
            rows.append({'case': name, 'inputs': options, 'observed': decode_json(run.stdout)})
            stdout_rows.append({'selector': options['selector'], 'stdout': run.stdout})
    validate_records(rows)
    raw_stdout = (json.dumps(stdout_rows, indent=2) + '\n').encode()
    exports.update({stem + '.c': generated.encode(), stem: data, stem + '.stdout.json': raw_stdout})
    probes = {'pci': {'current': {'source_file': stem + '.c', 'source_sha256': sha(generated.encode()),
                                  'binary_file': stem, 'binary_sha256': sha(data), 'ELF': elf,
                                  'stdout_file': stem + '.stdout.json', 'stdout_sha256': sha(raw_stdout),
                                  'compile_flags': list(FLAGS)}}}
    binding = None
    if not preflight:
        parent_raw = read_regular(wifi_report, MAX_REPORT)
        artifacts = collect_compiled(trunk, wifi_report)
        binding = compiled_binding_from_bytes(inputs, parent_raw, artifacts, spi.inspect_elf)
        exports.update({n: d for n, d in artifacts.items() if n in compiled_export_names()})
    output.parent.mkdir(parents=True, exist_ok=True)
    for name, payload in exports.items():
        target = output.parent / name
        target.write_bytes(payload)
        if name == stem:
            target.chmod(0o755)
    report = {'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4',
              'phase': 'early-source-only' if preflight else 'final-module-reference-bound',
              'execution_role': ROLE, 'required_cases': [n for n, _ in CASES], 'checks': rows,
              'source_files': SOURCE_PATHS, 'source_sha256': {k: sha(v.encode()) for k, v in inputs.items()},
              'component_models': COMPONENTS, 'source_contract': source_contract,
              'function_manifest': {'pci': {'current': manifest}}, 'probes': probes,
              'compiled_binding': binding, 'compiler': str(compiler), 'limits': list(LIMITS)}
    output.write_text(json.dumps(report, indent=2) + '\n')
    print('PCI lifecycle: ' + str(len(rows)) + ' inert source/MIPS cases PASS')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--wifi-report', type=Path)
    args = parser.parse_args()
    try:
        check(args.trunk.resolve(), args.compiler.resolve(), args.output.resolve(), args.preflight,
              args.wifi_report.resolve() if args.wifi_report else None)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, 'PCI lifecycle validation failed: ' + str(error) + '\n')
