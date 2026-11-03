#!/usr/bin/env python3
"""Actual-source MT7621 controller MIPS controls, bound to the full kernel proof.

No firmware, kernel module, host proc setting, SPI device or reboot is executed.
The compiled adapter uses only explicitly inert low-level callbacks.
"""
import argparse
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

# Frozen from reviewed source controls before any candidate artifact is read.
SOURCE_PATHS = {'controller': 'trunk/linux-4.4.x/drivers/spi/spi-mt7621.c',
 'harness': 'tests/controller_clock_harness.py'}
HARNESS_SOURCE_PATHS = {'controller': 'trunk/linux-4.4.x/drivers/spi/spi-mt7621.c'}
FUNCTION_SOURCES = {'mt7621_spi_get_clk_div': 'controller'}
BASELINE_COMMIT = '6e91276a33d1bd83d416fc8253feb01f30677743'
BASELINE_FUNCTION_HASHES = {'mt7621_spi_get_clk_div': 'ffff94290f04b32c9c7baff6f32ba805f408434fefe7c7b2b3002b8274964571'}
PRODUCTION_FRAGMENT_SHA256 = '9c36f6cbc7b0026367cb9f309b3ddfce02a90b899e2a18b11aed06e7b24c91db'
CASES = (('current:normal-80m', {'baseline': False, 'selector': 'normal-80m'}),
 ('current:normal-half', {'baseline': False, 'selector': 'normal-half'}),
 ('current:normal-round-up', {'baseline': False, 'selector': 'normal-round-up'}),
 ('current:normal-four', {'baseline': False, 'selector': 'normal-four'}),
 ('current:normal-lowest', {'baseline': False, 'selector': 'normal-lowest'}),
 ('current:too-low', {'baseline': False, 'selector': 'too-low'}),
 ('current:zero-rate', {'baseline': False, 'selector': 'zero-rate'}),
 ('current:above-half', {'baseline': False, 'selector': 'above-half'}),
 ('current:above-source', {'baseline': False, 'selector': 'above-source'}),
 ('current:overflow-high', {'baseline': False, 'selector': 'overflow-high'}),
 ('current:overflow-max', {'baseline': False, 'selector': 'overflow-max'}),
 ('current:max-encoding', {'baseline': False, 'selector': 'max-encoding'}),
 ('current:before-max', {'baseline': False, 'selector': 'before-max'}),
 ('current:clamp-max', {'baseline': False, 'selector': 'clamp-max'}),
 ('current:min-provider', {'baseline': False, 'selector': 'min-provider'}),
 ('current:min-above', {'baseline': False, 'selector': 'min-above'}),
 ('current:max-both', {'baseline': False, 'selector': 'max-both'}),
 ('current:max-half', {'baseline': False, 'selector': 'max-half'}),
 ('current:max-small', {'baseline': False, 'selector': 'max-small'}),
 ('current:zero-source', {'baseline': False, 'selector': 'zero-source'}),
 ('baseline:normal-80m', {'baseline': True, 'selector': 'normal-80m'}),
 ('baseline:normal-half', {'baseline': True, 'selector': 'normal-half'}),
 ('baseline:normal-round-up', {'baseline': True, 'selector': 'normal-round-up'}),
 ('baseline:normal-four', {'baseline': True, 'selector': 'normal-four'}),
 ('baseline:normal-lowest', {'baseline': True, 'selector': 'normal-lowest'}),
 ('baseline:too-low', {'baseline': True, 'selector': 'too-low'}),
 ('baseline:above-half', {'baseline': True, 'selector': 'above-half'}),
 ('baseline:above-source', {'baseline': True, 'selector': 'above-source'}),
 ('baseline:overflow-high', {'baseline': True, 'selector': 'overflow-high'}),
 ('baseline:overflow-max', {'baseline': True, 'selector': 'overflow-max'}),
 ('baseline:max-encoding', {'baseline': True, 'selector': 'max-encoding'}),
 ('baseline:before-max', {'baseline': True, 'selector': 'before-max'}),
 ('baseline:clamp-max', {'baseline': True, 'selector': 'clamp-max'}),
 ('baseline:min-provider', {'baseline': True, 'selector': 'min-provider'}),
 ('baseline:min-above', {'baseline': True, 'selector': 'min-above'}),
 ('baseline:max-both', {'baseline': True, 'selector': 'max-both'}),
 ('baseline:max-half', {'baseline': True, 'selector': 'max-half'}),
 ('baseline:max-small', {'baseline': True, 'selector': 'max-small'}),
 ('baseline:zero-source', {'baseline': True, 'selector': 'zero-source'}))
EXPECTED = {'current:normal-80m': {'case': 'normal-80m', 'hclk': 220000000, 'rate': 80000000, 'divider': 1},
 'current:normal-half': {'case': 'normal-half', 'hclk': 220000000, 'rate': 110000000, 'divider': 0},
 'current:normal-round-up': {'case': 'normal-round-up',
                             'hclk': 220000000,
                             'rate': 100000000,
                             'divider': 1},
 'current:normal-four': {'case': 'normal-four', 'hclk': 220000000, 'rate': 55000000, 'divider': 2},
 'current:normal-lowest': {'case': 'normal-lowest',
                           'hclk': 220000000,
                           'rate': 53697,
                           'divider': 4095},
 'current:too-low': {'case': 'too-low', 'hclk': 220000000, 'rate': 1, 'divider': 4095},
 'current:zero-rate': {'case': 'zero-rate', 'hclk': 220000000, 'rate': 0, 'divider': 4095},
 'current:above-half': {'case': 'above-half', 'hclk': 220000000, 'rate': 220000000, 'divider': 0},
 'current:above-source': {'case': 'above-source',
                          'hclk': 220000000,
                          'rate': 4294967295,
                          'divider': 0},
 'current:overflow-high': {'case': 'overflow-high',
                           'hclk': 4000000000,
                           'rate': 900000000,
                           'divider': 3},
 'current:overflow-max': {'case': 'overflow-max',
                          'hclk': 4294967295,
                          'rate': 800000000,
                          'divider': 4},
 'current:max-encoding': {'case': 'max-encoding', 'hclk': 4097, 'rate': 1, 'divider': 4095},
 'current:before-max': {'case': 'before-max', 'hclk': 4096, 'rate': 1, 'divider': 4094},
 'current:clamp-max': {'case': 'clamp-max', 'hclk': 4098, 'rate': 1, 'divider': 4095},
 'current:min-provider': {'case': 'min-provider', 'hclk': 2, 'rate': 1, 'divider': 0},
 'current:min-above': {'case': 'min-above', 'hclk': 2, 'rate': 2, 'divider': 0},
 'current:max-both': {'case': 'max-both', 'hclk': 4294967295, 'rate': 4294967295, 'divider': 0},
 'current:max-half': {'case': 'max-half', 'hclk': 4294967295, 'rate': 2147483647, 'divider': 1},
 'current:max-small': {'case': 'max-small', 'hclk': 4294967295, 'rate': 1048576, 'divider': 4094},
 'current:zero-source': {'case': 'zero-source', 'hclk': 0, 'rate': 1, 'divider': 0},
 'baseline:normal-80m': {'case': 'normal-80m', 'hclk': 220000000, 'rate': 80000000, 'divider': 1},
 'baseline:normal-half': {'case': 'normal-half',
                          'hclk': 220000000,
                          'rate': 110000000,
                          'divider': 0},
 'baseline:normal-round-up': {'case': 'normal-round-up',
                              'hclk': 220000000,
                              'rate': 100000000,
                              'divider': 1},
 'baseline:normal-four': {'case': 'normal-four', 'hclk': 220000000, 'rate': 55000000, 'divider': 2},
 'baseline:normal-lowest': {'case': 'normal-lowest',
                            'hclk': 220000000,
                            'rate': 53697,
                            'divider': 4095},
 'baseline:too-low': {'case': 'too-low', 'hclk': 220000000, 'rate': 1, 'divider': 4095},
 'baseline:above-half': {'case': 'above-half', 'hclk': 220000000, 'rate': 220000000, 'divider': 2},
 'baseline:above-source': {'case': 'above-source',
                           'hclk': 220000000,
                           'rate': 4294967295,
                           'divider': 2},
 'baseline:overflow-high': {'case': 'overflow-high',
                            'hclk': 4000000000,
                            'rate': 900000000,
                            'divider': 2},
 'baseline:overflow-max': {'case': 'overflow-max',
                           'hclk': 4294967295,
                           'rate': 800000000,
                           'divider': 2},
 'baseline:max-encoding': {'case': 'max-encoding', 'hclk': 4097, 'rate': 1, 'divider': 4095},
 'baseline:before-max': {'case': 'before-max', 'hclk': 4096, 'rate': 1, 'divider': 4094},
 'baseline:clamp-max': {'case': 'clamp-max', 'hclk': 4098, 'rate': 1, 'divider': 4095},
 'baseline:min-provider': {'case': 'min-provider', 'hclk': 2, 'rate': 1, 'divider': 0},
 'baseline:min-above': {'case': 'min-above', 'hclk': 2, 'rate': 2, 'divider': 2},
 'baseline:max-both': {'case': 'max-both', 'hclk': 4294967295, 'rate': 4294967295, 'divider': 2},
 'baseline:max-half': {'case': 'max-half', 'hclk': 4294967295, 'rate': 2147483647, 'divider': 2},
 'baseline:max-small': {'case': 'max-small', 'hclk': 4294967295, 'rate': 1048576, 'divider': 2},
 'baseline:zero-source': {'case': 'zero-source', 'hclk': 0, 'rate': 1, 'divider': 2}}

ROLE = 'Actual MT7621 divider compiled as static MIPS userspace with inert arithmetic inputs'
LIMITS = ('No real clock, MMIO, flash, reset, router connection or host proc is accessed.',
 'This adapter proves arithmetic boundary behavior, not physical SPI frequency or historical reset '
 'cause.',
 'Zero requested rate is handled defensively; normal spi_setup supplies a nonzero rate.',
 'Complete kernel/image identity is independently bound by the mandatory SPI proof.')
MAX_SOURCE = 4 * 1024 * 1024
MAX_REPORT = 16 * 1024 * 1024
MAX_COMMAND_SECONDS = 20
FLAGS = ('-std=gnu99', '-Os', '-static', '-s', '-Wall', '-Wextra', '-Werror',
         '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-sign-compare', '-Wno-pointer-sign')
KERNEL_SYMBOLS = {'mt7621': ('mt7621_spi_probe', 'mt7621_spi_remove', 'mt7621_spi_transfer_one_message')}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact(left, right, message):
    require(json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True), message)


def validate_contract():
    require(SOURCE_PATHS and HARNESS_SOURCE_PATHS and FUNCTION_SOURCES and
            BASELINE_FUNCTION_HASHES and CASES and EXPECTED and
            type(PRODUCTION_FRAGMENT_SHA256) is str and re.fullmatch("[0-9a-f]{64}", PRODUCTION_FRAGMENT_SHA256),
            'Controller clock source contract has not been frozen')
    require(len({name for name, _ in CASES}) == len(CASES) and
            set(EXPECTED) == {name for name, _ in CASES}, 'Incomplete Controller clock case contract')


def clock_function(text,name):
    token=r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*'
    masked=re.sub(token,lambda m:' '*len(m.group()),text)
    pattern=r'(?:static\s+)?(?:inline\s+)?(?:void|int|ssize_t|u32)\s+\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{'
    found=list(re.finditer(pattern,masked));require(len(found)==1,'Missing/ambiguous actual SPI function '+name)
    at=masked.index('{',found[0].start());depth=0
    for match in re.finditer(token+r'|[{}]',text[at:]):
        if match.group()=='{':depth+=1
        elif match.group()=='}':
            depth-=1
            if depth==0:return text[found[0].start():at+match.end()]
    raise ValueError('Unterminated actual SPI function '+name)


def generate_source(inputs, fixture_root, owner_uid, baseline=False):
    validate_contract()
    require(set(inputs) == set(SOURCE_PATHS), 'Controller clock source mapping changed')
    require(type(owner_uid) is int and 0 <= owner_uid < 2**32, 'Invalid Controller clock fixture owner')
    require(type(baseline) is bool, 'Invalid Controller clock baseline profile')
    module = resident.checked_module(inputs['harness'], 'mt7621-controller')
    exact(module.SOURCE_PATHS, HARNESS_SOURCE_PATHS, 'Controller clock fixture source contract changed')
    exact(module.BASELINE_COMMIT, BASELINE_COMMIT, 'Controller clock public baseline source identity changed')
    for profile, contract in ((False, module.CASES), (True, module.BASELINE_CASES)):
        expected = tuple((options['selector'], EXPECTED[name]) for name, options in CASES
                         if options['baseline'] is profile)
        exact(contract, expected, 'Controller clock fixture expected contract changed')
    exact(module.BASELINE_FUNCTIONS_SHA256, BASELINE_FUNCTION_HASHES,
          'Public old Controller clock baseline changed')
    texts = {key: inputs[key] for key in HARNESS_SOURCE_PATHS}
    fragments = module.production_fragments(texts)
    require(type(fragments) is str and 0 < len(fragments.encode()) <= MAX_SOURCE and
            sha(fragments.encode()) == PRODUCTION_FRAGMENT_SHA256,
            'Controller clock production macro/struct fragments changed')
    generated = module.generate_source(texts, str(fixture_root), owner_uid=owner_uid, baseline=baseline)
    require(type(generated) is str and 0 < len(generated.encode()) <= MAX_SOURCE,
            'Invalid Controller clock generated source')
    require(generated.count(fragments) == 1, 'Controller clock adapter omitted/duplicated production fragments')
    bodies = (module.BASELINE_FUNCTIONS if baseline else
              {name: clock_function(inputs[key], name) for name, key in FUNCTION_SOURCES.items()})
    if baseline:
        exact({name: sha(body.encode()) for name, body in bodies.items()}, BASELINE_FUNCTION_HASHES,
              'Old Controller clock body bytes differ from reviewed public baseline')
    for name, body in bodies.items():
        require(generated.count(body) == 1, 'Controller clock adapter omitted/duplicated actual body: ' + name)
    return generated, bodies


def validate_records(rows):
    validate_contract()
    require(type(rows) is list and len(rows) == len(CASES), 'Controller clock cases missing/extra')
    for row, (name, inputs) in zip(rows, CASES):
        require(type(row) is dict and set(row) == {'case', 'inputs', 'observed'} and
                row['case'] == name, 'Controller clock record order/schema differs')
        exact(row['inputs'], inputs, 'Controller clock inputs differ: ' + name)
        exact(row['observed'], EXPECTED[name], 'Controller clock outcome/ready/registration differs: ' + name)


def read_regular(path, limit):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError('Controller clock artifact cannot be opened without following aliases') from error
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit,
                'Controller clock artifact must be a bounded regular file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(descriptor)
    require(len(data) == info.st_size, 'Controller clock artifact changed or exceeds budget')
    return data


def kernel_reference(inputs, report_path):
    """Reuse the separately required whole-image proof, export compact identities.

    This checks the existing sidecar bytes and selected public functions instead
    of duplicating all kernel bytes or asserting static-inline symbol presence.
    """
    raw = read_regular(report_path, MAX_REPORT)
    report = json.loads(raw)
    require(type(report.get('schema_version')) is int and report['schema_version'] == 1 and report.get('status') == 'PASS' and
            report.get('profile') == 'k2p-4.4' and report.get('phase') == 'final-kernel-image-bound',
            'Controller clock final proof requires the completed SPI kernel/image gate')
    exact(report.get('required_cases'), [name for name, _ in spi.CASES], 'SPI case set differs')
    spi.validate_records(report.get('checks'))
    for key in ('controller',):
        require(report.get('source_sha256', {}).get(key) == sha(inputs[key].encode()),
                'Controller clock and SPI source identities differ: ' + key)
    binding = report.get('kernel_binding')
    require(type(binding) is dict and binding.get('whole_byte_equality') is True,
            'Controller clock requires exact whole kernel/image binding')
    expected_exports = {'target-spi-kernel-vmlinux.elf', 'target-spi-kernel-raw.bin',
                        'target-spi-kernel-vendor.bin', 'target-spi-vmlinux.cmd'}
    for label in spi.OBJECTS:
        expected_exports.update(('target-spi-' + label + '.o', 'target-spi-' + label + '.cmd'))
    exports = binding.get('exports')
    require(type(exports) is dict and set(exports) == expected_exports,
            'Controller clock SPI kernel sidecar set differs')
    for name, value in exports.items():
        require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
                'Malformed SPI sidecar SHA256')
        require(sha(read_regular(report_path.parent / name, spi.MAX_ELF)) == value,
                'Controller clock referenced SPI sidecar bytes differ: ' + name)
    linked = spi.inspect_elf(read_regular(report_path.parent / 'target-spi-kernel-vmlinux.elf', spi.MAX_ELF), 2)
    exact(linked, binding.get('vmlinux'), 'Controller clock linked kernel metadata differs from sidecar')
    selected = binding.get('selected_objects')
    require(type(selected) is dict and set(selected) == set(spi.OBJECTS), 'SPI selected objects differ')
    symbols = {}
    for label, names in KERNEL_SYMBOLS.items():
        row = selected[label]
        object_name = 'target-spi-' + label + '.o'
        require(row.get('object_file') == object_name, 'Controller clock selected object filename differs')
        obj = spi.inspect_elf(read_regular(report_path.parent / object_name, spi.MAX_ELF), 1)
        exact(obj, row.get('ELF'), 'Controller clock selected object metadata differs from sidecar')
        command_name = 'target-spi-' + label + '.cmd'
        command = read_regular(report_path.parent / command_name, 2 * 1024 * 1024)
        require(row.get('command_file') == command_name and
                row.get('command_sha256') == sha(command) and
                Path(spi.OBJECTS[label][0]).with_suffix('.c').name.encode() in command,
                'Controller clock selected object command/source binding differs')
        for name in names:
            require(len(obj['function_symbols'].get(name, [])) == 1 and
                    len(linked['function_symbols'].get(name, [])) == 1 and
                    obj['function_symbols'][name][0]['bytes'] > 0 and
                    linked['function_symbols'][name][0]['bytes'] > 0,
                    'Controller clock actual controller implementation symbol absent: ' + name)
            require(name in row.get('required_symbols', []), 'SPI proof does not require Controller clock caller: ' + name)
            symbols[name] = {'object': label, 'object_symbol': obj['function_symbols'][name][0],
                             'linked_symbol': linked['function_symbols'][name][0]}
    return {'role': 'Reference to separately mandatory exact whole-kernel SPI proof',
            'report_file': report_path.name, 'report_sha256': sha(raw),
            'image_sha256': binding['image']['image_sha256'],
            'vmlinux_sha256': linked['sha256'], 'required_symbols': symbols,
            'source_sha256': {key: sha(inputs[key].encode()) for key in ('controller',)},
            'kernel_exports_sha256': exports, 'whole_kernel_image_equality': True,
            'object_to_link_scope': binding['object_to_link_scope']}


def check(trunk, compiler, output, preflight=False, spi_report=None):
    validate_contract()
    require(type(preflight) is bool, 'Controller clock preflight selection must be boolean')
    require((preflight and spi_report is None) or (not preflight and spi_report is not None),
            'Controller clock requires preflight alone or a final SPI report')
    config = (trunk / '.config').read_text()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M),
            'Controller clock gate requires configured K2P4.4')
    qemu = shutil.which('qemu-mipsel')
    require(qemu is not None, 'qemu-mipsel required')
    inputs = {key: (trunk.parent / relative).read_text() for key, relative in SOURCE_PATHS.items()}
    rows, probes, exports, function_hashes = [], {}, {}, {}
    with tempfile.TemporaryDirectory(prefix='k2p-controller-clock-source-', dir='/tmp') as temporary:
        base = Path(temporary).resolve()
        for baseline in (False, True):
            profile = 'baseline' if baseline else 'current'
            fixture = base / (profile + '-fixture')
            generated, bodies = generate_source(inputs, fixture, os.geteuid(), baseline)
            source, binary = base / (profile + '.c'), base / profile
            source.write_text(generated)
            run = subprocess.run([str(compiler), *FLAGS, str(source), '-o', str(binary)],
                                 capture_output=True, text=True, timeout=90)
            require(run.returncode == 0, 'Controller clock MIPS source compile failed: ' + run.stdout + run.stderr)
            data = binary.read_bytes()
            elf = resident.validate_static_helper(data)
            for name, options in CASES:
                if options['baseline'] is not baseline:
                    continue
                run = subprocess.run([qemu, str(binary), options['selector']],
                                     capture_output=True, text=True, timeout=MAX_COMMAND_SECONDS)
                require(run.returncode == 0 and not run.stderr,
                        'Controller clock fixture failed ' + name + ': ' + run.stdout + run.stderr)
                rows.append({'case': name, 'inputs': options, 'observed': json.loads(run.stdout)})
            name = 'target-controller-clock' + ('-baseline' if baseline else '')
            exports[name + '.c'], exports[name] = generated.encode(), data
            function_hashes[profile] = {name: sha(body.encode()) for name, body in bodies.items()}
            probes[profile] = {'source_file': name + '.c', 'source_sha256': sha(generated.encode()),
                               'binary_file': name, 'binary_sha256': sha(data), 'ELF': elf,
                               'compile_flags': list(FLAGS), 'fixture_root': str(fixture),
                               'owner_uid': os.geteuid()}
    validate_records(rows)
    reference = kernel_reference(inputs, spi_report) if spi_report is not None else None
    output.parent.mkdir(parents=True, exist_ok=True)
    for name, data in exports.items():
        path = output.parent / name
        path.write_bytes(data)
        if not name.endswith('.c'):
            path.chmod(0o755)
    report = {'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4',
              'phase': 'early-source-only' if preflight else 'final-kernel-reference-bound',
              'execution_role': ROLE, 'required_cases': [name for name, _ in CASES], 'checks': rows,
              'source_files': SOURCE_PATHS,
              'source_sha256': {key: sha(text.encode()) for key, text in inputs.items()},
              'baseline_source_commit': BASELINE_COMMIT,
              'production_fragments_sha256': PRODUCTION_FRAGMENT_SHA256,
              'actual_functions_sha256': function_hashes, 'probes': probes,
              'kernel_reference': reference, 'compiler': str(compiler), 'limits': list(LIMITS)}
    output.write_text(json.dumps(report, indent=2) + '\n')
    print('MT7621 controller: ' + str(len(rows)) + ' inert actual-source MIPS cases PASS')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--spi-report', type=Path)
    args = parser.parse_args()
    try:
        check(args.trunk.resolve(), args.compiler.resolve(), args.output.resolve(), args.preflight,
              args.spi_report.resolve() if args.spi_report else None)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Controller clock target validation failed: ' + str(error) + '\n')
