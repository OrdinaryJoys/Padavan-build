#!/usr/bin/env python3
"""Fixed current MTD preflight controls; only Linux CI runs static inert MIPS C."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import check_target_mtd_backup as backup
import check_target_resident_upgrade as resident
import check_target_dynamic_dns as dns

SOURCE_PATHS = {'mtd': 'trunk/user/mtd_write/mtd.c',
                'harness': 'tests/mtd_preflight_harness.py',
                'legacy_guard': 'trunk/user/mtd_write/legacy_guard.h',
                'makefile': 'trunk/user/mtd_write/Makefile'}
FUNCTION_SOURCES = {'mtd_check': 'mtd', 'image_check': 'mtd', 'mtd_write': 'mtd', 'main': 'mtd'}
MODEL_NAMES = ('SOURCE_PATHS', 'FUNCTIONS', 'MAIN_CASES', 'DIRECT_CASES', 'PREFIX', 'SUFFIX')
MODEL_DATA_SHA256 = 'ff4b5b41c12fed3b3f316f271b5224d550d7ca5b11509cd235dfd5c209eedafa'
CASES = (('configured-k2p', {'mode': 'current', 'selector': 'configured-k2p'}),
 ('small-large', {'mode': 'current', 'selector': 'small-large'}),
 ('large-small', {'mode': 'current', 'selector': 'large-small'}),
 ('resume-larger', {'mode': 'current', 'selector': 'resume-larger'}),
 ('scratch-refused', {'mode': 'current', 'selector': 'scratch-refused'}),
 ('existing-scratch-growth-refused', {'mode': 'current', 'selector': 'existing-scratch-growth-refused'}),
 ('first-open-error', {'mode': 'current', 'selector': 'first-open-error'}),
 ('second-open-error', {'mode': 'current', 'selector': 'second-open-error'}),
 ('first-close-error', {'mode': 'current', 'selector': 'first-close-error'}),
 ('second-close-error', {'mode': 'current', 'selector': 'second-close-error'}),
 ('zero-erase', {'mode': 'current', 'selector': 'zero-erase'}),
 ('negative-erase', {'mode': 'current', 'selector': 'negative-erase'}),
 ('name-allocation-refused', {'mode': 'current', 'selector': 'name-allocation-refused'}),
 ('writer-geometry-growth', {'mode': 'current', 'selector': 'writer-geometry-growth'}),
 ('resume-offset-refused', {'mode': 'current', 'selector': 'resume-offset-refused'}),
 ('null-target', {'mode': 'current', 'selector': 'null-target'}),
 ('overlong-target', {'mode': 'current', 'selector': 'overlong-target'}),
 ('writer-null-buffer', {'mode': 'current', 'selector': 'writer-null-buffer'}),
 ('writer-short-capacity', {'mode': 'current', 'selector': 'writer-short-capacity'}),
 ('writer-negative-length', {'mode': 'current', 'selector': 'writer-negative-length'}),
 ('writer-carried-length', {'mode': 'current', 'selector': 'writer-carried-length'}),
 ('writer-zero-erase', {'mode': 'current', 'selector': 'writer-zero-erase'}))
EXPECTED = {'configured-k2p': {'case': 'configured-k2p',
                    'returncode': 0,
                    'trace': 'metadata-open,metadata-close,scratch-allocation,image-read,sync,unlock,pre-erase,unlock,metadata-open,writer-ready,image-read,erase,write,image-read,image-read,erase,write,image-read,metadata-close,sync',
                    'opens': 2,
                    'closes': 2,
                    'live_fds': 0,
                    'allocations': 1,
                    'allocation_bytes': 65536,
                    'capacity': 65536,
                    'name_allocations': 0,
                    'late_allocations': 0,
                    'unlocks': 2,
                    'erases': 3,
                    'writes': 2,
                    'image_reads': 5,
                    'written_bytes': 131072,
                    'bad_range': 0,
                    'writer_ready': 1,
                    'old_allocation_preserved': False},
 'small-large': {'case': 'small-large',
                 'returncode': 0,
                 'trace': 'metadata-open,metadata-close,metadata-open,metadata-close,scratch-allocation,image-read,sync,unlock,pre-erase,unlock,metadata-open,writer-ready,image-read,erase,write,image-read,image-read,erase,write,image-read,metadata-close,sync',
                 'opens': 3,
                 'closes': 3,
                 'live_fds': 0,
                 'allocations': 1,
                 'allocation_bytes': 64,
                 'capacity': 64,
                 'name_allocations': 0,
                 'late_allocations': 0,
                 'unlocks': 2,
                 'erases': 3,
                 'writes': 2,
                 'image_reads': 5,
                 'written_bytes': 32,
                 'bad_range': 0,
                 'writer_ready': 1,
                 'old_allocation_preserved': False},
 'large-small': {'case': 'large-small',
                 'returncode': 0,
                 'trace': 'metadata-open,metadata-close,metadata-open,metadata-close,scratch-allocation,image-read,sync,unlock,pre-erase,unlock,metadata-open,writer-ready,image-read,image-read,erase,write,image-read,metadata-close,sync',
                 'opens': 3,
                 'closes': 3,
                 'live_fds': 0,
                 'allocations': 1,
                 'allocation_bytes': 64,
                 'capacity': 64,
                 'name_allocations': 0,
                 'late_allocations': 0,
                 'unlocks': 2,
                 'erases': 2,
                 'writes': 1,
                 'image_reads': 4,
                 'written_bytes': 64,
                 'bad_range': 0,
                 'writer_ready': 1,
                 'old_allocation_preserved': False},
 'resume-larger': {'case': 'resume-larger',
                   'returncode': 0,
                   'trace': 'metadata-open,metadata-close,metadata-open,metadata-close,scratch-allocation,image-read,sync,unlock,pre-erase,unlock,metadata-open,writer-ready,image-read,erase,metadata-close,metadata-open,writer-ready,image-read,image-read,erase,write,image-read,metadata-close,sync',
                   'opens': 4,
                   'closes': 4,
                   'live_fds': 0,
                   'allocations': 1,
                   'allocation_bytes': 64,
                   'capacity': 64,
                   'name_allocations': 0,
                   'late_allocations': 0,
                   'unlocks': 2,
                   'erases': 3,
                   'writes': 1,
                   'image_reads': 5,
                   'written_bytes': 64,
                   'bad_range': 0,
                   'writer_ready': 2,
                   'old_allocation_preserved': False},
 'scratch-refused': {'case': 'scratch-refused',
                     'returncode': 1,
                     'trace': 'metadata-open,metadata-close,metadata-open,metadata-close,scratch-allocation',
                     'opens': 2,
                     'closes': 2,
                     'live_fds': 0,
                     'allocations': 1,
                     'allocation_bytes': 64,
                     'capacity': 0,
                     'name_allocations': 0,
                     'late_allocations': 0,
                     'unlocks': 0,
                     'erases': 0,
                     'writes': 0,
                     'image_reads': 0,
                     'written_bytes': 0,
                     'bad_range': 0,
                     'writer_ready': 0,
                     'old_allocation_preserved': False},
 'existing-scratch-growth-refused': {'case': 'existing-scratch-growth-refused',
                                     'returncode': 1,
                                     'trace': 'metadata-open,metadata-close,metadata-open,metadata-close,scratch-allocation',
                                     'opens': 2,
                                     'closes': 2,
                                     'live_fds': 0,
                                     'allocations': 1,
                                     'allocation_bytes': 64,
                                     'capacity': 8,
                                     'name_allocations': 0,
                                     'late_allocations': 0,
                                     'unlocks': 0,
                                     'erases': 0,
                                     'writes': 0,
                                     'image_reads': 0,
                                     'written_bytes': 0,
                                     'bad_range': 0,
                                     'writer_ready': 0,
                                     'old_allocation_preserved': True},
 'first-open-error': {'case': 'first-open-error',
                      'returncode': 1,
                      'trace': 'metadata-open',
                      'opens': 1,
                      'closes': 0,
                      'live_fds': 0,
                      'allocations': 0,
                      'allocation_bytes': 0,
                      'capacity': 0,
                      'name_allocations': 0,
                      'late_allocations': 0,
                      'unlocks': 0,
                      'erases': 0,
                      'writes': 0,
                      'image_reads': 0,
                      'written_bytes': 0,
                      'bad_range': 0,
                      'writer_ready': 0,
                      'old_allocation_preserved': False},
 'second-open-error': {'case': 'second-open-error',
                       'returncode': 1,
                       'trace': 'metadata-open,metadata-close,metadata-open',
                       'opens': 2,
                       'closes': 1,
                       'live_fds': 0,
                       'allocations': 0,
                       'allocation_bytes': 0,
                       'capacity': 0,
                       'name_allocations': 0,
                       'late_allocations': 0,
                       'unlocks': 0,
                       'erases': 0,
                       'writes': 0,
                       'image_reads': 0,
                       'written_bytes': 0,
                       'bad_range': 0,
                       'writer_ready': 0,
                       'old_allocation_preserved': False},
 'first-close-error': {'case': 'first-close-error',
                       'returncode': 1,
                       'trace': 'metadata-open,metadata-close',
                       'opens': 1,
                       'closes': 1,
                       'live_fds': 0,
                       'allocations': 0,
                       'allocation_bytes': 0,
                       'capacity': 0,
                       'name_allocations': 0,
                       'late_allocations': 0,
                       'unlocks': 0,
                       'erases': 0,
                       'writes': 0,
                       'image_reads': 0,
                       'written_bytes': 0,
                       'bad_range': 0,
                       'writer_ready': 0,
                       'old_allocation_preserved': False},
 'second-close-error': {'case': 'second-close-error',
                        'returncode': 1,
                        'trace': 'metadata-open,metadata-close,metadata-open,metadata-close',
                        'opens': 2,
                        'closes': 2,
                        'live_fds': 0,
                        'allocations': 0,
                        'allocation_bytes': 0,
                        'capacity': 0,
                        'name_allocations': 0,
                        'late_allocations': 0,
                        'unlocks': 0,
                        'erases': 0,
                        'writes': 0,
                        'image_reads': 0,
                        'written_bytes': 0,
                        'bad_range': 0,
                        'writer_ready': 0,
                        'old_allocation_preserved': False},
 'zero-erase': {'case': 'zero-erase',
                'returncode': 1,
                'trace': 'metadata-open,metadata-close',
                'opens': 1,
                'closes': 1,
                'live_fds': 0,
                'allocations': 0,
                'allocation_bytes': 0,
                'capacity': 0,
                'name_allocations': 0,
                'late_allocations': 0,
                'unlocks': 0,
                'erases': 0,
                'writes': 0,
                'image_reads': 0,
                'written_bytes': 0,
                'bad_range': 0,
                'writer_ready': 0,
                'old_allocation_preserved': False},
 'negative-erase': {'case': 'negative-erase',
                    'returncode': 1,
                    'trace': 'metadata-open,metadata-close',
                    'opens': 1,
                    'closes': 1,
                    'live_fds': 0,
                    'allocations': 0,
                    'allocation_bytes': 0,
                    'capacity': 0,
                    'name_allocations': 0,
                    'late_allocations': 0,
                    'unlocks': 0,
                    'erases': 0,
                    'writes': 0,
                    'image_reads': 0,
                    'written_bytes': 0,
                    'bad_range': 0,
                    'writer_ready': 0,
                    'old_allocation_preserved': False},
 'name-allocation-refused': {'case': 'name-allocation-refused',
                             'returncode': 0,
                             'trace': 'metadata-open,metadata-close,metadata-open,metadata-close,scratch-allocation,image-read,sync,unlock,pre-erase,unlock,metadata-open,writer-ready,image-read,erase,write,image-read,image-read,erase,write,image-read,metadata-close,sync',
                             'opens': 3,
                             'closes': 3,
                             'live_fds': 0,
                             'allocations': 1,
                             'allocation_bytes': 64,
                             'capacity': 64,
                             'name_allocations': 0,
                             'late_allocations': 0,
                             'unlocks': 2,
                             'erases': 3,
                             'writes': 2,
                             'image_reads': 5,
                             'written_bytes': 32,
                             'bad_range': 0,
                             'writer_ready': 1,
                             'old_allocation_preserved': False},
 'writer-geometry-growth': {'case': 'writer-geometry-growth',
                            'returncode': 1,
                            'trace': 'metadata-open,metadata-close,scratch-allocation,image-read,sync,unlock,pre-erase,unlock,metadata-open,metadata-close',
                            'opens': 2,
                            'closes': 2,
                            'live_fds': 0,
                            'allocations': 1,
                            'allocation_bytes': 16,
                            'capacity': 16,
                            'name_allocations': 0,
                            'late_allocations': 0,
                            'unlocks': 2,
                            'erases': 1,
                            'writes': 0,
                            'image_reads': 1,
                            'written_bytes': 0,
                            'bad_range': 0,
                            'writer_ready': 0,
                            'old_allocation_preserved': False},
 'resume-offset-refused': {'case': 'resume-offset-refused',
                           'returncode': 1,
                           'trace': 'metadata-open,metadata-close,metadata-open,metadata-close,metadata-open,metadata-close,metadata-open,metadata-close,scratch-allocation,image-read,sync,unlock,pre-erase,unlock,metadata-open,writer-ready,image-read,erase,metadata-close,metadata-open,writer-ready,erase,erase,write,metadata-close,metadata-open,metadata-close',
                           'opens': 7,
                           'closes': 7,
                           'live_fds': 0,
                           'allocations': 1,
                           'allocation_bytes': 128,
                           'capacity': 128,
                           'name_allocations': 0,
                           'late_allocations': 0,
                           'unlocks': 2,
                           'erases': 4,
                           'writes': 1,
                           'image_reads': 2,
                           'written_bytes': 16,
                           'bad_range': 0,
                           'writer_ready': 2,
                           'old_allocation_preserved': False},
 'null-target': {'case': 'null-target',
                 'returncode': 1,
                 'trace': '',
                 'opens': 0,
                 'closes': 0,
                 'live_fds': 0,
                 'allocations': 0,
                 'allocation_bytes': 0,
                 'capacity': 0,
                 'name_allocations': 0,
                 'late_allocations': 0,
                 'unlocks': 0,
                 'erases': 0,
                 'writes': 0,
                 'image_reads': 0,
                 'written_bytes': 0,
                 'bad_range': 0,
                 'writer_ready': 0,
                 'old_allocation_preserved': False},
 'overlong-target': {'case': 'overlong-target',
                     'returncode': 1,
                     'trace': '',
                     'opens': 0,
                     'closes': 0,
                     'live_fds': 0,
                     'allocations': 0,
                     'allocation_bytes': 0,
                     'capacity': 0,
                     'name_allocations': 0,
                     'late_allocations': 0,
                     'unlocks': 0,
                     'erases': 0,
                     'writes': 0,
                     'image_reads': 0,
                     'written_bytes': 0,
                     'bad_range': 0,
                     'writer_ready': 0,
                     'old_allocation_preserved': False},
 'writer-null-buffer': {'case': 'writer-null-buffer',
                        'returncode': 1,
                        'trace': 'metadata-open,metadata-close',
                        'opens': 1,
                        'closes': 1,
                        'live_fds': 0,
                        'allocations': 0,
                        'allocation_bytes': 0,
                        'capacity': 0,
                        'name_allocations': 0,
                        'late_allocations': 0,
                        'unlocks': 0,
                        'erases': 0,
                        'writes': 0,
                        'image_reads': 0,
                        'written_bytes': 0,
                        'bad_range': 0,
                        'writer_ready': 0,
                        'old_allocation_preserved': False},
 'writer-short-capacity': {'case': 'writer-short-capacity',
                           'returncode': 1,
                           'trace': 'metadata-open,metadata-close',
                           'opens': 1,
                           'closes': 1,
                           'live_fds': 0,
                           'allocations': 0,
                           'allocation_bytes': 0,
                           'capacity': 8,
                           'name_allocations': 0,
                           'late_allocations': 0,
                           'unlocks': 0,
                           'erases': 0,
                           'writes': 0,
                           'image_reads': 0,
                           'written_bytes': 0,
                           'bad_range': 0,
                           'writer_ready': 0,
                           'old_allocation_preserved': False},
 'writer-negative-length': {'case': 'writer-negative-length',
                            'returncode': 1,
                            'trace': 'metadata-open,metadata-close',
                            'opens': 1,
                            'closes': 1,
                            'live_fds': 0,
                            'allocations': 0,
                            'allocation_bytes': 0,
                            'capacity': 16,
                            'name_allocations': 0,
                            'late_allocations': 0,
                            'unlocks': 0,
                            'erases': 0,
                            'writes': 0,
                            'image_reads': 0,
                            'written_bytes': 0,
                            'bad_range': 0,
                            'writer_ready': 0,
                            'old_allocation_preserved': False},
 'writer-carried-length': {'case': 'writer-carried-length',
                           'returncode': 1,
                           'trace': 'metadata-open,metadata-close',
                           'opens': 1,
                           'closes': 1,
                           'live_fds': 0,
                           'allocations': 0,
                           'allocation_bytes': 0,
                           'capacity': 16,
                           'name_allocations': 0,
                           'late_allocations': 0,
                           'unlocks': 0,
                           'erases': 0,
                           'writes': 0,
                           'image_reads': 0,
                           'written_bytes': 0,
                           'bad_range': 0,
                           'writer_ready': 0,
                           'old_allocation_preserved': False},
 'writer-zero-erase': {'case': 'writer-zero-erase',
                       'returncode': 1,
                       'trace': 'metadata-open,metadata-close',
                       'opens': 1,
                       'closes': 1,
                       'live_fds': 0,
                       'allocations': 0,
                       'allocation_bytes': 0,
                       'capacity': 16,
                       'name_allocations': 0,
                       'late_allocations': 0,
                       'unlocks': 0,
                       'erases': 0,
                       'writes': 0,
                       'image_reads': 0,
                       'written_bytes': 0,
                       'bad_range': 0,
                       'writer_ready': 0,
                       'old_allocation_preserved': False}}
FLAGS = ('-std=gnu89', '-Os', '-static', '-s', '-Wall', '-Wextra', '-Werror',
         '-Wno-unused-parameter', '-Wno-unused-function', '-Wno-sign-compare')
ROLE = 'Four complete current MTD preflight/image-check/writer/main bodies in static MIPS adapters with inert device effects'
LIMITS = (
    'No router, real MTD/proc, private backup, flash mutation or reboot is used.',
    'Only current safe functions run; no historical unsafe buffer implementation is executed.',
    'Legacy admission and unlock/erase callbacks are inert; zero late allocation covers the four selected functions only.',
    'A rejected partial cross-target carry may follow partial ordinary-file modeled writes; atomic flash rollback is not proved.',
    'Static probe ABI and exact typed records do not prove whole-system memory pressure survival or runtime residency.',
    'The final source/binary/image reference relies on clean locked full-build provenance and separate independent image extraction.',
    'The running efd2 first-hop userspace/kernel and hardware reset chain are not retroactively repaired.',
)
MAX_SOURCE = 1024 * 1024
MAX_REPORT = 2 * 1024 * 1024
MAX_PROBE = 8 * 1024 * 1024
MAX_IMAGE = 15925248


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact(left, right, message):
    require(json.dumps(left, sort_keys=True, separators=(',', ':')) ==
            json.dumps(right, sort_keys=True, separators=(',', ':')), message)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate preflight JSON key')
            result[key] = value
        return result
    def nonfinite(value):
        raise ValueError('Non-finite preflight JSON value: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def literal_data(source):
    values = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in MODEL_NAMES:
                require(name not in values, 'Duplicate preflight literal assignment')
                try:
                    values[name] = ast.literal_eval(node.value)
                except (ValueError, TypeError, SyntaxError) as error:
                    raise ValueError('Preflight model data must be literal: ' + name) from error
    require(set(values) == set(MODEL_NAMES), 'Preflight literal model set differs')
    return values


def model_data_hash(values):
    return sha(json.dumps(values, sort_keys=True, separators=(',', ':')).encode())


def regenerate(inputs, fixture_root, owner_uid):
    require(type(inputs) is dict and set(inputs) == set(SOURCE_PATHS), 'Preflight source set differs')
    require(type(owner_uid) is int and 0 <= owner_uid < 2**32, 'Preflight fixture owner differs')
    require(type(fixture_root) is str and
            re.fullmatch(r'/tmp/k2p-mtd-preflight-[A-Za-z0-9_-]+/fixture', fixture_root),
            'Preflight requires a literal private /tmp fixture root')
    require('-DMTD_K2P_LEGACY_GUARD=1' in inputs['makefile'], 'Preflight K2P build guard absent')
    require('static size_t buf_capacity;' in inputs['mtd'], 'Preflight source scratch capacity declaration absent')
    values = literal_data(inputs['harness'])
    require(model_data_hash(values) == MODEL_DATA_SHA256, 'Preflight literal model pin differs')
    exact(values['SOURCE_PATHS'], {'mtd': SOURCE_PATHS['mtd']}, 'Preflight harness source mapping differs')
    exact(values['FUNCTIONS'], tuple(FUNCTION_SOURCES), 'Preflight whole-function set differs')
    exact(values['MAIN_CASES'] + values['DIRECT_CASES'], tuple(name for name, _ in CASES),
          'Preflight fixed selectors differ')
    bodies = {name: backup.function(inputs[key], name) for name, key in FUNCTION_SOURCES.items()}
    defines = '\n'.join('#define %s %s' % (name, json.dumps(fixture_root + '/' + leaf))
                        for name, leaf in (('FIXTURE_IMAGE', 'image'), ('FIXTURE_DEVICE', 'device')))
    macros = '\n#define realloc seam_realloc\n#define malloc seam_malloc\n#define strdup seam_strdup\n'
    macros += '#define open seam_open\n#define close seam_close\n#define read seam_read\n#define write seam_write\n'
    macros += '#define sync seam_sync\n#define exit seam_exit\n'
    code = defines + '\n' + values['PREFIX'] + macros
    code += '\n\n'.join(bodies[name] for name in tuple(FUNCTION_SOURCES)[:-1])
    code += '\n#define main preflight_main\n' + bodies['main'] + '\n#undef main\n'
    code += ''.join('#undef ' + name + '\n' for name in
                    ('realloc', 'malloc', 'strdup', 'open', 'close', 'read', 'write', 'sync', 'exit'))
    code += values['SUFFIX']
    require(0 < len(code.encode()) <= MAX_SOURCE, 'Preflight generated source budget')
    manifest = {}
    for name, body in bodies.items():
        require(code.count(body) == 1, 'Preflight complete body missing/ambiguous: ' + name)
        manifest[name] = {'source': FUNCTION_SOURCES[name], 'full_body_sha256': sha(body.encode()),
                          'execution': 'whole-current-function'}
    return code, manifest


def generate_source(inputs, fixture_root, owner_uid):
    return regenerate(inputs, str(fixture_root), owner_uid)


def validate_records(rows):
    require(type(rows) is list and len(rows) == len(CASES) == 22, 'Preflight exact22 record set differs')
    for row, (name, options) in zip(rows, CASES):
        require(type(row) is dict and set(row) == {'case', 'inputs', 'observed'} and row['case'] == name,
                'Preflight record schema/order differs')
        exact(row['inputs'], options, 'Preflight fixed typed input differs: ' + name)
        exact(row['observed'], EXPECTED[name], 'Preflight fixed typed outcome differs: ' + name)


def stdout_observation(raw, name):
    require(type(raw) is str and 0 < len(raw.encode()) <= MAX_REPORT and raw.endswith('\n') and
            raw.count('\n') == 1, 'Preflight requires exactly one complete stdout JSON line: ' + name)
    observed = strict_json(raw)
    require(type(observed) is dict and observed.get('case') == name, 'Preflight stdout selector differs')
    exact(observed, EXPECTED[name], 'Preflight raw stdout fixed typed outcome differs: ' + name)
    return observed


def parent_reference_from_bytes(inputs, raw, shipped, image):
    parent = strict_json(raw)
    require(type(parent) is dict and type(parent.get('schema_version')) is int and
            parent['schema_version'] == 1 and parent.get('status') == 'PASS' and
            parent.get('profile') == 'k2p-4.4' and parent.get('phase') == 'final-shipped-image-reference-bound',
            'Preflight requires completed final backup parent')
    exact(parent.get('required_cases'), [name for name, _ in backup.CASES], 'Preflight parent case set differs')
    require(len(backup.CASES) == 71, 'Preflight backup parent generation differs')
    backup.validate_records(parent.get('checks'))
    shared = {key: sha(inputs[key].encode()) for key in ('mtd', 'legacy_guard', 'makefile')}
    require(type(parent.get('source_sha256')) is dict and type(parent.get('source_files')) is dict,
            'Preflight parent source mapping absent')
    exact({key: parent['source_files'].get(key) for key in shared},
          {key: SOURCE_PATHS[key] for key in shared}, 'Preflight parent shared source paths differ')
    exact({key: parent['source_sha256'].get(key) for key in shared}, shared, 'Preflight parent source identities differ')
    metadata = dns.elf(shipped, True)
    expected = {'path': 'bin/mtd_write', 'bytes': len(shipped), 'sha256': sha(shipped), 'ELF': metadata,
                'source_sha256': shared['mtd'], 'guard_sha256': shared['legacy_guard'],
                'image_byte_binding_required': True, 'execution_performed': False}
    exact(parent.get('shipped_legacy'), expected, 'Preflight parent/shipped MTD bytes differ')
    require(type(image) is bytes and 64 <= len(image) <= MAX_IMAGE, 'Preflight image reference budget')
    return {'status': 'PASS', 'report_file': 'target-mtd-backup.json', 'report_sha256': sha(raw),
            'parent_cases': 71, 'shared_source_sha256': shared, 'shipped_legacy': expected,
            'image_sha256': sha(image), 'image_bytes': len(image),
            'independent_image_extraction_required': True, 'shipped_execution_performed': False}


def check(trunk, compiler, output, preflight=False, rootfs=None, image=None, mtd_backup_report=None):
    require(type(preflight) is bool and
            ((preflight and rootfs is None and image is None and mtd_backup_report is None) or
             (not preflight and all(value is not None for value in (rootfs, image, mtd_backup_report)))),
            'Preflight gate needs source-only preflight or all final parent/rootfs/image inputs')
    config = (trunk / '.config').read_text()
    require(re.search(r'^CONFIG_LINUXDIR=linux-4\.4\.x$', config, re.M) and
            re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', config, re.M), 'Preflight gate requires configured K2P4.4')
    qemu = shutil.which('qemu-mipsel')
    require(qemu is not None, 'Preflight gate requires qemu-mipsel')
    inputs = {key: (trunk.parent / path).read_text() for key, path in SOURCE_PATHS.items()}
    reference = None
    if not preflight:
        reference = parent_reference_from_bytes(inputs, backup.regular(mtd_backup_report, MAX_REPORT),
                                               backup.regular(rootfs / 'bin/mtd_write', MAX_PROBE),
                                               backup.regular(image, MAX_IMAGE))
    rows, stdout = [], []
    with tempfile.TemporaryDirectory(prefix='k2p-mtd-preflight-', dir='/tmp') as temporary:
        base = Path(temporary).absolute()
        fixture = base / 'fixture'
        fixture.mkdir(mode=0o700)
        (fixture / 'device').write_bytes(bytes(131072))
        generated, manifest = regenerate(inputs, str(fixture), os.geteuid())
        source, binary = base / 'current.c', base / 'current'
        source.write_text(generated)
        run = subprocess.run([str(compiler), *FLAGS, str(source), '-o', str(binary)],
                             capture_output=True, text=True, timeout=90)
        require(run.returncode == 0 and run.stderr == '', 'Preflight MIPS warning-clean compile failed: ' + run.stdout + run.stderr)
        data = binary.read_bytes()
        metadata = resident.validate_static_helper(data)
        for name, options in CASES:
            size = 70000 if name == 'configured-k2p' else 64 if name == 'resume-offset-refused' else 24
            (fixture / 'image').write_bytes((b'ordinary fixture' * ((size + 15) // 16))[:size])
            run = subprocess.run([qemu, str(binary), options['selector']], capture_output=True, text=True, timeout=10)
            require(run.returncode == 0, 'Preflight inert current MIPS process failed: ' + name + ': ' + run.stderr)
            observed = stdout_observation(run.stdout, name)
            rows.append({'case': name, 'inputs': options, 'observed': observed})
            stdout.append({'case': name, 'stdout': run.stdout})
        probe = {'source_file': 'target-mtd-preflight.c', 'source_sha256': sha(generated.encode()),
                 'binary_file': 'target-mtd-preflight', 'binary_sha256': sha(data), 'ELF': metadata,
                 'compile_flags': list(FLAGS), 'fixture_root': str(fixture), 'owner_uid': os.geteuid()}
    validate_records(rows)
    stdout_bytes = (json.dumps(stdout, indent=2) + '\n').encode()
    report = {'schema_version': 1, 'status': 'PASS', 'profile': 'k2p-4.4',
              'phase': 'early-source-only' if preflight else 'final-parent-image-reference-bound',
              'execution_role': ROLE, 'required_cases': [name for name, _ in CASES], 'checks': rows,
              'source_files': SOURCE_PATHS, 'source_sha256': {key: sha(value.encode()) for key, value in inputs.items()},
              'model_data_sha256': MODEL_DATA_SHA256, 'function_manifest': manifest,
              'actual_functions_sha256': {'current': {name: value['full_body_sha256'] for name, value in manifest.items()}},
              'probes': {'current': probe},
              'stdout': {'file': 'target-mtd-preflight.stdout.json', 'sha256': sha(stdout_bytes), 'bytes': len(stdout_bytes), 'records': 22},
              'parent_reference': reference, 'compiler': str(compiler), 'limits': list(LIMITS)}
    output.parent.mkdir(parents=True, exist_ok=True)
    for name, value in {'target-mtd-preflight.c': generated.encode(), 'target-mtd-preflight': data,
                        'target-mtd-preflight.stdout.json': stdout_bytes}.items():
        (output.parent / name).write_bytes(value)
    (output.parent / 'target-mtd-preflight').chmod(0o755)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print('MTD preflight:22 inert current-source MIPS cases PASS')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trunk', 'compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--preflight', action='store_true')
    for name in ('rootfs', 'image', 'mtd-backup-report'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    try:
        check(args.trunk.resolve(), args.compiler.resolve(), args.output.resolve(), args.preflight,
              args.rootfs.resolve() if args.rootfs else None, args.image.resolve() if args.image else None,
              args.mtd_backup_report.resolve() if args.mtd_backup_report else None)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, 'MTD preflight validation failed: ' + str(error) + '\n')
