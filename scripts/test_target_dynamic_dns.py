"""Strict target-proof/fixture controls; no MIPS or long-running script here."""
import copy
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('dynamic',Path(__file__).with_name('check_target_dynamic_dns.py'))
dynamic = importlib.util.module_from_spec(spec);spec.loader.exec_module(dynamic)


def report_fixture():
    host = {'path':'/usr/bin/dash','bytes':100,'sha256':'b'*64,
            'elf':{'class':64,'byte_order':'little','machine':62,'type':3}}
    rows = []
    for i,rule in enumerate(dynamic.RULES):
        name,status,reason,minimum,maximum,registrations = rule
        err = 'dnsmasq: '+reason+'\n'
        session = 10000+i
        markers = [{'pid':20000+i*100+k,'group':30000+i*100+k,'session':session,
                    'parent_executable':host['path'],'parent_sha256':host['sha256'],
                    'parent_elf_machine':62} for k in range(registrations)]
        events = ['start','complete']*3+['start'] if name == 'shared-total-30s' else []
        rows.append({'case':name,'exit_code':status,'elapsed_seconds':minimum+0.25,
                     'stdout':'','stderr':err,'stdout_sha256':dynamic.sha(b''),
                     'stderr_sha256':dynamic.sha(err.encode()),'marker_records':markers,
                     'parser_session':session,'active_fixture_tasks':[],'watchdog_timeout':False,
                     'progress':{'started':4 if events else 0,'completed':3 if events else 0,'events':events}})
    return {'schema_version':1,'status':'PASS','profile':'k2p-4.4',
            'target':{'path':'usr/sbin/dnsmasq','bytes':100,'sha256':'a'*64,
                      'elf':{'class':32,'byte_order':'little','machine':8,'type':2}},
            'source_sha256':{key:'c'*64 for key in dynamic.SOURCE_PATHS},
            'production_limits':dict(dynamic.PRODUCTION_LIMITS),
            'execution_role':dynamic.EXECUTION_ROLE,'generator_role':dynamic.GENERATOR_ROLE,
            'host_shell':host,'checks':rows,'failure':None}


class TargetDynamicDNSProofTests(unittest.TestCase):
    def test_exact_sixteen_cases_with_production_limits_are_accepted(self):
        report = report_fixture();self.assertEqual(len(dynamic.CASE_NAMES),16)
        dynamic.validate_report(report,'a'*64,report['source_sha256'])
        self.assertEqual(dynamic.PRODUCTION_LIMITS['script_ms'],10000)
        self.assertEqual(dynamic.PRODUCTION_LIMITS['total_ms'],30000)
        self.assertEqual(dynamic.PRODUCTION_LIMITS['directory_entries'],4096)

    def test_missing_duplicate_or_reordered_case_is_rejected(self):
        base = report_fixture()
        for rows in [base['checks'][:-1],[base['checks'][0],*base['checks']],list(reversed(base['checks']))]:
            report=copy.deepcopy(base);report['checks']=rows
            with self.assertRaisesRegex(ValueError,'case set/order'):dynamic.validate_report(report)

    def test_signal_unknown_exit_or_boolean_is_never_a_valid_rejection(self):
        for code in (-11,-9,11,256,False,1.0):
            report=report_fixture();report['checks'][2]['exit_code']=code
            with self.subTest(code=code),self.assertRaises(ValueError):dynamic.validate_report(report)

    def test_controller_timeout_or_surviving_group_is_rejected(self):
        for key,value in [('watchdog_timeout',True),('active_fixture_tasks',[{'pid':999}])]:
            report=report_fixture();report['checks'][5][key]=value
            with self.assertRaisesRegex(ValueError,'surviving generator'):dynamic.validate_report(report)

    def test_ten_and_thirty_second_deadlines_must_be_actually_observed(self):
        for index,elapsed in [(5,0.2),(6,9.0),(7,15),(15,10),(15,36),(0,float('nan')),(0,False)]:
            report=report_fixture();report['checks'][index]['elapsed_seconds']=elapsed
            with self.subTest(index=index,elapsed=elapsed),self.assertRaises(ValueError):dynamic.validate_report(report)

    def test_shared_total_progress_requires_four_starts_only_three_completions(self):
        for progress in [{'started':3,'completed':3,'events':['start','complete']*3},
                         {'started':4,'completed':4,'events':['start','complete']*4}]:
            report=report_fixture();report['checks'][-1]['progress']=progress
            with self.assertRaisesRegex(ValueError,'progress'):dynamic.validate_report(report)

    def test_host_shell_execution_must_be_registered_and_not_claimed_mips(self):
        for key,value in [('parent_elf_machine',8),('session',999),('group',10000),
                          ('parent_sha256','d'*64),('parent_executable','/unexpected/sh')]:
            report=report_fixture();report['checks'][0]['marker_records'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):dynamic.validate_report(report)
        report=report_fixture();report['checks'][0]['marker_records']=[]
        with self.assertRaises(ValueError):dynamic.validate_report(report)

    def test_expected_diagnostic_and_exact_stream_sha_are_required(self):
        for key,value in [('stderr','other rejection'),('stderr_sha256','d'*64),
                          ('stdout','unexpected output')]:
            report=report_fixture();report['checks'][2][key]=value
            with self.assertRaises(ValueError):dynamic.validate_report(report)
        report=report_fixture();row=report['checks'][2]
        row['stderr']+='bad option';row['stderr_sha256']=dynamic.sha(row['stderr'].encode())
        with self.assertRaisesRegex(ValueError,'expected rejection'):dynamic.validate_report(report)

    def test_binary_and_locked_source_sha_bindings_are_required(self):
        report=report_fixture()
        with self.assertRaisesRegex(ValueError,'image binary SHA'):dynamic.validate_report(report,'f'*64)
        with self.assertRaisesRegex(ValueError,'locked source SHA'):dynamic.validate_report(report,source_sha={})
        report['source_sha256'].pop('option.c')
        with self.assertRaises(ValueError):dynamic.validate_report(report)

    def test_extra_fields_changed_caps_or_misleading_role_are_rejected(self):
        for change in ('top','row','limit','role'):
            report=report_fixture()
            if change=='top':report['extra']=1
            elif change=='row':report['checks'][0]['extra']=1
            elif change=='limit':report['production_limits']['directory_entries']=99999
            else:report['generator_role']='MIPS scripts fully executed'
            with self.subTest(change=change),self.assertRaises(ValueError):dynamic.validate_report(report)

    def test_mips_binary_gate_checks_class_endian_machine_and_type(self):
        data=bytearray(52);data[:7]=b'\x7fELF\x01\x01\x01';struct.pack_into('<H',data,16,2);struct.pack_into('<H',data,18,8)
        dynamic.elf(data,True)
        for offset,value in [(4,2),(5,2),(18,62),(16,1)]:
            wrong=bytearray(data);wrong[offset]=value
            with self.subTest(offset=offset),self.assertRaises(ValueError):dynamic.elf(wrong,True)

    def test_header_limit_parser_does_not_evaluate_arbitrary_code(self):
        self.assertEqual(dynamic.integer_expression('(2U * 1024U * 1024U)'),2097152)
        for text in ['__import__("os").system("false")','1 << 99','True','1 / 0']:
            with self.subTest(text=text),self.assertRaises(ValueError):dynamic.integer_expression(text)

    def test_all_generated_shell_and_marker_fixtures_have_valid_syntax(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for case in dynamic.CASE_NAMES:
                directory=root/case;config,marker,progress=dynamic.make_fixture(directory,case)
                subprocess.run(['/bin/sh','-n',str(directory/'generator.sh')],check=True,capture_output=True)
                compile((directory/'register.py').read_text(),str(directory/'register.py'),'exec')
                self.assertIn('conf-script=',config.read_text())
                self.assertEqual(directory.stat().st_mode&0o777,0o700)
            self.assertEqual((root/dynamic.CASE_NAMES[0]/'output').stat().st_size,2097152)
            self.assertEqual((root/dynamic.CASE_NAMES[0]/'error-output').stat().st_size,65536)
            self.assertEqual((root/'stdout-over2MiB/output').stat().st_size,2097153)
            self.assertEqual((root/'stderr-over64KiB/output').stat().st_size,65537)
            self.assertEqual((root/'device-alias-include/null-device-alias').readlink(),Path('/dev/null'))

    def test_source_gate_binds_four_files_and_exact_header_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            trunk=Path(temporary);(trunk/'.config').write_text('CONFIG_LINUXDIR=linux-4.4.x\n')
            for key,relative in dynamic.SOURCE_PATHS.items():
                path=trunk/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('public fixture\n')
            header=trunk/dynamic.SOURCE_PATHS['dynamic_conf.h']
            header.write_text(''.join('#define '+macro+' '+str(dynamic.PRODUCTION_LIMITS[key])+'U\n' for key,macro in dynamic.MACROS.items()))
            proof=dynamic.source_proof(trunk);self.assertEqual(set(proof),set(dynamic.SOURCE_PATHS))
            header.write_text(header.read_text().replace('10000U','100U'))
            with self.assertRaisesRegex(ValueError,'Production DNS limits'):dynamic.source_proof(trunk)
            (trunk/'.config').write_text('CONFIG_LINUXDIR=linux-3.4.x\n')
            with self.assertRaisesRegex(ValueError,'only for the 4.4'):dynamic.source_proof(trunk)


if __name__ == '__main__':
    unittest.main()
