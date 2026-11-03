"""Fixed typed mutation producer controls; no compiler, MTD or target execution."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import check_target_mtd_mutation as gate


class MtdMutationTargetTests(unittest.TestCase):
    def rows(self):
        return [{'case':name,'inputs':copy.deepcopy(options),'observed':copy.deepcopy(gate.EXPECTED[name])}
                for name,options in gate.CASES]

    def test_fixed_case_set_schema_and_order(self):
        rows=self.rows();gate.validate_records(rows)
        self.assertEqual((len(gate.CASES),len(gate.CASE_ARGS),len(gate.BASELINE_CASES),len(gate.FUNCTION_SOURCES)),(40,26,12,4))
        for changed in ([],rows[:-1],rows+rows[:1],list(reversed(rows))):
            with self.assertRaises(ValueError):gate.validate_records(changed)
        changed=copy.deepcopy(rows);changed[0]['extra']=0
        with self.assertRaises(ValueError):gate.validate_records(changed)

    def test_typed_observations_reject_every_changed_field(self):
        rows=self.rows()
        for index,row in enumerate(rows):
            for field,value in row['observed'].items():
                changed=copy.deepcopy(rows);changed[index]['observed'][field]=bool(value) if type(value) is int else None
                with self.subTest(case=row['case'],field=field),self.assertRaises(ValueError):gate.validate_records(changed)
        for field in ('mode','selector'):
            changed=copy.deepcopy(rows);changed[0]['inputs'][field]=False
            with self.assertRaises(ValueError):gate.validate_records(changed)

    def test_baseline_and_disabled_oracle_cannot_be_relabelled_as_current(self):
        rows=self.rows()
        for old_name in ('baseline:erase-error-first','baseline:preerase-failure','disabled:erase-ok','disabled:erase-error-first'):
            changed=copy.deepcopy(rows);index=next(i for i,(n,_) in enumerate(gate.CASES) if n==old_name)
            target=next(i for i,(n,_) in enumerate(gate.CASES) if n=='current:'+gate.CASES[index][1]['selector'])
            changed[target]['observed']=copy.deepcopy(changed[index]['observed'])
            with self.assertRaises(ValueError):gate.validate_records(changed)

    def test_function_parser_refuses_comment_duplicate_or_truncation(self):
        body='static int mutation(void) { const char *s="}"; /* } */ if (s) { return 0; } return 1; }'
        self.assertEqual(gate.function(body,'mutation'),body)
        for source in ('/* '+body+' */',body+'\n'+body,body[:-1]):
            with self.assertRaises(ValueError):gate.function(source,'mutation')

    def test_regular_reader_refuses_alias_hardlink_fifo_size_and_swapped_fifo(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=root/'data';path.write_bytes(b'123')
            self.assertEqual(gate.regular(path,3),b'123')
            (root/'alias').symlink_to(path)
            with self.assertRaises(ValueError):gate.regular(root/'alias',3)
            os.link(path,root/'hard')
            with self.assertRaises(ValueError):gate.regular(path,3)
            (root/'hard').unlink()
            with self.assertRaises(ValueError):gate.regular(path,2)
            os.mkfifo(root/'fifo')
            with self.assertRaises(ValueError):gate.regular(root/'fifo',3)
            original=gate.os.open
            def swapped(p,flags,*args,**kwargs):
                self.assertTrue(flags&os.O_NONBLOCK);path.unlink();os.mkfifo(path)
                return original(p,flags,*args,**kwargs)
            with mock.patch.object(gate.os,'open',side_effect=swapped),self.assertRaises(ValueError):gate.regular(path,3)

    def test_preflight_final_profile_and_source_identity_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'.config').write_text('CONFIG_LINUXDIR=linux-3.4.x\n')
            for preflight,rootfs in ((True,root),(False,None),(False,root)):
                with self.assertRaises(ValueError):gate.check(root,root/'gcc',root/'out',preflight,rootfs)
        for uid in (True,-1,2**32):
            with self.assertRaises(ValueError):gate.generate_source({k:'' for k in gate.SOURCE_PATHS},'/tmp/inert',uid)
        with self.assertRaises(ValueError):gate.generate_source({},'/tmp/inert',0)


if __name__=='__main__':unittest.main()
