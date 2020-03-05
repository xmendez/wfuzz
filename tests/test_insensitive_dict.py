import unittest

from wfuzz.utils import CaseInsensitiveDict


class CaseInsensitiveDictTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(CaseInsensitiveDictTest, self).__init__(*args, **kwargs)

    def test_ins_key(self):
        dd = CaseInsensitiveDict({"OnE": 1})

        self.assertEqual(dd['one'], 1)
        self.assertEqual(dd['oNe'], 1)

    def test_ins_update(self):
        dd = CaseInsensitiveDict({})

        dd.update({"OnE": 1})
        self.assertEqual(dd['one'], 1)
        self.assertEqual(dd['oNe'], 1)

    def test_ins_key_in(self):
        dd = CaseInsensitiveDict({"OnE": 1})

        self.assertEqual(list(dd.keys()), ['OnE'])
        self.assertEqual('OnE' in list(dd.keys()), True)
        self.assertEqual('one' in list(dd.keys()), False)
        self.assertEqual('one' in dd, True)
        self.assertEqual('One' in dd, True)
