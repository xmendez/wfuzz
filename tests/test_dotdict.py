import unittest

from wfuzz.helpers.obj_dic import DotDict


class FilterDotDict(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(FilterDotDict, self).__init__(*args, **kwargs)
        self.maxDiff = 1000

    def test_code_set(self):
        dd = DotDict({'a': '1'})
        dd2 = DotDict({'a': '2'})

        self.assertEqual(dd + "test", {'a': "1test"})
        self.assertEqual("test" + dd, {'a': "test1"})
        self.assertEqual(dd + dd2, {'a': "2"})
