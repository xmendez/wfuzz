import unittest

from wfuzz.ui.console.clparser import CLParser


class CLParserTest(unittest.TestCase):
    def test_listplugins(self):
        with self.assertRaises(SystemExit) as cm:
            CLParser(['wfuzz', '-e', 'iterators']).parse_cl()

        self.assertEqual(cm.exception.code, 0)
