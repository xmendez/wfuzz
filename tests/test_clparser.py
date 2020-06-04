import unittest

from wfuzz.ui.console.clparser import CLParser


class CLParserTest(unittest.TestCase):
    def test_listplugins(self):
        with self.assertRaises(SystemExit) as cm:
            CLParser(["wfuzz", "-e", "iterators"]).parse_cl()

        self.assertEqual(cm.exception.code, 0)

    def test_ip_option(self):
        options = CLParser(["wfuzz", "--ip", "127.0.0.1"]).parse_cl()

        self.assertEqual(options.data["connect_to_ip"]["ip"], "127.0.0.1")
        self.assertEqual(options.data["connect_to_ip"]["port"], "80")

        options = CLParser(["wfuzz", "--ip", "127.0.0.1:22"]).parse_cl()

        self.assertEqual(options.data["connect_to_ip"]["ip"], "127.0.0.1")
        self.assertEqual(options.data["connect_to_ip"]["port"], "22")

        options = CLParser(["wfuzz", "--ip", "127.0.0.1:"]).parse_cl()

        self.assertEqual(options.data["connect_to_ip"]["ip"], "127.0.0.1")
        self.assertEqual(options.data["connect_to_ip"]["port"], "80")

        with self.assertRaises(Exception) as cm:
            options = CLParser(["wfuzz", "--ip", ":80"]).parse_cl()
        self.assertTrue("An IP must be specified" in str(cm.exception))

    def test_ze_zd_option(self):
        with self.assertRaises(Exception) as cm:
            options = CLParser(
                ["wfuzz", "-z", "range,0-10", "--zD", "0-10", "url"]
            ).parse_cl()
        self.assertTrue("exclusive" in str(cm.exception))

        options = CLParser(
            ["wfuzz", "-z", "range", "--zD", "0-1", "--zE", "md5", "url"]
        ).parse_cl()
        self.assertEqual(
            options.data["payloads"],
            [("range", {"default": "0-1", "encoder": ["md5"]}, None)],
        )

        options = CLParser(
            ["wfuzz", "-z", "range,0-1", "--zE", "md5", "url"]
        ).parse_cl()
        self.assertEqual(
            options.data["payloads"],
            [("range", {"default": "0-1", "encoder": ["md5"]}, None)],
        )

        options = CLParser(
            ["wfuzz", "-z", "range", "--zD", "0-1", "--zE", "md5", "url"]
        ).parse_cl()
        self.assertEqual(
            options.data["payloads"],
            [("range", {"default": "0-1", "encoder": ["md5"]}, None)],
        )

        options = CLParser(["wfuzz", "-z", "range", "--zD", "0-1"]).parse_cl()
        self.assertEqual(
            options.data["payloads"],
            [("range", {"default": "0-1", "encoder": None}, None)],
        )

        options = CLParser(["wfuzz", "-z", "range,0-1"]).parse_cl()
        self.assertEqual(
            options.data["payloads"],
            [("range", {"default": "0-1", "encoder": None}, None)],
        )
