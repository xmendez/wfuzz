import unittest

# Python 2 and 3: urlib.parse

from wfuzz.fuzzobjects import FuzzRequest


raw_req = """GET /a HTTP/1.1
Host: www.wfuzz.org
Content-Type: application/x-www-form-urlencoded
User-Agent: Wfuzz/2.2

"""


class FuzzRequestTest(unittest.TestCase):
    def test_seturl(self):
        fr = FuzzRequest()

        fr.url = "http://www.wfuzz.org/"
        self.assertEqual(fr.url, "http://www.wfuzz.org/")
        self.assertEqual(fr.host, "www.wfuzz.org")
        self.assertEqual(fr.redirect_url, "http://www.wfuzz.org/")
        self.assertEqual(fr.scheme, "http")
        self.assertEqual(fr.path, "/")
        self.assertEqual(fr.follow, False)

        fr.url = "http://www.wfuzz.org"
        self.assertEqual(fr.url, "http://www.wfuzz.org/")

        fr.url = "www.wfuzz.org"
        self.assertEqual(fr.url, "http://www.wfuzz.org/")

        fr.url = "FUZZ://www.wfuzz.org/"
        self.assertEqual(fr.url, "FUZZ://www.wfuzz.org/")
        self.assertEqual(fr.scheme, "FUZZ")

        fr.url = "http://www.wfuzz.org/FUZZ"
        self.assertEqual(fr.url, "http://www.wfuzz.org/FUZZ")

        fr.url = "http://www.wfuzz.org/a"
        self.assertEqual(fr.url, "http://www.wfuzz.org/a")
        self.assertEqual(fr.path, "/a")

        fr.url = "http://www.wfuzz.org/a"
        self.assertEqual(sorted(str(fr)), sorted(raw_req))

        fr.auth = ('basic', 'admin:admin')
        self.assertEqual(fr.auth, ('basic', 'admin:admin'))

        fr.url = "FUZZ"
        self.assertEqual(fr.url, "FUZZ")
        self.assertEqual(fr.host, "")
        self.assertEqual(fr.redirect_url, "FUZZ")
        self.assertEqual(fr.scheme, "")
        self.assertEqual(fr.path, "FUZZ")
        self.assertEqual(fr.follow, False)


if __name__ == '__main__':
    unittest.main()
