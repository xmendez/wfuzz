import unittest

# Python 2 and 3: urlib.parse

from wfuzz.fuzzobjects import FuzzRequest
from wfuzz import __version__ as wfuzz_version


raw_req = """GET /a HTTP/1.1
Host: www.wfuzz.org
Content-Type: application/x-www-form-urlencoded
User-Agent: Wfuzz/{}

""".format(wfuzz_version)


class FuzzRequestTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(FuzzRequestTest, self).__init__(*args, **kwargs)
        self.maxDiff = 1000

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
        self.assertEqual(sorted(str(fr).split("\n")), sorted(raw_req.split("\n")))

        fr.auth = ('basic', 'admin:admin')
        self.assertEqual(fr.auth, ('basic', 'admin:admin'))

        fr.url = "FUZZ"
        self.assertEqual(fr.url, "FUZZ")
        self.assertEqual(fr.host, "")
        self.assertEqual(fr.redirect_url, "FUZZ")
        self.assertEqual(fr.scheme, "")
        self.assertEqual(fr.path, "FUZZ")
        self.assertEqual(fr.follow, False)

    def test_setpostdata(self):
        fr = FuzzRequest()

        fr.url = "http://www.wfuzz.org/"
        fr.params.post = 'a=1'
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {'a': '1'})

        fr.url = "http://www.wfuzz.org/"
        fr.params.post = ''
        self.assertEqual(fr.method, "POST")

        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {}
        self.assertEqual(fr.method, "POST")

        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {'a': 1}
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {'a': '1'})

        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {'a': '1'}
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {'a': '1'})



if __name__ == '__main__':
    unittest.main()
