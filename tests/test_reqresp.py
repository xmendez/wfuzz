import unittest

# Python 2 and 3: urlib.parse

from wfuzz.fuzzobjects import FuzzRequest
from wfuzz.fuzzobjects import FuzzResultFactory
from wfuzz.ui.console.clparser import CLParser
from wfuzz import __version__ as wfuzz_version


raw_req = """GET /a HTTP/1.1
Host: www.wfuzz.org
Content-Type: application/x-www-form-urlencoded
User-Agent: Wfuzz/{}

""".format(wfuzz_version)


class FuzzResultFactoryTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(FuzzResultFactoryTest, self).__init__(*args, **kwargs)
        self.maxDiff = 1000

    def test_baseline(self):
        options = CLParser(['wfuzz', '-z', 'range,1-1', 'http://localhost:9000/FUZZ{first}']).parse_cl()
        seed = FuzzResultFactory.from_options(options)
        baseline = FuzzResultFactory.from_baseline(seed, options)

        self.assertEqual(baseline.description, 'first')

        options = CLParser(['wfuzz', '-z', 'range,1-1', '-z', 'range,2-2', 'http://localhost:9000/FUZZ{first}/FUZ2Z{second}']).parse_cl()
        seed = FuzzResultFactory.from_options(options)
        baseline = FuzzResultFactory.from_baseline(seed, options)

        self.assertEqual(baseline.description, 'first - second')


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

        fr.url = "http://www.wfuzz.org:80/a"
        self.assertEqual(fr.host, "www.wfuzz.org:80")

        fr.url = "https://www.wfuzz.org:80/a"
        self.assertEqual(fr.host, "www.wfuzz.org:80")

        fr.url = "www.wfuzz.org:80/a"
        self.assertEqual(fr.host, "www.wfuzz.org:80")

        fr.url = "www.wfuzz.org:80"
        self.assertEqual(fr.host, "www.wfuzz.org:80")

        fr.url = "www.wfuzz.org"
        self.assertEqual(fr.host, "www.wfuzz.org")

    def test_setpostdata(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = 'a=1'
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {'a': '1'})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = '1'
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {'1': None})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = ''
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {'': None})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {}
        self.assertEqual(fr.method, "GET")
        self.assertEqual(fr.params.post, {})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {'a': 1}
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {'a': '1'})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {'a': '1'}
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {'a': '1'})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = "{'a': '1'}"
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {"{'a': '1'}": None})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = '1'
        fr.headers.request = {'Content-Type': 'application/json'}
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {'1': None})

    def test_setgetdata(self):
        fr = FuzzRequest()

        fr.url = "http://www.wfuzz.org/"
        fr.params.get = {'a': '1'}
        self.assertEqual(fr.method, "GET")
        self.assertEqual(fr.params.get, {'a': '1'})

    def test_allvars(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.get = {'a': '1', 'b': '2'}
        fr.wf_allvars = "allvars"
        self.assertEqual(fr.wf_allvars_set, {'a': '1', 'b': '2'})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {'a': '1', 'b': '2'}
        fr.wf_allvars = "allpost"
        self.assertEqual(fr.wf_allvars_set, {'a': '1', 'b': '2'})

        default_headers = dict([
            ('Content-Type', 'application/x-www-form-urlencoded'),
            ('User-Agent', 'Wfuzz/{}'.format(wfuzz_version)),
            ('Host', 'www.wfuzz.org')
        ])

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.wf_allvars = "allheaders"
        self.assertEqual(fr.wf_allvars_set, default_headers)

    def test_cache_key(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        self.assertEqual(fr.to_cache_key(), 'http://www.wfuzz.org/-')

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.get = {'a': '1', 'b': '2'}
        self.assertEqual(fr.to_cache_key(), 'http://www.wfuzz.org/-ga-gb')

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {'c': '1', 'd': '2'}
        self.assertEqual(fr.to_cache_key(), 'http://www.wfuzz.org/-pc-pd')

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.get = {'a': '1', 'b': '2'}
        fr.params.post = {'c': '1', 'd': '2'}
        self.assertEqual(fr.to_cache_key(), 'http://www.wfuzz.org/-ga-gb-pc-pd')

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.get = {'a': '1', 'b': '2'}
        fr.params.post = {'a': '1', 'b': '2'}
        self.assertEqual(fr.to_cache_key(), 'http://www.wfuzz.org/-ga-gb-pa-pb')

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = '1'
        self.assertEqual(fr.to_cache_key(), 'http://www.wfuzz.org/-p1')

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = ''
        self.assertEqual(fr.to_cache_key(), 'http://www.wfuzz.org/-p')


if __name__ == '__main__':
    unittest.main()
