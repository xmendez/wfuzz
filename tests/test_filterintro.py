import unittest

# Python 2 and 3: urlib.parse

from wfuzz.fuzzobjects import FuzzRequest
from wfuzz.fuzzobjects import FuzzResult
from wfuzz.filter import FuzzResFilter


raw_req = """GET / HTTP/1.1
Host: www.wfuzz.org
User-Agent: curl/7.58.0
Accept: */*
"""

raw_resp = b"""HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Content-Language: en
Location: https://wfuzz.readthedocs.io/en/latest/
Vary: Accept-Language, Cookie
Server: nginx/1.14.0 (Ubuntu)
X-Fallback: True
X-Served: Django
X-Deity: web01
Date: Wed, 23 Jan 2019 21:43:59 GMT
Content-Length: 0
"""


class FilterTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(FilterTest, self).__init__(*args, **kwargs)
        self.maxDiff = 1000

    def get_filtered_fuzzrequest(self, filter_str):
        fr = FuzzRequest()
        fr.update_from_raw_http(raw_req, "http", raw_resp, b"")

        fuzz_res = FuzzResult(history=fr)

        ffilter = FuzzResFilter(filter_string=filter_str)
        ffilter.is_visible(fuzz_res)

        return fuzz_res

    def test_code_set(self):
        self.assertEqual(self.get_filtered_fuzzrequest("r.code:=429").code, 429)
        self.assertEqual(self.get_filtered_fuzzrequest("r.c:=404").code, 404)
        self.assertEqual(self.get_filtered_fuzzrequest("r.c=+404").code, 706)
        self.assertEqual(self.get_filtered_fuzzrequest("r.c=-404").code, 706)

    def test_url_set(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/path?param=1&param2=2"

        fuzz_res = FuzzResult(history=fr)

        ffilter = FuzzResFilter(filter_string="r.url=+'test'")
        ffilter.is_visible(fuzz_res)
        self.assertEqual(fuzz_res.history.url, "http://www.wfuzz.org/path?param=1&param2=2test")

        ffilter = FuzzResFilter(filter_string="r.url:='test'")
        ffilter.is_visible(fuzz_res)
        self.assertEqual(fuzz_res.history.url, "http://test/")

        ffilter = FuzzResFilter(filter_string="r.url=-'test'")
        ffilter.is_visible(fuzz_res)
        self.assertEqual(fuzz_res.history.url, "testhttp://test/")

    def test_nonexisting(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/path?param=1&param2=2"

        fuzz_res = FuzzResult(history=fr)

        with self.assertRaises(Exception) as context:
            ffilter = FuzzResFilter(filter_string="url=-'test'")
            ffilter.is_visible(fuzz_res)
            self.assertTrue("rsetattr: Can't set" in str(context.exception))

        with self.assertRaises(Exception) as context:
            ffilter = FuzzResFilter(filter_string="notthere=-'test'")
            ffilter.is_visible(fuzz_res)
            self.assertTrue("rgetattr: Can't get" in str(context.exception))

        with self.assertRaises(Exception) as context:
            ffilter = FuzzResFilter(filter_string="r.params.get.notthere=-'test'")
            ffilter.is_visible(fuzz_res)
            self.assertTrue("DotDict: Non-existing field" in str(context.exception))

    def test_params_set_no_value(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/path?param"

        fuzz_res = FuzzResult(history=fr)

        ffilter = FuzzResFilter(filter_string="r.params.all=+'test'")
        ffilter.is_visible(fuzz_res)
        self.assertEqual(fuzz_res.history.params.get, {'param': None})

    def test_params_set(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/path?param=1&param2=2"

        fuzz_res = FuzzResult(history=fr)

        ffilter = FuzzResFilter(filter_string="r.params.get.param=+'test'")
        ffilter.is_visible(fuzz_res)
        self.assertEqual(fuzz_res.history.params.get.param, "1test")
        self.assertEqual(fuzz_res.history.params.get, {'param': "1test", 'param2': "2"})

        ffilter = FuzzResFilter(filter_string="r.params.get.param=-'test'")
        ffilter.is_visible(fuzz_res)
        self.assertEqual(fuzz_res.history.params.get.param, "test1test")
        self.assertEqual(fuzz_res.history.params.get, {'param': "test1test", 'param2': "2"})

        ffilter = FuzzResFilter(filter_string="r.params.get.param:='test'")
        ffilter.is_visible(fuzz_res)
        self.assertEqual(fuzz_res.history.params.get.param, "test")
        self.assertEqual(fuzz_res.history.params.get, {'param': "test", 'param2': "2"})

        ffilter = FuzzResFilter(filter_string="r.params.get.param2='2'")
        self.assertEqual(ffilter.is_visible(fuzz_res), True)

        fr.url = "http://www.wfuzz.org/path?param=1&param2=2"
        ffilter = FuzzResFilter(filter_string="r.params.all=+'2'")
        ffilter.is_visible(fuzz_res)
        self.assertEqual(fuzz_res.history.params.all, {'param': "12", 'param2': "22"})

        fr.url = "http://www.wfuzz.org/path?param=1&param2=2"
        ffilter = FuzzResFilter(filter_string="r.params.all:='2'")
        ffilter.is_visible(fuzz_res)
        self.assertEqual(fuzz_res.history.params.all, {'param': "2", 'param2': "2"})

    def test_urlp(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/path/test.php?param=1&param2=2"

        fuzz_res = FuzzResult(history=fr)

        ffilter = FuzzResFilter(filter_string="r.urlp.scheme='http'")
        self.assertEqual(True, ffilter.is_visible(fuzz_res))

        ffilter = FuzzResFilter(filter_string="r.urlp.netloc='www.wfuzz.org'")
        self.assertEqual(True, ffilter.is_visible(fuzz_res))

        ffilter = FuzzResFilter(filter_string="r.urlp.path='/path/test.php'")
        self.assertEqual(True, ffilter.is_visible(fuzz_res))

        ffilter = FuzzResFilter(filter_string="r.urlp.ffname='test.php'")
        self.assertEqual(True, ffilter.is_visible(fuzz_res))

        ffilter = FuzzResFilter(filter_string="r.urlp.fext='.php'")
        self.assertEqual(True, ffilter.is_visible(fuzz_res))

        ffilter = FuzzResFilter(filter_string="r.urlp.fname='test'")
        self.assertEqual(True, ffilter.is_visible(fuzz_res))

        ffilter = FuzzResFilter(filter_string="r.urlp.hasquery")
        self.assertEqual(True, ffilter.is_visible(fuzz_res))

        ffilter = FuzzResFilter(filter_string="not r.urlp.isbllist")
        self.assertEqual(True, ffilter.is_visible(fuzz_res))

    def test_ispath(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/path?param=1&param2=2"
        fuzz_res = FuzzResult(history=fr)

        ffilter = FuzzResFilter(filter_string="r.is_path")
        self.assertEqual(False, ffilter.is_visible(fuzz_res))

        ffilter = FuzzResFilter(filter_string="r.pstrip")
        self.assertEqual(ffilter.is_visible(fuzz_res), "http://www.wfuzz.org/path-gparam-gparam2")

    def test_lwh(self):
        fr = FuzzRequest()
        fr.update_from_raw_http(raw_req, "http", raw_resp, b"Some line\n and words\nasdsdas")

        fuzz_res = FuzzResult(history=fr)

        ffilter = FuzzResFilter(filter_string="h=28 or w=6 or l=2")
        ffilter.is_visible(fuzz_res)
        self.assertEqual(True, ffilter.is_visible(fuzz_res))

    def test_location(self):
        fr = FuzzRequest()
        fr.update_from_raw_http(raw_req, "http", raw_resp, b"Some line\n and words\nasdsdas")

        fuzz_res = FuzzResult(history=fr)

        ffilter = FuzzResFilter(filter_string="r.headers.response.Location")
        ffilter.is_visible(fuzz_res)
        self.assertEqual('https://wfuzz.readthedocs.io/en/latest/', ffilter.is_visible(fuzz_res))
