import unittest

# Python 2 and 3: urlib.parse

from wfuzz.fuzzobjects import FuzzResult
from wfuzz.fuzzrequest import FuzzRequest
from wfuzz.filters.ppfilter import FuzzResFilter


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
