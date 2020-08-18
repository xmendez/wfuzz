import unittest

# Python 2 and 3: urlib.parse

from wfuzz.fuzzrequest import FuzzRequest
from wfuzz.ui.console.clparser import CLParser
from wfuzz import __version__ as wfuzz_version


raw_req = """GET /a HTTP/1.1
Host: www.wfuzz.org
Content-Type: application/x-www-form-urlencoded
User-Agent: Wfuzz/{}

""".format(
    wfuzz_version
)

raw_response_header = b"""HTTP/1.0 200 Connection established

HTTP/1.1 404 Not Found
Content-Type: text/html; charset=UTF-8
Referrer-Policy: no-referrer
Content-Length: 1564
Date: Wed, 24 Apr 2019 22:03:52 GMT
Alt-Svc: quic=":443"; ma=2592000; v="46,44,43,39"
Connection: close

"""

raw_response_body = b'<!DOCTYPE html>\n<html lang=en>\n  <meta charset=utf-8>\n  <meta name=viewport content="initial-scale=1, minimum-scale=1, width=device-width">\n  <title>Error 404 (Not Found)!!1</title>\n  <style>\n    *{margin:0;padding:0}html,code{font:15px/22px arial,sans-serif}html{background:#fff;color:#222;padding:15px}body{margin:7% auto 0;max-width:390px;min-height:180px;padding:30px 0 15px}* > body{background:url(//www.google.com/images/errors/robot.png) 100% 5px no-repeat;padding-right:205px}p{margin:11px 0 22px;overflow:hidden}ins{color:#777;text-decoration:none}a img{border:0}@media screen and (max-width:772px){body{background:none;margin-top:0;max-width:none;padding-right:0}}#logo{background:url(//www.google.com/images/branding/googlelogo/1x/googlelogo_color_150x54dp.png) no-repeat;margin-left:-5px}@media only screen and (min-resolution:192dpi){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat 0% 0%/100% 100%;-moz-border-image:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) 0}}@media only screen and (-webkit-min-device-pixel-ratio:2){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat;-webkit-background-size:100% 100%}}#logo{display:inline-block;height:54px;width:150px}\n  </style>\n  <a href=//www.google.com/><span id=logo aria-label=Google></span></a>\n  <p><b>404.</b> <ins>That\xe2\x80\x99s an error.</ins>\n  <p>The requested URL <code>/one</code> was not found on this server.  <ins>That\xe2\x80\x99s all we know.</ins>\n'


class FuzzResultFactoryTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(FuzzResultFactoryTest, self).__init__(*args, **kwargs)
        self.maxDiff = 1000

    def test_baseline(self):
        options = CLParser(
            ["wfuzz", "-z", "range,1-1", "http://localhost:9000/FUZZ{first}"]
        ).parse_cl()
        options.compile_seeds()
        baseline = options["compiled_baseline"]

        self.assertEqual(baseline.description, "first")

        options = CLParser(
            [
                "wfuzz",
                "-z",
                "range,1-1",
                "-z",
                "range,2-2",
                "http://localhost:9000/FUZZ{first}/FUZ2Z{second}",
            ]
        ).parse_cl()
        options.compile_seeds()
        baseline = options["compiled_baseline"]

        self.assertEqual(baseline.description, "first - second")

    def test_from_conn(self):
        fr = FuzzRequest()
        fr.update_from_raw_http(
            raw_req, "https", raw_response_header, raw_response_body
        )

        self.assertEqual(fr.code, 404)
        self.assertEqual(fr.content.count("\n"), 11)


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

        fr.auth = {"method": "basic", "credentials": "admin:admin"}
        self.assertEqual(fr.auth, {"method": "basic", "credentials": "admin:admin"})

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

    def test_empy_post(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = ""
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {"": None})
        self.assertEqual(fr.params.raw_post, "")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {}
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {})
        self.assertEqual(fr.params.raw_post, "")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = None
        self.assertEqual(fr.method, "GET")
        self.assertEqual(fr.params.post, {})
        self.assertEqual(fr.params.raw_post, None)

    def test_setpostdata(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = "a=1"
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.raw_post, "a=1")
        self.assertEqual(fr.params.post, {"a": "1"})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = "1"
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {"1": None})
        self.assertEqual(fr.params.raw_post, "1")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {"a": 1}
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {"a": "1"})
        self.assertEqual(fr.params.raw_post, "a=1")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {"a": "1"}
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {"a": "1"})
        self.assertEqual(fr.params.raw_post, "a=1")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = "{'a': '1'}"
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {"{'a': '1'}": None})

    def test_setgetdata(self):
        fr = FuzzRequest()

        fr.url = "http://www.wfuzz.org/"
        fr.params.get = {"a": "1"}
        self.assertEqual(fr.method, "GET")
        self.assertEqual(fr.params.get, {"a": "1"})

    def test_allvars(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.get = {"a": "1", "b": "2"}
        fr.wf_allvars = "allvars"
        self.assertEqual(fr.wf_allvars_set, {"a": "1", "b": "2"})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {"a": "1", "b": "2"}
        fr.wf_allvars = "allpost"
        self.assertEqual(fr.wf_allvars_set, {"a": "1", "b": "2"})

        default_headers = dict(
            [
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("User-Agent", "Wfuzz/{}".format(wfuzz_version)),
                ("Host", "www.wfuzz.org"),
            ]
        )

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.wf_allvars = "allheaders"
        self.assertEqual(fr.wf_allvars_set, default_headers)

    def test_cache_key(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        self.assertEqual(fr.to_cache_key(), "http://www.wfuzz.org/-")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.get = {"a": "1", "b": "2"}
        self.assertEqual(fr.to_cache_key(), "http://www.wfuzz.org/-ga-gb")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = {"c": "1", "d": "2"}
        self.assertEqual(fr.to_cache_key(), "http://www.wfuzz.org/-pc-pd")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.get = {"a": "1", "b": "2"}
        fr.params.post = {"c": "1", "d": "2"}
        self.assertEqual(fr.to_cache_key(), "http://www.wfuzz.org/-ga-gb-pc-pd")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.get = {"a": "1", "b": "2"}
        fr.params.post = {"a": "1", "b": "2"}
        self.assertEqual(fr.to_cache_key(), "http://www.wfuzz.org/-ga-gb-pa-pb")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = "1"
        self.assertEqual(fr.to_cache_key(), "http://www.wfuzz.org/-p1")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = ""
        self.assertEqual(fr.to_cache_key(), "http://www.wfuzz.org/-p")

    def test_cache_key_json_header_before(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = "1"
        fr.headers.request = {"Content-Type": "application/json"}

        self.assertEqual(fr.to_cache_key(), "http://www.wfuzz.org/-p1")

    def test_cache_key_json_header_after(self):
        fr = FuzzRequest()
        fr.headers.request = {"Content-Type": "application/json"}
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = "1"

        self.assertEqual(fr.to_cache_key(), "http://www.wfuzz.org/-p1")

    def test_cache_key_get_var(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/?a&b=1"

        self.assertEqual(fr.to_cache_key(), "http://www.wfuzz.org/-ga-gb")

    def test_get_vars(self):
        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/?a&b=1"
        self.assertEqual(fr.params.get, {"a": None, "b": "1"})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/?"
        self.assertEqual(fr.params.get, {})

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        self.assertEqual(fr.params.get, {})

    def test_setpostdata_with_json(self):
        fr = FuzzRequest()
        fr.headers.request = {"Content-Type": "application/json"}
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = '{"string": "Foo bar","boolean": false}'
        self.assertEqual(fr.params.post, {"string": "Foo bar", "boolean": False})

        fr = FuzzRequest()
        fr.headers.request = {"Content-Type": "application/json"}
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = '{"array": [1,2]}'
        self.assertEqual(fr.params.post, {"array": [1, 2]})

    def test_post_bad_json(self):
        fr = FuzzRequest()
        fr.headers.request = {"Content-Type": "application/json"}
        fr.url = "http://www.wfuzz.org/"
        fr.params.post = "1"

        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {"1": None})
        self.assertEqual(fr.params.raw_post, "1")

        fr = FuzzRequest()
        fr.url = "http://www.wfuzz.org/"
        fr.headers.request = {"Content-Type": "application/json"}
        fr.params.post = "a=1"
        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.raw_post, "a=1")
        self.assertEqual(fr.params.post, {"a": "1"})


if __name__ == "__main__":
    unittest.main()
