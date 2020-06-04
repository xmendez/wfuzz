import unittest

from wfuzz.fuzzrequest import FuzzRequest


http_post_request = """POST /slipstream/view HTTP/1.1
Host: www
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: */*
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www
Content-Type: text/plain;charset=UTF-8
Origin: https://www
Content-Length: 3387
Connection: close



a=1"""


http_get_request = """GET /sttc/bpk-fonts/55b577a1.woff2 HTTP/1.1
Host: js.skyscnr.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: application/font-woff2;q=1.0,application/font-woff;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: https://www.skyscanner.es
Connection: close
Referer: https://js.skyscnr.com/sttc/oc-registry/components/base-stylesheet/0.1.33/build//static/css/main.e09b44e2.css


"""

http_response = """HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 51
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0
Expires: -1
Last-Modified: Mon, 30 Dec 2019 13:16:57 GMT
Pragma: no-cache
Server: Unspecified
Date: Mon, 30 Dec 2019 13:16:57 GMT
Connection: close

LINE_1"""

http_response_no_content = """HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 51
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0
Expires: -1
Last-Modified: Mon, 30 Dec 2019 13:16:57 GMT
Pragma: no-cache
Server: Unspecified
Date: Mon, 30 Dec 2019 13:16:57 GMT
Connection: close
"""

http_multi_request = """POST /tr/ HTTP/1.1
Host: www.facebook.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: */*
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------18698393981150719881279620016
Content-Length: 3320
Origin: https://www.skyscanner.es
Connection: close
Referer: https://www.skyscanner.es/

-----------------------------18698393981150719881279620016
Content-Disposition: form-data; name="id"

561358470665569
-----------------------------18698393981150719881279620016
Content-Disposition: form-data; name="rqm"

SB
-----------------------------18698393981150719881279620016--

"""

http_follow_response = """HTTP/1.1 301 Moved Permanently
Location: http://www.google.com/
Content-Type: text/html; charset=UTF-8
Date: Mon, 30 Dec 2019 20:26:23 GMT
Expires: Wed, 29 Jan 2020 20:26:23 GMT
Cache-Control: public, max-age=2592000
Server: gws
Content-Length: 219
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN

HTTP/1.1 200 OK
Date: Mon, 30 Dec 2019 20:26:23 GMT
Expires: -1
Cache-Control: private, max-age=0
Content-Type: text/html; charset=ISO-8859-1
P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
Server: gws
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Set-Cookie: 1P_JAR=2019-12-30-20; expires=Wed, 29-Jan-2020 20:26:23 GMT; path=/; domain=.google.com
Set-Cookie: NID=194=Tygb5SRWSRvznMKZn4Dnl0SIkI9zcjk_U9OnBb9RlhyXWKlvEJSCorghYsp5IPR-bAm31XZlKGiL0RjLxjGigGqkGguTVmJ1C4Ae6JUKLoAYLbR-C8xAvuwoXm6Nw61Wep9U1zkq6evNZ-WbKyfYvOS6WrUi_3TXU7BqUaWZsJY; expires=Tue, 30-Jun-2020 20:26:23 GMT; path=/; domain=.google.com; HttpOnly
Accept-Ranges: none
Vary: Accept-Encoding
Transfer-Encoding: chunked

LINE_1"""


class ParseRequestTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(ParseRequestTest, self).__init__(*args, **kwargs)
        self.maxDiff = 1000

    def test_2_ways_of_parsing_content(self):
        fr = FuzzRequest()
        fr.update_from_raw_http(http_multi_request, "https", http_response)

        fr2 = FuzzRequest()
        fr2.update_from_raw_http(
            http_multi_request, "https", http_response_no_content, b"LINE_1"
        )

        # raw content takes precedence
        fr3 = FuzzRequest()
        fr3.update_from_raw_http(http_multi_request, "https", http_response, b"LINE_0")

        self.assertEqual(fr.content, fr2.content)
        self.assertEqual(fr3.content, "LINE_0")

    def test_parse_multi_raw_request(self):
        fr = FuzzRequest()
        fr.update_from_raw_http(http_multi_request, "https", http_response)

        self.assertEqual(fr.params.post.id, "561358470665569")
        self.assertEqual(fr.params.post.rqm, "SB")
        self.assertEqual(fr.content, "LINE_1")

    def test_parse_raw_multi_response(self):
        fr = FuzzRequest()
        fr.update_from_raw_http(http_multi_request, "https", http_follow_response)

        self.assertEqual(fr.content, "LINE_1")
        self.assertEqual(fr.code, 200)

    def test_parse_get_crlf_request(self):
        fr = FuzzRequest()
        fr.update_from_raw_http(http_get_request, "https", "\n\n\n")

        self.assertEqual(fr.method, "GET")
        self.assertEqual(fr.params.raw_post, None)

    def test_parse_crlf_post_request(self):
        fr = FuzzRequest()
        fr.update_from_raw_http(http_post_request, "https", "\n\n\n")

        self.assertEqual(fr.method, "POST")
        self.assertEqual(fr.params.post, {"a": "1"})
