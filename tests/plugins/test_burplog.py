import pytest
import sys
from io import BytesIO

import wfuzz
from wfuzz.facade import Facade

try:
    # Python >= 3.3
    from unittest import mock
except ImportError:
    # Python < 3.3
    import mock


@pytest.fixture
def burplog_file(request):
    class mock_saved_session(object):
        def __init__(self, infile):
            self.outfile = BytesIO(bytes(infile, "ascii"))
            self.outfile.seek(0)
            self.outfile.name = "mockfile"

        def close(self):
            pass

        def read(self, *args, **kwargs):
            return self.outfile.read(*args, **kwargs)

        def seek(self, *args, **kwargs):
            return self.outfile.seek(*args, **kwargs)

        def tell(self):
            return self.outfile.tell()

        def readline(self, *args, **kwargs):
            line = self.outfile.readline()
            if line:
                return line.decode("utf-8")
            return ""

    return mock_saved_session(request.param)


@pytest.mark.parametrize(
    "burplog_file, expected_content",
    [
        # (
        #     (
        #         "======================================================\n"
        #         "22:35:55  https://aus5.mozilla.org:443  [35.244.181.201]\n"
        #         "======================================================\n"
        #         "GET /update/3/SystemAddons/81.0/20200917005511/Linux_x86_64-gcc3/null/release-cck-ubuntu/Linux%205.4.0-48-generic%20(GTK%203.24.20%2Clibpulse%2013.99.0)/canonical/1.0/update.xml HTTP/1.1\n"
        #         "Host: aus5.mozilla.org\n"
        #         "\n"
        #         "\n"
        #         "======================================================\n"
        #         "HTTP/1.1 200 OK\n"
        #         "Server: nginx/1.17.9\n"
        #         "\n"
        #         "<?xml version=\"1.0\"?>\n"
        #         "<updates>\n"
        #         "</updates>\r\n"
        #         "======================================================\n"
        #         "\n"
        #         "\n"
        #         "\n"
        #     ),
        #     '<?xml version="1.0"?>\n<updates>\n</updates>',
        # ),
        (
            (
                "======================================================\n"
                "22:35:55  https://aus5.mozilla.org:443  [35.244.181.201]\n"
                "======================================================\n"
                "GET /update/3/SystemAddons/81.0/20200917005511/Linux_x86_64-gcc3/null/release-cck-ubuntu/Linux%205.4.0-48-generic%20(GTK%203.24.20%2Clibpulse%2013.99.0)/canonical/1.0/update.xml HTTP/1.1\n"
                "Host: aus5.mozilla.org\n"
                "\n"
                "\n"
                "======================================================\n"
                "HTTP/1.1 200 OK\n"
                "Server: nginx/1.17.9\n"
                "\n"
                '<?xml version="1.0"?>\n'
                "<updates>\n"
                "</updates>   \n"
                "======================================================\n"
                "\n"
                "\n"
                "\n"
            ),
            '<?xml version="1.0"?>\n<updates>\n</updates>   ',
        ),
        (
            (
                "======================================================\n"
                "22:35:55  https://aus5.mozilla.org:443  [35.244.181.201]\n"
                "======================================================\n"
                "GET /update/3/SystemAddons/81.0/20200917005511/Linux_x86_64-gcc3/null/release-cck-ubuntu/Linux%205.4.0-48-generic%20(GTK%203.24.20%2Clibpulse%2013.99.0)/canonical/1.0/update.xml HTTP/1.1\n"
                "Host: aus5.mozilla.org\n"
                "\n"
                "\n"
                "======================================================\n"
                "HTTP/1.1 200 OK\n"
                "Server: nginx/1.17.9\n"
                "\n"
                '<?xml version="1.0"?>\n'
                "<updates>\n"
                "</updates>\n"
                "\n"
                "======================================================\n"
                "\n"
                "\n"
                "\n"
            ),
            '<?xml version="1.0"?>\n<updates>\n</updates>\n',
        ),
        (
            (
                "======================================================\n"
                "22:35:55  https://aus5.mozilla.org:443  [35.244.181.201]\n"
                "======================================================\n"
                "GET /update/3/SystemAddons/81.0/20200917005511/Linux_x86_64-gcc3/null/release-cck-ubuntu/Linux%205.4.0-48-generic%20(GTK%203.24.20%2Clibpulse%2013.99.0)/canonical/1.0/update.xml HTTP/1.1\n"
                "Host: aus5.mozilla.org\n"
                "\n"
                "\n"
                "======================================================\n"
                "HTTP/1.1 200 OK\n"
                "Server: nginx/1.17.9\n"
                "\n"
                '<?xml version="1.0"?>\n'
                "<updates>\n"
                "</updates>\n"
                "======================================================\n"
                "\n"
                "\n"
                "\n"
            ),
            '<?xml version="1.0"?>\n<updates>\n</updates>',
        ),
        (
            (
                "======================================================\n"
                "2:17:05 PM  https://www.xxx.es:443  [2.2.2.1]\n"
                "======================================================\n"
                "GET /sttc/dbook-fp/ctrip-prod-2.4.0.min.js HTTP/1.1\n"
                "Host: www.xxx.es\n"
                "\n"
                "\n"
                "======================================================\n"
                "HTTP/1.1 200 OK\n"
                "\n"
                'HTTP"," 333D Visionplugin\n'
                "======================================================\n"
                "\n"
                "\n"
                "\n"
            ),
            'HTTP"," 333D Visionplugin',
        ),
        (
            (
                "======================================================\n"
                "22:26:48  http://testphp.vulnweb.com:80  [176.28.50.165]\n"
                "======================================================\n"
                "GET /style.css HTTP/1.1\n"
                "Host: testphp.vulnweb.com\n"
                "\n"
                "\n"
                "======================================================\n"
                "HTTP/1.1 304 Not Modified\n"
                "Server: nginx/1.4.1\n"
                "Date: Mon, 19 Jan 1970 15:36:40 GMT\n"
                "Last-Modified: Wed, 11 May 2011 10:27:48 GMT\n"
                "Connection: close\n"
                'ETag: "4dca64a4-156a"\n'
                "\n"
                "\n"
                "======================================================\n"
                "\n"
                "\n"
                "\n"
            ),
            "",
        ),
    ],
    indirect=["burplog_file"],
)
def test_burplog_content(burplog_file, expected_content):
    # load plugins before mocking file object
    Facade().payloads

    m = mock.MagicMock(name="open", spec=open)
    m.return_value = burplog_file

    mocked_fun = "builtins.open" if sys.version_info >= (3, 0) else "__builtin__.open"
    with mock.patch(mocked_fun, m, create=True):
        payload_list = list(
            wfuzz.payload(
                **{
                    "payloads": [
                        ("burplog", {"default": "mockedfile", "encoder": None}, None)
                    ],
                }
            )
        )

        fres = payload_list[0][0]

        assert fres.history.content == expected_content


@pytest.mark.parametrize(
    "burplog_file, expected_req_headers, expected_resp_headers",
    [
        (
            (
                "======================================================\n"
                "22:35:55  https://aus5.mozilla.org:443  [35.244.181.201]\n"
                "======================================================\n"
                "GET /update/3/SystemAddons/81.0/20200917005511/Linux_x86_64-gcc3/null/release-cck-ubuntu/Linux%205.4.0-48-generic%20(GTK%203.24.20%2Clibpulse%2013.99.0)/canonical/1.0/update.xml HTTP/1.1\n"
                "Host: aus5.mozilla.org\n"
                "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:81.0) Gecko/20100101 Firefox/81.0\n"
                "Accept: */*\n"
                "Accept-Language: en-GB,en;q=0.5\n"
                "Accept-Encoding: gzip, deflate\n"
                "Cache-Control: no-cache\n"
                "Pragma: no-cache\n"
                "Connection: close\n"
                "\n"
                "\n"
                "======================================================\n"
                "HTTP/1.1 200 OK\n"
                "Server: nginx/1.17.9\n"
                "Date: Sun, 01 Nov 2020 21:35:08 GMT\n"
                "Content-Type: text/xml; charset=utf-8\n"
                "Content-Length: 42\n"
                "Strict-Transport-Security: max-age=31536000;\n"
                "X-Content-Type-Options: nosniff\n"
                "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\n"
                "X-Proxy-Cache-Status: EXPIRED\n"
                "Via: 1.1 google\n"
                "Age: 47\n"
                "Cache-Control: public, max-age=90\n"
                "Alt-Svc: clear\n"
                "Connection: close\n"
                "\n"
                '<?xml version="1.0"?>\n'
                "<updates>\n"
                "</updates>\n"
                "======================================================\n"
                "\n"
                "\n"
                "\n"
            ),
            {
                "Host": "aus5.mozilla.org",
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:81.0) Gecko/20100101 Firefox/81.0",
                "Accept": "*/*",
                "Accept-Language": "en-GB,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Connection": "close",
            },
            {
                "Server": "nginx/1.17.9",
                "Date": "Sun, 01 Nov 2020 21:35:08 GMT",
                "Content-Type": "text/xml; charset=utf-8",
                "Content-Length": "42",
                "Strict-Transport-Security": "max-age=31536000;",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                "X-Proxy-Cache-Status": "EXPIRED",
                "Via": "1.1 google",
                "Age": "47",
                "Cache-Control": "public, max-age=90",
                "Alt-Svc": "clear",
                "Connection": "close",
            },
        ),
    ],
    indirect=["burplog_file"],
)
def test_burplog_headers(burplog_file, expected_req_headers, expected_resp_headers):
    # load plugins before mocking file object
    Facade().payloads

    m = mock.MagicMock(name="open", spec=open)
    m.return_value = burplog_file

    mocked_fun = "builtins.open" if sys.version_info >= (3, 0) else "__builtin__.open"
    with mock.patch(mocked_fun, m, create=True):
        payload_list = list(
            wfuzz.payload(
                **{
                    "payloads": [
                        ("burplog", {"default": "mockedfile", "encoder": None}, None)
                    ],
                }
            )
        )

        fres = payload_list[0][0]

        assert fres.history.headers.request == expected_req_headers
        assert fres.history.headers.response == expected_resp_headers
