import pytest

# Python 2 and 3: urlib.parse

from wfuzz.fuzzrequest import FuzzRequest


@pytest.fixture
def full_fuzzreq(request):
    http_req, http_response = request.param
    fr = FuzzRequest()
    fr.update_from_raw_http(http_req, "http", http_response, None)

    return fr


@pytest.mark.parametrize(
    "full_fuzzreq, expected_result",
    [
        (
            (
                "GET /a HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                "HTTP/1.0 301 Moved Permanently\n"
                "Server: SimpleHTTP/0.6 Python/3.6.5\n"
                "Date: Tue, 21 Apr 2020 21:10:53 GMT\n"
                "Location: /recursive_dir/a/\n",
            ),
            "http://www.wfuzz.org/recursive_dir/a/",
        ),
        (
            (
                "GET /a HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                "HTTP/1.1 301 Moved Permanently\n"
                "Date: Fri, 24 Apr 2020 11:17:51 GMT\n"
                "Server: Apache/2.4.41 () OpenSSL/1.0.2k-fips\n"
                "Strict-Transport-Security: max-age=31536000; includeSubdomains; preload\n"
                "Location: https://www.wfuzz.org/\n"
                "Content-Type: text/html; charset=iso-8859-1\n",
            ),
            None,
        ),
        (
            (
                "GET /a HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                "HTTP/1.0 404 File not found\n"
                "Server: SimpleHTTP/0.6 Python/3.6.5\n"
                "Date: Fri, 24 Apr 2020 12:37:54 GMT\n"
                "Connection: close\n"
                "Content-Type: text/html;charset=utf-8\n"
                "Content-Length: 469\n",
            ),
            None,
        ),
    ],
    indirect=["full_fuzzreq"],
)
def test_relative_url(full_fuzzreq, expected_result):
    assert full_fuzzreq.recursive_url == expected_result


@pytest.mark.parametrize(
    "full_fuzzreq, expected_result",
    [
        (
            (
                "GET /a HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                "HTTP/1.0 301 Moved Permanently\n"
                "Server: SimpleHTTP/0.6 Python/3.6.5\n"
                "Date: Tue, 21 Apr 2020 21:10:53 GMT\n"
                "Location: /recursive_dir/a/\n",
            ),
            True,
        ),
        (
            (
                "GET /a HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                "HTTP/1.1 301 Moved Permanently\n"
                "Date: Fri, 24 Apr 2020 11:17:51 GMT\n"
                "Server: Apache/2.4.41 () OpenSSL/1.0.2k-fips\n"
                "Strict-Transport-Security: max-age=31536000; includeSubdomains; preload\n"
                "Location: https://www.wfuzz.org/\n"
                "Content-Type: text/html; charset=iso-8859-1\n",
            ),
            False,
        ),
        (
            (
                "GET /a HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                "HTTP/1.0 404 File not found\n"
                "Server: SimpleHTTP/0.6 Python/3.6.5\n"
                "Date: Fri, 24 Apr 2020 12:37:54 GMT\n"
                "Connection: close\n"
                "Content-Type: text/html;charset=utf-8\n"
                "Content-Length: 469\n",
            ),
            False,
        ),
        (
            (
                "GET /a/ HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                "HTTP/1.0 200\n"
                "Server: SimpleHTTP/0.6 Python/3.6.5\n"
                "Date: Fri, 24 Apr 2020 12:37:54 GMT\n"
                "Connection: close\n"
                "Content-Type: text/html;charset=utf-8\n"
                "Content-Length: 469\n",
            ),
            True,
        ),
    ],
    indirect=["full_fuzzreq"],
)
def test_is_path(full_fuzzreq, expected_result):
    assert full_fuzzreq.is_path == expected_result
