import pytest

from wfuzz.fuzzrequest import FuzzRequest
from wfuzz.fuzzobjects import FuzzResult
from wfuzz.filters.ppfilter import FuzzResFilter


@pytest.fixture
def full_fuzzres(request):
    raw_req, raw_resp = request.param
    fr = FuzzRequest()
    fr.update_from_raw_http(raw_req, 'http', raw_resp, None)

    return FuzzResult(history=fr)


@pytest.fixture
def full_fuzzreq(request):
    raw_req, raw_resp = request.param
    fr = FuzzRequest()
    fr.update_from_raw_http(raw_req, 'http', raw_resp, None)

    return fr


@pytest.fixture
def fuzzres_from_url(request):
    fr = FuzzRequest()
    fr.url = request.param

    return FuzzResult(history=fr)


@pytest.fixture
def filter_obj():
    return FuzzResFilter()


@pytest.fixture
def example_full_fuzzres():
    raw_req, raw_resp = (
        "GET /path?param1=1&param2=2 HTTP/1.1\n"
        "Host: www.wfuzz.org\n"
        "User-Agent: curl/7.58.0\n"
        "Accept: */*\n",

        "HTTP/1.1 302 Found\n"
        "Content-Type: text/html; charset=utf-8\n"
        "Content-Language: en\n"
        "Location: https://wfuzz.readthedocs.io/en/latest/\n"
        "Vary: Accept-Language, Cookie\n"
        "Server: nginx/1.14.0 (Ubuntu)\n"
        "X-Fallback: True\n"
        "X-Served: Django\n"
        "X-Deity: web01\n"
        "Date: Wed, 23 Jan 2019 21:43:59 GMT\n"
        "Content-Length: 0\n"
    )
    fr = FuzzRequest()
    fr.update_from_raw_http(raw_req, 'http', raw_resp, b"Some line\n and words\nasdsdas")

    return FuzzResult(history=fr)
