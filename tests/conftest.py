import pytest


from wfuzz.fuzzrequest import FuzzRequest
from wfuzz.fuzzobjects import FuzzResult
from wfuzz.fuzzobjects import FPayloadManager
from wfuzz.filters.ppfilter import FuzzResFilter
from wfuzz.facade import Facade


@pytest.fixture
def full_fuzzres(request):
    raw_req, raw_resp = request.param
    fr = FuzzRequest()
    fr.update_from_raw_http(raw_req, "http", raw_resp, None)

    return FuzzResult(history=fr)


@pytest.fixture
def full_fuzzreq(request):
    raw_req, raw_resp = request.param
    fr = FuzzRequest()
    fr.update_from_raw_http(raw_req, "http", raw_resp, None)

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
        "Accept: */*\n"
        "Cookie: cookie1=1\n",
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
        "Set-Cookie: name=Nicholas; expires=Sat, 02 May 2009 23:38:25 GMT\n",
    )
    fr = FuzzRequest()
    fr.update_from_raw_http(
        raw_req, "http", raw_resp, b"Some line\n and words\nasdsdas"
    )

    return FuzzResult(history=fr)


@pytest.fixture
def example_full_fuzzres_content(request):
    raw_content = request.param

    raw_req, raw_resp = (
        "GET /path?param1=1&param2=2 HTTP/1.1\n"
        "Host: www.wfuzz.org\n"
        "User-Agent: curl/7.58.0\n"
        "Accept: */*\n"
        "Cookie: cookie1=1\n",
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html; charset=utf-8\n"
        "Content-Language: en\n"
        "Vary: Accept-Language, Cookie\n"
        "Server: nginx/1.14.0 (Ubuntu)\n"
        "X-Fallback: True\n"
        "X-Served: Django\n"
        "X-Deity: web01\n"
        "Date: Wed, 23 Jan 2019 21:43:59 GMT\n"
        "Content-Length: 0\n"
        "Set-Cookie: name=Nicholas; expires=Sat, 02 May 2009 23:38:25 GMT\n",
    )
    fr = FuzzRequest()
    fr.update_from_raw_http(raw_req, "http", raw_resp, raw_content)

    fuzzres = FuzzResult(history=fr)
    fuzzres.payload_man = FPayloadManager()

    return fuzzres


@pytest.fixture
def example_full_fuzzres_no_response():
    raw_req = "GET /path?param1=1&param2=2 HTTP/1.1\nHost: www.wfuzz.org\nUser-Agent: curl/7.58.0\nAccept: */*\n"

    fr = FuzzRequest()
    fr.update_from_raw_http(raw_req, "http", None, None)

    return FuzzResult(history=fr)


@pytest.fixture
def get_plugin():
    def _get_customer_plugin(name):
        return [x() for x in Facade().scripts.get_plugins(name)]

    return _get_customer_plugin
