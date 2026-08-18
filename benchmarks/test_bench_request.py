"""Benchmarks for the HTTP request/response objects.

Every fuzzed request is built from a seed request and every response is parsed
and turned into a FuzzResult, so these paths run once per HTTP request.
"""

from wfuzz.fuzzobjects import FuzzResult
from wfuzz.fuzzrequest import FuzzRequest
from wfuzz.plugin_api.urlutils import parse_url

from conftest import make_fuzz_result

URL = "http://www.wfuzz.org/admin/login.php?id=1&lang=en&redirect=%2Fhome"


def test_parse_raw_request(benchmark, raw_request):
    def run():
        request = FuzzRequest()
        request.update_from_raw_http(raw_request, "http")
        return request

    assert benchmark(run).url == URL


def test_parse_raw_post_request(benchmark, raw_post_request):
    def run():
        request = FuzzRequest()
        request.update_from_raw_http(raw_post_request, "http")
        return request

    assert benchmark(run).params.post["user"] == "admin"


def test_parse_raw_request_and_response(
    benchmark, raw_request, raw_response, html_page
):
    content = html_page.encode("utf-8")

    def run():
        request = FuzzRequest()
        request.update_from_raw_http(raw_request, "http", raw_response, content)
        return request

    assert benchmark(run).code == 200


def test_build_request_from_url(benchmark):
    def run():
        request = FuzzRequest()
        request.url = URL
        request.headers.request = {
            "User-Agent": "Wfuzz/3.1.0",
            "Accept": "*/*",
            "Cookie": "session=39ad7bcb9a0f4c0b",
        }
        request.params.post = "user=admin&password=admin"
        return request

    assert benchmark(run).method == "POST"


def test_request_to_cache_key(benchmark, fuzz_result):
    history = fuzz_result.history

    assert "login.php" in benchmark(history.to_cache_key)


def test_request_params_access(benchmark, fuzz_result):
    history = fuzz_result.history

    def run():
        return (
            dict(history.params.get),
            dict(history.headers.request),
            dict(history.headers.response),
            dict(history.cookies.response),
        )

    assert benchmark(run)[0]["lang"] == "en"


def test_fuzz_result_update(benchmark, raw_request, html_page):
    """md5, chars, words and lines computation over the response body."""
    result = make_fuzz_result(raw_request, html_page)

    assert benchmark(result.update).words > 1000


def test_fuzz_result_from_history(benchmark, raw_request, raw_response, html_page):
    content = html_page.encode("utf-8")
    request = FuzzRequest()
    request.update_from_raw_http(raw_request, "http", raw_response, content)

    def run():
        return FuzzResult(history=request, track_id=False)

    assert benchmark(run).code == 200


def test_fuzz_result_str(benchmark, fuzz_result):
    assert "C=200" in benchmark(lambda: str(fuzz_result))


def test_parse_url(benchmark):
    urls = ["%s&index=%d" % (URL, index) for index in range(200)]

    parsed = benchmark(lambda: [parse_url(url) for url in urls])

    assert len(parsed) == len(urls)
