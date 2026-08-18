"""Benchmarks for the internal helpers.

These small utilities are used pervasively: the case insensitive dictionaries
back the HTTP headers/params and the dynamic attribute lookup backs the filter
language.
"""

from wfuzz.helpers.obj_dic import CaseInsensitiveDict, DotDict
from wfuzz.helpers.obj_dyn import rgetattr, rsetattr
from wfuzz.helpers.str_func import json_minify, value_in_any_list_item

HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Server": "nginx/1.14.0 (Ubuntu)",
    "Set-Cookie": "session=39ad7bcb9a0f4c0b; Path=/; HttpOnly",
    "Vary": "Accept-Language, Cookie",
    "X-Frame-Options": "SAMEORIGIN",
    "Content-Length": "37966",
    "Date": "Wed, 23 Jan 2019 21:43:59 GMT",
}

JSON_DOCUMENT = """
{
    // a comment
    "results": [
%s
    ]
}
""" % (
    ",\n".join(
        '        {"id": %d, "url": "/dir%d/item%d.html", "code": 200}' % (i, i, i)
        for i in range(25)
    )
)


def test_case_insensitive_dict_build(benchmark):
    def run():
        headers = CaseInsensitiveDict()
        for key, value in HEADERS.items():
            headers[key] = value
        return headers

    assert benchmark(run)["server"].startswith("nginx")


def test_case_insensitive_dict_lookup(benchmark):
    headers = CaseInsensitiveDict(HEADERS)
    keys = ["content-type", "SERVER", "Set-Cookie", "vary", "content-length"] * 20

    assert len(benchmark(lambda: [headers[key] for key in keys])) == len(keys)


def test_dot_dict_access(benchmark):
    dot_dict = DotDict(HEADERS)

    assert benchmark(lambda: [dot_dict.Server for _ in range(100)])


def test_rgetattr_result_fields(benchmark, fuzz_result):
    fields = [
        "code",
        "lines",
        "words",
        "chars",
        "md5",
        "url",
        "history.headers.response.Server",
        "history.params.get.lang",
        "history.cookies.response",
    ]

    assert len(benchmark(lambda: [rgetattr(fuzz_result, f) for f in fields])) == len(
        fields
    )


def test_rsetattr_request_field(benchmark, fuzz_result):
    def run():
        rsetattr(fuzz_result, "history.params.get.lang", "fr", None)
        return rgetattr(fuzz_result, "history.params.get.lang")

    assert benchmark(run) == "fr"


def test_json_minify(benchmark):
    assert len(benchmark(lambda: json_minify(JSON_DOCUMENT))) < len(JSON_DOCUMENT)


def test_value_in_any_list_item(benchmark):
    items = ["/dir%d/item%d.html" % (i, i) for i in range(500)]

    assert benchmark(lambda: value_in_any_list_item("item499", items))
