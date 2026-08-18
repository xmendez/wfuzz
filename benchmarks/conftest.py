import os

import pytest

from wfuzz.fuzzobjects import FuzzResult
from wfuzz.fuzzrequest import FuzzRequest

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMMON_WORDLIST = os.path.join(REPO_DIR, "wordlist", "general", "common.txt")

RAW_REQUEST = """GET /admin/login.php?id=1&lang=en&redirect=%2Fhome HTTP/1.1
Host: www.wfuzz.org
User-Agent: Wfuzz/3.1.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: session=39ad7bcb9a0f4c0b; lang=en; consent=1
Connection: close

"""

RAW_POST_REQUEST = """POST /admin/login.php HTTP/1.1
Host: www.wfuzz.org
User-Agent: Wfuzz/3.1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 61
Cookie: session=39ad7bcb9a0f4c0b

user=admin&password=admin&remember=1&csrf=39ad7bcb9a0f4c0b0e2a
"""

RAW_RESPONSE_HEADERS = """HTTP/1.1 200 OK
Date: Wed, 23 Jan 2019 21:43:59 GMT
Content-Type: text/html; charset=utf-8
Server: nginx/1.14.0 (Ubuntu)
Set-Cookie: session=39ad7bcb9a0f4c0b; Path=/; HttpOnly
Vary: Accept-Language, Cookie
X-Frame-Options: SAMEORIGIN
Content-Length: {content_length}

{content}"""


def build_html_page(rows=150):
    """Build a deterministic HTML page, representative of a crawled response."""
    parts = [
        "<html><head><title>Wfuzz benchmark page</title>",
        '<link rel="stylesheet" href="/static/main.css">',
        "</head><body>",
        '<div id="content">',
    ]

    for i in range(rows):
        parts.append(
            '<div class="row"><a href="/dir{i}/item{i}.html?id={i}&amp;ref=list">'
            "Item {i}</a>"
            '<img src="/static/img/thumb{i}.png" alt="thumb {i}"/>'
            "<p>Some textual content for the item number {i}, used to make the "
            "response body large enough to be representative.</p></div>".format(i=i)
        )

    parts.append("</div>")
    parts.append('<script src="/static/js/app.js"></script>')
    parts.append("</body></html>")

    return "\n".join(parts)


HTML_PAGE = build_html_page()


@pytest.fixture(scope="session")
def words():
    """A realistic list of fuzzing words, taken from the shipped wordlists."""
    with open(COMMON_WORDLIST) as f:
        return [line.strip() for line in f if line.strip()]


@pytest.fixture(scope="session")
def common_wordlist_path():
    return COMMON_WORDLIST


@pytest.fixture(scope="session")
def html_page():
    return HTML_PAGE


@pytest.fixture(scope="session")
def raw_request():
    return RAW_REQUEST


@pytest.fixture(scope="session")
def raw_post_request():
    return RAW_POST_REQUEST


@pytest.fixture(scope="session")
def raw_response():
    return RAW_RESPONSE_HEADERS.format(
        content_length=len(HTML_PAGE), content=HTML_PAGE
    ).encode("utf-8")


def make_fuzz_result(raw_req=RAW_REQUEST, content=HTML_PAGE):
    raw_resp = RAW_RESPONSE_HEADERS.format(
        content_length=len(content), content=content
    ).encode("utf-8")

    request = FuzzRequest()
    request.update_from_raw_http(raw_req, "http", raw_resp, content.encode("utf-8"))

    return FuzzResult(history=request).update()


@pytest.fixture
def fuzz_result():
    return make_fuzz_result()
