from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin

import re

KBASE_KEY = "http.servers"
KBASE_KEY_RESP_UNCOMMON = "http.response.headers.uncommon"
KBASE_KEY_REQ_UNCOMMON = "http.request.headers.uncommon"

SERVER_HEADERS = ["server", "x-powered-by" "via"]

COMMON_RESPONSE_HEADERS_REGEX_LIST = [
    r"^Server$",
    r"^X-Powered-By$",
    r"^Via$",
    r"^Access-Control.*$",
    r"^Accept-.*$",
    r"^age$",
    r"^allow$",
    r"^Cache-control$",
    r"^Client-.*$",
    r"^Connection$",
    r"^Content-.*$",
    r"^Cross-Origin-Resource-Policy$",
    r"^Date$",
    r"^Etag$",
    r"^Expires$",
    r"^Keep-Alive$",
    r"^Last-Modified$",
    r"^Link$",
    r"^Location$",
    r"^P3P$",
    r"^Pragma$",
    r"^Proxy-.*$",
    r"^Refresh$",
    r"^Retry-After$",
    r"^Referrer-Policy$",
    r"^Set-Cookie$",
    r"^Server-Timing$",
    r"^Status$",
    r"^Strict-Transport-Security$",
    r"^Timing-Allow-Origin$",
    r"^Trailer$",
    r"^Transfer-Encoding$",
    r"^Upgrade$",
    r"^Vary$",
    r"^Warning^$",
    r"^WWW-Authenticate$",
    r"^X-Content-Type-Options$",
    r"^X-Download-Options$",
    r"^X-Frame-Options$",
    r"^X-Microsite$",
    r"^X-Request-Handler-Origin-Region$",
    r"^X-XSS-Protection$",
]

COMMON_RESPONSE_HEADERS_REGEX = re.compile(
    "({})".format("|".join(COMMON_RESPONSE_HEADERS_REGEX_LIST)), re.IGNORECASE
)

COMMON_REQ_HEADERS_REGEX_LIST = [
    r"A-IM$",
    r"Accept$",
    r"Accept-.*$",
    r"Access-Control-.*$",
    r"Authorization$",
    r"Cache-Control$",
    r"Connection$",
    r"Content-.*$",
    r"Cookie$",
    r"Date$",
    r"Expect$",
    r"Forwarded$",
    r"From$",
    r"Host$",
    r"If-.*$",
    r"Max-Forwards$",
    r"Origin$",
    r"Pragma$",
    r"Proxy-Authorization$",
    r"Range$",
    r"Referer$",
    r"TE$",
    r"User-Agent$",
    r"Upgrade$",
    r"Upgrade-Insecure-Requests$",
    r"Via$",
    r"Warning$",
    r"X-Requested-With$",
    r"X-HTTP-Method-Override$",
    r"X-Requested-With$",
]

COMMON_REQ_HEADERS_REGEX = re.compile(
    "({})".format("|".join(COMMON_REQ_HEADERS_REGEX_LIST)), re.IGNORECASE
)


@moduleman_plugin
class headers(BasePlugin):
    name = "headers"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Looks for HTTP headers."
    description = (
        "Looks for NEW HTTP headers:",
        "\t- Response HTTP headers associated to web servers.",
        "\t- Uncommon response HTTP headers.",
        "\t- Uncommon request HTTP headers.",
        "It is worth noting that, only the FIRST match of the above headers is registered.",
    )
    category = ["info", "passive", "default"]
    priority = 99
    parameters = ()

    def __init__(self):
        BasePlugin.__init__(self)

    def validate(self, fuzzresult):
        return True

    def check_request_header(self, fuzzresult, header, value):
        header_value = None
        if not COMMON_REQ_HEADERS_REGEX.match(header):
            header_value = header

        if header_value is not None:
            if (
                header_value.lower() not in self.kbase[KBASE_KEY_REQ_UNCOMMON]
                or KBASE_KEY_REQ_UNCOMMON not in self.kbase
            ):
                self.add_result(
                    "reqheader",
                    "New uncommon HTTP request header",
                    "{}: {}".format(header_value, value),
                )

                self.kbase[KBASE_KEY_REQ_UNCOMMON].append(header_value.lower())

    def check_response_header(self, fuzzresult, header, value):
        header_value = None
        if not COMMON_RESPONSE_HEADERS_REGEX.match(header):
            header_value = header

        if header_value is not None:
            if (
                header_value.lower() not in self.kbase[KBASE_KEY_RESP_UNCOMMON]
                or KBASE_KEY_RESP_UNCOMMON not in self.kbase
            ):
                self.add_result(
                    "header",
                    "New uncommon HTTP response header",
                    "{}: {}".format(
                        header_value, fuzzresult.history.headers.response[header_value],
                    ),
                )

                self.kbase[KBASE_KEY_RESP_UNCOMMON].append(header_value.lower())

    def check_server_header(self, fuzzresult, header, value):
        if header.lower() in SERVER_HEADERS:
            if (
                value.lower() not in self.kbase[KBASE_KEY]
                or KBASE_KEY not in self.kbase
            ):
                self.add_result(
                    "server", "New server HTTP response header", "{}".format(value),
                )

                self.kbase[KBASE_KEY].append(value.lower())

    def process(self, fuzzresult):
        for header, value in fuzzresult.history.headers.request.items():
            self.check_request_header(fuzzresult, header, value)

        for header, value in fuzzresult.history.headers.response.items():
            self.check_response_header(fuzzresult, header, value)
            self.check_server_header(fuzzresult, header, value)
