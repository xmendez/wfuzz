from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin

import re


KBASE_KEY_UNCOMMON = "http.response.headers.uncommon"


@moduleman_plugin
class unheaders(BasePlugin):
    name = "unheaders"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Looks for new uncommon reponse headers"
    description = ("Looks for new uncommon http reponse headers",)
    category = ["info", "passive", "verbose"]
    priority = 99
    parameters = ()

    def __init__(self):
        BasePlugin.__init__(self)

        common_headers_regex = [
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

        self.common_headers_regex = re.compile("({})".format("|".join(common_headers_regex)), re.IGNORECASE)

    def validate(self, fuzzresult):
        return True

    def process(self, fuzzresult):
        for header in fuzzresult.history.headers.response.keys():
            header_value = None
            if not self.common_headers_regex.match(header):
                header_value = header

            if header_value is not None:
                if header_value.lower() not in self.kbase[KBASE_KEY_UNCOMMON] or KBASE_KEY_UNCOMMON not in self.kbase:
                    self.add_result("New uncommon reponse header. {}: {}".format(header_value, fuzzresult.history.headers.response[header_value]))

                    self.kbase[KBASE_KEY_UNCOMMON].append(header_value.lower())
