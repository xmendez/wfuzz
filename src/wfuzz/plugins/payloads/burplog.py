from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptBadFile
from wfuzz.fuzzobjects import FuzzResult
from wfuzz.fuzzrequest import FuzzRequest
from wfuzz.plugin_api.base import BasePayload
from wfuzz.helpers.obj_dyn import rgetattr
from wfuzz.fuzzobjects import FuzzWordType

import re

import sys

if sys.version_info < (3, 0):
    from io import open

CRLF = "\n"
DELIMITER = "%s%s" % ("=" * 54, CRLF)
CRLF_DELIMITER = CRLF + DELIMITER
HEADER = re.compile(
    r"(\d{1,2}:\d{2}:\d{2} (AM|PM|))[ \t]+(\S+)([ \t]+\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|unknown host)\])?"
)


@moduleman_plugin
class burplog(BasePayload):
    name = "burplog"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = ("Returns fuzz results' URL from a Burp log.",)
    summary = "Returns fuzz results from a Burp log."
    category = ["default"]
    priority = 99

    parameters = (
        ("fn", "", True, "Filename of a valid Burp log file."),
        (
            "attr",
            None,
            False,
            "Attribute of fuzzresult to return. If not specified the whole object is returned.",
        ),
    )

    default_parameter = "fn"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        self.__max = -1
        self.attr = self.params["attr"]
        self._it = self.parse_burp_log(self.params["fn"])

    def count(self):
        return self.__max

    def get_type(self):
        return FuzzWordType.FUZZRES if not self.attr else FuzzWordType.WORD

    def get_next(self):
        next_item = next(self._it)

        return next_item if not self.attr else rgetattr(next_item, self.attr)

    def parse_burp_log(self, burp_log):
        burp_file = None

        try:
            burp_file = open(
                self.find_file(burp_log),
                "r",
                encoding="utf-8",
                errors="surrogateescape",
            )

            history = "START"

            rl = burp_file.readline()
            while rl != "":
                if history == "START":
                    if rl == DELIMITER:
                        history = "HEADER"
                elif history == "HEADER":
                    if rl == DELIMITER:
                        raw_request = ""
                        history = "REQUEST"
                    else:
                        matched = HEADER.match(rl)
                        ctime, host, ip_address = matched.group(1, 3, 5)
                elif history == "REQUEST":
                    if rl == DELIMITER:
                        history = "DELIM1"
                    else:
                        raw_request += rl
                elif history == "DELIM1":
                    if rl == CRLF:
                        raw_response = ""
                        history = "DELIM3"
                    else:
                        raw_response = rl
                        history = "RESPONSE"
                elif history == "RESPONSE":
                    if rl == DELIMITER:
                        history = "DELIM2"
                    else:
                        raw_response += rl
                elif history == "DELIM2":
                    if rl == CRLF:
                        history = "DELIM3"
                elif history == "DELIM3":
                    if rl == CRLF:
                        history = "DELIM4"
                elif history == "DELIM4":
                    if rl == CRLF:
                        fr = FuzzRequest()
                        fr.update_from_raw_http(
                            raw_request, host[: host.find("://")], raw_response
                        )
                        frr = FuzzResult(history=fr)

                        yield frr.update()

                        history = "START"

                rl = burp_file.readline()

        except IOError as e:
            raise FuzzExceptBadFile("Error opening burp log file. %s" % str(e))
        finally:
            if burp_file is not None:
                burp_file.close()
