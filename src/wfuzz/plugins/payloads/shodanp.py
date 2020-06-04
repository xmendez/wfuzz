from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.payloadtools import ShodanIter
from wfuzz.plugin_api.base import BasePayload
from wfuzz.fuzzobjects import FuzzWordType


@moduleman_plugin
class shodanp(BasePayload):
    name = "shodanp"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = ("Queries the Shodan API",)

    summary = "Returns URLs of a given Shodan API search (needs api key)."
    category = ["default"]
    priority = 99

    parameters = (
        ("search", "", True, "Shodan search string."),
        ("page", "0", False, "Offset page, starting at zero."),
        (
            "limit",
            "0",
            False,
            "Number of pages (1 query credit = 100 results). Zero for all.",
        ),
    )

    default_parameter = "search"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        search = params["search"]
        page = int(params["page"])
        limit = int(params["limit"])

        self._it = ShodanIter(search, page, limit)

    def count(self):
        return -1

    def close(self):
        self._it._stop()

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        match = next(self._it)

        port = match["port"]
        scheme = "https" if "ssl" in match or port == 443 else "http"

        if match["hostnames"]:
            for hostname in match["hostnames"]:
                return "{}://{}:{}".format(scheme, hostname, port)
        else:
            return "{}://{}:{}".format(scheme, match["ip_str"], port)
