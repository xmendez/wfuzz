from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.payloadtools import ShodanIter
from wfuzz.plugin_api.base import BasePayload


@moduleman_plugin
class shodanp(BasePayload):
    name = "shodanp"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = (
        "Queries the Shodan API",
    )

    summary = "Returns hostnames or IPs of a given Shodan API search (needs api key)."
    category = ["default"]
    priority = 99

    parameters = (
        ("search", "", True, "Shodan search string."),
        ("page", "0", False, "Offset page, starting at zero."),
        # TODO: ("limit", "0", False, "Number of results (1 query credit = 100 results). Zero for all."),
    )

    default_parameter = "search"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        search = params["search"]
        page = int(params["page"])
        limit = int(params["limit"])

        self._it = ShodanIter(search, page, limit)

    def __iter__(self):
        return self

    def count(self):
        return -1

    def close(self):
        self._it._stop()

    def __next__(self):
        match = next(self._it)
        if match['hostnames']:
            for hostname in match['hostnames']:
                return hostname
        else:
            return match['ip_str']
