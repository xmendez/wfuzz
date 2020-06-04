from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.payloadtools import BingIter
from wfuzz.plugin_api.base import BasePayload
from wfuzz.fuzzobjects import FuzzWordType


@moduleman_plugin
class bing(BasePayload):
    name = "bing"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.2"
    description = (
        'intitle:"JBoss JMX Management Console"',
        "Some examples of bing hacking:",
        "http://www.elladodelmal.com/2010/02/un-poco-de-bing-hacking-i-de-iii.html",
    )

    summary = "Returns URL results of a given bing API search (needs api key)."
    category = ["default"]
    priority = 99

    parameters = (
        ("dork", "", True, "Google dork search string."),
        ("offset", "0", False, "Offset index, starting at zero."),
        ("limit", "0", False, "Number of results. Zero for all."),
    )

    default_parameter = "dork"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        offset = int(params["offset"])
        limit = int(params["limit"])

        self._it = BingIter(params["dork"], offset, limit)

    def count(self):
        return self._it.max_count

    def get_next(self):
        return next(self._it)

    def get_type(self):
        return FuzzWordType.WORD
