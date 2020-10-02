from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin


KBASE_KEY = "http.headers.servers"


@moduleman_plugin
class headers(BasePlugin):
    name = "headers"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Looks for new headers associated to HTTP servers in HTTP responses"
    description = ("Looks for new server headers",)
    category = ["info", "passive", "default"]
    priority = 99
    parameters = ()

    def __init__(self):
        BasePlugin.__init__(self)

    def validate(self, fuzzresult):
        return True

    def process(self, fuzzresult):

        watch_headers = [
            "Server",
            "X-Powered-By"
        ]

        for header in watch_headers:
            header_value = None
            if header in fuzzresult.history.headers.response:
                header_value = fuzzresult.history.headers.response[header]

            if header_value is not None:
                if header_value.lower() not in self.kbase[KBASE_KEY] or KBASE_KEY not in self.kbase:
                    self.add_result("New server header. {}: {}".format(header, header_value))

                    self.kbase[KBASE_KEY].append(header_value.lower())
