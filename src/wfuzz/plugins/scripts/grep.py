import re

from wfuzz.plugin_api.base import BasePlugin
from wfuzz.exception import FuzzExceptPluginBadParams
from wfuzz.externals.moduleman.plugin import moduleman_plugin


@moduleman_plugin
class grep(BasePlugin):
    name = "grep"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "HTTP response grep"
    description = (
        "Extracts the given regex pattern from the HTTP response and prints it",
        "(It is not a filter operator)",
    )
    category = ["tools"]
    priority = 99

    parameters = (("regex", "", True, "Regex to perform the grep against."),)

    def __init__(self):
        BasePlugin.__init__(self)
        try:
            print(self.kbase["grep.regex"])
            self.regex = re.compile(
                self.kbase["grep.regex"][0], re.MULTILINE | re.DOTALL
            )
        except Exception:
            raise FuzzExceptPluginBadParams(
                "Incorrect regex or missing regex parameter."
            )

    def validate(self, fuzzresult):
        return True

    def process(self, fuzzresult):
        for r in self.regex.findall(fuzzresult.history.content):
            self.add_result("Pattern match %s" % r)
