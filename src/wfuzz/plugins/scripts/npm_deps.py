import re

from wfuzz.plugin_api.base import BasePlugin
from wfuzz.exception import FuzzExceptPluginBadParams
from wfuzz.externals.moduleman.plugin import moduleman_plugin


@moduleman_plugin
class npm_deps(BasePlugin):
    name = "npm_deps"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Looks for npm dependencies definition in js code"
    description = (
        "Extracts npm packages by using regex pattern from the HTTP response and prints it",
    )
    category = ["default"]
    priority = 99

    parameters = ()

    REGEX_PATT = re.compile(r'"([^"]+)":"([^"]+)"', re.MULTILINE | re.DOTALL)
    REGEX_DEP = re.compile(
        r"dependencies:\{(.*?)\}", re.MULTILINE | re.DOTALL | re.IGNORECASE
    )
    REGEX_DEV_DEP = re.compile(
        r"devdependencies:\{(.*?)\}", re.MULTILINE | re.DOTALL | re.IGNORECASE
    )

    def __init__(self):
        BasePlugin.__init__(self)

    def validate(self, fuzzresult):
        if fuzzresult.history.urlparse.fext != ".js" or fuzzresult.code != 200:
            return False

        self.match = self.REGEX_DEP.search(fuzzresult.history.content)
        self.match_dev = self.REGEX_DEV_DEP.search(fuzzresult.history.content)

        return self.match is not None or self.match_dev is not None

    def process(self, fuzzresult):
        if self.match_dev:
            for name, version in self.REGEX_PATT.findall(self.match_dev.group(1)):
                self.add_result(name)

        if self.match:
            for name, version in self.REGEX_PATT.findall(self.match.group(1)):
                self.add_result(name)
