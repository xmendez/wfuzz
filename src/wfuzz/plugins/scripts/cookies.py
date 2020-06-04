from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin


@moduleman_plugin
class cookies(BasePlugin):
    name = "cookies"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Looks for new cookies"
    description = ("Looks for new cookies",)
    category = ["verbose", "passive"]
    priority = 99

    parameters = ()

    def __init__(self):
        BasePlugin.__init__(self)

    def validate(self, fuzzresult):
        return True

    def process(self, fuzzresult):
        new_cookies = list(fuzzresult.history.cookies.response.items())

        if len(new_cookies) > 0:
            for name, value in new_cookies:

                if (
                    name != ""
                    and "cookie" not in self.kbase
                    or name not in self.kbase["cookie"]
                ):
                    self.kbase["cookie"] = name
                    self.add_result("Cookie first set - %s=%s" % (name, value))
