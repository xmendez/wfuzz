from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin


KBASE_NEW_COOKIE = "cookies.cookie"


@moduleman_plugin
class cookies(BasePlugin):
    name = "cookies"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Looks for new cookies"
    description = ("Looks for new cookies",)
    category = ["info", "passive", "default"]
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
                    and KBASE_NEW_COOKIE not in self.kbase
                    or name not in self.kbase[KBASE_NEW_COOKIE]
                ):
                    self.kbase[KBASE_NEW_COOKIE] = name
                    self.add_result(
                        "cookie", "Cookie first set", "%s=%s" % (name, value)
                    )
