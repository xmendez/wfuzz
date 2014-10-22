from framework.plugins.api import BasePlugin

from externals.moduleman.plugin import moduleman_plugin

@moduleman_plugin
class cookies(BasePlugin):
    name = "cookies"
    description = "Looks for new cookies"
    category = ["default", "passive"]
    priority = 99

    def validate(self, fuzzresult):
	return True

    def process(self, fuzzresult):
        new_cookies = fuzzresult.history.fr_cookies()['response'].items()

	if len(new_cookies) > 0:
	    for name, value in new_cookies:

		if name != "" and not self.has_kbase("cookie") or name not in self.get_kbase("cookie"):
		    self.add_kbase("cookie", name)
		    self.add_result("Cookie first set - %s=%s" % (name, value))
