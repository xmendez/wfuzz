import re

from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin

@moduleman_plugin
class errors(BasePlugin):
    name = "errors"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Looks for error messages"
    description = ("Looks for common error messages",)
    category = ["default", "passive"]
    priority = 99

    parameters = (
    )

    def __init__(self):
	BasePlugin.__init__(self)

	regex = [
	    ('Apache Tomcat', 'Apache Tomcat/(.*?) - Error report'),
	]

	self.regex = []
	for server_name, i in regex:
	    self.regex.append((server_name, re.compile(i, re.MULTILINE|re.DOTALL)))

    def validate(self, fuzzresult):
	return True

    def process(self, fuzzresult):
	for server_name, r in self.regex:
	    for i in r.findall(fuzzresult.history.content):
		self.add_result("Server error identified, version: %s %s" % (server_name, i))
