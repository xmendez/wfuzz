import re

from framework.plugins.base import BasePlugin
from externals.moduleman.plugin import moduleman_plugin

@moduleman_plugin
class errors(BasePlugin):
    name = "errors"
    description = "Looks for error messages"
    category = ["default", "passive"]
    priority = 99

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
	    for i in r.findall(fuzzresult.history.fr_content()):
		self.add_result("Server error identified, version: %s %s" % (server_name, i))
