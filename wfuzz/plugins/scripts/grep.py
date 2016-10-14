import re

from wfuzz.plugin_api.base import BasePlugin
from wfuzz.exception import FuzzException
from wfuzz.externals.moduleman.plugin import moduleman_plugin

@moduleman_plugin
class grep(BasePlugin):
    name = "grep"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Extracts the given pattern from the HTTP response. Parameters: grep.regex=\"<exp>\""
    category = ["passive"]
    priority = 99

    def __init__(self):
	try:
	    self.regex = re.compile(self.get_kbase("grep.regex")[0], re.MULTILINE|re.DOTALL)
	except Exception, e:
	    raise FuzzException(FuzzException.FATAL, "Incorrect regex or missing regex parameter.")
	    
    def validate(self, fuzzresult):
	return True

    def process(self, fuzzresult):
	for r in self.regex.findall(fuzzresult.history.content):
	    self.add_result("Pattern match %s" % r)
