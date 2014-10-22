import re

from framework.plugins.api import BasePlugin
from externals.moduleman.plugin import moduleman_plugin

@moduleman_plugin
class listing(BasePlugin):
    name = "listing"
    description = "Looks for directory listing vulnerabilities"
    category = ["default", "passive"]
    priority = 99

    def __init__(self):
	dir_indexing_regexes = []

	dir_indexing_regexes.append("<title>Index of /") 
	dir_indexing_regexes.append('<a href="\\?C=N;O=D">Name</a>') 
	dir_indexing_regexes.append("Last modified</a>")
	dir_indexing_regexes.append("Parent Directory</a>")
	dir_indexing_regexes.append("Directory Listing for")
	dir_indexing_regexes.append("<TITLE>Folder Listing.")
	dir_indexing_regexes.append("<TITLE>Folder Listing.")
	dir_indexing_regexes.append('<table summary="Directory Listing" ')
	dir_indexing_regexes.append("- Browsing directory ")
	dir_indexing_regexes.append('">\\[To Parent Directory\\]</a><br><br>') # IIS 6.0 and 7.0
	dir_indexing_regexes.append('<A HREF=".*?">.*?</A><br></pre><hr></body></html>') # IIS 5.0

	self.regex = []
	for i in dir_indexing_regexes:
	    self.regex.append(re.compile(i,re.MULTILINE|re.DOTALL))

    def validate(self, fuzzresult):
	return fuzzresult.code in [200]

    def process(self, fuzzresult):
	for r in self.regex:
	    if len(r.findall(fuzzresult.history.fr_content())) > 0:
		self.add_result("Directory listing identified")
		break
