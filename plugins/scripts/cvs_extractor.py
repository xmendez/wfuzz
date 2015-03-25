from urlparse import urljoin

from framework.plugins.api.urlutils import check_content_type

from framework.plugins.base import DiscoveryPlugin
from externals.moduleman.plugin import moduleman_plugin

# Entries format based on:
# http://docstore.mik.ua/orelly/other/cvs/cvs-CHP-6-SECT-9.htm
# Good example at http://webscantest.com/CVS/Entries 

@moduleman_plugin
class cvs_extractor(DiscoveryPlugin):
    name = "cvs_extractor"
    description = "Parses CVS/Entries file. Optional: discovery.bl=\".txt,.gif\""
    category = ["default", "active", "discovery"]
    priority = 99

    def validate(self, fuzzresult):
	return fuzzresult.url.find("CVS/Entries") >= 0 and fuzzresult.code == 200 and check_content_type(fuzzresult, 'text')

    def process(self, fuzzresult):
	base_url = urljoin(fuzzresult.url, "..")

	for line in fuzzresult.history.fr_content().splitlines():
	    record = line.split("/")
	    if len(record) == 6 and record[1]:
		self.queue_url(urljoin(base_url, record[1]))

		# Directory
		if record[0] == 'D':
		    self.queue_url(urljoin(base_url, record[1]))
		    self.queue_url(urljoin(base_url, "%s/CVS/Entries" % (record[1])))
