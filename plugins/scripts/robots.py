import re
from urlparse import urlparse, urljoin


from framework.plugins.base import DiscoveryPlugin
from framework.plugins.api.urlutils import parse_res
from framework.plugins.api.urlutils import check_content_type
from externals.moduleman.plugin import moduleman_plugin

@moduleman_plugin
class robots(DiscoveryPlugin):
    name = "robots"
    description = "Parses robots.txt looking for new content. Optional: discovery.bl=\".txt,.gif\""
    category = ["default", "active", "discovery"]
    priority = 99

    def validate(self, fuzzresult):
	return parse_res(fuzzresult).file_fullname == "robots.txt" and fuzzresult.code == 200 and check_content_type(fuzzresult, 'text')

    def process(self, fuzzresult):
	# Shamelessly (partially) copied from w3af's plugins/discovery/robotsReader.py
	for line in fuzzresult.history.content.split('\n'):
	    line = line.strip()

	    if len(line) > 0 and line[0] != '#' and (line.upper().find('ALLOW') == 0 or\
	    line.upper().find('DISALLOW') == 0 or line.upper().find('SITEMAP') == 0):

		url = line[ line.find(':') + 1 : ]
		url = url.strip(" *")

		if url:
		    self.queue_url(urljoin(fuzzresult.url, url))

