import re
from urlparse import urlparse, urljoin


from framework.plugins.api import DiscoveryPlugin
from framework.plugins.api import url_filename
from externals.moduleman.plugin import moduleman_plugin

@moduleman_plugin
class robots(DiscoveryPlugin):
    name = "robots"
    description = "Parses robots.txt looking for new content. Optional: discovery.bl=\".txt,.gif\""
    category = ["default", "active", "discovery"]
    priority = 99

    def validate(self, fuzzresult):
	return url_filename(fuzzresult) == "robots.txt" and fuzzresult.code == 200

    def process(self, fuzzresult):
	# Shamelessly (partially) copied from w3af's plugins/discovery/robotsReader.py
	for line in fuzzresult.history.fr_content().split('\n'):
	    line = line.strip()

	    if len(line) > 0 and line[0] != '#' and (line.upper().find('ALLOW') == 0 or\
	    line.upper().find('DISALLOW') == 0 or line.upper().find('SITEMAP') == 0):

		url = line[ line.find(':') + 1 : ]
		url = url.strip(" *")

		if url and not self.blacklisted_extension(url):
		    self.queue_url(urljoin(fuzzresult.url, url))

