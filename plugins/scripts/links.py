import re
from urlparse import urlparse, urljoin

from framework.plugins.api import DiscoveryPlugin
from framework.plugins.api import url_same_domain
from externals.moduleman.plugin import moduleman_plugin

@moduleman_plugin
class links(DiscoveryPlugin):
    name = "links"
    description = "Parses HTML looking for new content. Optional: discovery.bl=\".txt,.gif\""
    category = ["default", "active", "discovery"]
    priority = 99

    def __init__(self):
	DiscoveryPlugin.__init__(self)

	regex = [ 'href="((?!mailto:|tel:|#|javascript:).*?)"',
	    'src="((?!javascript:).*?)"',
	    'action="((?!javascript:).*?)"',
	    # http://en.wikipedia.org/wiki/Meta_refresh
	    '<meta.*content="\d+;url=(.*?)">',
	    'getJSON\("(.*?)"',
	]

	self.regex = []
	for i in regex:
	    self.regex.append(re.compile(i, re.MULTILINE|re.DOTALL))

    def validate(self, fuzzresult):
	return fuzzresult.code in [200]

    def process(self, fuzzresult):
	l = []

	#<a href="www.owasp.org/index.php/OWASP_EU_Summit_2008">O
	#ParseResult(scheme='', netloc='', path='www.owasp.org/index.php/OWASP_EU_Summit_2008', params='', query='', fragment='')

	for r in self.regex:
	    for i in r.findall(fuzzresult.history.fr_content()):
		schema, host, path, params, variables, f = urlparse(i)

		if (not schema or schema == "http" or schema == "https") and \
		    (url_same_domain(i, fuzzresult.url) or (not host and path)):
		    if i not in l:
			l.append(i)

			# dir path
			split_path = path.split("/")
			newpath = '/'.join(split_path[:-1]) + "/"
			self.queue_url(urljoin(fuzzresult.url, newpath))

			# file path
			u = urljoin(fuzzresult.url, i)
			if not self.blacklisted_extension(u):
			    self.queue_url(u)

