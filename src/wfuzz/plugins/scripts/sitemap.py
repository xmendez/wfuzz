from wfuzz.plugin_api.mixins import DiscoveryPluginMixin
from wfuzz.plugin_api.base import BasePlugin
from wfuzz.plugin_api.urlutils import parse_url
from wfuzz.exception import FuzzExceptResourceParseError
from wfuzz.externals.moduleman.plugin import moduleman_plugin

import xml.dom.minidom
import urlparse

@moduleman_plugin
class sitemap(BasePlugin, DiscoveryPluginMixin):
    name = "sitemap"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Parses sitemap.xml file"
    description = ("Parses sitemap.xml file",)
    category = ["default", "active", "discovery"]
    priority = 99

    parameters = (
    )

    def __init__(self):
        BasePlugin.__init__(self)

    def validate(self, fuzzresult):
	return fuzzresult.history.urlparse.ffname == "sitemap.xml" and fuzzresult.code == 200

    def process(self, fuzzresult):
	base_url = fuzzresult.url

	try:
	    dom = xml.dom.minidom.parseString(fuzzresult.history.content)
	except:
	    raise FuzzExceptResourceParseError('Error while parsing %s.' % fuzzresult.url)

	urlList = dom.getElementsByTagName("loc")
	for url in urlList:
	    u = url.childNodes[0].data

            self.queue_url(u)

