import sys

# Python 2 and 3
if sys.version_info >= (3, 0):
    from urllib.parse import urljoin
else:
    from urlparse import urljoin

from wfuzz.plugin_api.mixins import DiscoveryPluginMixin
from wfuzz.plugin_api.base import BasePlugin
from wfuzz.plugin_api.urlutils import check_content_type
from wfuzz.externals.moduleman.plugin import moduleman_plugin


@moduleman_plugin
class robots(BasePlugin, DiscoveryPluginMixin):
    name = "robots"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Parses robots.txt looking for new content."
    description = ("Parses robots.txt looking for new content.",)
    category = ["default", "active", "discovery"]
    priority = 99

    parameters = ()

    def __init__(self):
        BasePlugin.__init__(self)

    def validate(self, fuzzresult):
        return (
            fuzzresult.history.urlparse.ffname == "robots.txt"
            and fuzzresult.code == 200
            and check_content_type(fuzzresult, "text")
        )

    def process(self, fuzzresult):
        # Shamelessly (partially) copied from w3af's plugins/discovery/robotsReader.py
        for line in fuzzresult.history.content.split("\n"):
            line = line.strip()

            if (
                len(line) > 0
                and line[0] != "#"
                and (
                    line.upper().find("ALLOW") == 0
                    or line.upper().find("DISALLOW") == 0
                    or line.upper().find("SITEMAP") == 0
                )
            ):

                url = line[line.find(":") + 1 :]
                url = url.strip(" *")

                if url:
                    self.queue_url(urljoin(fuzzresult.url, url))
