# Python 2 and 3
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

from wfuzz.plugin_api.urlutils import check_content_type

from wfuzz.plugin_api.mixins import DiscoveryPluginMixin
from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin

# Entries format based on:
# http://docstore.mik.ua/orelly/other/cvs/cvs-CHP-6-SECT-9.htm
# Good example at http://webscantest.com/CVS/Entries


@moduleman_plugin
class cvs_extractor(BasePlugin, DiscoveryPluginMixin):
    name = "cvs_extractor"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Parses CVS/Entries file."
    description = ("Parses CVS/Entries file and enqueues found entries",)
    category = ["default", "active", "discovery"]
    priority = 99
    parameters = ()

    def __init__(self):
        BasePlugin.__init__(self)

    def validate(self, fuzzresult):
        return (
            fuzzresult.url.find("CVS/Entries") >= 0
            and fuzzresult.code == 200
            and check_content_type(fuzzresult, "text")
        )

    def process(self, fuzzresult):
        base_url = urljoin(fuzzresult.url, "..")

        for line in fuzzresult.history.content.splitlines():
            record = line.split("/")
            if len(record) == 6 and record[1]:
                self.queue_url(urljoin(base_url, record[1]))

                # Directory
                if record[0] == "D":
                    self.queue_url(urljoin(base_url, record[1]))
                    self.queue_url(urljoin(base_url, "%s/CVS/Entries" % (record[1])))
