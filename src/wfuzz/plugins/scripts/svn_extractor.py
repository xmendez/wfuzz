# Python 2 and 3
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

from wfuzz.plugin_api.mixins import DiscoveryPluginMixin
from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin


@moduleman_plugin
class svn_extractor(BasePlugin, DiscoveryPluginMixin):
    name = "svn_extractor"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Parses .svn/entries file."
    description = ("Parses CVS/Entries file and enqueues found entries",)
    category = ["default", "active", "discovery"]
    priority = 99

    parameters = ()

    def __init__(self):
        BasePlugin.__init__(self)

    def validate(self, fuzzresult):
        return fuzzresult.url.find(".svn/entries") > 0 and fuzzresult.code == 200

    def readsvn(self, content):
        """
        Function shamesly copied (and adapted) from https://github.com/anantshri/svn-extractor/
        Credit (C) Anant Shrivastava http://anantshri.info
        """
        old_line = ""
        file_list = []
        dir_list = []
        author_list = []

        for a in content.splitlines():
            # below functionality will find all usernames from svn entries file
            if a == "has-props":
                if old_line not in author_list:
                    author_list.append(old_line)
            if a == "file":
                if old_line not in file_list:
                    file_list.append(old_line)
            if a == "dir":
                if old_line != "":
                    dir_list.append(old_line)
            old_line = a
        return file_list, dir_list, author_list

    def process(self, fuzzresult):
        base_url = fuzzresult.url

        file_list, dir_list, author_list = self.readsvn(fuzzresult.history.content)

        if author_list:
            self.add_result("SVN authors: %s" % ", ".join(author_list))

        for f in file_list:
            u = urljoin(base_url.replace("/.svn/", "/"), f)
            self.queue_url(u)

        for d in dir_list:
            self.queue_url(
                urljoin(base_url.replace("/.svn/", "/"), d) + "/.svn/entries"
            )
