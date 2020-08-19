# Python 2 and 3
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

from wfuzz.plugin_api.mixins import DiscoveryPluginMixin
from wfuzz.plugin_api.base import BasePlugin
from wfuzz.exception import FuzzExceptResourceParseError
from wfuzz.externals.moduleman.plugin import moduleman_plugin

import tempfile
import sqlite3


@moduleman_plugin
class wcdb_extractor(BasePlugin, DiscoveryPluginMixin):
    name = "wc_extractor"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Parses subversion's wc.db file."
    description = ("Parses subversion's wc.db file.",)
    category = ["default", "active", "discovery"]
    priority = 99

    parameters = ()

    def __init__(self):
        BasePlugin.__init__(self)

    def validate(self, fuzzresult):
        return fuzzresult.url.find(".svn/wc.d") > 0 and fuzzresult.code == 200

    def readwc(self, content):
        """
        Function shamesly copied (and adapted) from https://github.com/anantshri/svn-extractor/
        Credit (C) Anant Shrivastava http://anantshri.info
        """
        author_list = []
        list_items = None
        (fd, filename) = tempfile.mkstemp()

        with open(filename, "wb") as f:
            f.write(content)

        conn = sqlite3.connect(filename)
        c = conn.cursor()
        try:
            c.execute(
                'select local_relpath, ".svn/pristine/" || substr(checksum,7,2) || "/" || substr(checksum,7) || ".svn-base" as alpha from NODES where kind="file";'
            )
            list_items = c.fetchall()
            # below functionality will find all usernames who have commited atleast once.
            c.execute("select distinct changed_author from nodes;")
            author_list = [r[0] for r in c.fetchall()]
            c.close()
        except Exception:
            raise FuzzExceptResourceParseError(
                "Error reading wc.db, either database corrupt or invalid file"
            )

        return author_list, list_items

    def process(self, fuzzresult):
        author_list, list_items = self.readwc(fuzzresult.history.content)

        if author_list:
            self.add_result("SVN authors: %s" % ", ".join(author_list))

        if list_items:
            for f, pristine in list_items:
                u = urljoin(fuzzresult.url.replace("/.svn/wc.db", "/"), f)
                if self.queue_url(u):
                    self.add_result("SVN %s source code in %s" % (f, pristine))
