from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePlugin

# Python 2 and 3
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin


@moduleman_plugin
class backups(BasePlugin):
    name = "backups"
    summary = "Looks for known backup filenames."
    description = ("Looks for known backup filenames.",)
    "For example, given http://localhost.com/dir/index.html, it will perform the following requests",
    "* http://localhost/dir/index.EXTENSIONS",
    "* http://localhost/dir/index.html.EXTENSIONS",
    "* http://localhost/dir.EXTENSIONS",
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    category = ["re-enqueue", "active", "discovery"]
    priority = 99

    parameters = (
        (
            "ext",
            ".bak,.tgz,.zip,.tar.gz,~,.rar,.old,.-.swp",
            False,
            "Extensions to look for.",
        ),
    )

    def __init__(self):
        BasePlugin.__init__(self)
        self.extensions = self.kbase["backups.ext"][0].split(",")

    def validate(self, fuzzresult):
        return fuzzresult.code != 404 and (
            fuzzresult.history.urlparse.fext not in self.extensions
        )

    def process(self, fuzzresult):
        # >>> urlparse.urlparse("http://www.localhost.com/kk/index.html?id=1")
        # ParseResult(scheme='http', netloc='www.localhost.com', path='/kk/index.html', params='', query='id=1', fragment='')

        for pre_extension in self.extensions:
            pre, nothing, extension = pre_extension.partition("-")

            # http://localhost/dir/test.html -----> test.BAKKK
            self.queue_url(
                urljoin(
                    fuzzresult.url, pre + fuzzresult.history.urlparse.fname + extension
                )
            )

            # http://localhost/dir/test.html ---> test.html.BAKKK
            self.queue_url(
                urljoin(fuzzresult.url, fuzzresult.history.urlparse.ffname + extension)
            )

            # http://localhost/dir/test.html ----> dir.BAKKK
