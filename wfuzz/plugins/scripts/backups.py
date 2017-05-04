from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePlugin

from urlparse import urljoin

@moduleman_plugin
class backups(BasePlugin):
    name = "backups"
    summary = "Looks for knowb backup filenames."
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    category = ["default", "active", "discovery"]
    priority = 99

    def __init__(self):
	self.extensions = [('', '.bak'), ('', '.tgz'), ('', '.zip'), ('', '.tar.gz'), ('', '~'), ('', '.rar'), ('', '.old'), ('.', '.swp')]

    def validate(self, fuzzresult):
	return fuzzresult.code != 404 and (fuzzresult.history.urlparse.fext not in self.extensions)

    def process(self, fuzzresult):
	#>>> urlparse.urlparse("http://www.localhost.com/kk/index.html?id=1")
	#ParseResult(scheme='http', netloc='www.localhost.com', path='/kk/index.html', params='', query='id=1', fragment='')

	for pre, extension in self.extensions:
	    # http://localhost/dir/test.html -----> test.BAKKK
	    self.queue_url(urljoin(fuzzresult.url, pre + fuzzresult.history.urlparse.fname + extension))

	    # http://localhost/dir/test.html ---> test.html.BAKKK
	    self.queue_url(urljoin(fuzzresult.url, fuzzresult.history.urlparse.ffname + extension))

	    # http://localhost/dir/test.html ----> dir.BAKKK
