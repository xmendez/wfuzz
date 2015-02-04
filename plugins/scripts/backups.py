from externals.moduleman.plugin import moduleman_plugin
from framework.plugins.api import BasePlugin
from framework.plugins.api import FuzzResParse

from urlparse import urljoin

@moduleman_plugin
class backups(BasePlugin):
    name = "backups"
    description = "Looks for knowb backup filenames."
    category = ["default", "active", "discovery"]
    priority = 99

    def __init__(self):
	self.extensions = [('', '.bak'), ('', '.tgz'), ('', '.zip'), ('', '.tar.gz'), ('', '~'), ('', '.rar'), ('', '.old'), ('.', '.swp')]

    def validate(self, fuzzresult):
	return fuzzresult.code != 404 and (FuzzResParse.parse_res(fuzzresult).file_extension not in self.extensions)

    def process(self, fuzzresult):
	#>>> urlparse.urlparse("http://www.localhost.com/kk/index.html?id=1")
	#ParseResult(scheme='http', netloc='www.localhost.com', path='/kk/index.html', params='', query='id=1', fragment='')

	for pre, extension in self.extensions:
	    # http://localhost/dir/test.html -----> test.BAKKK
	    self.queue_url(urljoin(fuzzresult.url, pre + FuzzResParse.parse_res(fuzzresult).file_name + extension))

	    # http://localhost/dir/test.html ---> test.html.BAKKK
	    self.queue_url(urljoin(fuzzresult.url, FuzzResParse.parse_res(fuzzresult).file_fullname + extension))

	    # http://localhost/dir/test.html ----> dir.BAKKK
