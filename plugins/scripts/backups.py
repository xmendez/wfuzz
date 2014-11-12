from framework.plugins.api import url_filename, url_filename_name, url_filename_ext
from externals.moduleman.plugin import moduleman_plugin
from framework.plugins.api import BasePlugin

from urlparse import urljoin
from posixpath import basename, dirname

@moduleman_plugin
class backups(BasePlugin):
    name = "backups"
    description = "Looks for knowb backup filenames."
    category = ["default", "active", "discovery"]
    priority = 99

    def __init__(self):
	self.extensions = [('', '.bak'), ('', '.tgz'), ('', '.zip'), ('', '.tar.gz'), ('', '~'), ('', '.rar'), ('', '.old'), ('.', '.swp')]

    def validate(self, fuzzresult):
	return fuzzresult.code != 404 and (url_filename_ext(fuzzresult.url) not in self.extensions)

    def process(self, fuzzresult):
	#>>> urlparse.urlparse("http://www.localhost.com/kk/index.html?id=1")
	#ParseResult(scheme='http', netloc='www.localhost.com', path='/kk/index.html', params='', query='id=1', fragment='')

	for pre, extension in self.extensions:
	    # http://localhost/dir/test.html -----> test.BAKKK
	    self.queue_url(urljoin(fuzzresult.url, pre + url_filename_name(url_filename(fuzzresult)) + extension))

	    # http://localhost/dir/test.html ---> test.html.BAKKK
	    self.queue_url(urljoin(fuzzresult.url, url_filename(fuzzresult) + extension))

	    # http://localhost/dir/test.html ----> dir.BAKKK
