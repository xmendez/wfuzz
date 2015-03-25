import os
import urlparse

class FuzzResParse(urlparse.ParseResult):
    @property
    def domain(self):
	'''
	Returns domain from an URL. ie. http://www.localhost.com/kk/index.html?id=3
	will return localhost.com
	'''
	return '.'.join(self.netloc.split(":")[0].split(".")[-2:])

    @property
    def file_fullname(self):
	'''
	Returns script plus extension from an URL. ie. http://www.localhost.com/kk/index.html?id=3
	will return index.html
	'''
	u = self.path.split('/')[-1:][0]

	return u

    @property
    def file_extension(self):
	'''
	Returns script extension from an URL. ie. http://www.localhost.com/kk/index.html?id=3
	will return .html
	'''
	return os.path.splitext(self.file_fullname)[1]

    @property
    def file_name(self):
	'''
	Returns script name from an URL. ie. http://www.localhost.com/kk/index.html?id=3
	will return index
	'''
	return os.path.splitext(self.file_fullname)[0]


def parse_url(url):
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
    return FuzzResParse(scheme, netloc, path, params, query, fragment)

def parse_res(fuzzres):
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(fuzzres.url)
    return FuzzResParse(scheme, netloc, path, params, query, fragment)


def check_content_type(fuzzresult, which):
    ctype = None
    if fuzzresult.history.fr_headers()['response'].has_key('Content-Type'):
	ctype = fuzzresult.history.fr_headers()['response']['Content-Type']

    if which == 'text':
	return not ctype or (ctype and any(map(lambda x: ctype.find(x) >= 0, ['text/plain'])))
    else:
	raise FuzzException(FuzzException.FATAL, "Unknown content type")
