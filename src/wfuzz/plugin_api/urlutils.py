import os


# Python 2 and 3
import sys
if sys.version_info >= (3, 0):
    from urllib.parse import ParseResult
    from urllib.parse import urlparse
else:
    from urlparse import ParseResult
    from urlparse import urlparse

from wfuzz.facade import Facade
from wfuzz.exception import FuzzExceptBadAPI


class FuzzRequestParse(ParseResult):
    @property
    def ffname(self):
        '''
        Returns script plus extension from an URL. ie. http://www.localhost.com/kk/index.html?id=3
        will return index.html
        '''
        u = self.path.split('/')[-1:][0]

        return u

    @property
    def fext(self):
        '''
        Returns script extension from an URL. ie. http://www.localhost.com/kk/index.html?id=3
        will return .html
        '''
        return os.path.splitext(self.ffname)[1]

    @property
    def fname(self):
        '''
        Returns script name from an URL. ie. http://www.localhost.com/kk/index.html?id=3
        will return index
        '''
        return os.path.splitext(self.ffname)[0]

    @property
    def isbllist(self):
        fext = self.fext
        return fext != "." and fext in Facade().sett.get("kbase", "discovery.blacklist").split("-")

    @property
    def hasquery(self):
        return self.query != ""


def parse_url(url):
    scheme, netloc, path, params, query, fragment = urlparse(url)
    return FuzzRequestParse(scheme, netloc, path, params, query, fragment)


def check_content_type(fuzzresult, which):
    ctype = None
    if 'Content-Type' in fuzzresult.history.headers.response:
        ctype = fuzzresult.history.headers.response['Content-Type']

    if which == 'text':
        return not ctype or (ctype and any([ctype.find(x) >= 0 for x in ['text/plain']]))
    else:
        raise FuzzExceptBadAPI("Unknown content type")
