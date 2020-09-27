from .plugin_api.urlutils import parse_url
from .exception import FuzzExceptBadInstall

# python 2 and 3
import sys

if sys.version_info >= (3, 0):
    from urllib.parse import urljoin, urlparse
else:
    from urlparse import urljoin, urlparse


class FuzzRequestSoupMixing(object):
    def get_soup(self):
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            raise FuzzExceptBadInstall("You need to install beautifulsoup4 first!")

        soup = BeautifulSoup(self.content, "html.parser")

        return soup


class FuzzRequestUrlMixing(object):
    # urlparse functions
    @property
    def urlparse(self):
        return parse_url(self.url)

    @property
    def urlp(self):
        return parse_url(self.url)

    @property
    def pstrip(self):
        return self.to_cache_key()

    @property
    def is_path(self):
        if self.recursive_url and self.recursive_url[-1] == "/":
            return True

        return False

    @property
    def recursive_url(self):
        if self.code >= 300 and self.code < 308 and "Location" in self.headers.response:
            location_url = self.headers.response["Location"]
            location_parsed_url = urlparse(location_url)

            if not location_parsed_url.scheme and not location_parsed_url.netloc:
                return urljoin(self.url, location_url)
        elif self.code in [200, 401] and self.url[-1] == "/":
            return self.url

        return None
