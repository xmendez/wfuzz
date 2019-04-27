from .plugin_api.urlutils import parse_url
from .exception import FuzzExceptBadInstall

# python 2 and 3
import sys
if sys.version_info >= (3, 0):
    from urllib.parse import urljoin
else:
    from urlparse import urljoin


class FuzzRequestSoupMixing(object):
    def get_soup(self):
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            raise FuzzExceptBadInstall("You need to install beautifulsoup4 first!")

        soup = BeautifulSoup(self.content, 'html.parser')

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
        if self.code == 200 and self.url[-1] == '/':
            return True
        elif self.code >= 300 and self.code < 400:
            if "Location" in self.headers.response and self.headers.response["Location"][-1] == '/':
                return True
        elif self.code == 401:
            if self.url[-1] == '/':
                return True

        return False

    @property
    def recursive_url(self):
        if self.code >= 300 and self.code < 400 and "Location" in self.headers.response:
            new_url = self.headers.response["Location"]
            if not new_url[-1] == '/':
                new_url += "/"
            # taking into consideration redirections to /xxx/ without full URL
            new_url = urljoin(self.url, new_url)
        elif self.code == 401 or self.code == 200:
            new_url = self.url
            if not self.url[-1] == '/':
                new_url = "/"
        else:
            raise Exception("Error generating recursive url")

        return new_url + "FUZZ"
