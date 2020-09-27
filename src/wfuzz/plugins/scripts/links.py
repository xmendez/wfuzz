import re

# Python 2 and 3
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

from wfuzz.plugin_api.mixins import DiscoveryPluginMixin
from wfuzz.plugin_api.base import BasePlugin
from wfuzz.plugin_api.urlutils import parse_url
from wfuzz.externals.moduleman.plugin import moduleman_plugin


@moduleman_plugin
class links(BasePlugin, DiscoveryPluginMixin):
    name = "links"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Parses HTML looking for new content."
    description = ("Parses HTML looking for new content",)
    category = ["active", "discovery"]
    priority = 99

    parameters = (
        ("add_path", False, False, "Add parsed paths as results."),
        ("regex", None, False, "Regex of accepted domains."),
    )

    def __init__(self):
        BasePlugin.__init__(self)

        regex = [
            r'href="((?!mailto:|tel:|#|javascript:).*?)"',
            r'src="((?!javascript:).*?)"',
            r'action="((?!javascript:).*?)"',
            # http://en.wikipedia.org/wiki/Meta_refresh
            r'<meta.*content="\d+;url=(.*?)">',
            r'getJSON\("(.*?)"',
        ]

        self.regex = []
        for i in regex:
            self.regex.append(re.compile(i, re.MULTILINE | re.DOTALL))

        self.add_path = self.kbase["links.add_path"]

        self.domain_regex = None
        if self.kbase["links.regex"][0]:
            self.domain_regex = re.compile(
                self.kbase["links.regex"][0], re.MULTILINE | re.DOTALL
            )

    def validate(self, fuzzresult):
        return fuzzresult.code in [200]

    def process(self, fuzzresult):
        list_links = set()
        # <a href="www.owasp.org/index.php/OWASP_EU_Summit_2008">O
        # ParseResult(scheme='', netloc='', path='www.owasp.org/index.php/OWASP_EU_Summit_2008', params='', query='', fragment='')

        for regex in self.regex:
            for link_url in regex.findall(fuzzresult.history.content):
                if not link_url:
                    continue

                parsed_link = parse_url(link_url)

                if (
                    not parsed_link.scheme
                    or parsed_link.scheme == "http"
                    or parsed_link.scheme == "https"
                ) and self.from_domain(fuzzresult, parsed_link):
                    cache_key = parsed_link.cache_key(self.base_fuzz_res.history.urlp)
                    if cache_key not in list_links:
                        list_links.add(cache_key)
                        self.enqueue_link(fuzzresult, link_url, parsed_link)

    def enqueue_link(self, fuzzresult, link_url, parsed_link):
        # dir path
        if self.add_path:
            split_path = parsed_link.path.split("/")
            newpath = "/".join(split_path[:-1]) + "/"
            self.queue_url(urljoin(fuzzresult.url, newpath))

        # file path
        self.queue_url(urljoin(fuzzresult.url, link_url))

    def from_domain(self, fuzzresult, parsed_link):
        # relative path
        if not parsed_link.netloc and parsed_link.path:
            return True

        # same domain
        if parsed_link.netloc == self.base_fuzz_res.history.urlp.netloc:
            return True

        # regex domain
        if (
            self.domain_regex
            and self.domain_regex.search(parsed_link.netloc) is not None
        ):
            return True

        if (
            parsed_link.netloc
            and parsed_link.netloc not in self.kbase["links.new_domains"]
        ):
            self.kbase["links.new_domains"].append(parsed_link.netloc)
            self.add_result(
                "New domain found, link not enqueued %s" % parsed_link.netloc
            )
