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


KBASE_PARAM_PATH = "links.add_path"
KBASE_PARAM_ENQUEUE = "links.enqueue"
KBASE_PARAM_DOMAIN_REGEX = "links.domain"
KBASE_PARAM_REGEX = "links.regex"
KBASE_NEW_DOMAIN = "links.new_domains"


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
        ("enqueue", "True", False, "If True, enqueue found links.",),
        (
            "add_path",
            "False",
            False,
            "if True, re-enqueue found paths. ie. /path/link.html link enqueues also /path/",
        ),
        (
            "domain",
            None,
            False,
            "Regex of accepted domains tested against url.netloc. This is useful for restricting crawling certain domains.",
        ),
        (
            "regex",
            None,
            False,
            "Regex of accepted links tested against the full url. If domain is not set and regex is, domain defaults to .*. This is useful for restricting crawling certain file types.",
        ),
    )

    def __init__(self):
        BasePlugin.__init__(self)

        regex = [
            r'\b(?:(?<!data-)href)="((?!mailto:|tel:|#|javascript:).*?)"',
            r'\bsrc="((?!javascript:).*?)"',
            r'\baction="((?!javascript:).*?)"',
            r'<meta.*content="\d+;url=(.*?)">',  # http://en.wikipedia.org/wiki/Meta_refresh
            r'getJSON\("(.*?)"',
            r"[^/][`'\"]([\/][a-zA-Z0-9_.-]+)+(?!(?:[,;\s]))",  # based on https://github.com/nahamsec/JSParser/blob/master/handler.py#L93
        ]

        self.regex = []
        for regex_str in regex:
            self.regex.append(re.compile(regex_str, re.MULTILINE | re.DOTALL))

        self.regex_header = [
            ("Link", re.compile(r"<(.*)>;")),
            ("Location", re.compile(r"(.*)")),
        ]

        self.add_path = self._bool(self.kbase[KBASE_PARAM_PATH][0])
        self.enqueue_links = self._bool(self.kbase[KBASE_PARAM_ENQUEUE][0])

        self.domain_regex = None
        if self.kbase[KBASE_PARAM_DOMAIN_REGEX][0]:
            self.domain_regex = re.compile(
                self.kbase[KBASE_PARAM_DOMAIN_REGEX][0], re.IGNORECASE
            )

        self.regex_param = None
        if self.kbase[KBASE_PARAM_REGEX][0]:
            self.regex_param = re.compile(
                self.kbase[KBASE_PARAM_REGEX][0], re.IGNORECASE
            )

        if self.regex_param and self.domain_regex is None:
            self.domain_regex = re.compile(".*", re.IGNORECASE)

        self.list_links = set()

    def validate(self, fuzzresult):
        self.list_links = set()
        return fuzzresult.code in [200, 301, 302, 303, 307, 308]

    def process(self, fuzzresult):
        # <a href="www.owasp.org/index.php/OWASP_EU_Summit_2008">O
        # ParseResult(scheme='', netloc='', path='www.owasp.org/index.php/OWASP_EU_Summit_2008', params='', query='', fragment='')

        for header, regex in self.regex_header:
            if header in fuzzresult.history.headers.response:
                for link_url in regex.findall(
                    fuzzresult.history.headers.response[header]
                ):
                    if link_url:
                        self.process_link(fuzzresult, link_url)

        for regex in self.regex:
            for link_url in regex.findall(fuzzresult.history.content):
                if link_url:
                    self.process_link(fuzzresult, link_url)

    def process_link(self, fuzzresult, link_url):
        parsed_link = parse_url(link_url)

        if (
            not parsed_link.scheme
            or parsed_link.scheme == "http"
            or parsed_link.scheme == "https"
        ) and self.from_domain(fuzzresult, parsed_link):
            cache_key = parsed_link.cache_key(self.base_fuzz_res.history.urlp)
            if cache_key not in self.list_links:
                self.list_links.add(cache_key)
                self.enqueue_link(fuzzresult, link_url, parsed_link)

    def enqueue_link(self, fuzzresult, link_url, parsed_link):
        # dir path
        if self.add_path:
            split_path = parsed_link.path.split("/")
            newpath = "/".join(split_path[:-1]) + "/"
            self.queue_url(urljoin(fuzzresult.url, newpath))

        # file path
        new_link = urljoin(fuzzresult.url, link_url)

        if not self.regex_param or (
            self.regex_param and self.regex_param.search(new_link) is not None
        ):
            if self.enqueue_links:
                self.queue_url(new_link)
            self.add_result("link", "New link found", new_link)

    def from_domain(self, fuzzresult, parsed_link):
        # relative path
        if not parsed_link.netloc and parsed_link.path:
            return True

        # regex domain
        if (
            self.domain_regex
            and self.domain_regex.search(parsed_link.netloc) is not None
        ):
            return True

        # same domain
        if parsed_link.netloc == self.base_fuzz_res.history.urlp.netloc:
            return True

        if (
            parsed_link.netloc
            and parsed_link.netloc not in self.kbase[KBASE_NEW_DOMAIN]
        ):
            self.kbase[KBASE_NEW_DOMAIN].append(parsed_link.netloc)
            self.add_result(
                "domain", "New domain found (link not enqueued)", parsed_link.netloc
            )
