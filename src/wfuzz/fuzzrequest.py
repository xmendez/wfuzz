import pycurl

# Python 2 and 3
import sys

if sys.version_info >= (3, 0):
    from urllib.parse import urlparse
else:
    from urlparse import urlparse

from collections import namedtuple

from .externals.reqresp import Request, Response
from .exception import FuzzExceptBadAPI, FuzzExceptBadOptions
from .facade import Facade
from .mixins import FuzzRequestUrlMixing, FuzzRequestSoupMixing

from .helpers.str_func import python2_3_convert_from_unicode
from .helpers.obj_dic import DotDict


class headers(object):
    class header(DotDict):
        def __str__(self):
            return "\n".join(["{}: {}".format(k, v) for k, v in self.items()])

    def __init__(self, req):
        self._req = req

    @property
    def response(self):
        return (
            headers.header(self._req.response.getHeaders())
            if self._req.response
            else headers.header()
        )

    @property
    def request(self):
        return headers.header(self._req._headers)

    @request.setter
    def request(self, values_dict):
        self._req._headers.update(values_dict)
        if "Content-Type" in values_dict:
            self._req.ContentType = values_dict["Content-Type"]

    @property
    def all(self):
        return headers.header(self.request + self.response)


class cookies(object):
    class cookie(DotDict):
        def __str__(self):
            return "\n".join(["{}={}".format(k, v) for k, v in self.items()])

    def __init__(self, req):
        self._req = req

    @property
    def response(self):
        if self._req.response:
            c = self._req.response.getCookie().split("; ")
            if c[0]:
                return cookies.cookie(
                    {x[0]: x[2] for x in [x.partition("=") for x in c]}
                )

        return cookies.cookie({})

    @property
    def request(self):
        if "Cookie" in self._req._headers:
            c = self._req._headers["Cookie"].split("; ")
            if c[0]:
                return cookies.cookie(
                    {x[0]: x[2] for x in [x.partition("=") for x in c]}
                )

        return cookies.cookie({})

    @request.setter
    def request(self, values):
        self._req._headers["Cookie"] = "; ".join(values)

    @property
    def all(self):
        return cookies.cookie(self.request + self.response)


class params(object):
    class param(DotDict):
        def __str__(self):
            return "\n".join(["{}={}".format(k, v) for k, v in self.items()])

    def __init__(self, req):
        self._req = req

    @property
    def get(self):
        return params.param({x.name: x.value for x in self._req.getGETVars()})

    @get.setter
    def get(self, values):
        if isinstance(values, dict) or isinstance(values, DotDict):
            for key, value in values.items():
                self._req.setVariableGET(key, str(value))
        else:
            raise FuzzExceptBadAPI("GET Parameters must be specified as a dictionary")

    @property
    def post(self):
        return params.param({x.name: x.value for x in self._req.getPOSTVars()})

    @post.setter
    def post(self, pp):
        if isinstance(pp, dict) or isinstance(pp, DotDict):
            for key, value in pp.items():
                self._req.setVariablePOST(
                    key, str(value) if value is not None else value
                )

            self._req._non_parsed_post = self._req._variablesPOST.urlEncoded()

        elif isinstance(pp, str):
            self._req.setPostData(pp)

    @property
    def raw_post(self):
        return self._req._non_parsed_post

    @property
    def all(self):
        return params.param(self.get + self.post)

    @all.setter
    def all(self, values):
        self.get = values
        self.post = values


class FuzzRequest(FuzzRequestUrlMixing, FuzzRequestSoupMixing):
    def __init__(self):
        self._request = Request()

        self._proxy = None
        self._allvars = None
        self.wf_fuzz_methods = None
        self.wf_retries = 0
        self.wf_ip = None

        self.headers.request = {
            "User-Agent": Facade().sett.get("connection", "user-agent")
        }

    # methods for accessing HTTP requests information consistenly accross the codebase

    def __str__(self):
        return self._request.getAll()

    @property
    def raw_request(self):
        return self._request.getAll()

    @raw_request.setter
    def raw_request(self, rawReq, scheme):
        self.update_from_raw_http(rawReq, scheme)

    @property
    def raw_content(self):
        if self._request.response:
            return self._request.response.getAll()

        return ""

    @property
    def headers(self):
        return headers(self._request)

    @property
    def params(self):
        return params(self._request)

    @property
    def cookies(self):
        return cookies(self._request)

    @property
    def method(self):
        return self._request.method

    @method.setter
    def method(self, method):
        self._request.method = method

    @property
    def scheme(self):
        return self._request.schema

    @scheme.setter
    def scheme(self, s):
        self._request.schema = s

    @property
    def host(self):
        return self._request.getHost()

    @property
    def path(self):
        return self._request.path

    @property
    def redirect_url(self):
        return self._request.completeUrl

    @property
    def url(self):
        return self._request.finalUrl

    @url.setter
    def url(self, u):
        # urlparse goes wrong with IP:port without scheme (https://bugs.python.org/issue754016)
        if not u.startswith("FUZ") and (
            urlparse(u).netloc == "" or urlparse(u).scheme == ""
        ):
            u = "http://" + u

        if urlparse(u).path == "":
            u += "/"

        if Facade().sett.get("general", "encode_space") == "1":
            u = u.replace(" ", "%20")

        self._request.setUrl(u)
        if self.scheme.startswith("fuz") and self.scheme.endswith("z"):
            # avoid FUZZ to become fuzz
            self.scheme = self.scheme.upper()

    @property
    def content(self):
        return self._request.response.getContent() if self._request.response else ""

    @property
    def code(self):
        return self._request.response.code if self._request.response else 0

    @code.setter
    def code(self, c):
        self._request.response.code = int(c)

    @property
    def auth(self):
        method, creds = self._request.getAuth()

        return DotDict({"method": method, "credentials": creds})

    @auth.setter
    def auth(self, creds_dict):
        self._request.setAuth(creds_dict["method"], creds_dict["credentials"])
        method, creds = self._request.getAuth()

        return DotDict({"method": method, "credentials": creds})

    @property
    def follow(self):
        return self._request.followLocation

    @follow.setter
    def follow(self, f):
        self._request.setFollowLocation(f)

    @property
    def reqtime(self):
        return self._request.totaltime

    @reqtime.setter
    def reqtime(self, t):
        self._request.totaltime = t

    # Info extra that wfuzz needs within an HTTP request
    @property
    def wf_allvars_set(self):
        if self.wf_allvars == "allvars":
            return self.params.get
        elif self.wf_allvars == "allpost":
            return self.params.post
        elif self.wf_allvars == "allheaders":
            return self.headers.request
        else:
            raise FuzzExceptBadOptions("Unknown variable set: " + self.wf_allvars)

    @wf_allvars_set.setter
    def wf_allvars_set(self, varset):
        try:
            if self.wf_allvars == "allvars":
                self.params.get = varset
            elif self.wf_allvars == "allpost":
                self.params.post = varset
            elif self.wf_allvars == "allheaders":
                self._request.headers.request = varset
            else:
                raise FuzzExceptBadOptions("Unknown variable set: " + self.wf_allvars)
        except TypeError:
            raise FuzzExceptBadOptions(
                "It is not possible to use all fuzzing with duplicated parameters."
            )

    @property
    def wf_allvars(self):
        return self._allvars

    @wf_allvars.setter
    def wf_allvars(self, bl):
        if bl is not None and bl not in ["allvars", "allpost", "allheaders"]:
            raise FuzzExceptBadOptions(
                "Incorrect all parameters brute forcing type specified, correct values are allvars, allpost or allheaders."
            )

        self._allvars = bl

    @property
    def wf_proxy(self):
        return self._proxy

    @wf_proxy.setter
    def wf_proxy(self, proxy_tuple):
        if proxy_tuple:
            prox, ptype = proxy_tuple
            self._request.setProxy("%s" % prox, ptype if ptype else "HTML")
        self._proxy = proxy_tuple

    # methods wfuzz needs to perform HTTP requests (this might change in the future).

    def update_from_raw_http(self, raw, scheme, raw_response=None, raw_content=None):
        self._request.parseRequest(raw, scheme)

        # Parse request sets postdata = '' when there's POST request without data
        if self.method == "POST" and self.params.raw_post is None:
            self.params.post = ""

        if raw_response:
            rp = Response()
            if not isinstance(raw_response, str):
                raw_response = python2_3_convert_from_unicode(
                    raw_response.decode("utf-8", errors="surrogateescape")
                )
            rp.parseResponse(raw_response, raw_content)
            self._request.response = rp

        return self._request

    def to_cache_key(self):
        key = self._request.urlWithoutVariables

        dicc = {"g{}".format(key): True for key in self.params.get.keys()}
        dicc.update({"p{}".format(key): True for key in self.params.post.keys()})

        # take URL parameters into consideration
        url_params = list(dicc.keys())
        url_params.sort()
        key += "-" + "-".join(url_params)

        return key

    # methods wfuzz needs for substituing payloads and building dictionaries

    def update_from_options(self, options):
        if options["url"] != "FUZZ":
            self.url = options["url"]

        # headers must be parsed first as they might affect how reqresp parases other params
        self.headers.request = dict(options["headers"])

        if options["auth"].get("method") is not None:
            self.auth = options["auth"]

        if options["follow"]:
            self.follow = options["follow"]

        if options["postdata"] is not None:
            self.params.post = options["postdata"]

        if options["connect_to_ip"]:
            self.wf_ip = options["connect_to_ip"]

        if options["method"]:
            self.method = options["method"]
            self.wf_fuzz_methods = options["method"]

        if options["cookie"]:
            self.cookies.request = options["cookie"]

        if options["allvars"]:
            self.wf_allvars = options["allvars"]
