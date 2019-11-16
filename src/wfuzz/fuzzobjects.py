import time
import hashlib
import re
import itertools
import operator
import pycurl

# Python 2 and 3
import sys
if sys.version_info >= (3, 0):
    from urllib.parse import urlparse
else:
    from urlparse import urlparse

from threading import Lock
from collections import namedtuple
from collections import defaultdict

from .filter import FuzzResFilter
from .externals.reqresp import Request, Response
from .exception import FuzzExceptBadAPI, FuzzExceptBadOptions, FuzzExceptInternalError, FuzzException
from .facade import Facade, ERROR_CODE
from .mixins import FuzzRequestUrlMixing, FuzzRequestSoupMixing

from .utils import python2_3_convert_to_unicode, python2_3_convert_from_unicode
from .utils import MyCounter
from .utils import rgetattr
from .utils import DotDict

auth_header = namedtuple("auth_header", "method credentials")


class headers(object):
    class header(DotDict):
        def __str__(self):
            return "\n".join(["{}: {}".format(k, v) for k, v in self.items()])

    def __init__(self, req):
        self._req = req

    @property
    def response(self):
        return headers.header(self._req.response.getHeaders()) if self._req.response else {}

    @property
    def request(self):
        return headers.header([x.split(": ", 1) for x in self._req.getHeaders()])

    @request.setter
    def request(self, values_dict):
        self._req._headers.update(values_dict)
        if "Content-Type" in values_dict:
            self._req.ContentType = values_dict['Content-Type']

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
                return cookies.cookie([[x[0], x[2]] for x in [x.partition("=") for x in c]])

        return cookies.cookie({})

    @property
    def request(self):
        if 'Cookie' in self._req._headers:
            c = self._req._headers['Cookie'].split("; ")
            if c[0]:
                return cookies.cookie([[x[0], x[2]] for x in [x.partition("=") for x in c]])

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
        return params.param([(x.name, x.value) for x in self._req.getGETVars()])

    @get.setter
    def get(self, values):
        if isinstance(values, dict):
            for key, value in values.items():
                self._req.setVariableGET(key, str(value))
        else:
            raise FuzzExceptBadAPI("GET Parameters must be specified as a dictionary")

    @property
    def post(self):
        return params.param([(x.name, x.value) for x in self._req.getPOSTVars()])

    @post.setter
    def post(self, pp):
        if isinstance(pp, dict):
            for key, value in pp.items():
                self._req.setVariablePOST(key, str(value) if value is not None else value)

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

        self.headers.request = {"User-Agent": Facade().sett.get("connection", "user-agent")}

    # methods for accessing HTTP requests information consistenly accross the codebase

    def __str__(self):
        return self._request.getAll()

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
        if not u.startswith("FUZ") and (urlparse(u).netloc == "" or urlparse(u).scheme == ""):
            u = "http://" + u

        if urlparse(u).path == "":
            u += '/'

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
        m, up = self._request.getAuth()
        return auth_header(m, up)

    @auth.setter
    def auth(self, ah):
        method, credentials = ah
        self._request.setAuth(method, credentials)

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
            raise FuzzExceptBadOptions("It is not possible to use all fuzzing with duplicated parameters.")

    @property
    def wf_allvars(self):
        return self._allvars

    @wf_allvars.setter
    def wf_allvars(self, bl):
        if bl is not None and bl not in ['allvars', 'allpost', 'allheaders']:
            raise FuzzExceptBadOptions("Incorrect all parameters brute forcing type specified, correct values are allvars, allpost or allheaders.")

        self._allvars = bl

    @property
    def wf_proxy(self):
        return self._proxy

    @wf_proxy.setter
    def wf_proxy(self, l):
        if l:
            prox, ptype = l
            self._request.setProxy("%s" % prox, ptype if ptype else "HTML")
        self._proxy = l

    # methods wfuzz needs to perform HTTP requests (this might change in the future).

    def perform(self):
        res = FuzzResult(self, track_id=False)
        return Facade().http_pool.perform(res)

    def to_http_object(self, c):
        pycurl_c = Request.to_pycurl_object(c, self._request)

        if self.wf_ip:
            pycurl_c.setopt(pycurl.CONNECT_TO, ["::{}:{}".format(self.wf_ip['ip'], self.wf_ip['port'])])

        return pycurl_c

    def from_http_object(self, c, bh, bb):
        raw_header = python2_3_convert_from_unicode(bh.decode("utf-8", errors='surrogateescape'))
        return self._request.response_from_conn_object(c, raw_header, bb)

    def update_from_raw_http(self, raw, scheme, raw_response=None, raw_content=None):
        self._request.parseRequest(raw, scheme)

        # Parse request sets postdata = '' when there's POST request without data
        if self.method == "POST" and self.params.raw_post is None:
            self.params.post = ''

        if raw_response:
            rp = Response()
            if not isinstance(raw_response, str):
                raw_response = python2_3_convert_from_unicode(raw_response.decode("utf-8", errors='surrogateescape'))
            rp.parseResponse(raw_response, raw_content)
            self._request.response = rp

        return self._request

    def to_cache_key(self):
        key = self._request.urlWithoutVariables

        dicc = {'g{}'.format(key): True for key in self.params.get.keys()}
        dicc.update({'p{}'.format(key): True for key in self.params.post.keys()})

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
        self.headers.request = dict(options['headers'])

        if options['auth'][0] is not None:
            self.auth = (options['auth'][0], options['auth'][1])

        if options['follow']:
            self.follow = options['follow']

        if options['postdata'] is not None:
            self.params.post = options['postdata']

        if options['connect_to_ip']:
            self.wf_ip = options['connect_to_ip']

        if options['method']:
            self.method = options['method']
            self.wf_fuzz_methods = options['method']

        if options['cookie']:
            self.cookies.request = options['cookie']

        if options['allvars']:
            self.wf_allvars = options['allvars']

    def from_copy(self):
        newreq = FuzzRequest()

        newreq.wf_proxy = self.wf_proxy
        newreq.wf_allvars = self.wf_allvars
        newreq.wf_fuzz_methods = self.wf_fuzz_methods
        newreq.wf_ip = self.wf_ip

        newreq.headers.request = self.headers.request
        newreq.params.post = self.params.raw_post

        newreq.follow = self.follow
        newreq.auth = self.auth
        newreq.url = self.url
        newreq.reqtime = self.reqtime
        newreq.scheme = self.scheme
        newreq.method = self.wf_fuzz_methods if self.wf_fuzz_methods else self.method

        return newreq


class FuzzResultFactory:
    @staticmethod
    def replace_fuzz_word(text, fuzz_word, payload):
        marker_regex = re.compile(r"(%s)(?:\[(.*?)\])?" % (fuzz_word,), re.MULTILINE | re.DOTALL)

        for fuzz_word, field in marker_regex.findall(text):
            if field:
                marker_regex = re.compile(r"(%s)(?:\[(.*?)\])?" % (fuzz_word,), re.MULTILINE | re.DOTALL)
                fields_array = []

                for fuzz_word, field in marker_regex.findall(text):
                    if not field:
                        raise FuzzExceptBadOptions("You must specify a field when using a payload containing a full fuzz request, ie. FUZZ[url], or use FUZZ only to repeat the same request.")

                    try:
                        subs = str(rgetattr(payload, field))
                    except AttributeError:
                        raise FuzzExceptBadOptions("A FUZZ[field] expression must be used with a fuzzresult payload not a string.")

                    text = text.replace("%s[%s]" % (fuzz_word, field), subs)
                    fields_array.append(field)

                return (text, fields_array)
            else:
                try:
                    return (text.replace(fuzz_word, payload), [None])
                except TypeError:
                    raise FuzzExceptBadOptions("Tried to replace {} with a whole fuzzresult payload.".format(fuzz_word))

    @staticmethod
    def from_seed(seed, payload, seed_options):
        newres = seed.from_soft_copy()

        rawReq = str(newres.history)
        rawUrl = newres.history.redirect_url
        scheme = newres.history.scheme
        auth_method, userpass = newres.history.auth

        for payload_pos, payload_content in enumerate(payload, start=1):
            fuzz_word = "FUZ" + str(payload_pos) + "Z" if payload_pos > 1 else "FUZZ"

            fuzz_values_array = []

            # substitute entire seed when using a request payload generator without specifying field
            if fuzz_word == "FUZZ" and seed_options["seed_payload"] and isinstance(payload_content, FuzzResult):
                # new seed
                newres = payload_content.from_soft_copy()
                newres.payload = []

                fuzz_values_array.append(None)

                newres.history.update_from_options(seed_options)
                newres.update_from_options(seed_options)
                rawReq = str(newres.history)
                rawUrl = newres.history.redirect_url
                scheme = newres.history.scheme
                auth_method, userpass = newres.history.auth

            desc = []

            if auth_method and (userpass.count(fuzz_word)):
                userpass, desc = FuzzResultFactory.replace_fuzz_word(userpass, fuzz_word, payload_content)
            if newres.history.redirect_url.count(fuzz_word):
                rawUrl, desc = FuzzResultFactory.replace_fuzz_word(rawUrl, fuzz_word, payload_content)
            if rawReq.count(fuzz_word):
                rawReq, desc = FuzzResultFactory.replace_fuzz_word(rawReq, fuzz_word, payload_content)

            if scheme.count(fuzz_word):
                scheme, desc = FuzzResultFactory.replace_fuzz_word(scheme, fuzz_word, payload_content)

            if desc:
                fuzz_values_array += desc

            newres.payload.append(FuzzPayload(payload_content, fuzz_values_array))

        newres.history.update_from_raw_http(rawReq, scheme)
        newres.history.url = rawUrl
        if auth_method != 'None':
            newres.history.auth = (auth_method, userpass)

        newres.type = FuzzResult.result

        return newres

    @staticmethod
    def from_baseline(fuzzresult, options):
        scheme = fuzzresult.history.scheme
        rawReq = str(fuzzresult.history)
        auth_method, userpass = fuzzresult.history.auth

        # get the baseline payload ordered by fuzz number and only one value per same fuzz keyword.
        b1 = dict([matchgroup.groups() for matchgroup in re.finditer(r"FUZ(\d*)Z(?:\[.*?\])?(?:{(.*?)})?", rawReq, re.MULTILINE | re.DOTALL)])
        b2 = dict([matchgroup.groups() for matchgroup in re.finditer(r"FUZ(\d*)Z(?:\[.*?\])?(?:{(.*?)})?", userpass, re.MULTILINE | re.DOTALL)])
        baseline_control = dict(list(b1.items()) + list(b2.items()))
        baseline_payload = [x[1] for x in sorted(list(baseline_control.items()), key=operator.itemgetter(0))]

        # if there is no marker, there is no baseline request
        if not [x for x in baseline_payload if x is not None]:
            return None

        # remove baseline marker from seed request
        for i in baseline_payload:
            if not i:
                raise FuzzExceptBadOptions("You must supply a baseline value for all the FUZZ words.")
            rawReq = rawReq.replace("{" + i + "}", '')

            if fuzzresult.history.wf_fuzz_methods:
                fuzzresult.history.wf_fuzz_methods = fuzzresult.history.wf_fuzz_methods.replace("{" + i + "}", '')

            if auth_method:
                userpass = userpass.replace("{" + i + "}", '')

        # re-parse seed without baseline markers
        fuzzresult.history.update_from_raw_http(rawReq, scheme)
        if auth_method:
            fuzzresult.history.auth = (auth_method, userpass)

        # create baseline request from seed
        baseline_res = fuzzresult.from_soft_copy()

        # remove field markers from baseline
        marker_regex = re.compile(r"(FUZ\d*Z)\[(.*?)\]", re.DOTALL)
        results = marker_regex.findall(rawReq)
        if results:
            for fw, f in results:
                rawReq = rawReq.replace("%s[%s]" % (fw, f), fw)

                if fuzzresult.history.wf_fuzz_methods:
                    fuzzresult.history.wf_fuzz_methods = fuzzresult.history.wf_fuzz_methods.replace("{" + i + "}", '')

                if auth_method:
                    userpass = userpass.replace("{" + i + "}", '')

            baseline_res.history.update_from_raw_http(rawReq, scheme)

        baseline_res = FuzzResultFactory.from_seed(baseline_res, baseline_payload, options)
        baseline_res.is_baseline = True

        return baseline_res

    @staticmethod
    def from_all_fuzz_request(seed, payload):
        # only a fuzz payload is allowed using this technique
        if len(payload) > 1:
            raise FuzzExceptBadOptions("Only one payload is allowed when fuzzing all parameters!")

        for var_name in seed.history.wf_allvars_set.keys():
            payload_content = payload[0]
            fuzzres = seed.from_soft_copy()
            fuzzres.payload.append(FuzzPayload(payload_content, [None]))

            fuzzres.history.wf_allvars_set = {var_name: payload_content}

            yield fuzzres

    @staticmethod
    def from_options(options):
        fr = FuzzRequest()

        fr.url = options['url']
        fr.wf_fuzz_methods = options['method']
        fr.update_from_options(options)

        fuzz_res = FuzzResult(fr)
        fuzz_res.update_from_options(options)

        return fuzz_res


class FuzzStats:
    def __init__(self):
        self.mutex = Lock()

        self.url = ""
        self.seed = None

        self.total_req = 0
        self.pending_fuzz = MyCounter()
        self.pending_seeds = MyCounter()
        self.processed = MyCounter()
        self.backfeed = MyCounter()
        self.filtered = MyCounter()

        self.totaltime = 0
        self.__starttime = 0

        self._cancelled = False

    @staticmethod
    def from_requestGenerator(rg):
        tmp_stats = FuzzStats()

        tmp_stats.url = rg.seed.history.redirect_url
        tmp_stats.total_req = rg.count()
        tmp_stats.seed = rg.seed

        return tmp_stats

    def get_stats(self):
        return {
            "url": self.url,
            "total": self.total_req,

            "backfed": self.backfeed(),
            "Processed": self.processed(),
            "Pending": self.pending_fuzz(),
            "filtered": self.filtered(),

            "Pending_seeds": self.pending_seeds(),

            "totaltime": self._totaltime,
        }

    def mark_start(self):
        with self.mutex:
            self.__starttime = time.time()

    def mark_end(self):
        with self.mutex:
            self.totaltime = time.time() - self.__starttime

    @property
    def cancelled(self):
        with self.mutex:
            return self._cancelled

    @cancelled.setter
    def cancelled(self, v):
        with self.mutex:
            self._cancelled = v

    def __str__(self):
        string = ""

        string += "Total time: %s\n" % str(self.totaltime)[:8]

        if self.backfeed() > 0:
            string += "Processed Requests: %s (%d + %d)\n" % (str(self.processed())[:8], (self.processed() - self.backfeed()), self.backfeed())
        else:
            string += "Processed Requests: %s\n" % (str(self.processed())[:8])
        string += "Filtered Requests: %s\n" % (str(self.filtered())[:8])
        string += "Requests/sec.: %s\n" % str(self.processed() / self.totaltime if self.totaltime > 0 else 0)[:8]

        return string

    def update(self, fuzzstats2):
        self.url = fuzzstats2.url
        self.total_req += fuzzstats2.total_req
        self.totaltime += fuzzstats2.totaltime

        self.backfeed._operation(fuzzstats2.backfeed())
        self.processed._operation(fuzzstats2.processed())
        self.pending_fuzz._operation(fuzzstats2.pending_fuzz())
        self.filtered._operation(fuzzstats2.filtered())
        self.pending_seeds._operation(fuzzstats2.pending_seeds())


class FuzzPayload():
    def __init__(self, content, fields):
        self.content = content
        self.fields = fields

    def description(self, default):
        ret_str_values = []
        for fuzz_value in self.fields:
            if fuzz_value is None and isinstance(self.content, FuzzResult):
                ret_str_values.append(default)
            elif fuzz_value is not None and isinstance(self.content, FuzzResult):
                ret_str_values.append(str(rgetattr(self.content, fuzz_value)))
            elif fuzz_value is None:
                ret_str_values.append(self.content)
            else:
                ret_str_values.append(fuzz_value)

        return " - ".join(ret_str_values)

    def __str__(self):
        return "content: {} fields: {}".format(self.content, self.fields)


class FuzzResult:
    seed, backfeed, result, error, startseed, endseed, cancel, discarded = list(range(8))
    newid = itertools.count(0)

    def __init__(self, history=None, exception=None, track_id=True):
        self.history = history

        self.type = None
        self.exception = exception
        self.is_baseline = False
        self.rlevel = 1
        self.nres = next(FuzzResult.newid) if track_id else 0

        self.chars = 0
        self.lines = 0
        self.words = 0
        self.md5 = ""

        self.update()

        self.plugins_res = []
        self.plugins_backfeed = []

        self.payload = []

        self._description = None
        self._show_field = False

    @property
    def plugins(self):
        dic = defaultdict(list)

        for pl in self.plugins_res:
            dic[pl.source].append(pl.issue)

        return dic

    def update(self, exception=None):
        self.type = FuzzResult.result

        if exception:
            self.exception = exception

        if self.history and self.history.content:
            m = hashlib.md5()
            m.update(python2_3_convert_to_unicode(self.history.content))
            self.md5 = m.hexdigest()

            self.chars = len(self.history.content)
            self.lines = self.history.content.count("\n")
            self.words = len(re.findall(r"\S+", self.history.content))

        return self

    def __str__(self):
        if self.type == FuzzResult.result:
            res = "%05d:  C=%03d   %4d L\t   %5d W\t  %5d Ch\t  \"%s\"" % (self.nres, self.code, self.lines, self.words, self.chars, self.description)
            for i in self.plugins_res:
                res += "\n  |_ %s" % i.issue

            return res
        else:
            return "Control result, type: %s" % ("seed", "backfeed", "result", "error", "startseed", "endseed", "cancel", "discarded")[self.type]

    def _payload_description(self):
        if not self.payload:
            return self.url

        payl_descriptions = [payload.description(self.url) for payload in self.payload]
        ret_str = ' - '.join([p_des for p_des in payl_descriptions if p_des])

        return ret_str

    @property
    def description(self):
        ret_str = ""

        if self._show_field is True:
            ret_str = self.eval(self._description)
        elif self._show_field is False and self._description is not None:
            ret_str = "{} | {}".format(self._payload_description(), self.eval(self._description))
        else:
            ret_str = self._payload_description()

        if self.exception:
            return ret_str + "! " + str(self.exception)

        return ret_str

    def eval(self, expr):
        return FuzzResFilter(filter_string=expr).is_visible(self)

    # parameters in common with fuzzrequest
    @property
    def content(self):
        return self.history.content if self.history else ""

    @property
    def url(self):
        return self.history.url if self.history else ""

    @property
    def code(self):
        if self.history and self.history.code >= 0 and not self.exception:
            return int(self.history.code)
        # elif not self.history.code:
            # return 0
        else:
            return ERROR_CODE

    @property
    def timer(self):
        return self.history.reqtime if self.history and self.history.reqtime else 0

    # factory methods

    def to_new_seed(self):
        seed = self.from_soft_copy(False)

        if seed.type == FuzzResult.error:
            raise FuzzExceptInternalError("A new seed cannot be created with a Fuzz item representing an error.")

        seed.history.url = self.history.recursive_url
        seed.rlevel += 1
        seed.type = FuzzResult.seed

        return seed

    def from_soft_copy(self, track_id=True):
        fr = FuzzResult(self.history.from_copy(), track_id=track_id)

        fr.exception = self.exception
        fr.is_baseline = self.is_baseline
        fr.type = self.type
        fr.rlevel = self.rlevel
        fr.payload = list(self.payload)
        fr._description = self._description
        fr._show_field = self._show_field

        return fr

    def update_from_options(self, options):
        self._description = options['description']
        self._show_field = options['show_field']

    @staticmethod
    def to_new_exception(exception):
        fr = FuzzResult(exception=exception, track_id=False)
        fr.type = FuzzResult.error

        return fr

    @staticmethod
    def to_new_signal(signal):
        fr = FuzzResult(track_id=False)
        fr.type = signal

        return fr

    def to_new_url(self, url):
        fr = self.from_soft_copy()
        fr.history.url = str(url)
        fr.rlevel = self.rlevel + 1
        fr.type = FuzzResult.backfeed
        fr.is_baseline = False

        return fr

    def __lt__(self, other):
        return self.nres < other.nres

    def __le__(self, other):
        return self.nres <= other.nres

    def __gt__(self, other):
        return self.nres > other.nres

    def __ge__(self, other):
        return self.nres >= other.nres

    def __eq__(self, other):
        return self.nres == other.nres

    def __ne__(self, other):
        return self.nres != other.nres


class PluginItem:
    undefined, result, backfeed = list(range(3))

    def __init__(self, ptype):
        self.source = ""
        self.plugintype = ptype


class PluginResult(PluginItem):
    def __init__(self):
        PluginItem.__init__(self, PluginItem.result)

        self.issue = ""


class PluginRequest(PluginItem):
    def __init__(self):
        PluginItem.__init__(self, PluginItem.backfeed)

        self.fuzzitem = None

    @staticmethod
    def from_fuzzRes(res, url, source):
        plreq = PluginRequest()
        plreq.source = source
        plreq.fuzzitem = res.to_new_url(url)
        plreq.fuzzitem.payload = [FuzzPayload(url, [None])]

        return plreq
