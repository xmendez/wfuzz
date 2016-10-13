import time
import hashlib
import re
import itertools
import operator

from urlparse import urljoin
from threading import Lock
from collections import namedtuple
from collections import defaultdict

from .externals.reqresp import Request
from .exception import FuzzException
from .facade import Facade
from .plugin_api.urlutils import parse_url

auth_header = namedtuple("auth_header", "method credentials")

class headers:
    def __init__(self, req):
        self._req = req

    @property
    def response(self):
        return dict(self._req.response.getHeaders()) if self._req.response else {}

    @property
    def request(self):
        return dict(map(lambda x: x.split(":",1), self._req.getHeaders()))

    def add(self, dd):
        for k, v in dd.items():
            self._req.addHeader(k, v)

    def get_field(self, field):
        attr = field.split(".")
        num_fields = len(attr)

        if num_fields == 2:
            if attr[1] == "request":
                return str(self.request)
            elif attr[1] == "response":
                return str(self.response)
            else:
                raise FuzzException(FuzzException.FATAL, "headers must be specified as headers.[request|response].<header name>")
        elif num_fields != 3:
            raise FuzzException(FuzzException.FATAL, "headers must be specified as headers.[request|response].<header name>")

        ret = ""
        try:
            if attr[1] == "request":
                ret = self.request[attr[2]]
            elif attr[1] == "response":
                ret = self.response[attr[2]]
            else:
                raise FuzzException(FuzzException.FATAL, "headers must be specified as headers.[request|response].<header name>")
        except KeyError:
            pass

        return ret.strip()

class cookies:
    def __init__(self, req):
        self._req = req

    @property
    def response(self):
        if self._req.response:
            c = self._req.response.getCookie().split("; ")
            if c[0]:
                #cc['response'] = dict(map(lambda x: x.split("=", 1), c))
                return dict(map(lambda x:[x[0],x[2]],map(lambda x:x.partition("="), c)))

        return {}


    @property
    def request(self):
        if self._req.headers.request.has_key('Cookie'):
            c = self._req.headers.request['Cookie'].split("; ")
            if c[0]:
                #cc['request'] = dict(map(lambda x: x.split("=", 1), c))
                return dict(map(lambda x:[x[0],x[2]],map(lambda x:x.partition("="), c)))

        return {}

    def get_field(self, field):
        attr = field.split(".")
        num_fields = len(attr)

        if num_fields != 2:
            raise FuzzException(FuzzException.FATAL, "Cookie must be specified as cookies.[request|response]")

        if attr[1] == "response":
            if self._req.response:
                return self._req.response.getCookie()
        elif attr[1] == "request":
            return self._req['COOKIE']
        else:
            raise FuzzException(FuzzException.FATAL, "Cookie must be specified as cookies.[request|response]")

        return ""

class parameters(object):
    def __init__(self, req):
        self._req = req

    @property
    def get(self):
        return dict(map(lambda x: (x.name, x.value), self._req.getGETVars()))

    @property
    def post(self):
        return dict(map(lambda x: (x.name, x.value), self._req.getPOSTVars()))

    @post.setter
    def post(self, pp):
        if isinstance(pp, dict):
            self._req.setPostData("&".join(["=".join([n,v]) if v is not None else n for n,v in pp.items()]))
        elif isinstance(pp, str):
            self._req.setPostData(pp)

    def get_field(self, field):
        attr = field.split(".")
        num_fields = len(attr)

        if num_fields == 2:
            if attr[1] == "get":
                return str(self.get)
            elif attr[1] == "post":
                return str(self.post)
            else:
                raise FuzzException(FuzzException.FATAL, "Parameters must be specified as parameters.[get/post].<name>")
        elif num_fields == 3:
            ret = ""
            try:
                if attr[1] == "get":
                    ret = self.get[attr[2]]
                elif attr[1] == "post":
                    ret = self.post[attr[2]]
                else:
                    raise FuzzException(FuzzException.FATAL, "Parameters must be specified as parameters.[get/post].<name>")
            except KeyError:
                pass

            return ret
        else:
            raise FuzzException(FuzzException.FATAL, "Parameters must be specified as parameters.[get/post].<name>")

class FuzzRequest(object):
    def __init__(self):
	self._request = Request()

	self._proxy = None
	self._allvars = None
	self.wf_fuzz_methods = None
        self.wf_retries = 0

	self.headers.add({"User-Agent": Facade().sett.get("connection","User-Agent").encode('utf-8')})

    # methods for accessing HTTP requests information consistenly accross the codebase

    def __str__(self):
        return self._request.getAll()

    @property
    def headers(self):
        return headers(self._request)

    @property
    def parameters(self):
	return parameters(self._request)

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
        if Facade().sett.get("general","encode_space") == "1":
            u = u.replace(" ", "%20")
	self._request.setUrl(u)

    @property
    def content(self):
	return self._request.response.getContent() if self._request.response else ""

    @property
    def code(self):
	return self._request.response.code if self._request.response else None

    @code.setter
    def code(self, c):
	self._request.response.code = c

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

    def set_field(self, field, value):
        if field in ["url"]:
            self.url = value

    def get_field(self, field):
        if field in ["url", "method", "scheme", "host", "content", "code"]:
            return str(getattr(self, field))
        elif field.startswith("cookies"):
            return self.cookies.get_field(field).strip()
        elif field.startswith("headers.request") or field.startswith("headers.response"):
            return self.headers.get_field(field)
        elif field.startswith("parameters."):
            return self.parameters.get_field(field)
        elif field.startswith("url."):
            attr = field.split(".")
            allowed_attr = ["scheme", "netloc", "path", "params", "query", "fragment", "domain", "file_fullname", "file_extension", "file_name"]

            if len(attr) != 2:
                raise FuzzException(FuzzException.FATAL, "Url must be specified as url.<field>")

            if attr[1] in allowed_attr:
                return getattr(self.urlparse, attr[1])
            else:
                raise FuzzException(FuzzException.FATAL, "Unknown url attribute. It must be one of %s" % ",".join(allowed_attr))

            return ""
        else:
            raise FuzzException(FuzzException.FATAL, "Unknown FuzzResult attribute: %s." % (field,))

    # urlparse functions
    @property
    def urlparse(self):
        return parse_url(self.url)

    @property
    def is_path(self):
	if self.code == 200 and self.url[-1] == '/':
	    return True
	elif self.code >= 300 and self.code < 400:
	    if "Location" in self.headers.response and self.headers.response["Location"][-1]=='/':
		return True
	elif self.code == 401:
	    if self.url[-1] == '/':
		return True

	return False

    @property
    def recursive_url(self):
	if self.code >= 300 and self.code < 400 and "Location" in self.headers.response:
	    new_url = self.headers.response["Location"]
	    if not new_url[-1] == '/': new_url += "/"
	    # taking into consideration redirections to /xxx/ without full URL
	    new_url = urljoin(self.url, new_url)
	elif self.code == 401 or self.code == 200:
	    new_url = self.url
	    if not self.url[-1] == '/': new_url = "/"
	else:
	    raise Exception, "Error generating recursive url"

	return new_url + "FUZZ"

    # Info extra that wfuzz needs within an HTTP request

    @property
    def wf_allvars_set(self):
	if self.wf_allvars == "allvars":
	    return self._request.getGETVars()
	elif self.wf_allvars == "allpost":
	    return self._request.getPOSTVars()
	elif self.wf_allvars == "allheaders":
	    return self._request.getHeaders()
	else:
	    return None

    @wf_allvars_set.setter
    def wf_allvars_set(self, varset):
        variable, payload_content = varset
        try:
            if self.wf_allvars == "allvars":
                self._request.setVariableGET(variable, payload_content)
            elif self.wf_allvars == "allpost":
                self._request.setVariablePOST(variable, payload_content)
            elif self.wf_allvars == "allheaders":
                self._request.headers.add({variable: payload_content})
            else:
                raise FuzzException(FuzzException.FATAL, "Unknown variable set: " + self.wf_allvars)
        except TypeError, e:
            raise FuzzException(FuzzException.FATAL, "It is not possible to use all fuzzing with duplicated parameters.")
        
    @property
    def wf_allvars(self):
	return self._allvars

    @wf_allvars.setter
    def wf_allvars(self, bl):
	if bl is not None and bl not in ['allvars', 'allpost','allheaders']: 
	    raise FuzzException(FuzzException.FATAL, "Incorrect all parameters brute forcing type specified, correct values are allvars, allpost or allheaders.")

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
        res = FuzzResult(self, track_id = False)
        return Facade().http_pool.perform(res)
        
    def to_http_object(self, c):
	return Request.to_pycurl_object(c, self._request)

    def from_http_object(self, c, bh, bb):
	return self._request.response_from_conn_object(c, bh, bb)

    def update_from_raw_http(self, raw, scheme):
        return self._request.parseRequest(raw, scheme)

    def to_cache_key(self):
	key = self._request.urlWithoutVariables

	dicc = {}

	for j in [i.name for i in self._request.getGETVars()]:
	    dicc[j] = True

	for j in [i.name for i in self._request.getPOSTVars()]:
	    dicc[j] = True

	# take URL parameters into consideration
	url_params = dicc.keys()
	url_params.sort()
	key += "-" + "-".join(url_params)

	return key

    # methods wfuzz needs for substituing payloads and building dictionaries

    def update_from_options(self, options):

	if options['auth'][0] is not None:
	    self.auth = (options['auth'][0], options['auth'][1])

	if options['follow']:
	    self.follow = options['follow']

        if options['postdata']:
            self.parameters.post = options['postdata']

        if options['method']:
            self.method = options['method']
            self.wf_fuzz_methods = options['method']

	if options['cookie']:
            self.headers.add({"Cookie": "; ".join(options['cookie'])})

        self.headers.add(dict(options['headers']))

        if options['allvars']:
	    self.wf_allvars = options['allvars']

    def from_copy(self):
	newreq = FuzzRequest()

	newreq.wf_proxy = self.wf_proxy
	newreq.wf_allvars = self.wf_allvars
	newreq.wf_fuzz_methods = self.wf_fuzz_methods


        newreq.headers.add(self.headers.request)
        newreq.parameters.post = self.parameters.post

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
	if isinstance(payload, str):
		return (text.replace(fuzz_word, payload), [payload])
	elif isinstance(payload, FuzzResult):
		marker_regex = re.compile("(%s)(?:\[(.*?)\])?" % (fuzz_word,),re.MULTILINE|re.DOTALL)
		subs_array = []

		for fw, field in marker_regex.findall(text):
                        if not field:
                            raise FuzzException(FuzzException.FATAL, "You must specify a field when using a payload containing a full fuzz request, ie. FUZZ[url], or use FUZZ only to repeat the same request.")

			subs = payload.get_field(field)
			text = text.replace("%s[%s]" % (fw, field), subs)
			subs_array.append(subs)

		return (text, subs_array)

    @staticmethod
    def from_seed(seed, payload, seed_options):
	newres = seed.from_soft_copy()

	rawReq = str(newres.history)
	rawUrl = newres.history.redirect_url
	scheme = newres.history.scheme
	auth_method, userpass = newres.history.auth

        descr_array = []

	for payload_pos, payload_content in enumerate(payload, start=1):
	    fuzz_word = "FUZ" + str(payload_pos) + "Z" if payload_pos > 1 else "FUZZ"

            newres.payload.append(payload_content)

            # substitute entire seed when using a request payload generator without specifying field
            if fuzz_word == "FUZZ" and rawUrl == "http://FUZZ/" and isinstance(payload_content, FuzzResult):
                # new seed
                newres = payload_content

                newres.payload = [payload_content]
                newres.history.update_from_options(seed_options)
                rawReq = str(newres.history)
                rawUrl = newres.history.redirect_url
                scheme = newres.history.scheme
                auth_method, userpass = newres.history.auth

                descr_array.append(rawUrl)

                continue

            desc = None

	    if auth_method and (userpass.count(fuzz_word)):
		userpass, desc = FuzzResultFactory.replace_fuzz_word(userpass, fuzz_word, payload_content)
	    if newres.history.redirect_url.count(fuzz_word):
		rawUrl, desc = FuzzResultFactory.replace_fuzz_word(rawUrl, fuzz_word, payload_content)

		# reqresp appends http:// if not indicated in the URL, but if I have a payload with a full URL
		# this messes up everything  => http://FUZZ and then http://http://asdkjsakd.com
		if rawUrl[:14] == 'http://http://':
		    rawUrl = rawUrl[7:]
	    if rawReq.count(fuzz_word):
		rawReq, desc = FuzzResultFactory.replace_fuzz_word(rawReq, fuzz_word, payload_content)

            if desc:
                descr_array += desc
            else:
		raise FuzzException(FuzzException.FATAL, "No %s word!" % fuzz_word)

	newres.history.update_from_raw_http(rawReq, scheme)
	newres.history.url = rawUrl
	if auth_method != 'None': newres.history.auth = (auth_method, userpass)

        if newres.description:
            newres.description += " - "

	newres.description += " - ".join(descr_array)
        newres.type = FuzzResult.result

	return newres

    @staticmethod
    def from_baseline(fuzzresult):
	scheme = fuzzresult.history.scheme
	rawReq = str(fuzzresult.history)
	auth_method, userpass = fuzzresult.history.auth

        # get the baseline payload ordered by fuzz number and only one value per same fuzz keyword.
        b1 = dict([matchgroup.groups() for matchgroup in re.finditer("FUZ(\d*)Z(?:{(.*?)})?", rawReq, re.MULTILINE|re.DOTALL)])
        b2 = dict([matchgroup.groups() for matchgroup in re.finditer("FUZ(\d*)Z(?:{(.*?)})?", userpass, re.MULTILINE|re.DOTALL)])
	baseline_control = dict(b1.items() + b2.items())
        baseline_payload = map(lambda x: x[1], sorted(baseline_control.items(), key=operator.itemgetter(0)))

	# if there is no marker, there is no baseline request
        if not filter(lambda x: x is not None, baseline_payload):
            return None

	## remove baseline marker from seed request
	for i in baseline_payload:
            if not i:
                raise FuzzException(FuzzException.FATAL, "You must supply a baseline value for all the FUZZ words.")
	    rawReq = rawReq.replace("{" + i + "}", '')

            if fuzzresult.history.wf_fuzz_methods:
                fuzzresult.history.wf_fuzz_methods = fuzzresult.history.wf_fuzz_methods.replace("{" + i + "}", '')

            if auth_method:
                userpass = userpass.replace("{" + i + "}", '')

	# re-parse seed without baseline markers
	fuzzresult.history.update_from_raw_http(rawReq, scheme)
	if auth_method: fuzzresult.history.auth = (auth_method, userpass)

        baseline_res = FuzzResultFactory.from_seed(fuzzresult, baseline_payload, None)
	baseline_res.is_baseline = True
        baseline_res.payload = baseline_payload

	return baseline_res

    @staticmethod
    def from_all_fuzz_request(seed, payload):
	# no FUZZ keyword allowed
	marker_regex = re.compile("FUZ\d*Z",re.MULTILINE|re.DOTALL)
	if len(marker_regex.findall(str(seed))) > 0:
	    raise FuzzException(FuzzException.FATAL, "FUZZ words not allowed when using all parameters brute forcing.")

	# only a fuzz payload is allowed using this technique
	if len(payload) > 1:
	    raise FuzzException(FuzzException.FATAL, "Only one payload is allowed when fuzzing all parameters!")

	if len(seed.wf_allvars_set) == 0:
	    raise FuzzException(FuzzException.FATAL, "No variables on specified variable set: " + seed.wf_allvars)

	for v in seed.wf_allvars_set:
	    variable = v.name
	    payload_content = payload[0]
	    fuzzres = FuzzResult(seed.from_copy())
	    fuzzres.description = variable + "=" + payload_content
            fuzzres.payload.append(payload_content)

            seed.wf_allvars_set = (variable, payload_content)

	    yield fuzzres

    @staticmethod
    def from_options(options):
	fr = FuzzRequest()

	fr.url = options['url']
	fr.wf_fuzz_methods = options['method']
	fr.update_from_options(options)

	return FuzzResult(fr)

class MyCounter:
    def __init__(self, count = 0):
        self._count = count
	self._mutex = Lock()

    def inc(self):
        self._operation(1)

    def dec(self):
        self._operation(-1)

    def _operation(self, dec):
        with self._mutex:
            self._count += dec

    def __call__(self):
        with self._mutex:
            return self._count

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

	self._totaltime = 0
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

class FuzzResult:
    seed, backfeed, result, error, startseed, endseed, cancel = range(7)
    newid = itertools.count(0).next
    ERROR_CODE = -1

    def __init__(self, history = None, exception = None, track_id = True):
	self.history = history

        self.type = None
	self.exception = exception
        self.description = ""
        self.is_baseline = False
	self.is_visible = True
        self.rlevel = 1
        self.nres = FuzzResult.newid() if  track_id else 0

        self.chars = 0
        self.lines = 0
        self.words = 0
        self.md5 = ""

        self.update()

	self.plugins_res = []
	self.plugins_backfeed = []

        self.payload = []

    def update(self, exception = None):
        self.type = FuzzResult.result

        if exception:
            self.exception = exception
            self.description = self.description + "! " + self.exception.msg

        if self.history and self.history.content:
            m = hashlib.md5()
            m.update(self.history.content)
            self.md5 = m.hexdigest()

            self.chars = len(self.history.content)
            self.lines = self.history.content.count("\n")
            self.words = len(re.findall("\S+", self.history.content))

        return self

    def set_field(self, field, value):
        return self.history.set_field(field, value)

    def get_field(self, field):
        if field in ["description", "nres", "chars", "lines", "words", "md5"]:
            return str(getattr(self, field))
        else:
            return self.history.get_field(field)

    def __str__(self):
        return "%05d:  C=%03d   %4d L\t   %5d W\t  %5d Ch\t  \"%s\"" % (self.nres, self.code, self.lines, self.words, self.chars, self.description)

    # parameters in common with fuzzrequest
    @property
    def url(self):
        return self.history.url if self.history else ""

    @property
    def code(self):
        if self.history and self.history.code >= 0 and not self.exception:
            return int(self.history.code)
        elif not self.history.code:
            return 0
        else:
            return FuzzResult.ERROR_CODE

    @property
    def timer(self):
        return self.history.reqtime if self.history and self.history.reqtime else 0

    # factory methods

    def to_new_seed(self):
        seed = self.from_soft_copy(False)

        if seed.type == FuzzResult.error:
            raise FuzzException(FuzzException.FATAL, "A new seed cannot be created with a Fuzz item representing an error.")

        seed.history.url = self.history.recursive_url
	seed.rlevel += 1
        seed.type = FuzzResult.seed

	return seed

    def from_soft_copy(self, track_id = True):
        fr = FuzzResult(self.history.from_copy(), track_id = track_id)

	fr.exception = self.exception
        fr.description = self.description
        fr.is_baseline = self.is_baseline
	fr.is_visible = self.is_visible
	fr.type = self.type
        fr.rlevel = self.rlevel
        fr.payload = list(self.payload)

        return fr

    @staticmethod
    def to_new_exception(exception):
        fr = FuzzResult(exception = exception, track_id = False)
        fr.type = FuzzResult.error

        return fr

    @staticmethod
    def to_new_signal(signal):
        fr = FuzzResult(track_id = False)
        fr.type = signal

        return fr

    def to_new_url(self, url):
        fr = self.from_soft_copy()
        fr.history.url = str(url)
	fr.description = fr.history.path
	fr.rlevel = self.rlevel + 1
        fr.type = FuzzResult.backfeed
        fr.is_baseline = False

        return fr

class PluginItem:
    undefined, result, backfeed = range(3)

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

	return plreq

