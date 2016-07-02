import types
import time
import hashlib
import re
from urlparse import urljoin
from threading import Lock
from collections import namedtuple

from externals.reqresp import Request
from framework.core.myexception import FuzzException
from framework.core.facade import Facade

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

class FuzzRequest(object):
    def __init__(self):
	self._request = Request()

	self._proxy = None
	self._allvars = None
	self.rlevel = 0
	self.wf_is_baseline = False
	self.wf_fuzz_methods = False
	self.wf_description = ""

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

    @staticmethod
    def replace_fuzz_word(text, fuzz_word, payload):
	if isinstance(payload, str):
		return (text.replace(fuzz_word, payload), [payload])
	elif isinstance(payload, FuzzResult):
		marker_regex = re.compile("(%s)(?:\$(.*?)\$)?" % (fuzz_word,),re.MULTILINE|re.DOTALL)
		subs_array = []

		for fw, field in marker_regex.findall(text):
			subs = str(getattr(payload, field))
			text = text.replace("%s$%s$" % (fw, field), subs)
			subs_array.append(subs)

		return (text, subs_array)

    @staticmethod
    def from_seed(seed, payload):
	newreq = seed.from_copy()

	rawReq = str(newreq)
	rawUrl = newreq.redirect_url
	scheme = newreq.scheme
	auth_method, userpass = newreq.auth

        descr_array = []
	new_http_method = None

	for payload_pos, payload_content in enumerate(payload, start=1):
	    fuzz_word = "FUZ" + str(payload_pos) + "Z" if payload_pos > 1 else "FUZZ"

            desc = None

	    if seed.wf_fuzz_methods and fuzz_word == "FUZZ":
		new_http_method = payload_content
		desc = [payload_content]
	    if auth_method and (userpass.count(fuzz_word)):
		userpass, desc = FuzzRequest.replace_fuzz_word(userpass, fuzz_word, payload_content)
	    if newreq.redirect_url.count(fuzz_word):
		rawUrl, desc = FuzzRequest.replace_fuzz_word(rawUrl, fuzz_word, payload_content)

		# reqresp appends http:// if not indicated in the URL, but if I have a payload with a full URL
		# this messes up everything  => http://FUZZ and then http://http://asdkjsakd.com
		if rawUrl[:14] == 'http://http://':
		    rawUrl = rawUrl[7:]
	    if rawReq.count(fuzz_word):
		rawReq, desc = FuzzRequest.replace_fuzz_word(rawReq, fuzz_word, payload_content)

            if desc:
                descr_array += desc
            else:
		raise FuzzException(FuzzException.FATAL, "No %s word!" % fuzz_word)

	newreq.update_from_raw_http(rawReq, scheme)
	newreq.url = rawUrl
	if new_http_method: newreq.method = new_http_method
	if auth_method != 'None': newreq.auth = (auth_method, userpass)

	newreq.wf_description = " - ".join(descr_array)

	return newreq

    @staticmethod
    def from_baseline(seed):
	scheme = seed.scheme
	rawReq = str(seed)

	marker_regex = re.compile("FUZ\d*Z{(.*?)}",re.MULTILINE|re.DOTALL)
	baseline_payload = marker_regex.findall(rawReq)

	# if there is no marker, there is no baseline request
	if len(baseline_payload) == 0:
	    return None

	# it is not possible to specify baseline value for HTTP method!
	if seed.wf_fuzz_methods:
	    baseline_payload = ['GET'] + baseline_payload

	## remove baseline marker from seed request
	for i in baseline_payload:
	    rawReq = rawReq.replace("{" + i + "}", '')

	# re-parse seed without baseline markers
	seed.update_from_raw_http(rawReq, scheme)
	if seed.wf_fuzz_methods: seed.method = "FUZZ"

	try:
	    baseline_req = FuzzRequest.from_seed(seed, baseline_payload)
	except FuzzException:
	    raise FuzzException(FuzzException.FATAL, "You must supply a baseline value for all the FUZZ words.")
	baseline_req.wf_is_baseline = True

	return baseline_req

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
	    copycat = seed.from_copy()
	    copycat.wf_description = variable + "=" + payload_content

            seed.wf_allvars_set = (variable, payload_content)

	    yield copycat

    # methods wfuzz needs for creating and converting a fuzz request to other internal objects, ie. fuzz result

    @staticmethod
    def from_fuzzRes(fuzz_res, new_url = None):
	fr = fuzz_res.history.from_copy()
	
	fr.wf_description = fuzz_res.description
	fr.rlevel = fuzz_res.rlevel

	if new_url: fr.url = new_url

	return fr

    def from_copy(self):
	newreq = FuzzRequest()

	newreq.rlevel = self.rlevel
	newreq.wf_description = self.wf_description
	newreq.wf_proxy = self.wf_proxy
	newreq.wf_is_baseline = self.wf_is_baseline
	newreq.wf_allvars = self.wf_allvars
	newreq.wf_fuzz_methods = self.wf_fuzz_methods


        newreq.headers.add(self.headers.request)
        newreq.parameters.post = self.parameters.post

	newreq.follow = self.follow
	newreq.auth = self.auth
	newreq.url = self.url
	newreq.reqtime = self.reqtime
	newreq.scheme = self.scheme

	if self.wf_fuzz_methods:
	    newreq.method = "FUZZ"
	else:
	    newreq.method = self.method

	return newreq

    def update_from_options(self, options):
	self.url = options['url']
        self._request.setUrl(options['url'])

	if options['auth'][0] is not None:
	    self.auth = (options['auth'][0], options['auth'][1])

	if options['follow']:
	    self.follow = options['follow']

        if options['postdata']:
            self.parameters.post = options['postdata']

        if options['head']:
            self.method = "HEAD"

	if options['cookie']:
            self.headers.add({"Cookie": "; ".join(options['cookie'])})

        self.headers.add(dict(options['extraheaders']))

        if options['allvars']:
	    self.wf_allvars = options['allvars']

    @staticmethod
    def from_options(seed_options, payload_options):
	fr = FuzzRequest()

	fr.url = ""
        fr.rlevel = 1
	fr.wf_fuzz_methods = seed_options['fuzz_methods']
	fr.update_from_options(seed_options)

	marker_regex = re.compile("FUZ\d*Z",re.MULTILINE|re.DOTALL)
	fuzz_words = marker_regex.findall(str(fr))
	method, userpass = fr.auth

	if fr.wf_fuzz_methods:
	    fuzz_words += ['FUZZ_METHOD']

	if method:
	    fuzz_words += fuzz_words + marker_regex.findall(userpass)

	if len(payload_options['payloads']) != len(set(fuzz_words)):
	    raise FuzzException(FuzzException.FATAL, "FUZZ words and number of payloads do not match!")

	return fr

class FuzzStats:
    def __init__(self):
	self.mutex = Lock()

	self.url = ""
	self.seed = None

	self.total_req = 0
	self._pending_fuzz = 0
	self._pending_seeds = 0
	self._processed = 0
	self._backfeed = 0
	self._filtered = 0

	self._totaltime = 0
	self.__starttime = 0

	self._cancelled = False

    @staticmethod
    def from_requestGenerator(rg):
	tmp_stats = FuzzStats()

	tmp_stats.url = rg.seed.redirect_url
	tmp_stats.total_req = rg.count()
	tmp_stats.seed = FuzzResult.from_fuzzReq(rg.seed)

	return tmp_stats

    def get_stats(self):
	return {
	    "url": self.url,
	    "total": self.total_req,

	    "backfed": self.backfeed,
	    "Processed": self.processed,
	    "Pending": self.pending_fuzz,
	    "filtered": self.filtered,

	    "Pending_seeds": self.pending_seeds,

	    "totaltime": self.totaltime,
	}

    def __getattr__(self, name):
        if name in ["cancelled", "pending_fuzz", "filtered", "backfeed", "processed", "pending_seeds"]:
            with self.mutex:
                return self.__dict__["_" + name]
        else:
            raise AttributeError

    def __setattr__(self, name, value):
        if name in ["cancelled", "pending_fuzz", "filtered", "backfeed", "processed", "pending_seeds"]:
            with self.mutex:
                self.__dict__["_" + name] = value

        self.__dict__[name] = value

    def mark_start(self):
	with self.mutex:
	    self.__starttime = time.time()	

    def mark_end(self):
	self.totaltime = time.time() - self.__starttime	


class FuzzResult:
    def __init__(self):
	self.is_visible = True

	self.exception = None

	self.chars = 0
	self.lines = 0
	self.words = 0
	self.md5 = ""

	self.history = None

	self.plugins_res = []
	self.plugins_backfeed = []

    # parameters in common with fuzzrequest
    @property
    def url(self):
        return self.history.url

    @property
    def code(self):
        if self.history.code and not self.exception:
            return int(self.history.code)
        else:
            return 0

    @property
    def is_baseline(self):
        return self.history.wf_is_baseline

    @property
    def description(self):
        desc = self.history.wf_description

        if self.exception:
            return desc + "! " + self.exception.msg

        return desc

    @property
    def timer(self):
        return self.history.reqtime if self.history.reqtime else 0

    @property
    def rlevel(self):
        return self.history.rlevel

    # factory methods

    @staticmethod
    def from_fuzzReq(req, exception = None):
	fr = FuzzResult()

	if req.content:
	    m = hashlib.md5()
	    m.update(req.content)
	    fr.md5 = m.hexdigest()

	    fr.chars = len(req.content)
	    fr.lines = req.content.count("\n")
	    fr.words = len(re.findall("\S+",req.content))

	fr.history = req
	if exception: fr.exception = exception

	return fr

    def to_new_seed(self):
	seed = FuzzRequest.from_fuzzRes(self, self.history.recursive_url)
	seed.rlevel += 1

	return seed

