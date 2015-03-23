import types
import time
import hashlib
import re
from urlparse import urljoin
from threading import Lock

from externals.reqresp import Request
from framework.core.myexception import FuzzException
from framework.fuzzer.base import BaseFuzzRequest

class FuzzRequest(BaseFuzzRequest, Request):
    def __init__(self):
	Request.__init__(self)
	self._rlevel = 0
	self._proxy = None
	self._allvars = None
	self._is_baseline = False
	self._fuzz_methods = False
	self._description = ""

    # read only methods for accessing HTTP requests information consistenly accross the codebase

    def fr_headers(self):
	h = dict(request = {}, response = {})

	h['request'] = dict(map(lambda x: x.split(":",1), self.getHeaders()))

	if self.response:
	    h['response'] = dict(self.response.getHeaders())

	return h

    def fr_parameters(self):
	p = dict(get = {}, post = {})

	p['get'] = dict(map(lambda x: (x.name, x.value), self.getGETVars()))
	p['post'] = dict(map(lambda x: (x.name, x.value), self.getPOSTVars()))

	return p

    def fr_cookies(self):
	cc = dict(request = {}, response = {})

	if self['Cookie']:
	    c = self['Cookie'].split("; ")
	    if c[0]:
		#cc['request'] = dict(map(lambda x: x.split("=", 1), c))
		cc['request'] = dict(map(lambda x:[x[0],x[2]],map(lambda x:x.partition("="), c)))

	if self.response:
	    c = self.response.getCookie().split("; ")
	    if c[0]:
		#cc['response'] = dict(map(lambda x: x.split("=", 1), c))
		cc['response'] = dict(map(lambda x:[x[0],x[2]],map(lambda x:x.partition("="), c)))

	return cc

    def fr_method(self):
	return self.method

    def fr_schema(self):
	return self.schema

    def fr_host(self):
	return self.getHost()

    def fr_url(self):
	return self.finalUrl

    def fr_redirect_url(self):
	return self.completeUrl

    def fr_content(self):
	return self.response.getContent() if self.response else ""

    def fr_code(self):
	return self.response.code if self.response else None

    def fr_auth(self):
	return self.getAuth()

    def fr_follow(self):
	return self.followLocation

    def fr_time(self):
	return self.totaltime

    # Info extra that wfuzz needs within an HTTP request

    def _get_baseline(self):
	return self._is_baseline

    def _set_baseline(self, bl):
	self._is_baseline = bl

    wf_is_baseline = property( _get_baseline, _set_baseline )

    def wf_allvars_len(self):
	if self.wf_allvars == "allvars":
	    varSET = self.getGETVars()
	elif self.wf_allvars == "allpost":
	    varSET = self.getPOSTVars()
	else:
	    raise FuzzException(FuzzException.FATAL, "Unknown variable set: " + self.wf_allvars)

	return len(varSET)

    def _get_allvars(self):
	return self._allvars

    def _set_allvars(self, bl):
	if bl is not None and bl not in ['allvars', 'allpost']: 
	    raise FuzzException(FuzzException.FATAL, "Incorrect all parameters brute forcing type specified, correct values are allvars, allpost or allheaders.")

	self._allvars = bl

    wf_allvars = property( _get_allvars, _set_allvars )

    def _set_rlevel(self, l):
	self._rlevel = l
	
    def _get_rlevel(self):
	return self._rlevel

    rlevel = property( _get_rlevel, _set_rlevel )

    def _set_fuzz_methods(self, l):
	self._fuzz_methods = l
	
    def _get_fuzz_methods(self):
	return self._fuzz_methods

    wf_fuzz_methods = property( _get_fuzz_methods, _set_fuzz_methods )

    def _set_description(self, l):
	self._description = l
	
    def _get_description(self):
	return self._description

    wf_description = property( _get_description, _set_description )

    def _set_proxies(self, l):
	if l:
	    prox, ptype = l
	    self.setProxy("%s" % prox, ptype if ptype else "HTML")
	self._proxy = l
	
    def _get_proxies(self):
	return self._proxy

    wf_proxy = property( _get_proxies, _set_proxies )

    # methods wfuzz needs to perform HTTP requests (this might change in the future).

    def to_http_object(self, c):
	return Request.to_pycurl_object(c, self)

    def from_http_object(self, c, bh, bb):
	return self.response_from_conn_object(c, bh, bb)

    # methods wfuzz needs for substituing payloads and building dictionaries

    @staticmethod
    def from_seed(seed, payload):
	rawReq = seed.getAll()
	schema = seed.schema
	method, userpass = seed.getAuth()
	http_method = None

	marker_regex = re.compile("FUZ\d*Z",re.MULTILINE|re.DOTALL)
	fuzz_words = len(set(marker_regex.findall(rawReq)))

	if seed.wf_fuzz_methods:
	    fuzz_words += 1

	if method:
	    fuzz_words += len(set(marker_regex.findall(userpass)))

	if len(payload) != fuzz_words:
	    raise FuzzException(FuzzException.FATAL, "FUZZ words and number of payloads do not match!")

	newreq = seed.from_copy()
	rawUrl = newreq.completeUrl

	for payload_pos, payload_content in enumerate(payload, start=1):
	    fuzz_word = "FUZ" + str(payload_pos) + "Z" if payload_pos > 1 else "FUZZ"

	    if newreq.wf_description:
		newreq.wf_description += " - "
	    newreq.wf_description += payload_content

	    if seed.wf_fuzz_methods and fuzz_word == "FUZZ":
		http_method = payload_content
	    elif method and (userpass.count(fuzz_word)):
		userpass = userpass.replace(fuzz_word, payload_content)
	    elif newreq.completeUrl.count(fuzz_word):
		rawUrl = rawUrl.replace(fuzz_word, payload_content)

		# reqresp appends http:// if not indicated in the URL, but if I have a payload with a full URL
		# this messes up everything  => http://FUZZ and then http://http://asdkjsakd.com
		if rawUrl[:11] == 'http://http':
		    rawUrl = rawUrl[7:]
	    elif rawReq.count(fuzz_word):
		rawReq = rawReq.replace(fuzz_word, payload_content)
	    else:
		raise FuzzException(FuzzException.FATAL, "No %s word!" % fuzz_word)

	newreq.parseRequest(rawReq, schema)
	newreq.setUrl(rawUrl)
	if http_method: newreq.method = http_method
	if method != 'None': newreq.setAuth(method, userpass)

	return newreq

    @staticmethod
    def from_baseline(seed):
	schema = seed.schema
	rawReq = seed.getAll()

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
	seed.parseRequest(rawReq, schema)
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
	if len(marker_regex.findall(seed.getAll())) > 0:
	    raise FuzzException(FuzzException.FATAL, "FUZZ words not allowed when using all parameters brute forcing.")

	# only a fuzz payload is allowed using this technique
	if len(payload) > 1:
	    raise FuzzException(FuzzException.FATAL, "Only one payload is allowed when fuzzing all parameters!")

	if seed.wf_allvars == "allvars":
	    varSET = seed.getGETVars()
	elif seed.wf_allvars == "allpost":
	    varSET = seed.getPOSTVars()
	elif seed.wf_allvars == "allheaders":
	    varSET = seed.getHeaders()
	else:
	    raise FuzzException(FuzzException.FATAL, "Unknown variable set: " + seed.wf_allvars)

	if len(varSET) == 0:
	    raise FuzzException(FuzzException.FATAL, "No variables on specified variable set: " + seed.wf_allvars)

	for v in varSET:
	    variable = v.name
	    payload_content = payload[0]
	    copycat = seed.from_copy()
	    copycat.wf_description = variable + "=" + payload_content

	    try:
		if seed.wf_allvars == "allvars":
		    copycat.setVariableGET(variable, payload_content)
		elif seed.wf_allvars == "allpost":
		    copycat.setVariablePOST(variable, payload_content)
		elif seed.wf_allvars == "allheaders":
		    copycat.addHeader(variable, payload_content)
		else:
		    raise FuzzException(FuzzException.FATAL, "Unknown variable set: " + seed.wf_allvars)
	    except TypeError, e:
		raise FuzzException(FuzzException.FATAL, "It is not possible to use all fuzzing with duplicated parameters.")

	    yield copycat

    # methods wfuzz needs for creating and converting a fuzz request to other internal objects, ie. fuzz result

    @staticmethod
    def from_fuzzRes(fuzz_res, new_url = None):
	fr = fuzz_res.history.from_copy()
	
	fr.wf_description = fuzz_res.description
	fr.rlevel = fuzz_res.rlevel

	if new_url: fr.setUrl(new_url)

	return fr

    def from_copy(self):
	newreq = FuzzRequest()

	newreq.rlevel = self.rlevel
	newreq.wf_description = self.wf_description
	newreq.wf_proxy = self.wf_proxy
	newreq.wf_is_baseline = self.wf_is_baseline
	newreq.wf_allvars = self.wf_allvars
	newreq.wf_fuzz_methods = self.wf_fuzz_methods


	for k,v in self.fr_headers()['request'].items():
	    newreq.addHeader(k, v)

	pp = self.fr_parameters()['post']
	if pp:
	   newreq.setPostData("&".join(["=".join([n,v]) if v is not None else n for n,v in pp.items()]))

	newreq.setFollowLocation(self.followLocation)
	m, up = self.getAuth()
	newreq.setAuth(m, up)
	newreq.setUrl(self.finalUrl)
	newreq.proxytype = self.proxytype
	newreq.totaltime = self.totaltime
	newreq.schema = self.schema

	if self.wf_fuzz_methods:
	    newreq.method = "FUZZ"
	else:
	    newreq.method = self.method

	return newreq

    @staticmethod
    def from_parse_options(options):
	fr = FuzzRequest()

        fr.rlevel = 1
        fr.setUrl(options['url'])
	fr.wf_fuzz_methods = options['fuzz_methods']

	if options['auth'][0] is not None:
	    fr.setAuth(options['auth'][0],options['auth'][1])

	if options['follow']:
	    fr.setFollowLocation(options['follow'])

        if options['postdata']:
            fr.setPostData(options['postdata'])

        if options['head']:
            fr.method="HEAD"

	if options['cookie']:
            fr.addHeader("Cookie", "; ".join(options['cookie']))

	for h,v in options['extraheaders']:
	    fr.addHeader(h, v)

        if options['allvars']:
	    fr.wf_allvars = options['allvars']

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

	self._cancel = False

    @staticmethod
    def from_requestGenerator(rg):
	tmp_stats = FuzzStats()

	tmp_stats.url = rg.seed.completeUrl
	tmp_stats.total_req = rg.count()
	tmp_stats.seed = FuzzResult.from_fuzzReq(rg.seed, -1)

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

    def get_cancelled(self):
	with self.mutex:
	    return self._cancel

    def set_cancelled(self, someValue):
	with self.mutex:
	    self._cancel = someValue

    cancelled = property( get_cancelled, set_cancelled )

    def get_pend_fuzz(self):
	with self.mutex:
	    return self._pending_fuzz

    def set_pend_fuzz(self, someValue):
	with self.mutex:
	    self._pending_fuzz = someValue

    pending_fuzz = property( get_pend_fuzz, set_pend_fuzz )

    def get_filtered(self):
	with self.mutex:
	    return self._filtered

    def set_filtered(self, someValue):
	with self.mutex:
	    self._filtered = someValue

    filtered = property( get_filtered, set_filtered )

    def get_backfeed(self):
	with self.mutex:
	    return self._backfeed

    def set_backfeed(self, someValue):
	with self.mutex:
	    self._backfeed = someValue

    backfeed = property( get_backfeed, set_backfeed )

    def get_processed(self):
	with self.mutex:
	    return self._processed

    def set_processed(self, someValue):
	with self.mutex:
	    self._processed = someValue

    processed = property( get_processed, set_processed )

    def get_pend_seeds(self):
	with self.mutex:
	    return self._pending_seeds

    def set_pend_seeds(self, someValue):
	with self.mutex:
	    self._pending_seeds = someValue

    pending_seeds = property( get_pend_seeds, set_pend_seeds )

    def get_total_time(self):
	with self.mutex:
	    return self._totaltime

    def set_total_time(self, someValue):
	with self.mutex:
	    self._totaltime = someValue

    totaltime = property( get_total_time, set_total_time )

    def mark_start(self):
	with self.mutex:
	    self.__starttime = time.time()	

    def mark_end(self):
	self.totaltime = time.time() - self.__starttime	


class FuzzResult:
    def __init__(self, nres):
	self.is_visible = True
	self.is_baseline = False

	self.nres = nres
	self.timer = 0
	self.rlevel = 1

	self.exception = None
	self.description = ""

	self.url = ""

	self.code = 0
	self.chars = 0
	self.lines = 0
	self.words = 0
	self.md5 = ""

	self.history = None

	self.plugins_res = []
	self.plugins_backfeed = []

    @staticmethod
    def from_fuzzReq(req, nres = -1, exception = None):
	fr = FuzzResult(nres)

	fr.nres = nres
	if req.fr_content():
	    m = hashlib.md5()
	    m.update(req.fr_content())
	    fr.md5 = m.hexdigest()

	    fr.chars = len(req.fr_content())
	    fr.lines = req.fr_content().count("\n")
	    fr.words = len(re.findall("\S+",req.fr_content()))

	fr.code = 0 if req.fr_code() is None else int(req.fr_code())
	fr.url = req.fr_url()
	fr.description = req.wf_description
	fr.timer = req.fr_time()
	fr.rlevel = req.rlevel

	fr.history = req
	fr.is_baseline = req.wf_is_baseline

	if exception:
	    fr.code = 0
	    fr.exception = exception
	    fr.description = fr.description + "! " + exception.msg

	return fr

    def is_path(self):
	if self.code == 200 and self.url[-1] == '/':
	    return True
	elif self.code >= 300 and self.code < 400:
	    if "Location" in self.history.fr_headers()['response'] and self.history.fr_headers()['response']["Location"][-1]=='/':
		return True
	elif self.code == 401:
	    if self.url[-1] == '/':
		return True

	return False

    def to_new_seed(self):
	seed = FuzzRequest.from_fuzzRes(self, self._recursive_url())
	seed.rlevel += 1

	return seed

    def _recursive_url(self):
	if self.code >= 300 and self.code < 400 and "Location" in self.history.fr_headers()['response']:
	    new_url = self.history.fr_headers()['response']["Location"]
	    if not new_url[-1] == '/': new_url += "/"
	    # taking into consideration redirections to /xxx/ without full URL
	    new_url = urljoin(self.url, new_url)
	elif self.code == 401 or self.code == 200:
	    new_url = self.url
	    if not self.url[-1] == '/': new_url = "/"
	else:
	    raise Exception, "Error generating seed from fuzz res"

	return new_url + "FUZZ"

