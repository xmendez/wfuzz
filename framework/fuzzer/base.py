import abc

# decorator for iterator plugins
def wfuzz_iterator(gen_func):
    class _reiterator:
	name = gen_func.name
	description = gen_func.description
	category = gen_func.category
	priority = gen_func.priority
	
        def __init__(self, *args, **kwargs):
            self.__args = args
            self.__kwargs = kwargs

	    self.__gen = gen_func(*self.__args, **self.__kwargs)

	def restart(self):
	    self.__gen = gen_func(*self.__args, **self.__kwargs)

	def __getattr__(self, method):
	    if method != "restart":
		return getattr(self.__gen, method)
	    else:
		return self.restart

    _reiterator.__PLUGIN_MODULEMAN_MARK = "Plugin mark"
    return _reiterator

class BaseFuzzRequest:
    """ Abstract class defining an interface for a Fuzz request.
    This is mainly due to the idea of not using reqresp in the future and therefore be agnostic on underneath HTTP request representation
    This allows plugins to access to fuzzrequest consistently across the code base.
    """
    __metaclass__ = abc.ABCMeta

    # read only methods for accessing HTTP requests information consistenly accross the codebase

    @abc.abstractmethod
    def fr_headers(self):
	"""
	Gets HTTP request headers in the form of a dictionary.dict(request = {}, response = {})
	"""
	return

    @abc.abstractmethod
    def fr_parameters(self):
	"""
	Gets HTTP request GET or POST parameters in the form of a dictionary.dict(get = {}, post = {})
	"""
	return

    @abc.abstractmethod
    def fr_cookies(self):
	"""
	Returns HTTP request cookies in the form of a dictionary.dict(request = {}, response = {})
	"""
	return

    @abc.abstractmethod
    def fr_method(self):
	"""
	Returns HTTP request method, ie. GET, POST, PUT,...
	"""
	return

    @abc.abstractmethod
    def fr_schema(self):
	"""
	Returns HTTP request schema, ie. HTTP or HTTPS
	"""
	return

    @abc.abstractmethod
    def fr_host(self):
	"""
	Returns HTTP request host
	"""
	return

    @abc.abstractmethod
    def fr_url(self):
	"""
	Sets/gets HTTP request final url (even if redirected)
	"""
	return

    @abc.abstractmethod
    def fr_redirect_url(self):
	"""
	Returns HTTP request original URL before redirection (or same as url() if none)
	"""
	return

    @abc.abstractmethod
    def fr_content(self):
	"""
	Returns HTTP response raw content (without headers)
	"""
	return

    @abc.abstractmethod
    def fr_code(self):
	"""
	Returns HTTP response return code (if no response none)
	"""
	return

    @abc.abstractmethod
    def fr_auth(self):
	"""
	Gets/Sets HTTP request auth in the form of (basic/digest/ntlm, user:pass)
	"""
	return

    @abc.abstractmethod
    def fr_follow(self):
	"""
	Property that sets/gets if HTTP request follows redirections
	"""
	return

    @abc.abstractmethod
    def fr_time(self):
	"""
	Returns time to fullfill HTTP request and response
	"""
	return

    # Info extra that wfuzz needs within an HTTP request

    @abc.abstractproperty
    def wf_is_baseline(self):
	"""
	Property that indicates if an HTTP request is from the baseline
	"""
	return

    @abc.abstractproperty
    def wf_proxy(self):
	"""
	Property that sets/gets HTTP request proxy in the form of (IP:PORT, TYPE)
	"""
	return

    @abc.abstractmethod
    def wf_allvars_len(self):
	"""
	Returns the number of variables of the HTTP request depending on alvars property ('allvars','allpost','allheaders')
	"""
	return

    @abc.abstractproperty
    def wf_allvars(self):
	"""
	Returns 'none','allvars','allpost','allheaders' if the HTTP request is a wfuzz request without FUZZ and fuzzing everything
	"""
	return

    @abc.abstractproperty
    def rlevel(self):
	"""
	Property that sets/gets HTTP request recursion level (this is need for priority queues)
	"""
	return

    @abc.abstractproperty
    def wf_fuzz_methods(self):
	"""
	Property that sets/gets if HTTP methods are fuzzed
	"""
	return

    @abc.abstractproperty
    def wf_description(self):
	"""
	Property that sets/gets HTTP request summary to show in console
	"""
	return

    # methods wfuzz needs to perform HTTP requests (this might change in the future).

    @abc.abstractmethod
    def from_http_object(self, c, h, b):
	"""
	Converts pycurl object to fuzz request
	"""
	return

    @abc.abstractmethod
    def to_http_object(self, c):
	"""
	Converts the fuzz request to a pycurl object
	"""
	return

    # methods wfuzz needs for substituing payloads and building dictionaries

    @staticmethod
    @abc.abstractmethod
    def from_seed(seed, payload):
	"""
	Returns a new fuzz request instance substituting all the FUZnZ marks to the corresponding payload.
	"""
	return

    @staticmethod
    @abc.abstractmethod
    def from_baseline(seed):
	"""
	Returns a new fuzz request instance replacing FUZZ{baseline} for baseline
	"""
	return

    @staticmethod
    @abc.abstractmethod
    def from_all_fuzz_request(seed, payload):
	"""
	yields a new fuzz request instance for earch variable and payload
	"""
	return

    # methods wfuzz needs for creating and converting a fuzz request to other internal objects, ie. fuzz result

    @staticmethod
    @abc.abstractmethod
    def from_fuzzRes(fuzz_res, new_url = None):
	"""
	Returns a new fuzz request instance based on the given fuzzresult.
	if new url is set, the new fuzz request must change it and not to be base on res history (due to recursivity)
	"""
	return

    @abc.abstractmethod
    def from_copy(self):
	"""
	Returns a new fuzz request instance copying itself
	"""
	return

    @staticmethod
    @abc.abstractmethod
    def from_parse_options(options):
	"""
	Returns a new fuzz request instance parsing command line options
	"""
	return
