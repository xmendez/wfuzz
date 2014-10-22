from Queue import Queue
from threading import Thread
from threading import Lock
from threading import Event
from cStringIO import StringIO

from externals.reqresp.exceptions import ReqRespException

from framework.core.myexception import FuzzException
from framework.utils.myqueue import FuzzQueue
from framework.fuzzer.fuzzobjects import FuzzResult

import pycurl

class HttpQueue(FuzzQueue):
    HTTPAUTH_BASIC, HTTPAUTH_NTLM, HTTPAUTH_DIGEST = ('basic', 'ntlm', 'digest')

    def __init__(self, options, q_out):
	FuzzQueue.__init__(self, q_out, options.get("max_concurrent") * 5)

	self.options = options

	self.processed = 0

	self.exit_job = False
	self.mutex_multi = Lock()
	self.mutex_stats = Lock()

	self.queue_out = q_out

	# Connection pool
	self.m = None
	self.freelist = Queue()
	self.create_pool(options.get("max_concurrent"))

	th2 = Thread(target=self.__read_multi_stack)
	th2.setName('__read_multi_stack')
	th2.start()

	self.pause = Event()
	self.pause.set()

	self._proxies = None
	if options.get("proxy_list"):
	    self._proxies = self.__get_next_proxy(options.get("proxy_list"))

    def get_name(self):
	return 'HttpQueue'

    def job_stats(self):
	with self.mutex_stats:
	    dic = {
		"http_Processed": self.processed,
		"http_Pending": self.qsize(),
		"http_Idle Workers": self.freelist.qsize()
	    }
	return dic

    # Pycurl management
    def create_pool(self, num_conn):
	# Pre-allocate a list of curl objects
	self.m = pycurl.CurlMulti()
	self.m.handles = []

	for i in range(num_conn):
	    c = pycurl.Curl()
	    self.m.handles.append(c)
	    self.freelist.put(c)

    def _cleanup(self):
	self.exit_job = True

    def __get_next_proxy(self, proxy_list):
	i = 0
	while 1:
	    yield proxy_list[i]
	    i += 1
	    i = i % len(proxy_list)

    def _set_proxy(self, c, freq):
	ip, port, ptype = self._proxies.next()

	freq.wf_proxy = (("%s:%s" % (ip, port)), ptype)

	c.setopt(pycurl.PROXY, "%s:%s" % (ip, port))
	if ptype == "SOCKS5":
	    c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
	elif ptype == "SOCKS4":
	    c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS4)
	elif ptype == "HTML":
	    pass
	else:
	    raise FuzzException(FuzzException.FATAL, "Bad proxy type specified, correct values are HTML, SOCKS4 or SOCKS5.")

	return c

    def process(self, prio, obj):
	self.pause.wait()
	c = obj.to_http_object(self.freelist.get())
	if self._proxies: c = self._set_proxy(c, obj)

	c.response_queue = ((StringIO(), StringIO(), obj))
	c.setopt(pycurl.WRITEFUNCTION, c.response_queue[0].write)
	c.setopt(pycurl.HEADERFUNCTION, c.response_queue[1].write)

	with self.mutex_multi:
	    self.m.add_handle(c)

    def __read_multi_stack(self):
	# Check for curl objects which have terminated, and add them to the freelist
	while not self.exit_job:
	    with self.mutex_multi:
		while not self.exit_job:
		    ret, num_handles = self.m.perform()
		    if ret != pycurl.E_CALL_MULTI_PERFORM:
			break

	    num_q, ok_list, err_list = self.m.info_read()
	    for c in ok_list:
		# Parse response
		buff_body, buff_header, req = c.response_queue
		req.from_http_object(c, buff_header.getvalue(), buff_body.getvalue())

		self.send(FuzzResult.from_fuzzReq(req))

		self.m.remove_handle(c)
		self.freelist.put(c)

		with self.mutex_stats:
		    self.processed += 1

	    for c, errno, errmsg in err_list:
		buff_body, buff_header, req = c.response_queue

		req.totaltime = 0
		self.m.remove_handle(c)
		self.freelist.put(c)
		
		# Usual suspects:

		#Exception in perform (35, 'error:0B07C065:x509 certificate routines:X509_STORE_add_cert:cert already in hash table')
		#Exception in perform (18, 'SSL read: error:0B07C065:x509 certificate routines:X509_STORE_add_cert:cert already in hash table, errno 11')
		#Exception in perform (28, 'Connection time-out')
		#Exception in perform (7, "couldn't connect to host")
		#Exception in perform (6, "Couldn't resolve host 'www.xxx.com'")
		#(28, 'Operation timed out after 20000 milliseconds with 0 bytes received')
		#Exception in perform (28, 'SSL connection timeout')
		#5 Couldn't resolve proxy 'aaa'

		err_number = ReqRespException.FATAL
		if errno == 35:
		    err_number = ReqRespException.SSL
		elif errno == 18:
		    err_number = ReqRespException.SSL
		elif errno == 28:
		    err_number = ReqRespException.TIMEOUT
		elif errno == 7:
		    err_number = ReqRespException.CONNECT_HOST
		elif errno == 6:
		    err_number = ReqRespException.RESOLVE_HOST
		elif errno == 5:
		    err_number = ReqRespException.RESOLVE_PROXY

		e = ReqRespException(err_number, "Pycurl error %d: %s" % (errno, errmsg))
		self.send(FuzzResult.from_fuzzReq(req, exception=e))

		if not self.options.get("scanmode"):
		    self._throw(e)

		with self.mutex_stats:
		    self.processed += 1

	# cleanup multi stack
	for c in self.m.handles:
	    c.close()
	self.m.close()
