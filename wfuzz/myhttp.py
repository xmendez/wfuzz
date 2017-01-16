import pycurl
from cStringIO import StringIO
from threading import Thread, Lock, Event
import itertools
from Queue import Queue

from .exception import FuzzException

class HttpPool:
    HTTPAUTH_BASIC, HTTPAUTH_NTLM, HTTPAUTH_DIGEST = ('basic', 'ntlm', 'digest')
    newid = itertools.count(0).next

    def __init__(self, retries):
    #def __init__(self, options):
	self.processed = 0

	self.exit_job = False
	self.mutex_multi = Lock()
	self.mutex_stats = Lock()

	self.m = None
	self.freelist = Queue()
	self.retrylist = Queue()

	self.ths = None

	self._proxies = None

        self.pool_map = {}
        self.default_poolid = 0

        self.options = None
        self.retries = retries

    def _start_threads(self):
        l = []

        for fn in ("_read_multi_stack", "_read_retry_queue"):
            th = Thread(target=getattr(self, fn))
            th.setName(fn)
            l.append(th)
            th.start()

        return l

    def initialize(self, options):
        self.options = options

	# pycurl Connection pool
	self._create_pool(options.get("concurrent"))

	if options.get("proxies"):
	    self._proxies = self._get_next_proxy(options.get("proxies"))

        # internal pool
        self.default_poolid = self._new_pool()

        self.ths = self._start_threads()

    def job_stats(self):
	with self.mutex_stats:
	    dic = {
		"http_Processed": self.processed,
		"http_Idle Workers": self.freelist.qsize()
	    }
	return dic

    # internal http pool control

    def perform(self, fuzzreq):
        poolid = self._new_pool()
        self.enqueue(fuzzreq, poolid)
        item = self.pool_map[poolid].get()
        return item

    def iter_results(self):
        item = self.pool_map[self.default_poolid].get()

        if not item: raise StopIteration

        yield item

    def _new_pool(self):
        poolid = self.newid()
        self.pool_map[poolid] = Queue()

        return poolid

    def enqueue(self, fuzzres, poolid = None):
	c = fuzzres.history.to_http_object(self.freelist.get())
	c = self._set_extra_options(c, fuzzres)

        if self.exit_job: return

	c.response_queue = ((StringIO(), StringIO(), fuzzres, self.default_poolid if not poolid else poolid))
	c.setopt(pycurl.WRITEFUNCTION, c.response_queue[0].write)
	c.setopt(pycurl.HEADERFUNCTION, c.response_queue[1].write)

	with self.mutex_multi:
	    self.m.add_handle(c)

    def _stop_to_pools(self):
        for p in self.pool_map.keys():
            self.pool_map[p].put(None)

    # Pycurl management
    def _create_pool(self, num_conn):
	# Pre-allocate a list of curl objects
	self.m = pycurl.CurlMulti()
	self.m.handles = []

	for i in range(num_conn):
	    c = pycurl.Curl()
	    self.m.handles.append(c)
	    self.freelist.put(c)

    def _cleanup(self):
	self.exit_job = True
        for th in self.ths:
            th.join()

    def _get_next_proxy(self, proxy_list):
	i = 0
	while 1:
	    yield proxy_list[i]
	    i += 1
	    i = i % len(proxy_list)

    def _set_extra_options(self, c, freq):
	if self._proxies:
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

	mdelay = self.options.get("req_delay")
	if mdelay is not None:
	    c.setopt(pycurl.TIMEOUT, mdelay)

	cdelay = self.options.get("conn_delay")
	if cdelay is not None:
	    c.setopt(pycurl.CONNECTTIMEOUT, cdelay)

	return c

    def _read_retry_queue(self):
	while not self.exit_job:
            res, poolid = self.retrylist.get()

            if res is None: break

            self.enqueue(res, poolid)

    def _read_multi_stack(self):
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
		buff_body, buff_header, res, poolid = c.response_queue

		res.history.from_http_object(c, buff_header.getvalue(), buff_body.getvalue())

                # reset type to result otherwise backfeed items will enter an infinite loop
                self.pool_map[poolid].put(res.update())

		self.m.remove_handle(c)
		self.freelist.put(c)

		with self.mutex_stats:
		    self.processed += 1

	    for c, errno, errmsg in err_list:
		buff_body, buff_header, res, poolid = c.response_queue

		res.history.totaltime = 0
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

                # retry requests with recoverable errors
                if errno not in [28, 7, 6, 5]:
                    res.history.wf_retries += 1

                    if res.history.wf_retries < self.retries:
                        self.retrylist.put((res, poolid))
                        continue

		e = FuzzException(FuzzException.FATAL, "Pycurl error %d: %s" % (errno, errmsg))
                self.pool_map[poolid].put(res.update(exception=e))

		with self.mutex_stats:
		    self.processed += 1

        self._stop_to_pools()
        self.retrylist.put((None, None))
	# cleanup multi stack
	for c in self.m.handles:
	    c.close()
            self.freelist.put(c)
	self.m.close()
