import time
import cPickle as pickle
import gzip
import pycurl
from cStringIO import StringIO
from threading import Thread, Lock, Event
from Queue import Queue

from framework.fuzzobjects import FuzzResult
from framework.utils.myqueue import FuzzQueue
from framework.facade import FuzzException
from framework.utils.myqueue import FuzzRRQueue
from framework.facade import Facade
from framework.fuzzobjects import PluginResult, PluginItem

from framework.externals.reqresp.exceptions import ReqRespException

class SeedQ(FuzzQueue):
    def __init__(self, options):
	FuzzQueue.__init__(self, options)
	self.delay = options.get("sleeper")
	self.genReq = options.get("genreq")

    def get_name(self):
	return 'SeedQ'

    def _cleanup(self):
	pass

    def process(self, prio, item):
	if item.type == FuzzResult.startseed:
	    self.genReq.stats.pending_seeds.inc()
	elif item.type == FuzzResult.seed:
	    self.genReq.restart(item)
	else:
	    raise FuzzException(FuzzException.FATAL, "SeedQ: Unknown item type in queue!")

	# Empty dictionary?
	try:
	    fuzzres = self.genReq.next()

	    if fuzzres.is_baseline:
		self.genReq.stats.pending_fuzz.inc()
		self.send_first(fuzzres)

		# wait for BBB to be completed before generating more items
		while(self.genReq.stats.processed() == 0 and not self.genReq.stats.cancelled):
		    time.sleep(0.0001)

		# more after baseline?
		fuzzres = self.genReq.next()

	except StopIteration:
	    raise FuzzException(FuzzException.FATAL, "Empty dictionary! Please check payload or filter.")

	# Enqueue requests
	try:
	    while fuzzres:
		self.genReq.stats.pending_fuzz.inc()
		if self.delay: time.sleep(self.delay)
		self.send(fuzzres)
		fuzzres = self.genReq.next()
	except StopIteration:
	    pass

	self.send_last(FuzzResult.to_new_signal(FuzzResult.endseed))

class SaveQ(FuzzQueue):
    def __init__(self, options):
	FuzzQueue.__init__(self, options)

	self.output_fn = None
        try:
            self.output_fn = gzip.open(options.get("output_filename"), 'w+b')
        except IOError, e:
            raise FuzzException(FuzzException.FATAL, "Error opening results file!. %s" % str(e))

    def get_name(self):
	return 'SaveQ'

    def _cleanup(self):
        self.output_fn.close()

    def process(self, prio, item):
        pickle.dump(item, self.output_fn)
        self.send(item)

class PrinterQ(FuzzQueue):
    def __init__(self, options):
	FuzzQueue.__init__(self, options)

        self.printer = options.get("printer_tool")
        self.printer.header(self.stats)

    def get_name(self):
	return 'PrinterQ'

    def _cleanup(self):
        self.printer.footer(self.stats)

    def process(self, prio, item):
        if item.is_visible:
            self.printer.result(item)

        self.send(item)

class RoutingQ(FuzzQueue):
    def __init__(self, options, routes):
	FuzzQueue.__init__(self, options)
	self.routes = routes

    def get_name(self):
	return 'RoutingQ'

    def _cleanup(self):
	pass

    def process(self, prio, item):
        if item.type in self.routes:
            self.routes[item.type].put(item)
        else:
            self.queue_out.put(item)

class FilterQ(FuzzQueue):
    def __init__(self, options):
	FuzzQueue.__init__(self, options)

	self.setName('filter_thread')
	self.ffilter = options.get("filter_params")

    def get_name(self):
	return 'filter_thread'

    def _cleanup(self):
	pass

    def process(self, prio, item):
	if item.is_baseline:
	    self.ffilter.set_baseline(item)
            item.is_visible = True
        else:
            item.is_visible = self.ffilter.is_visible(item)

	self.send(item)

class SliceQ(FuzzQueue):
    def __init__(self, options):
	FuzzQueue.__init__(self, options)

	self.setName('slice_thread')
	self.ffilter = options.get("slice_params")

    def get_name(self):
	return 'slice_thread'

    def _cleanup(self):
	pass

    def process(self, prio, item):
	if item.is_baseline or self.ffilter.is_visible(item):
            self.send(item)
        else:
            self.stats.pending_fuzz.dec()

class JobQ(FuzzRRQueue):
    def __init__(self, options, cache):
	# Get active plugins
        lplugins = Facade().get_parsers(options.get("script_string"))

        if not lplugins:
            raise FuzzException(FuzzException.FATAL, "No plugin selected, check the --script name or category introduced.")

        FuzzRRQueue.__init__(self, options, [JobMan(options, lplugins, cache) for i in range(3)])

    def get_name(self):
	return 'JobQ'

    def _cleanup(self):
	pass

    def process(self, prio, item):
	self.send(item)

class JobMan(FuzzQueue):
    def __init__(self, options, selected_plugins, cache):
	FuzzQueue.__init__(self, options)
	self.__walking_threads = Queue(20)
	self.selected_plugins = selected_plugins
	self.cache = cache

    def get_name(self):
	return 'Jobman'

    def _cleanup(self):
	pass

    # ------------------------------------------------
    # threading
    # ------------------------------------------------
    def process(self, prio, res):
	# process request through plugins
	if res.is_visible and not res.exception:
	    if self.cache.update_cache(res.history, "processed"):

		plugins_res_queue = Queue()

		for plugin_class in self.selected_plugins:
		    try:
			pl = plugin_class()
			if not pl.validate(res):
			    continue
			th = Thread(target = pl.run, kwargs={"fuzzresult": res, "control_queue": self.__walking_threads, "results_queue": plugins_res_queue})
		    except Exception, e:
			raise FuzzException(FuzzException.FATAL, "Error initialising plugin %s: %s " % (plugin_class.name, str(e)))
		    self.__walking_threads.put(th)
		    th.start()

		self.__walking_threads.join()


		while not plugins_res_queue.empty():
		    item = plugins_res_queue.get()

                    if item.plugintype == PluginItem.result:
			if Facade().sett.get("general","cancel_on_plugin_except") == "1" and item.source == "$$exception$$":
			    self._throw(FuzzException(FuzzException.FATAL, item.issue))
			res.plugins_res.append(item)
                    elif item.plugintype == PluginItem.backfeed:
			if self.cache.update_cache(item.fuzzitem.history, "backfeed"):
			    res.plugins_backfeed.append(item)
                    else:
                        raise FuzzException(FuzzException.FATAL, "Jobman: Unknown pluginitem type in queue!")

	# add result to results queue
	self.send(res)

class RecursiveQ(FuzzQueue):
    def __init__(self, options, cache):
	FuzzQueue.__init__(self, options)

	self.cache = cache
	self.max_rlevel = options.get("rlevel")

    def get_name(self):
	return 'RecursiveQ'

    def _cleanup(self):
	pass

    def process(self, prio, fuzz_res):
	# Getting results from plugins or directly from http if not activated
	enq_item = 0
	plugin_name = ""

	# Check for plugins new enqueued requests
	while fuzz_res.plugins_backfeed:
	    plg_backfeed = fuzz_res.plugins_backfeed.pop()
	    plugin_name = plg_backfeed.source

	    self.stats.backfeed.inc()
	    self.stats.pending_fuzz.inc()
	    self.send(plg_backfeed.fuzzitem)
	    enq_item += 1

	if enq_item > 0:
	    plres = PluginResult()
	    plres.source = "Backfeed"
	    fuzz_res.plugins_res.append(plres)
	    plres.issue = "Plugin %s enqueued %d more requests (rlevel=%d)" % (plugin_name, enq_item, fuzz_res.rlevel)

	# check if recursion is needed
	if self.max_rlevel >= fuzz_res.rlevel and fuzz_res.history.is_path:
	    if self.cache.update_cache(fuzz_res.history, "recursion"):
		self.send_new_seed(fuzz_res)

	# send new result
	self.send(fuzz_res)

    def send_new_seed(self, res):
	# Little hack to output that the result generates a new recursion seed
	plres = PluginResult()
	plres.source = "Recursion"
	plres.issue = "Enqueued response for recursion (level=%d)" % (res.rlevel)
	res.plugins_res.append(plres)

	# send new seed
	self.stats.pending_seeds.inc()
	self.send(res.to_new_seed())

class DryRunQ(FuzzQueue):
    def __init__(self, options):
	FuzzQueue.__init__(self, options)
	self.pause = Event()

    def get_name(self):
	return 'DryRunQ'

    def _cleanup(self):
	pass

    def process(self, prio, item):
	self.send(item)

class HttpQueue(FuzzQueue):
    HTTPAUTH_BASIC, HTTPAUTH_NTLM, HTTPAUTH_DIGEST = ('basic', 'ntlm', 'digest')

    def __init__(self, options):
	FuzzQueue.__init__(self, options, limit=options.get("max_concurrent") * 5)

	self.processed = 0

	self.exit_job = False
	self.mutex_multi = Lock()
	self.mutex_stats = Lock()

	# Connection pool
	self.m = None
	self.freelist = Queue()
	self._create_pool(options.get("max_concurrent"))

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

    def __get_next_proxy(self, proxy_list):
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

	mdelay = self.options.get("max_req_delay")
	if mdelay is not None:
	    c.setopt(pycurl.TIMEOUT, mdelay)

	cdelay = self.options.get("max_conn_delay")
	if cdelay is not None:
	    c.setopt(pycurl.CONNECTTIMEOUT, cdelay)

	return c

    def process(self, prio, obj):
	self.pause.wait()
	c = obj.history.to_http_object(self.freelist.get())
	c = self._set_extra_options(c, obj)

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
		buff_body, buff_header, res = c.response_queue
		res.history.from_http_object(c, buff_header.getvalue(), buff_body.getvalue())


                # reset type to result otherwise backfeed items will enter an infinite loop
		self.send(res.update(ftype=FuzzResult.result))

		self.m.remove_handle(c)
		self.freelist.put(c)

		with self.mutex_stats:
		    self.processed += 1

	    for c, errno, errmsg in err_list:
		buff_body, buff_header, res = c.response_queue

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
		self.send(res.update(exception=e, ftype=FuzzResult.result))

		if not self.options.get("scanmode"):
		    self._throw(e)

		with self.mutex_stats:
		    self.processed += 1

	# cleanup multi stack
	for c in self.m.handles:
	    c.close()
	self.m.close()
