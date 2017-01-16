import time
import cPickle as pickle
import gzip
from threading import Thread, Event
from Queue import Queue

from .fuzzobjects import FuzzResult
from .myqueues import FuzzQueue
from .exception import FuzzException
from .myqueues import FuzzRRQueue
from .facade import Facade
from .fuzzobjects import PluginResult, PluginItem

class SeedQ(FuzzQueue):
    def __init__(self, options):
	FuzzQueue.__init__(self, options)
	self.delay = options.get("delay")
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
            self.output_fn = gzip.open(options.get("save"), 'w+b')
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

        self.printer = options.get("printer")
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
	self.ffilter = options.get("filter")

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
	self.ffilter = options.get("prefilter")

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
    def __init__(self, options):
	# Get active plugins
        lplugins = Facade().scripts.get_plugins(options.get("script"))

        if not lplugins:
            raise FuzzException(FuzzException.FATAL, "No plugin selected, check the --script name or category introduced.")

        concurrent = int(Facade().sett.get('general', 'concurrent_plugins'))
        FuzzRRQueue.__init__(self, options, [JobMan(options, lplugins) for i in range(concurrent)])

    def get_name(self):
	return 'JobQ'

    def _cleanup(self):
	pass

    def process(self, prio, item):
	self.send(item)

class JobMan(FuzzQueue):
    def __init__(self, options, selected_plugins):
	FuzzQueue.__init__(self, options)
	self.__walking_threads = Queue(20)
	self.selected_plugins = selected_plugins
	self.cache = options.cache

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
    def __init__(self, options):
	FuzzQueue.__init__(self, options)

	self.cache = options.cache
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
    def __init__(self, options):
	FuzzQueue.__init__(self, options, limit=options.get("concurrent") * 5)

        self.http_pool = options.http_pool

	self.pause = Event()
	self.pause.set()
	self.exit_job = False

	th2 = Thread(target=self.__read_http_results)
	th2.setName('__read_http_results')
	th2.start()

    def get_name(self):
	return 'HttpQueue'

    def _cleanup(self):
	self.http_pool.exit_job = True
	self.exit_job = True

    def process(self, prio, obj):
	self.pause.wait()
        self.http_pool.enqueue(obj)

    def __read_http_results(self):
        try:
            while not self.exit_job:
                res = self.http_pool.iter_results().next()
                self.send(res)
        except StopIteration:
            pass

class HttpReceiver(FuzzQueue):
    def __init__(self, options):
	FuzzQueue.__init__(self, options, limit=options.get("concurrent") * 5)

    def get_name(self):
	return 'HttpReceiver'

    def _cleanup(self):
	pass

    def process(self, prio, res):
        if res.exception and not self.options.get("scanmode"):
            self._throw(res.exception)
        else:
            self.send(res)
