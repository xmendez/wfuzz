import threading
from Queue import Queue

from framework.fuzzer.fuzzobjects import FuzzResult
from framework.fuzzer.fuzzobjects import FuzzRequest
from framework.plugins.pluginobjects import PluginResult
from framework.plugins.pluginobjects import PluginRequest
from framework.core.myexception import FuzzException
from framework.utils.myqueue import FuzzQueue
from framework.utils.myqueue import FuzzListQueue

class RoundRobin(FuzzListQueue):
    def __init__(self, queue_out):
        FuzzListQueue.__init__(self, queue_out)
	self.next_route = self._get_next_route()

    def get_name(self):
	return 'RoundRobin'

    def _cleanup(self):
	pass

    def send(self, item):
	self.next_route.next().put(item)

    def _get_next_route(self):
	i = 0
	while 1:
	    yield self.queue_out[i]
	    i += 1
	    i = i % len(self.queue_out)

    def process(self, prio, item):
	self.send(item)

class JobMan(FuzzQueue):
    def __init__(self, selected_plugins, cache, queue_out):
        FuzzQueue.__init__(self, queue_out)
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
			th = threading.Thread(target = pl.run, kwargs={"fuzzresult": res, "control_queue": self.__walking_threads, "results_queue": plugins_res_queue})
		    except Exception, e:
			raise FuzzException(FuzzException.FATAL, "Error initialising plugin %s: %s " % (plugin_class.name, str(e)))
		    self.__walking_threads.put(th)
		    th.start()

		self.__walking_threads.join()


		while not plugins_res_queue.empty():
		    item = plugins_res_queue.get()
		    if isinstance(item, PluginResult):
			if item.source == "$$exception$$":
			    self._throw(FuzzException(FuzzException.FATAL, item.issue))
			res.plugins_res.append(item)
		    elif isinstance(item, PluginRequest):
			if self.cache.update_cache(item.request, "backfeed"):
			    res.plugins_backfeed.append(item)

	# add result to results queue
	self.send(res)

class ProcessorQ(FuzzQueue):
    def __init__(self, max_rlevel, stats, queue_out):
        FuzzQueue.__init__(self, queue_out)

	self.stats = stats
	self.max_rlevel = max_rlevel

    def get_name(self):
	return 'ProcessorQ'

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

	    self.stats.backfeed += 1
	    self.stats.pending_fuzz += 1
	    self.send(plg_backfeed)
	    enq_item += 1

	if enq_item > 0:
	    plres = PluginResult()
	    plres.source = "Backfeed"
	    fuzz_res.plugins_res.append(plres)
	    plres.issue = "Plugin %s enqueued %d more requests (rlevel=%d)" % (plugin_name, enq_item, fuzz_res.rlevel)

	# check if recursion is needed
	if self.max_rlevel >= fuzz_res.rlevel and fuzz_res.is_path():
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
	self.stats.pending_seeds += 1
	self.send(res.to_new_seed())
