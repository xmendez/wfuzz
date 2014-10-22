import threading
import time
from Queue import Queue

from framework.fuzzer.fuzzobjects import FuzzResult
from framework.fuzzer.fuzzobjects import FuzzRequest
from framework.fuzzer.dictio import requestGenerator

from framework.core.facade import Facade

from framework.core.myexception import FuzzException
from framework.utils.myqueue import MyPriorityQueue
from framework.utils.myqueue import FuzzQueue
from framework.fuzzer.myhttp import HttpQueue
from framework.plugins.jobs import JobMan
from framework.plugins.jobs import ProcessorQ
from framework.plugins.jobs import RoundRobin
from framework.fuzzer.filter import FilterQ

from externals.reqresp.exceptions import ReqRespException
from externals.reqresp.cache import HttpCache



class SeedQ(FuzzQueue):
    def __init__(self, genReq, delay, queue_out):
	FuzzQueue.__init__(self, queue_out)
	self.delay = delay
	self.genReq = genReq

    def get_name(self):
	return 'SeedQ'

    def _cleanup(self):
	pass

    def do_baseline(self):
	# initial baseline request
	bl = self.genReq.get_baseline()
	if bl:
	    self.genReq.stats.pending_fuzz += 1
	    self.queue_out.put_first(bl)

	    # wait for BBB to be completed before generating more items
	    while(self.genReq.stats.processed == 0):
		time.sleep(0.0001)

    def process(self, prio, item):
	if isinstance(item, requestGenerator):
	    if self.genReq.stats.pending_seeds == 0:
		self.genReq.stats.mark_start()
		self.genReq.stats.pending_seeds += 1
		self.do_baseline()
	    else:
		self.genReq.stats.pending_seeds += 1
	elif isinstance(item, FuzzRequest):
	    self.genReq.restart(item)
	else:
	    raise FuzzException(FuzzException.FATAL, "SeedQ: Unknown item type in queue!")

	# Enqueue requests
	try:
	    rq = self.genReq.next()
	    while rq:
		self.genReq.stats.pending_fuzz += 1
		if self.delay: time.sleep(self.delay)
		self.send(rq)
		rq = self.genReq.next()
	except StopIteration:
	    pass

	self.genReq.stats.pending_seeds -= 1


class RoutingQ(FuzzQueue):
    def __init__(self, routes, queue_out):
	FuzzQueue.__init__(self, queue_out)
	self.routes = routes

    def set_routes(self, routes):
	self.routes = routes

    def get_name(self):
	return 'RoutingQ'

    def _cleanup(self):
	pass

    def process(self, prio, item):
	if str(item.__class__) == "framework.plugins.pluginobjects.PluginRequest":
	    self.routes[str(item.__class__)].put(item.request)
	else:
	    self.routes[str(item.__class__)].put(item)

class Fuzzer:
    def __init__(self, options):
	self.genReq = options.get("genreq")

	# Get active plugins
	lplugins = None
	if options.get("script_string"):
	    lplugins = Facade().get_parsers(options.get("script_string"))

	    if not lplugins:
		raise FuzzException(FuzzException.FATAL, "No plugin selected, check the --script name or category introduced.")

	recursive = lplugins or options.get("rlevel") > 0
	filtering = options.get('filter_params')['active'] is True

	# Create queues (in reverse order)
	# genReq ---> seed_queue -> http_queue -> [round_robin] -> [plugins_queue] * N -> process_queue -> [routing_queue] -> [filter_queue]---> results_queue
	self.results_queue = MyPriorityQueue()
	self.filter_queue = FilterQ(options.get("filter_params"), self.results_queue) if filtering else None
	self.routing_queue = RoutingQ(None, self.filter_queue if filtering else self.results_queue) if recursive else None
	self.process_queue = ProcessorQ(options.get("rlevel"), self.genReq.stats, self.routing_queue if recursive else self.filter_queue if filtering else self.results_queue)
	self.plugins_queue = None
	if lplugins:
	    cache = HttpCache()
	    self.plugins_queue = RoundRobin([JobMan(lplugins, cache, self.process_queue), JobMan(lplugins, cache, self.process_queue), JobMan(lplugins, cache, self.process_queue)])
	self.http_queue = HttpQueue(options, self.plugins_queue if lplugins else self.process_queue)
	self.seed_queue = SeedQ(self.genReq, options.get("sleeper"), self.http_queue)

	# recursion routes
	if recursive:
	    self.routing_queue.set_routes({
		"<class 'framework.fuzzer.fuzzobjects.FuzzRequest'>": self.seed_queue,
		"framework.plugins.pluginobjects.PluginRequest": self.http_queue,
		"framework.fuzzer.fuzzobjects.FuzzResult": self.filter_queue if filtering else self.results_queue})

	## initial seed request
	self.seed_queue.put_priority(1, self.genReq)

    def __iter__(self):
	return self

    def process(self):
	# http://bugs.python.org/issue1360
	prio, item = self.results_queue.get(True, 365 * 24 * 60 * 60)

	# Return new result
	if isinstance(item, FuzzResult):
	    item.nres = self.genReq.stats.processed
	    self.genReq.stats.processed += 1
	    self.genReq.stats.pending_fuzz -= 1
	    if not item.is_visible: self.genReq.stats.filtered += 1 

	    self.results_queue.task_done()
	    return item
	# raise exceptions originated on other queues (not sigcancel which is to cancel the whole proces)
	elif isinstance(item, FuzzException) and item.etype == FuzzException.SIGCANCEL:
	    self.results_queue.task_done()
	elif isinstance(item, Exception):
	    self.results_queue.task_done()
	    raise item
	# We are done if a None arrives
	elif item == None:
	    self.results_queue.task_done()
	    self.genReq.stats.mark_end()
	    return None

    def next(self):
	res = self.process()

	# done! (None sent has gone through all queues).
	if not res:
	    raise StopIteration

	# check if we are done. If so, send None to everyone so the can stop nicely
	if self.genReq.stats.pending_fuzz == 0 and self.genReq.stats.pending_seeds == 0:
	    self.seed_queue.put_last(None)
	   
	return res

    def stats(self):
	dic = {
	    "plugins_queue": self.plugins_queue.qsize() if self.plugins_queue else -1,
	    "results_queue": self.process_queue.qsize(),
	    "results_queue": self.results_queue.qsize(),
	    "routing_queue": self.routing_queue.qsize() if self.routing_queue else -1,
	    "http_queue": self.http_queue.qsize(),
	    "seed_queue": self.seed_queue.qsize(),
	    "filter_queue": self.filter_queue.qsize() if self.filter_queue else -1,
	}

	if self.plugins_queue:
	    j = 0
	    for i in self.plugins_queue.queue_out:
		dic = dict(dic.items() + {"plugins_queue #%d" % j: i.qsize()}.items())
		j += 1

	return dict(self.http_queue.job_stats().items() + self.genReq.stats.get_stats().items() + dic.items())

    def cancel_job(self):
	# stop generating items
	self.http_queue.pause.set()
	self.genReq.stop()

	# stop processing pending items
	for q in [self.seed_queue, self.http_queue, self.plugins_queue, self.process_queue, self.filter_queue, self.routing_queue]:
	    if q: q.put_first(FuzzException(FuzzException.SIGCANCEL, "Cancel job"))

	# wait for cancel to be processed
	for q in [self.seed_queue, self.http_queue, self.plugins_queue] + self.plugins_queue.queue_out if self.plugins_queue else [] + [self.process_queue, self.filter_queue, self.routing_queue]:
	    if q: q.join()

	# send None to stop (almost nicely)
	self.seed_queue.put_last(None)

    def pause_job(self):
	self.http_queue.pause.clear()

    def resume_job(self):
	self.http_queue.pause.set()
