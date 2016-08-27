import threading
import time
from Queue import Queue
import cPickle as pickle
import gzip

from framework.fuzzer.fuzzobjects import FuzzResult
from framework.fuzzer.dictio import requestGenerator

from framework.core.facade import Facade

from framework.core.myexception import FuzzException
from framework.utils.myqueue import MyPriorityQueue
from framework.utils.myqueue import QueueManager
from framework.utils.myqueue import FuzzQueue
from framework.fuzzer.myhttp import HttpQueue
from framework.fuzzer.myhttp import DryRunQ
from framework.plugins.jobs import JobMan
from framework.plugins.jobs import RecursiveQ
from framework.plugins.jobs import RoundRobin
from framework.fuzzer.filter import FilterQ
from framework.fuzzer.filter import SliceQ

from externals.reqresp.exceptions import ReqRespException
from externals.reqresp.cache import HttpCache

class SeedQ(FuzzQueue):
    def __init__(self, options, genReq):
	FuzzQueue.__init__(self, options)
	self.delay = options.get("sleeper")
	self.genReq = genReq

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

class Fuzzer:
    def __init__(self, options):
	self.genReq = options.get("genreq")

	# save results
	self.output_fn = None
	if options.get("output_filename"):
	    try:
		self.output_fn = gzip.open(options.get("output_filename"), 'w+b')
	    except Exception:
		raise FuzzException(FuzzException.FATAL, "Error opening results file!")

        self.printer = options.get("printer_tool")

	# Get active plugins
	lplugins = None
	if options.get("script_string"):
	    lplugins = Facade().get_parsers(options.get("script_string"))

	    if not lplugins:
		raise FuzzException(FuzzException.FATAL, "No plugin selected, check the --script name or category introduced.")

	cache = HttpCache()

	# Create queues
	# genReq ---> seed_queue -> [slice_queue] -> http_queue/dryrun -> [round_robin -> plugins_queue] * N -> [recursive_queue -> routing_queue] -> [filter_queue]---> results_queue

        self.qmanager = QueueManager()
        self.results_queue = MyPriorityQueue()

        self.qmanager.add("seed_queue", SeedQ(options, self.genReq))

        if options.get('slice_params').is_active():
            self.qmanager.add("slice_queue", SliceQ(options))

	if options.get("dryrun"):
            self.qmanager.add("http_queue", DryRunQ(options))
	else:
            self.qmanager.add("http_queue", HttpQueue(options))


	if lplugins:
	    self.qmanager.add("plugins_queue", RoundRobin(options, [JobMan(options, lplugins, cache) for i in range(3)]))

        if lplugins or options.get("rlevel") > 0:
            self.qmanager.add("recursive_queue", RecursiveQ(options, cache))
            rq = RoutingQ(options, {
		FuzzResult.seed: self.qmanager["seed_queue"],
		FuzzResult.backfeed: self.qmanager["http_queue"]
		})

            self.qmanager.add("routing_queue", rq)

	if options.get('filter_params').is_active():
            self.qmanager.add("filter_queue", FilterQ(options))

        self.qmanager.bind(self.results_queue)

	# initial seed request
	self.genReq.stats.mark_start()
        if self.printer: self.printer.header(self.genReq.stats)
	self.qmanager["seed_queue"].put_first(FuzzResult.to_new_signal(FuzzResult.startseed))


    def __iter__(self):
	return self

    def process(self):
	# http://bugs.python.org/issue1360
	prio, item = self.results_queue.get(True, 365 * 24 * 60 * 60)

	self.results_queue.task_done()

        if item is None:
            return None

        if item.type == FuzzResult.result:
	    if item.is_processable: self.genReq.stats.processed.inc()
	    self.genReq.stats.pending_fuzz.dec()
	    if not item.is_visible: self.genReq.stats.filtered.inc()
        elif item.type == FuzzResult.endseed:
	    self.genReq.stats.pending_seeds.dec()
        elif item.type == FuzzResult.error:
	    raise item.exception

	# check if we are done. If so, send None to everyone so they can stop nicely
	if item and self.genReq.stats.pending_fuzz() == 0 and self.genReq.stats.pending_seeds() == 0:
	    self.qmanager.stop()

	return item

    def next(self):
	# ignore end seed marks and not processable items
	res = self.process()
	while res and (not res.is_processable or res.type == FuzzResult.cancel or res.type == FuzzResult.endseed):

	    res = self.process()

	# done! (None sent has gone through all queues).
	if not res:
	    self.genReq.stats.mark_end()

            if self.printer:
                self.printer.footer(self.genReq.stats)
	   
	    if self.output_fn: self.output_fn.close()
	    raise StopIteration

	# Save results?
	if res and self.output_fn: 
	    pickle.dump(res, self.output_fn)

        if self.printer:
            self.printer.result(res)

	return res

    def stats(self):
	return dict(self.qmanager.get_stats().items() + self.qmanager["http_queue"].job_stats().items() + self.genReq.stats.get_stats().items())

    def cancel_job(self):
	# stop generating items
	self.qmanager["http_queue"].pause.set()
	self.genReq.stop()

        self.qmanager.cancel()

    def pause_job(self):
	self.qmanager["http_queue"].pause.clear()

    def resume_job(self):
	self.qmanager["http_queue"].pause.set()
