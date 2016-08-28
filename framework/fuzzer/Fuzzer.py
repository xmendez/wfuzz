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
        if self.output_fn: 
            self.output_fn.close()

    def process(self, prio, item):
	if self.output_fn: 
	    pickle.dump(item, self.output_fn)

        self.send(item)

class PrinterQ(FuzzQueue):
    def __init__(self, options):
	FuzzQueue.__init__(self, options)

        self.printer = options.get("printer_tool")
        if self.printer: 
            self.printer.header(self.stats)

    def get_name(self):
	return 'PrinterQ'

    def _cleanup(self):
        if self.printer:
            self.printer.footer(self.stats)

    def process(self, prio, item):
        if self.printer and item.is_visible:
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

class Fuzzer:
    def __init__(self, options):
	self.genReq = options.get("genreq")

	# Get active plugins
	lplugins = None
	if options.get("script_string"):
	    lplugins = Facade().get_parsers(options.get("script_string"))

	    if not lplugins:
		raise FuzzException(FuzzException.FATAL, "No plugin selected, check the --script name or category introduced.")

	cache = HttpCache()

	# Create queues
	# genReq ---> seed_queue -> [slice_queue] -> http_queue/dryrun -> [round_robin -> plugins_queue] * N -> [recursive_queue -> routing_queue] -> [filter_queue] -> [printer_queue] ---> results_queue

        self.qmanager = QueueManager()
        self.results_queue = MyPriorityQueue()

        self.qmanager.add("seed_queue", SeedQ(options))

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

	if options.get('output_filename'):
            self.qmanager.add("save_queue", SaveQ(options))

	if options.get('printer_tool'):
            self.qmanager.add("printer_queue", PrinterQ(options))

        self.qmanager.bind(self.results_queue)

	# initial seed request
	self.qmanager.start()

    def __iter__(self):
	return self

    def next(self):
	# http://bugs.python.org/issue1360
	prio, res = self.results_queue.get(True, 365 * 24 * 60 * 60)
	self.results_queue.task_done()

	# done! (None sent has gone through all queues).
	if not res:
	    self.qmanager.stop()
	    raise StopIteration
        elif res.type == FuzzResult.error:
	    raise res.exception

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
