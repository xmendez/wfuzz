from framework.fuzzobjects import FuzzResult

from framework.myqueues import MyPriorityQueue
from framework.myqueues import QueueManager
from framework.fuzzqueues import SeedQ, SaveQ, PrinterQ, RoutingQ, FilterQ, SliceQ, JobQ, RecursiveQ, DryRunQ, HttpQueue

from framework.externals.reqresp.exceptions import ReqRespException
from framework.externals.reqresp.cache import HttpCache

class Fuzzer:
    def __init__(self, options):
	self.genReq = options.get("genreq")

	cache = HttpCache()

	# Create queues
	# genReq ---> seed_queue -> [slice_queue] -> http_queue/dryrun -> [round_robin -> plugins_queue] * N -> [recursive_queue -> routing_queue] -> [filter_queue] -> [save_queue] -> [printer_queue] ---> results

        self.qmanager = QueueManager()
        self.results_queue = MyPriorityQueue()

        self.qmanager.add("seed_queue", SeedQ(options))

        if options.get('slice_params').is_active():
            self.qmanager.add("slice_queue", SliceQ(options))

	if options.get("dryrun"):
            self.qmanager.add("http_queue", DryRunQ(options))
	else:
            self.qmanager.add("http_queue", HttpQueue(options))

	if options.get("script_string"):
	    self.qmanager.add("plugins_queue", JobQ(options, cache))

	if options.get("script_string") or options.get("rlevel") > 0:
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
