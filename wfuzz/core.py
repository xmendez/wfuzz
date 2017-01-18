from .fuzzobjects import FuzzResult

from .myqueues import MyPriorityQueue,QueueManager
from .fuzzqueues import SeedQ, SaveQ, PrinterQ, RoutingQ, FilterQ, SliceQ, JobQ, RecursiveQ, DryRunQ, HttpQueue, HttpReceiver

from .externals.reqresp.exceptions import ReqRespException

from .fuzzobjects import FuzzResultFactory, FuzzStats
from .facade import Facade
from .exception import FuzzException

from .filter import FuzzResFilter

import re
import itertools

class sliceit:
    def __init__(self, payload, slicestr):
	self.ffilter = FuzzResFilter(filter_string = slicestr)
        self.payload = payload

    def __iter__(self):
        return self

    def count(self):
        return -1

    def next(self):
        item = self.payload.next()
        while not self.ffilter.is_visible(item):
            item = self.payload.next()

	return item

class tupleit:
    def __init__(self, parent):
        self.parent = parent

    def count(self):
        return self.parent.count()

    def next(self):
        return (self.parent.next(),)

    def __iter__(self):
        return self


class dictionary:
	def __init__(self, payload, encoders_list):
	    self.__payload = payload
	    self.__encoders = encoders_list
	    self.__generator = self._gen() if self.__encoders else None

	def count (self):
	    return (self.__payload.count() * len(self.__encoders)) if self.__encoders else self.__payload.count()

	def __iter__(self):
	    return self

	def _gen(self):
	    while 1:
		pl = self.__payload.next()

		for name in self.__encoders:
		    if name.find('@') > 0:
			string = pl
			for i in reversed(name.split("@")):
			    string = Facade().encoders.get_plugin(i).encode(string)
			yield string
		    else:
			l = Facade().encoders.get_plugins(name)
			if not l:
			    raise FuzzException(FuzzException.FATAL, name + " encoder does not exists (-e encodings for a list of available encoders)")

			for e in l:
			    yield e().encode(pl)

	def next(self):
	    return self.__generator.next() if self.__encoders else self.__payload.next()

        @staticmethod
        def from_options(options):
            selected_dic = []

            for name, params, slicestr in options["payloads"]:
                p = Facade().payloads.get_plugin(name)(params)
                pp = dictionary(p, params["encoder"]) if params["encoder"] else p
                selected_dic.append(sliceit(pp, slicestr) if slicestr else pp)

            if not selected_dic:
                raise FuzzException(FuzzException.FATAL, "Empty dictionary! Check payload and filter")

            if len(selected_dic) == 1:
                return tupleit(selected_dic[0])
            elif options["iterator"]:
                return Facade().iterators.get_plugin(options["iterator"])(*selected_dic)
            else:
                return Facade().iterators.get_plugin("product")(*selected_dic)

class requestGenerator:
	def __init__(self, options):
            self.options = options
	    self.seed = FuzzResultFactory.from_options(options)
	    self._baseline = FuzzResultFactory.from_baseline(self.seed)
	    self.dictio = dictionary.from_options(self.options)

	    self.stats = FuzzStats.from_requestGenerator(self)

	    self._allvar_gen = None
	    if self.seed.history.wf_allvars is not None:
		self._allvar_gen = self.__allvars_gen(self.dictio)

	def stop(self):
	    self.stats.cancelled = True

	def restart(self, seed):
	    self.seed = seed
	    self.dictio = dictionary.from_options(self.options)

        def _check_dictio_len(self, element):
            marker_regex = re.compile("FUZ\d*Z",re.MULTILINE|re.DOTALL)
            fuzz_words = marker_regex.findall(str(self.seed.history))
            method, userpass = self.seed.history.auth

            if method:
                fuzz_words += marker_regex.findall(userpass)

            if len(element) != len(set(fuzz_words)):
                raise FuzzException(FuzzException.FATAL, "FUZZ words and number of payloads do not match!")

	def count(self):
	    v = self.dictio.count()
	    if self.seed.history.wf_allvars is not None:
		v *= len(self.seed.history.wf_allvars_set)

	    if self._baseline: v += 1

	    return v

	def __iter__(self):
	    return self

	def __allvars_gen(self, dic):
	    for payload in dic:
		for r in FuzzResultFactory.from_all_fuzz_request(self.seed, payload):
		    yield r

	def next(self):
	    if self.stats.cancelled:
		raise StopIteration

	    if self._baseline and self.stats.processed() == 0 and self.stats.pending_seeds() <= 1:
		return self._baseline

	    if self.seed.history.wf_allvars is not None:
		return self._allvar_gen.next()
	    else:
		n = self.dictio.next()
                if self.stats.processed() == 0 or (self._baseline and self.stats.processed() == 1): 
                    self._check_dictio_len(n)

		return FuzzResultFactory.from_seed(self.seed, n, self.options)

class Fuzzer:
    def __init__(self, options):
	self.genReq = options.get("genreq")


	# Create queues
	# genReq ---> seed_queue -> [slice_queue] -> http_queue/dryrun -> [round_robin -> plugins_queue] * N -> [recursive_queue -> routing_queue] -> [filter_queue] -> [save_queue] -> [printer_queue] ---> results

        self.qmanager = QueueManager()
        self.results_queue = MyPriorityQueue()

        self.qmanager.add("seed_queue", SeedQ(options))

        if options.get('prefilter').is_active():
            self.qmanager.add("slice_queue", SliceQ(options))

	if options.get("dryrun"):
            self.qmanager.add("http_queue", DryRunQ(options))
	else:
            # http_queue breaks process rules due to being asynchronous. Someone has to collects its sends, for proper fuzzqueue's count and sync purposes
            self.qmanager.add("http_queue", HttpQueue(options))
            self.qmanager.add("http_receiver", HttpReceiver(options))

	if options.get("script"):
	    self.qmanager.add("plugins_queue", JobQ(options))

	if options.get("script") or options.get("rlevel") > 0:
            self.qmanager.add("recursive_queue", RecursiveQ(options))
            rq = RoutingQ(options, {
		FuzzResult.seed: self.qmanager["seed_queue"],
		FuzzResult.backfeed: self.qmanager["http_queue"]
		})

            self.qmanager.add("routing_queue", rq)

	if options.get('filter').is_active():
            self.qmanager.add("filter_queue", FilterQ(options))

	if options.get('save'):
            self.qmanager.add("save_queue", SaveQ(options))

	if options.get('printer'):
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
	    raise StopIteration
        elif res.type == FuzzResult.error:
	    raise res.exception

	return res

    def stats(self):
	return dict(self.qmanager.get_stats().items() + self.qmanager["http_queue"].job_stats().items() + self.genReq.stats.get_stats().items())

    def cancel_job(self):
        self.qmanager.cancel()

    def pause_job(self):
	self.qmanager["http_queue"].pause.clear()

    def resume_job(self):
	self.qmanager["http_queue"].pause.set()
