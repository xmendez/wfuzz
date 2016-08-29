import time
import cPickle as pickle
import gzip

from framework.fuzzobjects import FuzzResult
from framework.utils.myqueue import FuzzQueue
from framework.core.myexception import FuzzException

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

