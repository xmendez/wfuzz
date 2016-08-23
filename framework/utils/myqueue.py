import sys
import traceback
import collections
import itertools

from Queue import PriorityQueue
from threading import Thread
from framework.core.myexception import FuzzException
from framework.fuzzer.fuzzobjects import FuzzResult


class MyPriorityQueue(PriorityQueue):
    def __init__(self, limit = 0):
        PriorityQueue.__init__(self, limit)

	self.max_prio = 0

    def put_priority(self, prio, item):
	self.max_prio = max(prio, self.max_prio)
	PriorityQueue.put(self, (prio, item))

    def put(self, item):
	self.max_prio = max(item.rlevel, self.max_prio)
	PriorityQueue.put(self, (item.rlevel, item))

    def put_first(self, item):
	PriorityQueue.put(self, (0, item))

    def put_last(self, item):
	self.max_prio += 1
	PriorityQueue.put(self, (self.max_prio, item))
	
class FuzzQueue(MyPriorityQueue, Thread):
    def __init__(self, queue_out = None, limit = 0):
        MyPriorityQueue.__init__(self, limit)
	self.queue_out = queue_out
	self.propagate = True

	Thread.__init__(self)
	self.setName(self.get_name())
	self.start()

    def next_queue(self, q):
        self.queue_out = q

    def process(self, prio, item):
	raise NotImplemented

    def get_name(self):
	raise NotImplemented

    def send_first(self, item):
	self.queue_out.put_first(item)

    def send_last(self, item):
	if not self.propagate and (item is None or item.type == FuzzResult.endseed):
	    return
	else:
	    self.queue_out.put_last(item)

    def qout_join(self):
	self.queue_out.join()

    def send(self, item):
	self.queue_out.put(item)

    def join(self):
	MyPriorityQueue.join(self)

    def tjoin(self):
	Thread.join(self)

    def _cleanup(self):
	raise NotImplemented

    def _throw(self, e):
	if isinstance(e, FuzzException):
	    self.send_first(FuzzResult.to_new_exception(e))
	else:
	    msg = "%s\n\n%s" %(str(e), traceback.format_exc())
	    self.send_first(FuzzResult.to_new_exception(FuzzException(FuzzException.FATAL, msg)))

    def get_stats(self):
        return {self.get_name(): self.qsize()}
        
    def run(self):
	cancelling = False

	while 1:
	    prio, item = self.get(True, 365 * 24 * 60 * 60)

	    try:
                if item == None:
                    self.send_last(None)
                    if not cancelling: self.qout_join()
                    self.task_done()
                    break
                elif cancelling:
                    self.task_done()
                    continue
                elif item.type == FuzzResult.endseed:
                    self.send_last(item)
                    self.task_done()
                    continue
                elif item.type in [FuzzResult.error, FuzzResult.cancel]:
                    cancelling = True if item.type == FuzzResult.cancel else False
                    self.send_first(item)
                    self.task_done()
                    continue
                elif not item.is_processable:
                    self.send(item)
                    self.task_done()
                    continue

		self.process(prio, item)
		self.task_done()
	    except Exception, e:
		self.task_done()
		self._throw(e)

	self._cleanup()

class FuzzListQueue(FuzzQueue):
    def __init__(self, queue_out, limit = 0):
        FuzzQueue.__init__(self, queue_out, limit)

	# not to convert a None/Exception to various elements, thus only propagate in one queue
	for q in queue_out:
	    q.propagate = False
	queue_out[0].propagate = True

    def send_first(self, item):
	for q in self.queue_out:
	    q.put_first(item)

    def send_last(self, item):
	for q in self.queue_out:
	    q.put_last(item)

    def send(self, item):
	for q in self.queue_out:
	    q.put(item)

    def qout_join(self):
	for q in self.queue_out:
	    q.join()

    def join(self):
        self.qout_join()
	MyPriorityQueue.join(self)

    def next_queue(self, nextq):
        for qq in self.queue_out:
            qq.next_queue(nextq)

    def get_stats(self):
        l = []

        for qq in self.queue_out:
            l = l + qq.get_stats().items()

        l = l + FuzzQueue.get_stats(self).items()

        return dict(l)

class FuzzRRQueue(FuzzListQueue):
    def __init__(self, queue_out, limit = 0):
        FuzzListQueue.__init__(self, queue_out, limit)
	self._next_queue = self._get_next_route()

    def send(self, item):
	self._next_queue.next().put(item)

    def _get_next_route(self):
	i = 0
	while 1:
	    yield self.queue_out[i]
	    i += 1
	    i = i % len(self.queue_out)

class QueueManager:
    def __init__(self):
        self._queues = collections.OrderedDict()

    def add(self, name, q):
        self._queues[name] = q

    def bind(self, lastq):
        l = self._queues.values()

        for first, second in itertools.izip_longest(l[0:-1:1], l[1::1]):
            first.next_queue(second)

        l[-1].next_queue(lastq) 

    def __getitem__(self, key):
        return self._queues[key]

    def join(self):
	for q in self._queues.values():
            q.join()

    def cancel(self):
	# stop processing pending items
	for q in self._queues.values():
	    q.put_first(FuzzResult.to_new_signal(FuzzResult.cancel))

	# wait for cancel to be processed
	for q in self._queues.values():
	    q.join()

	# send None to stop (almost nicely)
	self._queues.values()[0].put_last(None)

    def get_stats(self):
        l = []

	for q in self._queues.values():
            l = l + q.get_stats().items()

	return dict(l)
