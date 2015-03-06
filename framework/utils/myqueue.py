import sys
import traceback

from Queue import PriorityQueue
from threading import Thread
from framework.core.myexception import FuzzException


class MyPriorityQueue(PriorityQueue):
    def __init__(self, limit = 0):
        PriorityQueue.__init__(self, limit)

	self.max_prio = 0
	self.none_send = False

    def put_priority(self, prio, item):
	if self.should_sent(item):
	    self.max_prio = max(prio, self.max_prio)
	    PriorityQueue.put(self, (prio, item))

    def put(self, item):
	if self.should_sent(item):
	    self.max_prio = max(item.rlevel, self.max_prio)
	    PriorityQueue.put(self, (item.rlevel, item))

    def put_first(self, item):
	if self.should_sent(item):
	    PriorityQueue.put(self, (0, item))

    def put_last(self, item):
	if self.should_sent(item):
	    self.max_prio += 1
	    PriorityQueue.put(self, (self.max_prio, item))
	
    def should_sent(self, item):
	'''
	Little hack to avoid sending more than one None as it breaks sync (due to roundrobin queue)
	'''
	if (item is None and not self.none_send) \
	or (item is not None):
	    self.none_send = True if item is None else False
	    return True

	return False
	

class FuzzQueue(MyPriorityQueue, Thread):
    def __init__(self, queue_out, limit = 0, wait_qout = True):
	Thread.__init__(self)
        MyPriorityQueue.__init__(self, limit)

	self.queue_out = queue_out
	self.wait_qout = wait_qout

	self.setName(self.get_name())

	self.start()

    def process(self, prio, item):
	raise NotImplemented

    def get_name(self):
	raise NotImplemented

    def send_first(self, item):
	self.queue_out.put_first(item)

    def send_last(self, item):
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
	    self.send_first(e)
	else:
	    msg = "%s\n\n%s" %(str(e), traceback.format_exc())
	    self.send_first(FuzzException(FuzzException.FATAL, msg))

    def run(self):
	cancelling = False

	while 1:
	    prio, item = self.get(True, 365 * 24 * 60 * 60)

	    try:
		if item == None and not cancelling:
		    if self.wait_qout:
			self.send_last(None)
			self.qout_join()
		    self.task_done()
		    break
		elif item == None and cancelling:
		    self.send_last(None)
		    self.task_done()
		    break
		elif cancelling:
		    self.task_done()
		    continue
		elif isinstance(item, Exception):
		    cancelling = True if item.etype == FuzzException.SIGCANCEL else False
		    self.send_first(item)
		    self.task_done()
		    continue

		self.process(prio, item)
		self.task_done()
	    except Exception, e:
		self.task_done()
		self._throw(e)

	self._cleanup()

class FuzzListQueue(FuzzQueue):
    def __init__(self, queue_out, limit = 0, wait_qout = True):
        FuzzQueue.__init__(self, queue_out, limit, wait_qout)

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
