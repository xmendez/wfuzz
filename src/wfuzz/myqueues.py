import collections

# python 2 and 3
try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest

from queue import PriorityQueue
from threading import Thread, RLock
from .fuzzobjects import FuzzError, FuzzType, FuzzItem

from .exception import FuzzException, FuzzExceptInternalError


class MyPriorityQueue(PriorityQueue):
    def __init__(self, limit=0):
        PriorityQueue.__init__(self, limit)

        self.max_prio = 0

    def _put_priority(self, prio, item, wait):
        self.max_prio = max(prio, self.max_prio)
        PriorityQueue.put(self, (prio, item), wait)

    def put(self, item, wait=True):
        self._put_priority(item.rlevel, item, wait)

    def put_first(self, item, wait=True):
        self._put_priority(0, item, wait)

    def put_last(self, item, wait=True):
        self._put_priority(self.max_prio + 1, item, wait)

    def get(self):
        prio, item = PriorityQueue.get(self, True)

        return item


class FuzzQueue(MyPriorityQueue, Thread):
    def __init__(self, options, queue_out=None, limit=0):
        MyPriorityQueue.__init__(self, limit)
        self.queue_out = queue_out
        self.duplicated = False
        self.syncq = None

        self.stats = options.get("compiled_stats")
        self.options = options

        Thread.__init__(self)
        self.setName(self.get_name())

    def next_queue(self, q):
        self.queue_out = q

    def process(self, item):
        raise NotImplementedError

    def get_name(self):
        raise NotImplementedError

    def process_discarded(self):
        return False

    def items_to_process(self):
        return [FuzzType.RESULT]

    # Override this method if needed. This will be called just before cancelling the job.
    def cancel(self):
        pass

    # Override this method if needed. This will be called just before starting the job.
    def mystart(self):
        pass

    def set_syncq(self, q):
        self.syncq = q

    def qstart(self):
        self.mystart()
        self.start()

    def send_first(self, item):
        self.queue_out.put_first(item)

    def send_last(self, item):
        self.queue_out.put_last(item)

    def qout_join(self):
        self.queue_out.join()

    def send(self, item):
        self.queue_out.put(item)

    def discard(self, item):
        item.discarded = True
        self.send(item)

    def join(self):
        MyPriorityQueue.join(self)

    def tjoin(self):
        Thread.join(self)

    # Override this method if needed. This will be called after job's thread dies.
    def _cleanup(self):
        pass

    def _throw(self, e):
        self.syncq.put_first(FuzzError(e))

    def get_stats(self):
        return {self.get_name(): self.qsize()}

    def run(self):
        cancelling = False

        while 1:
            item = self.get()

            try:
                if item is None:
                    if not self.duplicated:
                        self.send_last(None)
                    self.task_done()
                    break
                elif cancelling:
                    self.task_done()
                    continue
                elif item.item_type == FuzzType.STARTSEED:
                    self.stats.mark_start()
                elif item.item_type == FuzzType.ENDSEED:
                    if not self.duplicated:
                        self.send_last(item)
                    self.task_done()
                    continue
                elif item.item_type == FuzzType.CANCEL:
                    cancelling = True
                    self.send_first(item)
                    self.task_done()
                    continue

                if (
                    not item.discarded or (item.discarded and self.process_discarded())
                ) and item.item_type in self.items_to_process():
                    self.process(item)
                else:
                    self.send(item)

                self.task_done()
            except Exception as e:
                self.task_done()
                self._throw(e)

        self._cleanup()


class LastFuzzQueue(FuzzQueue):
    def __init__(self, options, queue_out=None, limit=0):
        FuzzQueue.__init__(self, options, queue_out, limit)

    def get_name(self):
        return "LastFuzzQueue"

    def process(self):
        pass

    def _cleanup(self):
        pass

    def _throw(self, e):
        self.queue_out.put_first(FuzzError(e))

    def run(self):
        cancelling = False

        while 1:
            item = self.get()

            try:
                self.task_done()

                if item is None:
                    break
                elif cancelling:
                    continue
                elif item.item_type == FuzzType.ERROR:
                    self.qmanager.cancel()
                    self.send_first(item)
                    continue
                elif item.item_type == FuzzType.CANCEL:
                    cancelling = True
                    continue

                if item.item_type == FuzzType.RESULT and not item.discarded:
                    self.send(item)

                if item.item_type == FuzzType.ENDSEED:
                    self.stats.pending_seeds.dec()
                elif item.item_type == FuzzType.RESULT:
                    self.stats.processed.inc()
                    self.stats.pending_fuzz.dec()
                    if item.discarded:
                        self.stats.filtered.inc()

                if self.stats.pending_fuzz() == 0 and self.stats.pending_seeds() == 0:
                    self.qmanager.cleanup()

            except Exception as e:
                self._throw(e)
                self.qmanager.cancel()

        self._cleanup()


class FuzzListQueue(FuzzQueue):
    def __init__(self, options, queues_out, limit=0):
        FuzzQueue.__init__(self, options, queues_out, limit)

        # not to propagate a None/Exception to various queueas at the same level, only propagate through one queue
        for q in self.queue_out[1:]:
            q.duplicated = True

    def set_syncq(self, q):
        for q in self.queue_out:
            q.syncq = q

    def qstart(self):
        for q in self.queue_out:
            q.mystart()
            q.start()
        self.start()

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
        stat_list = []

        for qq in self.queue_out:
            stat_list = stat_list + list(qq.get_stats().items())

        stat_list = stat_list + list(FuzzQueue.get_stats(self).items())

        return dict(stat_list)


class FuzzRRQueue(FuzzListQueue):
    def __init__(self, options, queues_out, limit=0):
        FuzzListQueue.__init__(self, options, queues_out, limit)
        self._next_queue = self._get_next_route()

    def send(self, item):
        next(self._next_queue).put(item)

    def _get_next_route(self):
        i = 0
        while 1:
            yield self.queue_out[i]
            i += 1
            i = i % len(self.queue_out)


class QueueManager:
    def __init__(self, options):
        self._queues = collections.OrderedDict()
        self._lastq = None
        self._syncq = None
        self._mutex = RLock()

        self.options = options

    def add(self, name, q):
        self._queues[name] = q

    def bind(self, lastq):
        with self._mutex:

            queue_list = list(self._queues.values())
            self._lastq = lastq

            self._syncq = LastFuzzQueue(self.options, lastq)
            self._syncq.qmanager = self

            for first, second in zip_longest(queue_list[0:-1:1], queue_list[1::1]):
                first.next_queue(second)
                first.set_syncq(self._syncq)

            queue_list[-1].next_queue(self._syncq)
            queue_list[-1].set_syncq(self._syncq)

    def __getitem__(self, key):
        return self._queues[key]

    def join(self, remove=False):
        with self._mutex:
            for k, q in list(self._queues.items()):
                q.join()
                if remove:
                    del self._queues[k]

    def start(self):
        with self._mutex:
            if self._queues:
                self._syncq.qstart()
                for q in list(self._queues.values()):
                    q.qstart()

                list(self._queues.values())[0].put_first(FuzzItem(FuzzType.STARTSEED))

    def cleanup(self):
        with self._mutex:
            if self._queues:
                list(self._queues.values())[0].put_last(None)
                self.join(remove=True)
                self.options.get("compiled_stats").mark_end()
                self._lastq.put_last(None, wait=False)

                self._queues = collections.OrderedDict()
                self._lastq = None

    def cancel(self):
        with self._mutex:
            if self._queues:
                # stop processing pending items
                for q in list(self._queues.values()):
                    q.cancel()
                    q.put_first(FuzzItem(FuzzType.CANCEL))

                # wait for cancel to be processed
                self.join()

                # send None to stop (almost nicely)
                self.cleanup()

    def get_stats(self):
        stat_list = []

        for q in list(self._queues.values()):
            stat_list = stat_list + list(q.get_stats().items())

        return dict(stat_list)
