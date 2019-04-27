import time
import pickle as pickle
import gzip
from threading import Thread, Event
from queue import Queue

from .fuzzobjects import FuzzResult
from .myqueues import FuzzQueue
from .exception import FuzzExceptInternalError, FuzzExceptBadOptions, FuzzExceptBadFile, FuzzExceptPluginLoadError, FuzzExceptPluginError
from .myqueues import FuzzRRQueue
from .facade import Facade
from .fuzzobjects import PluginResult, PluginItem


class SeedQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)
        self.delay = options.get("delay")
        self.genReq = options.get("compiled_genreq")

    def get_name(self):
        return 'SeedQ'

    def cancel(self):
        self.genReq.stop()

    def process(self, item):
        if item.type == FuzzResult.startseed:
            self.genReq.stats.pending_seeds.inc()
        elif item.type == FuzzResult.seed:
            self.genReq.restart(item)
        else:
            raise FuzzExceptInternalError("SeedQ: Unknown item type in queue!")

        # Empty dictionary?
        try:
            fuzzres = next(self.genReq)

            if fuzzres.is_baseline:
                self.genReq.stats.pending_fuzz.inc()
                self.send_first(fuzzres)

                # wait for BBB to be completed before generating more items
                while(self.genReq.stats.processed() == 0 and not self.genReq.stats.cancelled):
                    time.sleep(0.0001)

        except StopIteration:
            raise FuzzExceptBadOptions("Empty dictionary! Please check payload or filter.")

        # Enqueue requests
        try:
            if fuzzres.is_baseline:
                # more after baseline?
                fuzzres = next(self.genReq)

            while fuzzres:
                self.genReq.stats.pending_fuzz.inc()
                if self.delay:
                    time.sleep(self.delay)
                self.send(fuzzres)
                fuzzres = next(self.genReq)
        except StopIteration:
            pass

        self.send_last(FuzzResult.to_new_signal(FuzzResult.endseed))


class SaveQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)

        self.output_fn = None
        try:
            self.output_fn = gzip.open(options.get("save"), 'w+b')
        except IOError as e:
            raise FuzzExceptBadFile("Error opening results file!. %s" % str(e))

    def get_name(self):
        return 'SaveQ'

    def _cleanup(self):
        self.output_fn.close()

    def process(self, item):
        pickle.dump(item, self.output_fn)
        self.send(item)


class PrinterQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)

        self.printer = options.get("compiled_printer")
        self.printer.header(self.stats)

    def get_name(self):
        return 'PrinterQ'

    def _cleanup(self):
        self.printer.footer(self.stats)

    def process(self, item):
        self.printer.result(item)
        self.send(item)


class RoutingQ(FuzzQueue):
    def __init__(self, options, routes):
        FuzzQueue.__init__(self, options)
        self.routes = routes

    def get_name(self):
        return 'RoutingQ'

    def process(self, item):
        if item.type in self.routes:
            self.routes[item.type].put(item)
        else:
            self.queue_out.put(item)


class FilterQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)

        self.ffilter = options.get("compiled_filter")

    def get_name(self):
        return 'filter_thread'

    def process(self, item):
        if item.is_baseline:
            self.ffilter.set_baseline(item)

        if self.ffilter.is_visible(item) or item.is_baseline:
            self.send(item)
        else:
            self.discard(item)


class SliceQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)

        self.ffilter = options.get("compiled_prefilter")

    def get_name(self):
        return 'slice_thread'

    def process(self, item):
        if item.is_baseline or self.ffilter.is_visible(item):
            self.send(item)
        else:
            self.discard(item)


class JobQ(FuzzRRQueue):
    def __init__(self, options):
        # Get active plugins
        lplugins = [x() for x in Facade().scripts.get_plugins(options.get("script"))]

        if not lplugins:
            raise FuzzExceptBadOptions("No plugin selected, check the --script name or category introduced.")

        concurrent = int(Facade().sett.get('general', 'concurrent_plugins'))
        FuzzRRQueue.__init__(self, options, [JobMan(options, lplugins) for i in range(concurrent)])

    def get_name(self):
        return 'JobQ'

    def process(self, item):
        self.send(item)


class JobMan(FuzzQueue):
    def __init__(self, options, selected_plugins):
        FuzzQueue.__init__(self, options)
        self.__walking_threads = Queue(20)
        self.selected_plugins = selected_plugins
        self.cache = options.cache

    def get_name(self):
        return 'Jobman'

    # ------------------------------------------------
    # threading
    # ------------------------------------------------
    def process(self, res):
        # process request through plugins
        if not res.exception:
            if self.options['no_cache'] or self.cache.update_cache(res.history, "processed"):

                plugins_res_queue = Queue()

                for pl in self.selected_plugins:
                    try:
                        if not pl.validate(res):
                            continue
                        th = Thread(target=pl.run, kwargs={"fuzzresult": res, "control_queue": self.__walking_threads, "results_queue": plugins_res_queue})
                    except Exception as e:
                        raise FuzzExceptPluginLoadError("Error initialising plugin %s: %s " % (pl.name, str(e)))
                    self.__walking_threads.put(th)
                    th.start()

                self.__walking_threads.join()

                while not plugins_res_queue.empty():
                    item = plugins_res_queue.get()

                    if item.plugintype == PluginItem.result:
                        if Facade().sett.get("general", "cancel_on_plugin_except") == "1" and item.source == "$$exception$$":
                            self._throw(FuzzExceptPluginError(item.issue))
                        res.plugins_res.append(item)
                    elif item.plugintype == PluginItem.backfeed:
                        if self.options['no_cache'] or self.cache.update_cache(item.fuzzitem.history, "backfeed"):
                            res.plugins_backfeed.append(item)
                    else:
                        raise FuzzExceptInternalError("Jobman: Unknown pluginitem type in queue!")

        # add result to results queue
        self.send(res)


class RecursiveQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)

        self.cache = options.cache
        self.max_rlevel = options.get("rlevel")

    def get_name(self):
        return 'RecursiveQ'

    def process(self, fuzz_res):
        # Getting results from plugins or directly from http if not activated
        enq_item = 0
        plugin_name = ""

        # Check for plugins new enqueued requests
        while fuzz_res.plugins_backfeed:
            plg_backfeed = fuzz_res.plugins_backfeed.pop()
            plugin_name = plg_backfeed.source

            self.stats.backfeed.inc()
            self.stats.pending_fuzz.inc()
            self.send(plg_backfeed.fuzzitem)
            enq_item += 1

        if enq_item > 0:
            plres = PluginResult()
            plres.source = "Backfeed"
            fuzz_res.plugins_res.append(plres)
            plres.issue = "Plugin %s enqueued %d more requests (rlevel=%d)" % (plugin_name, enq_item, fuzz_res.rlevel)

        # check if recursion is needed
        if self.max_rlevel >= fuzz_res.rlevel and fuzz_res.history.is_path:
            if self.cache.update_cache(fuzz_res.history, "recursion"):
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
        self.stats.pending_seeds.inc()
        self.send(res.to_new_seed())


class DryRunQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)
        self.pause = Event()

    def get_name(self):
        return 'DryRunQ'

    def process(self, item):
        self.send(item)


class HttpQueue(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options, limit=options.get("concurrent") * 5)

        self.http_pool = options.http_pool

        self.pause = Event()
        self.pause.set()
        self.exit_job = False

    def cancel(self):
        self.pause.set()

    def mystart(self):
        self.poolid = self.http_pool.register()

        th2 = Thread(target=self.__read_http_results)
        th2.setName('__read_http_results')
        th2.start()

    def get_name(self):
        return 'HttpQueue'

    def _cleanup(self):
        self.http_pool.deregister()
        self.exit_job = True

    def process(self, obj):
        self.pause.wait()
        self.http_pool.enqueue(obj, self.poolid)

    def __read_http_results(self):
        try:
            while not self.exit_job:
                res = next(self.http_pool.iter_results(self.poolid))
                self.send(res)
        except StopIteration:
            pass


class HttpReceiver(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options, limit=options.get("concurrent") * 5)

    def get_name(self):
        return 'HttpReceiver'

    def process(self, res):
        if res.exception and not self.options.get("scanmode"):
            self._throw(res.exception)
        else:
            self.send(res)
