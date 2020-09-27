import time
import pickle as pickle
import gzip
from threading import Thread, Event
from queue import Queue
from collections import defaultdict

from .factories.fuzzresfactory import resfactory
from .factories.plugin_factory import plugin_factory
from .fuzzobjects import FuzzType, FuzzItem
from .myqueues import FuzzQueue
from .exception import (
    FuzzExceptInternalError,
    FuzzExceptBadOptions,
    FuzzExceptBadFile,
    FuzzExceptPluginLoadError,
)
from .myqueues import FuzzRRQueue
from .facade import Facade
from .fuzzobjects import FuzzWordType
from .ui.console.mvc import View


class AllVarQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)
        self.delay = options.get("delay")
        self.seed = options["compiled_seed"]

    def get_name(self):
        return "AllVarQ"

    def cancel(self):
        self.options["compiled_stats"].cancelled = True

    def items_to_process(self, item):
        return item.item_type in [FuzzType.STARTSEED]

    def process(self, item):
        self.stats.pending_seeds.inc()

        for var_name, payload in self.options["compiled_dictio"]:
            if self.options["compiled_stats"].cancelled:
                break
            self.stats.pending_fuzz.inc()
            if self.delay:
                time.sleep(self.delay)
            self.send(
                resfactory.create(
                    "fuzzres_from_allvar", self.options, var_name.content, payload
                )
            )

        self.send_last(FuzzItem(FuzzType.ENDSEED))


class SeedQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)
        self.delay = options.get("delay")

    def get_name(self):
        return "SeedQ"

    def cancel(self):
        self.options["compiled_stats"].cancelled = True

    def items_to_process(self, item):
        return item.item_type in [FuzzType.STARTSEED, FuzzType.SEED]

    def send_baseline(self):
        fuzz_baseline = self.options["compiled_baseline"]

        if fuzz_baseline is not None and self.stats.pending_seeds() == 1:
            self.stats.pending_fuzz.inc()
            self.send_first(fuzz_baseline)

            # wait for BBB to be completed before generating more items
            while self.stats.processed() == 0 and not self.stats.cancelled:
                time.sleep(0.0001)

    def restart(self, seed):
        self.options["compiled_seed"] = seed
        self.options.compile_dictio()

    def process(self, item):
        if item.item_type == FuzzType.STARTSEED:
            self.stats.pending_seeds.inc()
        elif item.item_type == FuzzType.SEED:
            self.restart(item)
        else:
            raise FuzzExceptInternalError("SeedQ: Unknown item type in queue!")

        self.send_baseline()
        self.send_dictionary()

    def get_fuzz_res(self, dictio_item):
        if self.options["seed_payload"] and dictio_item[0].type == FuzzWordType.FUZZRES:
            return resfactory.create(
                "seed_from_options_and_dict", self.options, dictio_item
            )
        else:
            return resfactory.create(
                "fuzzres_from_options_and_dict", self.options, dictio_item
            )

    def send_dictionary(self):
        # Empty dictionary?
        try:
            fuzzres = next(self.options["compiled_dictio"])
        except StopIteration:
            raise FuzzExceptBadOptions(
                "Empty dictionary! Please check payload or filter."
            )

        # Enqueue requests
        try:
            while fuzzres:
                if self.options["compiled_stats"].cancelled:
                    break
                self.stats.pending_fuzz.inc()
                if self.delay:
                    time.sleep(self.delay)
                self.send(self.get_fuzz_res(fuzzres))
                fuzzres = next(self.options["compiled_dictio"])
        except StopIteration:
            pass

        self.send_last(FuzzItem(FuzzType.ENDSEED))


class SaveQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)

        self.output_fn = None
        try:
            self.output_fn = gzip.open(options.get("save"), "w+b")
        except IOError as e:
            raise FuzzExceptBadFile("Error opening results file!. %s" % str(e))

    def get_name(self):
        return "SaveQ"

    def _cleanup(self):
        self.output_fn.close()

    def process(self, item):
        pickle.dump(item, self.output_fn)
        self.send(item)


class ConsolePrinterQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)
        self.printer = Facade().printers.get_plugin(self.options["console_printer"])(
            None
        )

    def mystart(self):
        self.printer.header(self.stats)

    def items_to_process(self, item):
        return item.item_type in [FuzzType.RESULT]

    def get_name(self):
        return "ConsolePrinterQ"

    def _cleanup(self):
        self.printer.footer(self.stats)

    def process(self, item):
        self.printer.result(item)
        self.send(item)


class CLIPrinterQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)
        self.printer = View(self.options)

    def mystart(self):
        self.printer.header(self.stats)

    def items_to_process(self, item):
        return item.item_type in [FuzzType.RESULT, FuzzType.DISCARDED]

    def get_name(self):
        return "CLIPrinterQ"

    def _cleanup(self):
        self.printer.footer(self.stats)

    def process(self, item):
        self.printer.result(item)
        self.send(item)


class PrinterQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)

        self.printer = options.get("compiled_printer")
        self.printer.header(self.stats)

    def get_name(self):
        return "PrinterQ"

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
        return "RoutingQ"

    def items_to_process(self, item):
        return item.item_type in [FuzzType.SEED, FuzzType.BACKFEED]

    def process(self, item):
        if item.item_type in self.routes:
            self.routes[item.item_type].put(item)
        else:
            self.queue_out.put(item)


class FilterQ(FuzzQueue):
    def __init__(self, options, ffilter):
        FuzzQueue.__init__(self, options)

        self.ffilter = ffilter

    def get_name(self):
        return "filter_thread"

    def process(self, item):
        if item.is_baseline:
            self.ffilter.set_baseline(item)

        if self.ffilter.is_visible(item) or item.is_baseline:
            self.send(item)
        else:
            self.discard(item)


class SliceQ(FuzzQueue):
    def __init__(self, options, prefilter):
        FuzzQueue.__init__(self, options)

        self.ffilter = prefilter

    def get_name(self):
        return "slice_thread"

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
            raise FuzzExceptBadOptions(
                "No plugin selected, check the --script name or category introduced."
            )

        concurrent = int(Facade().sett.get("general", "concurrent_plugins"))
        FuzzRRQueue.__init__(
            self, options, [JobMan(options, lplugins) for i in range(concurrent)]
        )

    def get_name(self):
        return "JobQ"

    def process(self, item):
        self.send(item)


class JobMan(FuzzQueue):
    def __init__(self, options, selected_plugins):
        FuzzQueue.__init__(self, options)
        self.__walking_threads = Queue(20)
        self.selected_plugins = selected_plugins
        self.cache = options.cache
        self.max_dlevel = options.get("dlevel")

    def get_name(self):
        return "Jobman"

    # ------------------------------------------------
    # threading
    # ------------------------------------------------
    def process(self, res):
        # process request through plugins
        if not res.exception:
            if self.options["no_cache"] or self.cache.update_cache(
                res.history, "processed"
            ):

                plugins_res_queue = Queue()

                for pl in self.selected_plugins:
                    try:
                        if not pl.validate(res):
                            continue
                        th = Thread(
                            target=pl.run,
                            kwargs={
                                "fuzzresult": res,
                                "control_queue": self.__walking_threads,
                                "results_queue": plugins_res_queue,
                            },
                        )
                    except Exception as e:
                        raise FuzzExceptPluginLoadError(
                            "Error initialising plugin %s: %s " % (pl.name, str(e))
                        )
                    self.__walking_threads.put(th)
                    th.start()

                self.__walking_threads.join()

                self.process_results(res, plugins_res_queue)

        # add result to results queue
        self.send(res)

    def process_results(self, res, plugins_res_queue):
        enq_item = defaultdict(int)

        while not plugins_res_queue.empty():
            item = plugins_res_queue.get()

            if item._exception is not None:
                if Facade().sett.get("general", "cancel_on_plugin_except") == "1":
                    self._throw(item._exception)
                res.plugins_res.append(item)
            elif item._seed is not None:
                cache_hit = self.cache.update_cache(item._seed.history, "backfeed")
                if (self.options["no_cache"] or cache_hit) and (
                    self.max_dlevel == 0 or self.max_dlevel >= res.rlevel
                ):
                    self.stats.backfeed.inc()
                    self.stats.pending_fuzz.inc()
                    self.send(item._seed)
                    enq_item[item.source] += 1
            else:
                res.plugins_res.append(item)

        for plugin_name, enq_num in enq_item.items():
            res.plugins_res.append(
                plugin_factory.create(
                    "plugin_from_finding",
                    "Backfeed",
                    "Plugin %s enqueued %d more requests (rlevel=%d)"
                    % (plugin_name, enq_num, res.rlevel),
                )
            )


class RecursiveQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)

        self.cache = options.cache
        self.max_rlevel = options.get("rlevel")

    def get_name(self):
        return "RecursiveQ"

    def process(self, fuzz_res):
        # check if recursion is needed
        if self.max_rlevel >= fuzz_res.rlevel and fuzz_res.history.is_path:
            if self.cache.update_cache(fuzz_res.history, "recursion"):
                self.stats.pending_seeds.inc()
                seed = resfactory.create("seed_from_recursion", fuzz_res)
                self.send(seed)

                fuzz_res.plugins_res.append(
                    plugin_factory.create(
                        "plugin_from_finding",
                        "Recursion",
                        "Enqueued response for recursion (level=%d)" % (seed.rlevel),
                    )
                )

        # send new result
        self.send(fuzz_res)


class PassPayloadQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)
        self.pause = Event()

    def get_name(self):
        return "PassPayloadQ"

    def process(self, item):
        if item.payload_man.get_payload_type(1) == FuzzWordType.FUZZRES:
            item = item.payload_man.get_payload_content(1)
            item.update_from_options(self.options)

        self.send(item)


class DryRunQ(FuzzQueue):
    def __init__(self, options):
        FuzzQueue.__init__(self, options)
        self.pause = Event()

    def get_name(self):
        return "DryRunQ"

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
        th2.setName("__read_http_results")
        th2.start()

    def get_name(self):
        return "HttpQueue"

    def _cleanup(self):
        self.http_pool.deregister()
        self.exit_job = True

    def items_to_process(self, item):
        return item.item_type in [FuzzType.RESULT, FuzzType.BACKFEED]

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
        return "HttpReceiver"

    def process(self, res):
        if res.exception and not self.options.get("scanmode"):
            self._throw(res.exception)
        else:
            self.send(res)
