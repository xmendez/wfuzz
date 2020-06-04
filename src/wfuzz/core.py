from .fuzzobjects import FuzzType

from .myqueues import MyPriorityQueue, QueueManager
from .fuzzqueues import (
    SeedQ,
    SaveQ,
    PrinterQ,
    RoutingQ,
    FilterQ,
    SliceQ,
    JobQ,
    RecursiveQ,
    DryRunQ,
    HttpQueue,
    HttpReceiver,
    AllVarQ,
    CLIPrinterQ,
    ConsolePrinterQ,
    PassPayloadQ,
)


# python 2 and 3: iterator
from builtins import object


class Fuzzer(object):
    def __init__(self, options):
        # Create queues
        # genReq ---> seed_queue -> [slice_queue] -> http_queue/dryrun -> [round_robin -> plugins_queue] * N
        # -> [recursive_queue -> routing_queue] -> [filter_queue] -> [save_queue] -> [printer_queue] ---> results

        self.qmanager = QueueManager(options)
        self.results_queue = MyPriorityQueue()

        if options["allvars"]:
            self.qmanager.add("allvars_queue", AllVarQ(options))
        else:
            self.qmanager.add("seed_queue", SeedQ(options))

        for prefilter_idx, prefilter in enumerate(options.get("compiled_prefilter")):
            if prefilter.is_active():
                self.qmanager.add(
                    "slice_queue_{}".format(prefilter_idx), SliceQ(options, prefilter)
                )

        if options.get("transport") == "dryrun":
            self.qmanager.add("transport_queue", DryRunQ(options))
        elif options.get("transport") == "payload":
            self.qmanager.add("transport_queue", PassPayloadQ(options))
        else:
            # http_queue breaks process rules due to being asynchronous. Someone has to collects its sends, for proper fuzzqueue's count and sync purposes
            self.qmanager.add("transport_queue", HttpQueue(options))
            self.qmanager.add("http_receiver", HttpReceiver(options))

        if options.get("script"):
            self.qmanager.add("plugins_queue", JobQ(options))

        if options.get("script") or options.get("rlevel") > 0:
            self.qmanager.add("recursive_queue", RecursiveQ(options))
            rq = RoutingQ(
                options,
                {
                    FuzzType.SEED: self.qmanager["seed_queue"],
                    FuzzType.BACKFEED: self.qmanager["transport_queue"],
                },
            )

            self.qmanager.add("routing_queue", rq)

        if options.get("compiled_filter").is_active():
            self.qmanager.add(
                "filter_queue", FilterQ(options, options["compiled_filter"])
            )

        if options.get("compiled_simple_filter").is_active():
            self.qmanager.add(
                "simple_filter_queue",
                FilterQ(options, options["compiled_simple_filter"]),
            )

        if options.get("save"):
            self.qmanager.add("save_queue", SaveQ(options))

        if options.get("compiled_printer"):
            self.qmanager.add("printer_queue", PrinterQ(options))

        if options.get("exec_mode") == "cli":
            if options["console_printer"]:
                self.qmanager.add("printer_cli", ConsolePrinterQ(options))
            else:
                self.qmanager.add("printer_cli", CLIPrinterQ(options))

        self.qmanager.bind(self.results_queue)

        # initial seed request
        self.qmanager.start()

    def __iter__(self):
        return self

    def __next__(self):
        # http://bugs.python.org/issue1360
        res = self.results_queue.get()
        self.results_queue.task_done()

        # done! (None sent has gone through all queues).
        if not res:
            raise StopIteration
        elif res.item_type == FuzzType.ERROR:
            raise res.exception

        return res

    def stats(self):
        return dict(
            list(self.qmanager.get_stats().items())
            + list(self.qmanager["transport_queue"].job_stats().items())
            + list(self.options.stats.get_stats().items())
        )

    def cancel_job(self):
        self.qmanager.cancel()

    def pause_job(self):
        self.qmanager["transport_queue"].pause.clear()

    def resume_job(self):
        self.qmanager["transport_queue"].pause.set()
