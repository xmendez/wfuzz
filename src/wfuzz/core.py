from .fuzzfactory import reqfactory
from .fuzzobjects import FuzzType, FuzzResult

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
    CLIPrinterQ
)

from .facade import Facade
from .exception import FuzzExceptBadOptions, FuzzExceptNoPluginError

from .filter import FuzzResFilterSlice

# Python 2 and 3: zip_longest
try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest


# python 2 and 3: iterator
from builtins import object


class sliceit(object):
    def __init__(self, payload, slicestr):
        self.ffilter = FuzzResFilterSlice(filter_string=slicestr)
        self.payload = payload

    def __iter__(self):
        return self

    def count(self):
        return -1

    def __next__(self):
        item = next(self.payload)
        while not self.ffilter.is_visible(item):
            item = next(self.payload)

        return item


class tupleit(object):
    def __init__(self, parent):
        self.parent = parent

    def count(self):
        return self.parent.count()

    def __next__(self):
        return (next(self.parent),)

    def __iter__(self):
        return self


class dictionary(object):
    def __init__(self, payload, encoders_list):
        self.__payload = payload
        self.__encoders = encoders_list
        self.__generator = self._gen() if self.__encoders else None

    def count(self):
        return (self.__payload.count() * len(self.__encoders)) if self.__encoders else self.__payload.count()

    def __iter__(self):
        return self

    def _gen(self):
        while 1:
            try:
                payload_list = next(self.__payload)
            except StopIteration:
                return

            for name in self.__encoders:
                if name.find('@') > 0:
                    string = payload_list
                    for i in reversed(name.split("@")):
                        string = Facade().encoders.get_plugin(i)().encode(string)
                    yield string
                else:
                    plugin_list = Facade().encoders.get_plugins(name)
                    if not plugin_list:
                        raise FuzzExceptNoPluginError(name + " encoder does not exists (-e encodings for a list of available encoders)")

                    for e in plugin_list:
                        yield e().encode(payload_list)

    def __next__(self):
        return next(self.__generator) if self.__encoders else next(self.__payload)


class requestGenerator(object):
    def __init__(self, options):
        self.options = options
        self.seed = options["compiled_seed"]
        self.baseline = options["compiled_baseline"]
        self._payload_list = []
        self.dictio = self.get_dictio()

    def stop(self):
        self.options["compiled_stats"].cancelled = True
        self.close()

    def restart(self, seed):
        self.options["compiled_seed"] = seed
        self.options["compiled_seed"].payload_man = reqfactory.create("seed_payloadman_from_request", seed.history)
        self.seed = self.options["compiled_seed"]
        self.dictio = self.get_dictio()

    def _check_dictio_len(self, element):
        if len(element) != len(self.options.get_fuzz_words()):
            raise FuzzExceptBadOptions("FUZZ words and number of payloads do not match!")

    def count(self):
        v = self.dictio.count()
        if self.seed.history.wf_allvars is not None:
            v *= len(self.seed.history.wf_allvars_set)

        if self.baseline:
            v += 1

        return v

    def __iter__(self):
        return self

    def __next__(self):
        if self.options["compiled_stats"].cancelled:
            raise StopIteration

        dictio_item = next(self.dictio)
        if self.options["compiled_stats"].processed() == 0 or (self.baseline and self.options["compiled_stats"].processed() == 1):
            self._check_dictio_len(dictio_item)

        if self.options["seed_payload"] and isinstance(dictio_item[0], FuzzResult):
            new_seed = dictio_item[0].from_soft_copy()
            new_seed.history.update_from_options(self.options)
            new_seed.update_from_options(self.options)
            new_seed.payload_man = reqfactory.create("empty_payloadman", dictio_item)

            return new_seed
        else:
            return reqfactory.create("fuzzres_from_options_and_dict", self.options, dictio_item)

    def close(self):
        for payload in self._payload_list:
            payload.close()

    def get_dictio(self):
        class wrapper(object):
            def __init__(self, iterator):
                self._it = iter(iterator)

            def __iter__(self):
                return self

            def count(self):
                return -1

            def __next__(self):
                return str(next(self._it))

        selected_dic = []
        self._payload_list = []

        if self.options["dictio"]:
            for d in [wrapper(x) for x in self.options["dictio"]]:
                selected_dic.append(d)
        else:
            for payload in self.options["payloads"]:
                try:
                    name, params, slicestr = [x[0] for x in zip_longest(payload, (None, None, None))]
                except ValueError:
                    raise FuzzExceptBadOptions("You must supply a list of payloads in the form of [(name, {params}), ... ]")

                if not params:
                    raise FuzzExceptBadOptions("You must supply a list of payloads in the form of [(name, {params}), ... ]")

                p = Facade().payloads.get_plugin(name)(params)
                self._payload_list.append(p)
                pp = dictionary(p, params["encoder"]) if "encoder" in params else p
                selected_dic.append(sliceit(pp, slicestr) if slicestr else pp)

        if not selected_dic:
            raise FuzzExceptBadOptions("Empty dictionary! Check payload and filter")

        if len(selected_dic) == 1:
            if self.options["iterator"]:
                raise FuzzExceptBadOptions("Several dictionaries must be used when specifying an iterator")
            return tupleit(selected_dic[0])
        elif self.options["iterator"]:
            return Facade().iterators.get_plugin(self.options["iterator"])(*selected_dic)
        else:
            return Facade().iterators.get_plugin("product")(*selected_dic)


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

        for prefilter_idx, prefilter in enumerate(options.get('compiled_prefilter')):
            if prefilter.is_active():
                self.qmanager.add("slice_queue_{}".format(prefilter_idx), SliceQ(options, prefilter))

        if options.get("transport") == "dryrun":
            self.qmanager.add("http_queue", DryRunQ(options))
        else:
            # http_queue breaks process rules due to being asynchronous. Someone has to collects its sends, for proper fuzzqueue's count and sync purposes
            self.qmanager.add("http_queue", HttpQueue(options))
            self.qmanager.add("http_receiver", HttpReceiver(options))

        if options.get("script"):
            self.qmanager.add("plugins_queue", JobQ(options))

        if options.get("script") or options.get("rlevel") > 0:
            self.qmanager.add("recursive_queue", RecursiveQ(options))
            rq = RoutingQ(
                options,
                {
                    FuzzType.SEED: self.qmanager["seed_queue"],
                    FuzzType.BACKFEED: self.qmanager["http_queue"]
                }
            )

            self.qmanager.add("routing_queue", rq)

        if options.get('compiled_filter').is_active():
            self.qmanager.add("filter_queue", FilterQ(options))

        if options.get('save'):
            self.qmanager.add("save_queue", SaveQ(options))

        if options.get('compiled_printer'):
            self.qmanager.add("printer_queue", PrinterQ(options))

        if options.get('exec_mode') == "cli":
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
        return dict(list(self.qmanager.get_stats().items()) + list(self.qmanager["http_queue"].job_stats().items()) + list(self.options.stats.get_stats().items()))

    def cancel_job(self):
        self.qmanager.cancel()

    def pause_job(self):
        self.qmanager["http_queue"].pause.clear()

    def resume_job(self):
        self.qmanager["http_queue"].pause.set()
