from .exception import (
    FuzzExceptBadRecipe,
    FuzzExceptBadOptions,
    FuzzExceptBadFile,
)
from .facade import (
    Facade,
    ERROR_CODE,
    BASELINE_CODE,
)

from .factories.fuzzresfactory import resfactory
from .factories.dictfactory import dictionary_factory
from .fuzzobjects import FuzzStats
from .filters.ppfilter import FuzzResFilter
from .filters.simplefilter import FuzzResSimpleFilter
from .helpers.str_func import (
    json_minify,
    python2_3_convert_from_unicode,
)

from .core import Fuzzer
from .myhttp import HttpPool

from .externals.reqresp.cache import HttpCache

from collections import defaultdict

# python 2 and 3
try:
    from collections import UserDict
except ImportError:
    from UserDict import UserDict

import json


class FuzzSession(UserDict):
    def __init__(self, **kwargs):
        self.data = self._defaults()
        self.keys_not_to_dump = [
            "interactive",
            "recipe",
            "seed_payload",
            "compiled_stats",
            "compiled_dictio",
            "compiled_simple_filter",
            "compiled_filter",
            "compiled_prefilter",
            "compiled_printer",
            "description",
            "show_field",
            "transport",
        ]

        # recipe must be superseded by options
        if "recipe" in kwargs and kwargs["recipe"]:
            for recipe in kwargs["recipe"]:
                self.import_from_file(recipe)

        self.update(kwargs)

        self.cache = HttpCache()
        self.http_pool = None

        self.stats = FuzzStats()

    def _defaults(self):
        return dict(
            console_printer="",
            hs=None,
            hc=[],
            hw=[],
            hl=[],
            hh=[],
            ss=None,
            sc=[],
            sw=[],
            sl=[],
            sh=[],
            payloads=None,
            iterator=None,
            printer=(None, None),
            colour=False,
            previous=False,
            verbose=False,
            interactive=False,
            transport="http",
            recipe=[],
            save="",
            proxies=None,
            conn_delay=int(Facade().sett.get("connection", "conn_delay")),
            req_delay=int(Facade().sett.get("connection", "req_delay")),
            retries=int(Facade().sett.get("connection", "retries")),
            rlevel=0,
            dlevel=4,
            scanmode=False,
            delay=None,
            concurrent=int(Facade().sett.get("connection", "concurrent")),
            url="",
            method=None,
            auth={},
            follow=False,
            postdata=None,
            headers=[],
            cookie=[],
            allvars=None,
            script="",
            script_args={},
            connect_to_ip=None,
            fields=[],
            no_cache=False,
            show_field=None,
            # this is equivalent to payloads but in a different format
            dictio=None,
            # these will be compiled
            seed_payload=False,
            filter="",
            prefilter=[],
            compiled_filter=None,
            compiled_prefilter=[],
            compiled_printer=None,
            compiled_seed=None,
            compiled_baseline=None,
            compiled_stats=None,
            compiled_dictio=None,
            exec_mode="api",
        )

    def update(self, options):
        self.data.update(options)

    def validate(self):
        error_list = []

        if self.data["dictio"] and self.data["payloads"]:
            raise FuzzExceptBadOptions(
                "Bad usage: Dictio and payloads options are mutually exclusive. Only one could be specified."
            )

        if self.data["rlevel"] > 0 and self.data["transport"] == "dryrun":
            error_list.append(
                "Bad usage: Recursion cannot work without making any HTTP request."
            )

        if self.data["script"] and self.data["transport"] == "dryrun":
            error_list.append(
                "Bad usage: Plugins cannot work without making any HTTP request."
            )

        if self.data["no_cache"] not in [True, False]:
            raise FuzzExceptBadOptions("Bad usage: No-cache is a boolean value")

        if not self.data["url"]:
            error_list.append("Bad usage: You must specify an URL.")

        if not self.data["payloads"] and not self.data["dictio"]:
            error_list.append("Bad usage: You must specify a payload.")

        if self.data["hs"] and self.data["ss"]:
            raise FuzzExceptBadOptions(
                "Bad usage: Hide and show regex filters flags are mutually exclusive. Only one could be specified."
            )

        if self.data["rlevel"] < 0:
            raise FuzzExceptBadOptions(
                "Bad usage: Recursion level must be a positive int."
            )

        if self.data["allvars"] not in [None, "allvars", "allpost", "allheaders"]:
            raise FuzzExceptBadOptions(
                "Bad options: Incorrect all parameters brute forcing type specified, correct values are allvars,allpost or allheaders."
            )

        if self.data["proxies"]:
            for ip, port, ttype in self.data["proxies"]:
                if ttype not in ("SOCKS5", "SOCKS4", "HTTP"):
                    raise FuzzExceptBadOptions(
                        "Bad proxy type specified, correct values are HTTP, SOCKS4 or SOCKS5."
                    )

        return error_list

    def export_to_file(self, filename):
        try:
            with open(filename, "w") as f:
                f.write(self.export_json())
        except IOError:
            raise FuzzExceptBadFile("Error writing recipe file.")

    def import_from_file(self, filename):
        try:
            with open(filename, "r") as f:
                self.import_json(f.read())
        except IOError:
            raise FuzzExceptBadFile("Error loading recipe file {}.".format(filename))
        except json.decoder.JSONDecodeError as e:
            raise FuzzExceptBadRecipe(
                "Incorrect JSON recipe {} format: {}".format(filename, str(e))
            )

    def import_json(self, data):
        js = json.loads(json_minify(data))

        try:
            if js["version"] == "0.2" and "wfuzz_recipe" in js:
                for k, v in js["wfuzz_recipe"].items():
                    if k not in self.keys_not_to_dump:
                        # python 2 and 3 hack
                        if k in self.data and isinstance(self.data[k], list):
                            self.data[k] += python2_3_convert_from_unicode(v)
                        else:
                            self.data[k] = python2_3_convert_from_unicode(v)
            else:
                raise FuzzExceptBadRecipe("Unsupported recipe version.")
        except KeyError:
            raise FuzzExceptBadRecipe("Incorrect recipe format.")

    def export_json(self):
        tmp = dict(version="0.2", wfuzz_recipe=defaultdict(dict))
        defaults = self._defaults()

        # Only dump the non-default options
        for k, v in self.data.items():
            if v != defaults[k] and k not in self.keys_not_to_dump:
                tmp["wfuzz_recipe"][k] = self.data[k]

        return json.dumps(tmp, sort_keys=True, indent=4, separators=(",", ": "))

    def payload(self, **kwargs):
        try:
            self.data.update(kwargs)
            self.compile_seeds()
            self.compile_dictio()
            for r in self.data["compiled_dictio"]:
                yield tuple((fuzz_word.content for fuzz_word in r))
        finally:
            self.data["compiled_dictio"].cleanup()

    def fuzz(self, **kwargs):
        self.data.update(kwargs)

        fz = None
        try:
            fz = Fuzzer(self.compile())

            for f in fz:
                yield f

        finally:
            if fz:
                fz.cancel_job()
                self.stats.update(self.data["compiled_stats"])

            if self.http_pool:
                self.http_pool.deregister()
                self.http_pool = None

    def get_payloads(self, iterator):
        self.data["dictio"] = iterator

        return self

    def get_payload(self, iterator):
        return self.get_payloads([iterator])

    def __enter__(self):
        self.http_pool = HttpPool(self)
        self.http_pool.register()
        return self

    def __exit__(self, *args):
        self.close()

    def get_fuzz_words(self):
        fuzz_words = self.data["compiled_filter"].get_fuzz_words()

        for comp_obj in ["compiled_seed", "compiled_baseline"]:
            if self.data[comp_obj]:
                fuzz_words += self.data[comp_obj].payload_man.get_fuzz_words()

        for prefilter in self.data["compiled_prefilter"]:
            fuzz_words += prefilter.get_fuzz_words()

        if self.data["url"] == "FUZZ":
            fuzz_words.append("FUZZ")

        return set(fuzz_words)

    def compile_dictio(self):
        if self.data["allvars"]:
            self.data["compiled_dictio"] = dictionary_factory.create(
                "dictio_from_allvar", self
            )
        else:
            self.data["compiled_dictio"] = dictionary_factory.create(
                "dictio_from_options", self
            )

    def compile_seeds(self):
        self.data["compiled_seed"] = resfactory.create("seed_from_options", self)
        self.data["compiled_baseline"] = resfactory.create(
            "baseline_from_options", self
        )

    def compile(self):
        # Validate options
        error = self.validate()
        if error:
            raise FuzzExceptBadOptions(error[0])

        self.data["seed_payload"] = True if self.data["url"] == "FUZZ" else False

        # printer
        try:
            filename, printer = self.data["printer"]
        except ValueError:
            raise FuzzExceptBadOptions(
                "Bad options: Printer must be specified in the form of ('filename', 'printer')"
            )

        if filename:
            if printer == "default" or not printer:
                printer = Facade().sett.get("general", "default_printer")
            self.data["compiled_printer"] = Facade().printers.get_plugin(printer)(
                filename
            )

        try:
            for filter_option in ["hc", "hw", "hl", "hh", "sc", "sw", "sl", "sh"]:
                self.data[filter_option] = [
                    BASELINE_CODE
                    if i == "BBB"
                    else ERROR_CODE
                    if i == "XXX"
                    else int(i)
                    for i in self.data[filter_option]
                ]
        except ValueError:
            raise FuzzExceptBadOptions(
                "Bad options: Filter must be specified in the form of [int, ... , int, BBB, XXX]."
            )

        self.compile_seeds()
        self.compile_dictio()

        # filter options
        self.data["compiled_simple_filter"] = FuzzResSimpleFilter.from_options(self)
        self.data["compiled_filter"] = FuzzResFilter(self.data["filter"])
        for prefilter in self.data["prefilter"]:
            self.data["compiled_prefilter"].append(
                FuzzResFilter(filter_string=prefilter)
            )

        self.data["compiled_stats"] = FuzzStats.from_options(self)

        # Check payload num
        fuzz_words = self.get_fuzz_words()

        if self.data["compiled_dictio"].width() != len(fuzz_words):
            raise FuzzExceptBadOptions(
                "FUZZ words and number of payloads do not match!"
            )

        if self.data["allvars"] is None and len(fuzz_words) == 0:
            raise FuzzExceptBadOptions("You must specify at least a FUZZ word!")

        if self.data["compiled_baseline"] is None and (
            BASELINE_CODE in self.data["hc"]
            or BASELINE_CODE in self.data["hl"]
            or BASELINE_CODE in self.data["hw"]
            or BASELINE_CODE in self.data["hh"]
        ):
            raise FuzzExceptBadOptions(
                "Bad options: specify a baseline value when using BBB"
            )

        if self.data["script"]:
            Facade().scripts.kbase.update(self.data["script_args"])

            for k, v in Facade().sett.get_section("kbase"):
                if k not in self.data["script_args"]:
                    Facade().scripts.kbase[k] = v

        if not self.http_pool:
            self.http_pool = HttpPool(self)
            self.http_pool.register()

        if self.data["colour"]:
            Facade().printers.kbase["colour"] = True

        if self.data["verbose"]:
            Facade().printers.kbase["verbose"] = True

        return self

    def close(self):
        if self.data["compiled_dictio"]:
            self.data["compiled_dictio"].cleanup()

        if self.http_pool:
            self.http_pool.deregister()
            self.http_pool = None
