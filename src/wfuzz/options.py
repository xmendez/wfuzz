from .exception import FuzzExceptBadRecipe, FuzzExceptBadOptions, FuzzExceptBadFile
from .facade import Facade

from .fuzzobjects import FuzzResult, FuzzStats
from .filter import FuzzResFilter
from .core import requestGenerator
from .utils import (
    json_minify,
    python2_3_convert_from_unicode
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
        self.keys_not_to_dump = ["interactive", "recipe", "seed_payload", "send_discarded", "compiled_genreq", "compiled_filter", "compiled_prefilter", "compiled_printer"]

        # recipe must be superseded by options
        if "recipe" in kwargs and kwargs["recipe"]:
            self.import_from_file(kwargs["recipe"])

        self.update(kwargs)

        self.cache = HttpCache()
        self.http_pool = None

        self.fz = None
        self.stats = FuzzStats()

    def _defaults(self):
        return dict(
            seed_payload=False,
            send_discarded=False,
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
            dryrun=False,
            recipe="",
            save="",
            proxies=None,
            conn_delay=int(Facade().sett.get('connection', 'conn_delay')),
            req_delay=int(Facade().sett.get('connection', 'req_delay')),
            retries=int(Facade().sett.get('connection', 'retries')),
            rlevel=0,
            scanmode=False,
            delay=None,
            concurrent=int(Facade().sett.get('connection', 'concurrent')),
            url="",
            method=None,
            auth=(None, None),
            follow=False,
            postdata=None,
            headers=[],
            cookie=[],
            allvars=None,
            script="",
            script_args={},

            # this is equivalent to payloads but in a different format
            dictio=None,

            # these will be compiled
            filter="",
            prefilter="",
            compiled_genreq=None,
            compiled_filter=None,
            compiled_prefilter=None,
            compiled_printer=None,
        )

    def update(self, options):
        self.data.update(options)

    def validate(self):
        if self.data['dictio'] and self.data['payloads']:
            return "Bad usage: Dictio and payloads options are mutually exclusive. Only one could be specified."

        if self.data['rlevel'] > 0 and self.data['dryrun']:
            return "Bad usage: Recursion cannot work without making any HTTP request."

        if self.data['script'] and self.data['dryrun']:
            return "Bad usage: Plugins cannot work without making any HTTP request."

        if not self.data['url']:
            return "Bad usage: You must specify an URL."

        if not self.data['payloads'] and not self.data["dictio"]:
            return "Bad usage: You must specify a payload."

        if self.data["hs"] and self.data["ss"]:
            return "Bad usage: Hide and show regex filters flags are mutually exclusive. Only one could be specified."

        if self.data["rlevel"] < 0:
            return "Bad usage: Recursion level must be a positive int."

        if self.data['allvars'] not in [None, 'allvars', 'allpost', 'allheaders']:
            raise FuzzExceptBadOptions("Bad options: Incorrect all parameters brute forcing type specified, correct values are allvars,allpost or allheaders.")

        if self.data['proxies']:
            for ip, port, ttype in self.data['proxies']:
                if ttype not in ("SOCKS5", "SOCKS4", "HTML"):
                    raise FuzzExceptBadOptions("Bad proxy type specified, correct values are HTML, SOCKS4 or SOCKS5.")

        try:
            if [x for x in ["sc", "sw", "sh", "sl"] if len(self.data[x]) > 0] and \
               [x for x in ["hc", "hw", "hh", "hl"] if len(self.data[x]) > 0]:
                return "Bad usage: Hide and show filters flags are mutually exclusive. Only one group could be specified."

            if ([x for x in ["sc", "sw", "sh", "sl"] if len(self.data[x]) > 0] or
               [x for x in ["hc", "hw", "hh", "hl"] if len(self.data[x]) > 0]) and \
               self.data['filter']:
                    return "Bad usage: Advanced and filter flags are mutually exclusive. Only one could be specified."
        except TypeError:
            return "Bad options: Filter must be specified in the form of [int, ... , int]."

    def export_to_file(self, filename):
        try:
            with open(filename, 'w') as f:
                f.write(self.export_json())
        except IOError:
            raise FuzzExceptBadFile("Error writing recipe file.")

    def import_from_file(self, filename):
        try:
            with open(filename, 'r') as f:
                self.import_json(f.read())
        except IOError:
            raise FuzzExceptBadFile("Error loading recipe file.")

    def import_json(self, data):
        js = json.loads(json_minify(data))

        try:
            if js['version'] == "0.2" and 'wfuzz_recipe' in js:
                for section in js['wfuzz_recipe'].keys():
                    for k, v in js['wfuzz_recipe'].items():
                        if k not in self.keys_not_to_dump:
                            # python 2 and 3 hack
                            self.data[k] = python2_3_convert_from_unicode(v)
            else:
                raise FuzzExceptBadRecipe("Unsupported recipe version.")
        except KeyError:
            raise FuzzExceptBadRecipe("Incorrect recipe format.")

    def export_json(self):
        tmp = dict(
            version="0.2",
            wfuzz_recipe=defaultdict(dict)
        )
        defaults = self._defaults()

        # Only dump the non-default options
        for k, v in self.data.items():
            if v != defaults[k] and k not in self.keys_not_to_dump:
                tmp['wfuzz_recipe'][k] = self.data[k]

        return json.dumps(tmp, sort_keys=True, indent=4, separators=(',', ': '))

    def payload(self, **kwargs):
        self.data.update(kwargs)
        return requestGenerator(self).get_dictio()

    def fuzz(self, **kwargs):
        self.data.update(kwargs)

        try:
            self.fz = Fuzzer(self.compile())

            for f in self.fz:
                yield f

        finally:
            if self.fz:
                self.fz.cancel_job()
                self.stats.update(self.fz.genReq.stats)

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

    def compile(self):
        # Validate options
        error = self.validate()
        if error:
            raise FuzzExceptBadOptions(error)

        # printer
        try:
            filename, printer = self.data["printer"]
        except ValueError:
            raise FuzzExceptBadOptions("Bad options: Printer must be specified in the form of ('filename', 'printer')")

        if filename:
            if printer == "default" or not printer:
                printer = Facade().sett.get('general', 'default_printer')
            self.data["compiled_printer"] = Facade().printers.get_plugin(printer)(filename)

        try:
            self.data['hc'] = [FuzzResult.BASELINE_CODE if i == "BBB" else FuzzResult.ERROR_CODE if i == "XXX" else int(i) for i in self.data['hc']]
            self.data['hw'] = [FuzzResult.BASELINE_CODE if i == "BBB" else FuzzResult.ERROR_CODE if i == "XXX" else int(i) for i in self.data['hw']]
            self.data['hl'] = [FuzzResult.BASELINE_CODE if i == "BBB" else FuzzResult.ERROR_CODE if i == "XXX" else int(i) for i in self.data['hl']]
            self.data['hh'] = [FuzzResult.BASELINE_CODE if i == "BBB" else FuzzResult.ERROR_CODE if i == "XXX" else int(i) for i in self.data['hh']]

            self.data['sc'] = [FuzzResult.BASELINE_CODE if i == "BBB" else FuzzResult.ERROR_CODE if i == "XXX" else int(i) for i in self.data['sc']]
            self.data['sw'] = [FuzzResult.BASELINE_CODE if i == "BBB" else FuzzResult.ERROR_CODE if i == "XXX" else int(i) for i in self.data['sw']]
            self.data['sl'] = [FuzzResult.BASELINE_CODE if i == "BBB" else FuzzResult.ERROR_CODE if i == "XXX" else int(i) for i in self.data['sl']]
            self.data['sh'] = [FuzzResult.BASELINE_CODE if i == "BBB" else FuzzResult.ERROR_CODE if i == "XXX" else int(i) for i in self.data['sh']]
        except ValueError:
            raise FuzzExceptBadOptions("Bad options: Filter must be specified in the form of [int, ... , int, BBB, XXX].")

        # filter options
        self.data["compiled_filter"] = FuzzResFilter.from_options(self)
        self.data["compiled_prefilter"] = FuzzResFilter(filter_string=self.data['prefilter'])

        # seed
        self.data["compiled_genreq"] = requestGenerator(self)

        if self.data["compiled_genreq"].baseline is None and (FuzzResult.BASELINE_CODE in self.data['hc'] or
           FuzzResult.BASELINE_CODE in self.data['hl'] or FuzzResult.BASELINE_CODE in self.data['hw'] or
           FuzzResult.BASELINE_CODE in self.data['hh']):
                raise FuzzExceptBadOptions("Bad options: specify a baseline value when using BBB")

        if self.data["script"]:
            Facade().scripts.kbase.update(self.data["script_args"])

            for k, v in Facade().sett.get_section("kbase"):
                if k not in self.data["script_args"]:
                    Facade().scripts.kbase[k] = v

        if not self.http_pool:
            self.http_pool = HttpPool(self)
            self.http_pool.register()

        return self

    def close(self):
        self.http_pool.deregister()
        if self.fz:
            self.fz.cancel_job()
