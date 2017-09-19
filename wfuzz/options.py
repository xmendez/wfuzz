from .exception import FuzzExceptBadRecipe, FuzzExceptBadOptions, FuzzExceptBadFile
from .facade import Facade

from .fuzzobjects import FuzzRequest, FuzzResult, FuzzStats
from .filter import FuzzResFilter
from .core import requestGenerator
from .utils import json_minify

from .core import Fuzzer
from .myhttp import HttpPool

from .externals.reqresp.cache import HttpCache

from UserDict import UserDict
from collections import defaultdict
import json
import re

class FuzzSession(UserDict):
    def __init__(self, **kwargs):
	self.data = self._defaults()

        # recipe must be  options
        if "recipe" in kwargs and kwargs["recipe"]:
            self.import_from_file(kwargs["recipe"])

        self.data.update(kwargs)

        self.cache = HttpCache()
        self.http_pool = None

        self.fz = None
        self.stats = FuzzStats()

    def _defaults(self):
	return dict(
            seed_payload = False,
            hs = None,
            hc = [],
            hw = [],
            hl = [],
            hh = [],
            ss = None,
            sc = [],
            sw = [],
            sl = [],
            sh = [],
            payloads = None,
            iterator = None,
            printer = (None, None),
            colour = False,
            verbose = False,
            interactive = False,
            dryrun = False,
            recipe = "",
            save = "",
            proxies = None,
            conn_delay = int(Facade().sett.get('connection', 'conn_delay')),
            req_delay = int(Facade().sett.get('connection', 'req_delay')),
            retries = int(Facade().sett.get('connection', 'retries')),
            rlevel = 0,
            scanmode = False,
            delay = None,
            concurrent = int(Facade().sett.get('connection', 'concurrent')),
            url = "",
            method = None,
            auth = (None, None),
            follow = False,
            postdata = None,
            headers = [],
            cookie = [],
            allvars = None,
            script= "",
            script_args = {},

            # this is equivalent to payloads but in a different format
            dictio = None,

            # these will be compiled
            filter = "",
            prefilter = "",
            compiled_genreq = None,
            compiled_filter = None,
            compiled_prefilter = None,
            compiled_printer = None,
	)

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

        if self.data['allvars'] not in [None, 'allvars','allpost','allheaders']: 
            raise FuzzExceptBadOptions("Bad options: Incorrect all parameters brute forcing type specified, correct values are allvars,allpost or allheaders.")

        if self.data['proxies']:
            for ip, port, ttype in self.data['proxies']:
                if ttype not in ("SOCKS5","SOCKS4","HTML"):
                    raise FuzzExceptBadOptions("Bad proxy type specified, correct values are HTML, SOCKS4 or SOCKS5.")

        try:
            if filter(lambda x: len(self.data[x]) > 0, ["sc", "sw", "sh", "sl"]) and \
            filter(lambda x: len(self.data[x]) > 0, ["hc", "hw", "hh", "hl"]): 
                return "Bad usage: Hide and show filters flags are mutually exclusive. Only one group could be specified."

            if (filter(lambda x: len(self.data[x]) > 0, ["sc", "sw", "sh", "sl"]) or \
            filter(lambda x: len(self.data[x]) > 0, ["hc", "hw", "hh", "hl"])) and \
            self.data['filter']:
                return "Bad usage: Advanced and filter flags are mutually exclusive. Only one could be specified."
        except TypeError:
            return "Bad options: Filter must be specified in the form of [int, ... , int]."


    # pycurl does not like unicode strings
    def _convert_from_unicode(self, input):
	if isinstance(input, dict):
	    return {self._convert_from_unicode(key): self._convert_from_unicode(value) for key, value in input.iteritems()}
	elif isinstance(input, list):
	    return [self._convert_from_unicode(element) for element in input]
	elif isinstance(input, unicode):
	    return input.encode('utf-8')
	else:
	    return input

    def export_to_file(self, filename):
        try:
            f = open(filename,'w')
            f.write(self.export_json())
        except IOError:
            raise FuzzExceptBadFile("Error writing recipe file.")

    def import_from_file(self, filename):
        try:
            f = open(filename,'r')
            self.import_json(f.read())
        except IOError:
            raise FuzzExceptBadFile("Error loading recipe file.")

    def import_json(self, data):
	js = json.loads(json_minify(data))

        # fixme!

	try:
	    if js['version'] == "0.2" and 'wfuzz_recipe' in js:
		for section in js['wfuzz_recipe'].keys():
                    for k, v in js['wfuzz_recipe'].items():
			    self.data[k] = self._convert_from_unicode(v)
	    else:
		raise FuzzExceptBadRecipe("Unsupported recipe version.")
	except KeyError:
	    raise FuzzExceptBadRecipe("Incorrect recipe format.")

    def export_json(self):
	tmp = dict(
	    version = "0.2",
	    wfuzz_recipe = defaultdict(dict)
	)
	defaults = self._defaults()

	# Only dump the non-default options
	for k, v in self.data.items():
            if v != defaults[k]:
                tmp['wfuzz_recipe'][k] = self.data[k]

	# don't dump recipe
	if "recipe" in tmp['wfuzz_recipe']:
	    del(tmp['wfuzz_recipe']["recipe"])

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
        filename, printer = self.data["printer"]
        if filename:
            if printer == "default" or not printer: printer = Facade().sett.get('general', 'default_printer')
            self.data["compiled_printer"] = Facade().printers.get_plugin(printer)(filename)

        try:
            self.data['hc'] = [FuzzResult.BASELINE_CODE if i=="BBB" else FuzzResult.ERROR_CODE if i=="XXX" else int(i) for i in self.data['hc']]
            self.data['hw'] = [FuzzResult.BASELINE_CODE if i=="BBB" else FuzzResult.ERROR_CODE if i=="XXX" else int(i) for i in self.data['hw']]
            self.data['hl'] = [FuzzResult.BASELINE_CODE if i=="BBB" else FuzzResult.ERROR_CODE if i=="XXX" else int(i) for i in self.data['hl']]
            self.data['hh'] = [FuzzResult.BASELINE_CODE if i=="BBB" else FuzzResult.ERROR_CODE if i=="XXX" else int(i) for i in self.data['hh']]

            self.data['sc'] = [FuzzResult.BASELINE_CODE if i=="BBB" else FuzzResult.ERROR_CODE if i=="XXX" else int(i) for i in self.data['sc']]
            self.data['sw'] = [FuzzResult.BASELINE_CODE if i=="BBB" else FuzzResult.ERROR_CODE if i=="XXX" else int(i) for i in self.data['sw']]
            self.data['sl'] = [FuzzResult.BASELINE_CODE if i=="BBB" else FuzzResult.ERROR_CODE if i=="XXX" else int(i) for i in self.data['sl']]
            self.data['sh'] = [FuzzResult.BASELINE_CODE if i=="BBB" else FuzzResult.ERROR_CODE if i=="XXX" else int(i) for i in self.data['sh']]
        except ValueError, e:
	    raise FuzzExceptBadOptions("Bad options: Filter must be specified in the form of [int, ... , int, BBB, XXX].")

        if not self.http_pool:
            self.http_pool = HttpPool(self)

        # filter options
        self.data["compiled_filter"] = FuzzResFilter.from_options(self)
        self.data["compiled_prefilter"] = FuzzResFilter(filter_string = self.data['prefilter'])

        # seed
        self.data["compiled_genreq"] = requestGenerator(self)

        if self.data["compiled_genreq"].baseline == None and (FuzzResult.BASELINE_CODE in self.data['hc'] \
                or FuzzResult.BASELINE_CODE in self.data['hl'] \
                or FuzzResult.BASELINE_CODE in self.data['hw'] \
                or FuzzResult.BASELINE_CODE in self.data['hh']):
                    raise FuzzExceptBadOptions("Bad options: specify a baseline value when using BBB")

	if self.data["script"]:
            Facade().scripts.kbase.update(self.data["script_args"])

	    for k, v in Facade().sett.get_section("kbase"):
		if k not in self.data["script_args"]:
		    Facade().scripts.kbase[k] = v

	if self.data["colour"]:
	    Facade().printers.kbase["colour"] = True

	if self.data["verbose"]:
	    Facade().printers.kbase["verbose"] = True

        return self

    def close(self):
        self.http_pool.deregister()
        if self.fz: self.fz.cancel_job()
