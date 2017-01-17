from .exception import FuzzException
from .facade import Facade

from .fuzzobjects import FuzzRequest
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
        self.data.update(kwargs)

    def _defaults(self):
	return dict(
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
            filter = "",
            prefilter = "",
            payloads = None,
            iterator = None,
            printer = None,
            colour = False,
            verbose = False,
            interactive = False,
            dryrun = False,
            recipe = "",
            save = "",
            proxies = None,
            conn_delay = int(Facade().sett.get('connection', 'conn_delay')),
            req_delay = int(Facade().sett.get('connection', 'req_delay')),
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
            script_args = [],
	)

    def validate(self):
	if self.data['rlevel'] > 0 and self.data['dryrun']:
	    return "Bad usage: Recursion cannot work without making any HTTP request."

	if self.data['script'] and self.data['dryrun']:
	    return "Bad usage: Plugins cannot work without making any HTTP request."

	if not self.data['url']:
	    return "Bad usage: You must specify an URL."

	if self.data['payloads'] is None:
	    return "Bad usage: You must specify a payload."

	if filter(lambda x: len(self.data[x]) > 0, ["sc", "sw", "sh", "sl"]) and \
	 filter(lambda x: len(self.data[x]) > 0, ["hc", "hw", "hh", "hl"]): 
	    return "Bad usage: Hide and show filters flags are mutually exclusive. Only one group could be specified."

	if (filter(lambda x: len(self.data[x]) > 0, ["sc", "sw", "sh", "sl"]) or \
	 filter(lambda x: len(self.data[x]) > 0, ["hc", "hw", "hh", "hl"])) and \
	 self.data['filter']:
	    return "Bad usage: Advanced and filter flags are mutually exclusive. Only one could be specified."

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

    def import_json(self, data):
	js = json.loads(json_minify(data))

        # fixme!

	try:
	    if js['version'] == "0.2" and 'wfuzz_recipe' in js:
		for section in js['wfuzz_recipe'].keys():
                    for k, v in js['wfuzz_recipe'].items():
			    self.data[k] = self._convert_from_unicode(v)
	    else:
		raise FuzzException(FuzzException.FATAL, "Unsupported recipe version.")
	except KeyError:
	    raise FuzzException(FuzzException.FATAL, "Incorrect recipe format.")

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

    def fuzz(self, **kwargs):
        self.data.update(kwargs)
        return Fuzzer(FuzzCompiledSession.compile(self))

class FuzzCompiledSession(UserDict):
    def __init__(self):
	self.data = {
	    "filter": None,
	    "prefilter": None,
	    "printer": Facade().sett.get('general', 'default_printer'),
	    "rlevel": 0,
	    "script": "",
	    "delay": None,
	    "proxies": None,
	    "scanmode": False,
	    "interactive": False,
	    "colour": False,
	    "verbose": False,
	    "dryrun": False,
	    "concurrent": int(Facade().sett.get('connection', 'concurrent')),
	    "req_delay": int(Facade().sett.get('connection', 'req_delay')),
	    "conn_delay": int(Facade().sett.get('connection', 'conn_delay')),
	    "genreq": None,
	    "save": "",
	    }

        # common objects

        self.http_pool = HttpPool(int(Facade().sett.get("connection","retries")))
        self.http_pool.initialize(self)

	self.cache = HttpCache()

    @staticmethod
    def compile(options):
	fuzz_options = FuzzCompiledSession()

        # Validate options
        error = options.validate()
        if error:
            raise FuzzException(FuzzException.FATAL, error)

        # filter options
	fuzz_options["filter"] = FuzzResFilter.from_options(options)
	fuzz_options["prefilter"] = FuzzResFilter(filter_string = options['prefilter'])

	# conn options
	fuzz_options['proxies'] = options["proxies"]
	fuzz_options["conn_delay"] = options["conn_delay"]
	fuzz_options["req_delay"] = options["req_delay"]
	fuzz_options["rlevel"] = options["rlevel"]
	fuzz_options["scanmode"] = options["scanmode"]
	fuzz_options["delay"] = options["delay"]
	fuzz_options["concurrent"] = options["concurrent"]

	# seed
	fuzz_options["genreq"] = requestGenerator(options)

	# scripts
	script = options["script"]
	fuzz_options["script"] = script

	try:
	    script_args = {}
	    if options['script_args']:
		script_args = dict(map(lambda x: x.split("=", 1), options['script_args'].split(",")))
	except ValueError:
	    raise FuzzException(FuzzException.FATAL, "Incorrect arguments format supplied.")

	if script:
	    for k, v in Facade().sett.get_section("kbase"):
		if k in script_args:
		    value = script_args[k]

		    if value[0] == "+":
			value = value[1:]

			Facade().scripts.kbase[k] = v + "-" + value
		    else:
			Facade().scripts.kbase[k] = value

		else:
		    Facade().scripts.kbase[k] = v

	# grl options
	if options["save"]:
	    fuzz_options["save"] = options["save"]
	if options["colour"]:
	    Facade().printers.kbase["colour"] = True
            fuzz_options["colour"] = options["colour"]
	if options["verbose"]:
	    Facade().printers.kbase["verbose"] = True
            fuzz_options["verbose"] = options["verbose"]

	fuzz_options["printer"] = options["printer"]
	fuzz_options["interactive"] = options["interactive"]
	fuzz_options["dryrun"] = options["dryrun"]

	return fuzz_options
