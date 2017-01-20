from .exception import FuzzExceptBadRecipe, FuzzExceptBadOptions
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

        self.cache = HttpCache()
        self.http_pool = None

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
            script_args = [],

            # this is equivalent to payloads but in a different format
            dictio = None,

            # these will be compiled
            filter = "",
            prefilter = "",
            compiled_genreq = None,
            compiled_filter = None,
            compiled_prefilter = None,
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

    def fuzz(self, **kwargs):
        self.data.update(kwargs)

        fz = None

        try:
            fz = Fuzzer(self.compile())

            for f in fz:
                yield f

        finally:
            if fz: fz.cancel_job()

    def get_payloads(self, iterator):
        class wrapper:
            def __init__(self, iterator):
                self._it = iter(iterator)

            def __iter__(self):
                return self

            def count(self):
                return -1

            def next(self):
                return str(self._it.next())

        self.data["dictio"] = map(lambda x: wrapper(x), iterator)

        return self

    def get_payload(self, iterator):
        return self.get_payloads([iterator])

    def __enter__(self):
        self.http_pool = HttpPool(self)
        self.http_pool.register()
        return self

    def __exit__(self, *args):
        self.http_pool.deregister()

    def compile(self):
        # Validate options
        error = self.validate()
        if error:
            raise FuzzExceptBadOptions(error)


        if not self.http_pool:
            self.http_pool = HttpPool(self)

        # filter options
        self.data["compiled_filter"] = FuzzResFilter.from_options(self)
        self.data["compiled_prefilter"] = FuzzResFilter(filter_string = self.data['prefilter'])

        # seed
        self.data["compiled_genreq"] = requestGenerator(self)

	try:
	    script_args = {}
	    if self.data['script_args']:
		script_args = dict(map(lambda x: x.split("=", 1), self.data['script_args'].split(",")))
	except ValueError:
	    raise FuzzExceptBadOptions("Script arguments: Incorrect arguments format supplied.")

	if self.data["script"]:
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

	if self.data["colour"]:
	    Facade().printers.kbase["colour"] = True

	if self.data["verbose"]:
	    Facade().printers.kbase["verbose"] = True

        return self
