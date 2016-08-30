from .facade import FuzzException
from .facade import Facade

from .fuzzobjects import FuzzRequest
from .filter import FuzzResFilter
from .core import requestGenerator
from .utils import json_minify

from UserDict import UserDict
from collections import defaultdict
import json
import re

class FuzzOptions(UserDict):
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
            payloads = [],
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

	if len(self.data['payloads']) == 0:
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
	    if js['version'] == "0.1" and js.has_key('wfuzz_recipe'):
		for section in js['wfuzz_recipe'].keys():
		    if section in ['grl_options', 'conn_options', 'seed_options', 'payload_options', 'script_options', 'filter_options']:
			for k, v in js['wfuzz_recipe'][section].items():
			    self.data[section][k] = self._convert_from_unicode(v)

			# fix pycurl error when using unicode url
			if section == 'seed_options':
			    if js['wfuzz_recipe']['seed_options'].has_key('url'):
				self.data['seed_options']['url'] = self._convert_from_unicode(js['wfuzz_recipe']['seed_options']['url'])
		    else:
			raise FuzzException(FuzzException.FATAL, "Incorrect recipe format.")
	    else:
		raise FuzzException(FuzzException.FATAL, "Unsupported recipe version.")
	except KeyError:
	    raise FuzzException(FuzzException.FATAL, "Incorrect recipe format.")

    def export_json(self):
        # fixme!


	tmp = dict(
	    version = "0.1",
	    wfuzz_recipe = defaultdict(dict)
	)
	defaults = self._defaults()

	# Only dump the non-default options
	for section, d in self.data.items():
	    for k, v in d.items():
		if v != defaults[section][k]:
		    tmp['wfuzz_recipe'][section][k] = self.data[section][k]

	# don't dump recipe
	if tmp['wfuzz_recipe'].has_key("recipe"):
	    del(tmp['wfuzz_recipe']["recipe"])
	    if len(tmp['wfuzz_recipe']["grl_options"]) == 0:
		del(tmp['wfuzz_recipe']["grl_options"])
	    
	return json.dumps(tmp, sort_keys=True, indent=4, separators=(',', ': '))

class FuzzSession:
    def __init__(self):
	self._values = {
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

    def set(self, name, value):
	self._values[name] = value

    def get(self, name):
	return self._values[name]

    @staticmethod
    def from_options(options):
	fuzz_options = FuzzSession()

        # filter options
	fuzz_options.set("filter", FuzzResFilter.from_options(options))
	fuzz_options.set("prefilter", FuzzResFilter(filter_string = options['prefilter']))

	# conn options
	fuzz_options.set('proxies', options["proxies"])
	fuzz_options.set("conn_delay", options["conn_delay"])
	fuzz_options.set("req_delay", options["req_delay"])
	fuzz_options.set("rlevel", options["rlevel"])
	fuzz_options.set("scanmode", options["scanmode"])
	fuzz_options.set("delay", options["delay"])
	fuzz_options.set("concurrent", options["concurrent"])

	# seed
	fuzz_options.set("genreq", requestGenerator(options))

	# scripts
	script = options["script"]
	fuzz_options.set("script", script)

	try:
	    script_args = {}
	    if options['script_args']:
		script_args = dict(map(lambda x: x.split("=", 1), options['script_args'].split(",")))
	except ValueError:
	    raise FuzzException(FuzzException.FATAL, "Incorrect arguments format supplied.")

	if script:
	    for k, v in Facade().sett.get_section("kbase"):
		if script_args.has_key(k):
		    value = script_args[k]

		    if value[0] == "+":
			value = value[1:]

			Facade().parsers.kbase.add(k, v + "-" + value)
		    else:
			Facade().parsers.kbase.add(k, value)

		else:
		    Facade().parsers.kbase.add(k, v)

	# grl options
	if options["save"]:
	    fuzz_options.set("save", options["save"])
	if options["colour"]:
	    Facade().printers.kbase.add("colour", True)
            fuzz_options.set("colour", options["colour"])
	if options["verbose"]:
	    Facade().printers.kbase.add("verbose", True)
            fuzz_options.set("verbose", options["verbose"])

	fuzz_options.set("printer", options["printer"])
	fuzz_options.set("interactive", options["interactive"])
	fuzz_options.set("dryrun", options["dryrun"])

	return fuzz_options
