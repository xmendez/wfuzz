from framework.core.myexception import FuzzException
from framework.core.facade import Facade

from framework.fuzzer.fuzzobjects import FuzzRequest
from framework.fuzzer.filter import FuzzResFilter
from framework.fuzzer.dictio import requestGenerator
from framework.utils.minify_json import json_minify

from UserDict import UserDict
from collections import defaultdict
import json
import re

class FuzzOptions(UserDict):
    def __init__(self):
	self.data = self._defaults()

    def _defaults(self):
	return dict(
	    filter_options = dict(
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
		filterstr = "",
		slicestr = "",
		),
	    payload_options = dict(
		payloads = [],
		iterator = None,
	    ),
	    grl_options = dict(
		    printer_tool = None,
		    colour = False,
		    verbose = False,
		    interactive = False,
		    dryrun = False,
		    recipe = "",
		    output_filename = "",
	    ),
	    conn_options = dict(
		proxy_list = None,
		max_conn_delay = int(Facade().sett.get('connection', 'conn_delay')),
		max_req_delay = int(Facade().sett.get('connection', 'req_delay')),
		rlevel = 0,
		scanmode = False,
		sleeper = None,
		max_concurrent = int(Facade().sett.get('connection', 'concurrent')),
	    ),
	    seed_options = dict(
		url = "",
		fuzz_methods = None,
		auth = (None, None),
		follow = False,
		postdata = None,
		extraheaders = [],
		cookie = [],
		allvars = None,
	    ),
	    script_options = dict(
		script_string = "",
		script_args = [],
	    ),
	)

    def validate(self):
	if self.data['conn_options']['rlevel'] > 0 and self.data['grl_options']['dryrun']:
	    return "Bad usage: Recursion cannot work without making any HTTP request."

	if self.data['script_options']['script_string'] and self.data['grl_options']['dryrun']:
	    return "Bad usage: Plugins cannot work without making any HTTP request."

	if not self.data['seed_options']['url']:
	    return "Bad usage: You must specify an URL."

	if len(self.data['payload_options']['payloads']) == 0:
	    return "Bad usage: You must specify a payload."

	if filter(lambda x: len(self.data["filter_options"][x]) > 0, ["sc", "sw", "sh", "sl"]) and \
	 filter(lambda x: len(self.data["filter_options"][x]) > 0, ["hc", "hw", "hh", "hl"]): 
	    return "Bad usage: Hide and show filters flags are mutually exclusive. Only one group could be specified."

	if (filter(lambda x: len(self.data["filter_options"][x]) > 0, ["sc", "sw", "sh", "sl"]) or \
	 filter(lambda x: len(self.data["filter_options"][x]) > 0, ["hc", "hw", "hh", "hl"])) and \
	 self.data['filter_options']['filterstr']:
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
	if tmp['wfuzz_recipe']["grl_options"].has_key("recipe"):
	    del(tmp['wfuzz_recipe']["grl_options"]["recipe"])
	    if len(tmp['wfuzz_recipe']["grl_options"]) == 0:
		del(tmp['wfuzz_recipe']["grl_options"])
	    
	return json.dumps(tmp, sort_keys=True, indent=4, separators=(',', ': '))

class FuzzSession:
    def __init__(self):
	self._values = {
	    "filter_params": None,
	    "slice_params": None,
	    "printer_tool": Facade().sett.get('general', 'default_printer'),
	    "rlevel": 0,
	    "script_string": "",
	    "sleeper": None,
	    "proxy_list": None,
	    "scanmode": False,
	    "interactive": False,
	    "colour": False,
	    "verbose": False,
	    "dryrun": False,
	    "max_concurrent": int(Facade().sett.get('connection', 'concurrent')),
	    "max_req_delay": int(Facade().sett.get('connection', 'req_delay')),
	    "max_conn_delay": int(Facade().sett.get('connection', 'conn_delay')),
	    "genreq": None,
	    "output_filename": "",
	    }

    def set(self, name, value):
	self._values[name] = value

    def get(self, name):
	return self._values[name]

    @staticmethod
    def from_options(options):
	fuzz_options = FuzzSession()

        # filter options
	fuzz_options.set("filter_params", FuzzResFilter.from_options(options["filter_options"]))
	fuzz_options.set("slice_params", FuzzResFilter(filter_string = options["filter_options"]['slicestr']))

	# conn options
	fuzz_options.set('proxy_list', options["conn_options"]["proxy_list"])
	fuzz_options.set("max_conn_delay", options["conn_options"]["max_conn_delay"])
	fuzz_options.set("max_req_delay", options["conn_options"]["max_req_delay"])
	fuzz_options.set("rlevel", options["conn_options"]["rlevel"])
	fuzz_options.set("scanmode", options["conn_options"]["scanmode"])
	fuzz_options.set("sleeper", options["conn_options"]["sleeper"])
	fuzz_options.set("max_concurrent", options["conn_options"]["max_concurrent"])

	# seed
	fuzz_options.set("genreq", requestGenerator(options["seed_options"], options["payload_options"]))

	# scripts
	script_string = options["script_options"]["script_string"]
	fuzz_options.set("script_string", script_string)

	try:
	    script_args = {}
	    if options["script_options"]['script_args']:
		script_args = dict(map(lambda x: x.split("=", 1), options["script_options"]['script_args'].split(",")))
	except ValueError:
	    raise FuzzException(FuzzException.FATAL, "Incorrect arguments format supplied.")

	if script_string:
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
	if options["grl_options"]["output_filename"]:
	    fuzz_options.set("output_filename", options["grl_options"]["output_filename"])
	if options["grl_options"]["colour"]:
	    Facade().printers.kbase.add("colour", True)
            fuzz_options.set("colour", options["grl_options"]["colour"])
	if options["grl_options"]["verbose"]:
	    Facade().printers.kbase.add("verbose", True)
            fuzz_options.set("verbose", options["grl_options"]["verbose"])

	fuzz_options.set("printer_tool", options["grl_options"]["printer_tool"])
	fuzz_options.set("interactive", options["grl_options"]["interactive"])
	fuzz_options.set("dryrun", options["grl_options"]["dryrun"])

	return fuzz_options
