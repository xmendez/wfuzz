from patterns.singleton import Singleton
from framework.core.myexception import FuzzException
from externals.moduleman.registrant import BRegistrant
from externals.moduleman.loader import FileLoader
from externals.moduleman.loader import DirLoader
from externals.settings.settings import SettingsBase

from framework.fuzzer.dictio import dictionary
from framework.fuzzer.fuzzobjects import FuzzRequest
from framework.fuzzer.dictio import requestGenerator
from framework.utils.minify_json import json_minify
import plugins.encoders
import plugins.iterations

from UserDict import UserDict
from collections import defaultdict
import json
import re

version = "2.2"

class Settings(SettingsBase):
    def get_config_file(self):
	return "wfuzz.ini"

    def set_defaults(self):
	return dict(
	    plugins=[("file_bl", '.jpg,.gif,.png,.jpeg,.mov,.avi,.flv,.ico'), ("bing_apikey", '')],
	    connection=[("concurrent", '10'), ("conn_delay", '90')],
	    general=[("default_printer", 'default'),("cancel_on_plugin_except","1")],
	)

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
		),
	    payload_options = dict(
		payloads = [],
		iterator = None,
	    ),
	    grl_options = dict(
		    printer_tool = Facade().sett.get('general', 'default_printer'),
		    colour = False,
		    interactive = False,
		    recipe = "",
		    output_filename = "",
	    ),
	    conn_options = dict(
		proxy_list = None,
		max_conn_delay = int(Facade().sett.get('connection', 'conn_delay')),
		max_req_delay = None,
		rlevel = 0,
		scanmode = False,
		sleeper = None,
		max_concurrent = int(Facade().sett.get('connection', 'concurrent')),
	    ),
	    seed_options = dict(
		url = "",
		fuzz_methods = False,
		auth = (None, None),
		follow = False,
		head = False,
		postdata = None,
		extraheaders = None,
		cookie = None,
		allvars = None,
	    ),
	    script_options = dict(
		script_string = "",
		script_args = [],
	    ),
	)

    def validate(self):
	if not self.data['seed_options']['url']:
	    return "Bad usage: You must specify an URL."

	if len(self.data['payload_options']['payloads']) == 0:
	    return "Bad usage: You must specify a payload."

	if self.data['seed_options']['head'] and self.data['seed_options']['postdata']:
	    return "Bad usage: HEAD with POST parameters? Does it makes sense?"

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
	    "printer_tool": Facade().sett.get('general', 'default_printer'),
	    "rlevel": 0,
	    "script_string": "",
	    "sleeper": None,
	    "proxy_list": None,
	    "scanmode": False,
	    "interactive": False,
	    "max_concurrent": int(Facade().sett.get('connection', 'concurrent')),
	    "max_req_delay": None,
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

	# filter
	filter_params = dict(
	    active = False,
	    regex_show = None,
	    codes_show = None,
	    codes = [],
	    words = [],
	    lines = [],
	    chars = [],
	    regex = None,
	    filter_string = ""
	    )

	filter_params["filter_string"] = options["filter_options"]["filterstr"]

	try:
	    if options["filter_options"]["ss"] is not None:
		filter_params['regex_show'] = True
		filter_params['regex'] = re.compile(options["filter_options"]['ss'], re.MULTILINE|re.DOTALL)

	    elif options["filter_options"]["hs"] is not None:
		filter_params['regex_show'] = False
		filter_params['regex'] = re.compile(options["filter_options"]['hs'], re.MULTILINE|re.DOTALL)
	except Exception, e:
	    raise FuzzException(FuzzException.FATAL, "Invalied regex expression: %s" % str(e))

	if filter(lambda x: len(options["filter_options"][x]) > 0, ["sc", "sw", "sh", "sl"]):
	    filter_params['codes_show'] = True
	    filter_params['codes'] = options["filter_options"]["sc"]
	    filter_params['words'] = options["filter_options"]["sw"]
	    filter_params['lines'] = options["filter_options"]["sl"]
	    filter_params['chars'] = options["filter_options"]["sh"]
	elif filter(lambda x: len(options["filter_options"][x]) > 0, ["hc", "hw", "hh", "hl"]):
	    filter_params['codes_show'] = False
	    filter_params['codes'] = options["filter_options"]["hc"]
	    filter_params['words'] = options["filter_options"]["hw"]
	    filter_params['lines'] = options["filter_options"]["hl"]
	    filter_params['chars'] = options["filter_options"]["hh"]

	if filter_params['regex_show'] is not None or filter_params['codes_show'] is not None or filter_params['filter_string'] != "":
	    filter_params['active'] = True

	fuzz_options.set("filter_params", filter_params)

	# conn options
	fuzz_options.set('proxy_list', options["conn_options"]["proxy_list"])
	fuzz_options.set("max_conn_delay", options["conn_options"]["max_conn_delay"])
	fuzz_options.set("max_req_delay", options["conn_options"]["max_req_delay"])
	fuzz_options.set("rlevel", options["conn_options"]["rlevel"])
	fuzz_options.set("scanmode", options["conn_options"]["scanmode"])
	fuzz_options.set("sleeper", options["conn_options"]["sleeper"])
	fuzz_options.set("max_concurrent", options["conn_options"]["max_concurrent"])

	# payload
	selected_dic = []

	for name, params, extra, encoders in options["payload_options"]["payloads"]:
	    p = Facade().get_payload(name)(params, extra)

	    if encoders:
		l = []
		for i in encoders:
		    if i.find('@') > 0:
			l.append(plugins.encoders.pencoder_multiple([Facade().get_encoder(ii) for ii in i.split("@")]).encode)
		    else:
			l += map(lambda x: x().encode, Facade().proxy("encoders").get_plugins(i))
	    else:
		l = None

	    d = dictionary(p, l)
	    selected_dic.append(d)

	if options["payload_options"]["iterator"]:
	    iterat_tool = Facade().get_iterator(options["payload_options"]["iterator"])
	else:
	    iterat_tool = plugins.iterations.piterator_void

	payload = iterat_tool(*selected_dic)

	# seed
	seed = FuzzRequest.from_parse_options(options["seed_options"])
	fuzz_options.set("genreq", requestGenerator(seed, payload))

	# scripts
	fuzz_options.set("script_string", options["script_options"]["script_string"])
	for k, v in options["script_options"]["script_args"]:
	    Facade().proxy("parsers").kbase.add(k, v)

	# grl options
	if options["grl_options"]["output_filename"]:
	    fuzz_options.set("output_filename", options["grl_options"]["output_filename"])
	if options["grl_options"]["colour"]:
	    Facade().proxy("printers").kbase.add("colour", True)

	fuzz_options.set("printer_tool", options["grl_options"]["printer_tool"])
	fuzz_options.set("interactive", options["grl_options"]["interactive"])

	return fuzz_options

class Facade:
    __metaclass__ = Singleton 

    def __init__(self):
	self.__printers = None
	self.__plugins = None
	self.__encoders = None
	self.__iterators = None
	self.__payloads = None

	self.sett = Settings()

    def _load(self, cat):
	try:
	    if cat == "printers":
		if not self.__printers:
		    self.__printers = BRegistrant(FileLoader(**{"filename": "printers.py", "base_path": "./plugins" }))
		return self.__printers
	    elif cat == "plugins" or cat == "parsers":
		if not self.__plugins:
		    self.__plugins = BRegistrant(DirLoader(**{"base_dir": "scripts", "base_path": "./plugins" }))
		return self.__plugins
	    if cat == "encoders":
		if not self.__encoders:
		    self.__encoders = BRegistrant(FileLoader(**{"filename": "encoders.py", "base_path": "./plugins" }))
		return self.__encoders
	    if cat == "iterators":
		if not self.__iterators:
		    self.__iterators = BRegistrant(FileLoader(**{"filename": "iterations.py", "base_path": "./plugins" }))
		return self.__iterators
	    if cat == "payloads":
		if not self.__payloads:
		    self.__payloads = BRegistrant(FileLoader(**{"filename": "payloads.py", "base_path": "./plugins" }))
		return self.__payloads
	    else:
		raise FuzzException(FuzzException.FATAL, "Non-existent plugin category %s" % which)
	except Exception, e:
	    raise FuzzException(FuzzException.FATAL, "Error loading plugins: %s" % str(e))

    def proxy(self, which):
	return self._load(which)

    def get_printer(self, name):
	try:
	    return self._load("printers").get_plugin("printers/" + name)()
	except KeyError:
	    raise FuzzException(FuzzException.FATAL, name + " printer does not exists (-e printers for a list of available printers)")

    def get_payload(self, name):
	try:
	    return self._load("payloads").get_plugin("payloads/" + name)
	except KeyError:
	    raise FuzzException(FuzzException.FATAL, name + " payload does not exists (-e payloads for a list of available payloads)")

    def get_iterator(self, name):
	try:
	    return self._load("iterators").get_plugin("iterations/" + name)
	except KeyError:
	    raise FuzzException(FuzzException.FATAL, name + " iterator does not exists (-m iterators for a list of available iterators)")

    def get_encoder(self, name):
	try:
	    return self._load("encoders").get_plugin("encoders/" + name)()
	except KeyError:
	    raise FuzzException(FuzzException.FATAL, name + " encoder does not exists (-e encodings for a list of available encoders)")

    def get_parsers(self, filterstr):
	try:
	    return self._load("plugins").get_plugins(filterstr)
	except Exception, e:
	    raise FuzzException(FuzzException.FATAL, "Error selecting scripts: %s" % str(e))
