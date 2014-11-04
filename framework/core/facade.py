from patterns.singleton import Singleton
from framework.core.myexception import FuzzException
from externals.moduleman.registrant import BRegistrant
from externals.moduleman.loader import FileLoader
from externals.moduleman.loader import DirLoader
from externals.settings.settings import SettingsBase

from framework.fuzzer.dictio import dictionary
from framework.fuzzer.fuzzobjects import FuzzRequest
from framework.fuzzer.dictio import requestGenerator
import plugins.encoders
import plugins.iterations

version = "2.1"

class Settings(SettingsBase):
    def get_config_file(self):
	return "wfuzz.ini"

    def set_defaults(self):
	return dict(
	    plugins=[("file_bl", '.jpg,.gif,.png,.jpeg,.mov,.avi,.flv,.ico'), ("bing_apikey", '')],
	)

class FuzzSessionOptions:
    def __init__(self):
	self._values = {
	    "filter_params": None,
	    "printer_tool": "default",
	    "rlevel": 0,
	    "script_string": "",
	    "sleeper": None,
	    "proxy_list": None,
	    "scanmode": False,
	    "interactive": False,
	    "max_concurrent": 10,
	    "max_req_delay": None,
	    "max_conn_delay": 90,
	    "genreq": None,
	    }

    def set(self, name, value):
	self._values[name] = value

    def get(self, name):
	return self._values[name]

    @staticmethod
    def from_options(options):
	'''
	Options is a dictionary containing all wfuzz options in the form of:

	    options = dict(
		conn_options = dict(
		    proxy_list = [(ip, port, type), ...]
		    max_conn_delay = 90,
		    max_req_delay = int/None,
		    rlevel = 0,
		    scanmode = False,
		    sleeper = int/None,
		    max_concurrent = 10,
		),
		filter_options = dict(
		    active = False,
		    regex_show = True/False,
		    codes_show = True/False,
		    codes = [int, ...],
		    words = [int, ...],
		    lines = [int, ...],
		    chars = [int, ...],
		    regex = re.compile/None,
		    filter_string = "filter_exp"
		),
		seed_options = dict(
		    url = url,
		    fuzz_methods = False,
		    auth = ("ntlm/basic...", "user:pass"),
		    follow = False,
		    head = False,
		    postdata = ""/None,
		    extraheaders = "name: value, ..."/None,
		    cookie = "value"/None,
		    allvars = "allpost/..."/None,
		),
		payload_options = dict(
		    payloads = [(name, args, encoders),...],
		    iterator = "name"/,
		),
		grl_options = dict(
		    printer_tool = "default",
		    colour = False,
		    interactive = False,
		),
		script_options = dict(
		    script_string = "default",
		    script_args = [(param, value),...],
		),
	    )
	'''

	fuzz_options = FuzzSessionOptions()

	# filter
	fuzz_options.set("filter_params", options["filter_options"])

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

	for name, params, encoders in options["payload_options"]["payloads"]:
	    p = Facade().get_payload(name)(params)

	    if encoders:
		l = []
		for i in encoders:
		    if i.find('@') > 0:
			l.append(plugins.encoders.pencoder_multiple([Facade().get_encoder(ii) for ii in i.split("@")]).encode)
		    else:
			l += map(lambda x: x().encode, Facade().proxy("encoders").get_plugins(i))
	    else:
		l = [Facade().get_encoder('none').encode]

	    d = dictionary(p, l)
	    selected_dic.append(d)

	#iterat_tool = plugins.iterations.piterator_void
	iterat_tool = Facade().get_iterator("product")
	if options["payload_options"]["iterator"]:
	    iterat_tool = Facade().get_iterator(options["payload_options"]["iterator"])

	payload = iterat_tool(*selected_dic)

	# seed
	seed = FuzzRequest.from_parse_options(options["seed_options"])
	fuzz_options.set("genreq", requestGenerator(seed, payload))

	# scripts
	fuzz_options.set("script_string", options["script_options"]["script_string"])
	for k, v in options["script_options"]["script_args"]:
	    Facade().proxy("parsers").kbase.add(k, v)

	# grl options
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
