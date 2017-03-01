from wfuzz.fuzzobjects import PluginResult, PluginRequest
from wfuzz.exception import FuzzExceptBadFile, FuzzExceptBadOptions
from wfuzz.facade import Facade
from wfuzz.plugin_api.urlutils import parse_url

# Util methods for accessing search results
class BasePlugin():
    def __init__(self):
	self.results_queue = None
	self.base_fuzz_res = None

    def run(self, fuzzresult, control_queue, results_queue):
	try:
	    self.results_queue = results_queue
	    self.base_fuzz_res = fuzzresult
	    self.process(fuzzresult)
	except Exception, e:
	    plres = PluginResult()
	    plres.source = "$$exception$$"
	    plres.issue = "Exception within plugin %s: %s" % (self.name, str(e))
	    results_queue.put(plres)
	finally:
	    control_queue.get()
	    control_queue.task_done()
	    return

    def process(self, fuzzresult):
	'''
	This is were the plugin processing is done. Any wfuzz plugin must implement this method, do its job with the fuzzresult received and:
	- queue_url: if it is a discovery plugin enqueing more HTTP request that at some point will generate more results
	- add_result: Add information about the obtained results after the processing with an accurate description

	A kbase (get_kbase, has_kbase, add_kbase) is shared between all plugins. this can be used to store and retrieve relevant "collaborative" information.
	'''
	raise NotImplemented

    def validate(self):
        raise FuzzExceptPluginError("Method count not implemented")

    def add_result(self, issue):
	plres = PluginResult()
	plres.source = self.name
	plres.issue = issue

	self.results_queue.put(plres)

    def queue_url(self, url):
	self.results_queue.put(PluginRequest.from_fuzzRes(self.base_fuzz_res, url, self.name))

class BasePrinter:
    def __init__(self, output):
        self.f = None
        try:
            self.f = open(output,'w')
        except IOError, e:
            raise FuzzExceptBadFile("Error opening file. %s" % str(e))

        self.verbose = Facade().printers.kbase["verbose"]

    def header(self):
        raise FuzzExceptPluginError("Method header not implemented")

    def footer(self):
        raise FuzzExceptPluginError("Method footer not implemented")

    def result(self):
        raise FuzzExceptPluginError("Method result not implemented")

class BasePayload:
    def __init__(self, params):
        self.params = params

        # default params
        if "default" in self.params:
            self.params[self.default_parameter] = self.params["default"]

            if not self.default_parameter:
                raise FuzzExceptBadOptions("Too many plugin parameters specified")

        # Check for allowed parameters
        if [k for k in self.params.keys() if k not in map(lambda x: x[0], self.parameters) and k not in ["encoder", "default"]]:
            raise FuzzExceptBadOptions("Plugin %s, unknown parameter specified!" % (self.name))


        # check mandatory params, assign default values
        for name, default_value, required, description in self.parameters:
            if required and not name in self.params:
                raise FuzzExceptBadOptions("Plugin %s, missing parameter %s!" % (self.name, name))

            if not name in self.params:
                self.params[name] = default_value

    def next(self):
        raise FuzzExceptPluginError("Method next not implemented")

    def count(self):
        raise FuzzExceptPluginError("Method count not implemented")

    def __iter__(self):
        raise FuzzExceptPluginError("Method iter not implemented")

