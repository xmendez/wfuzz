from wfuzz.fuzzobjects import PluginResult, PluginRequest
from wfuzz.facade import FuzzException
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

    def add_result(self, issue):
	plres = PluginResult()
	plres.source = self.name
	plres.issue = issue

	self.results_queue.put(plres)

    def queue_raw_request(self, raw):
	self.results_queue.put(raw)

    def queue_url(self, url):
	self.results_queue.put(PluginRequest.from_fuzzRes(self.base_fuzz_res, url, self.name))

    def get_kbase(self, key):
	v = self.kbase.get(key)
	if not v:
	    raise FuzzException(FuzzException.FATAL, "Key not in kbase")
	return v

    def has_kbase(self, key):
	return self.kbase.has(key)

    def add_kbase(self, key, value):
	self.kbase.add(key, value)

# Plugins specializations with common methods useful for their own type

class DiscoveryPlugin(BasePlugin):
    def __init__(self):
	BasePlugin.__init__(self)
	self.black_list = self.get_kbase("discovery.blacklist")[0].split("-")

    def blacklisted_extension(self, url):
	return parse_url(url).file_extension in self.black_list

    def queue_url(self, url):
	if not self.blacklisted_extension(url):
	    BasePlugin.queue_url(self, url)
	    return True
	return False


class BasePrinter:
    def __init__(self, output):
        self.f = None
        try:
            self.f = open(output,'w')
        except IOError, e:
            raise FuzzException(FuzzException.FATAL, "Error opening file. %s" % str(e))

# decorator for iterator plugins
def wfuzz_iterator(cls):
    method_args = ["count", "next", "__iter__"]

    for method in method_args:
	if (not (method in dir(cls))):
	    raise Exception("Required method %s not implemented" % method)

    cls.__PLUGIN_MODULEMAN_MARK = "Plugin mark"

    return cls
