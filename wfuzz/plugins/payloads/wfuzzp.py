import cPickle as pickle
import gzip

from wfuzz.exception import FuzzException
from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.plugin_api.payloadtools import FuzzResPayload
from wfuzz.fuzzobjects import FuzzResult

@wfuzz_iterator
class wfuzzp(FuzzResPayload):
    name = "wfuzzp"
    description = "Returns fuzz results' URL from a previous stored wfuzz session."
    category = ["default"]
    priority = 99

    def __init__(self, default_param, extra_params):
	FuzzResPayload.__init__(self, default_param, extra_params)
	self.__max = -1
	self._it = self._gen_wfuzz(default_param)

    def __iter__(self):
	return self

    def count(self):
	return self.__max

    def _gen_wfuzz(self, output_fn):
	try:
	    with gzip.open(output_fn, 'r+b') as output:
	    #with open(self.output_fn, 'r+b') as output:
		while 1:
		    item = pickle.load(output)
                    if not isinstance(item, FuzzResult):
                        raise FuzzException(FuzzException.FATAL, "Wrong wfuzz payload format, the read object is not a valid fuzz result.")

		    yield item
	except IOError, e:
	    raise FuzzException(FuzzException.FATAL, "Error opening wfuzz payload file. %s" % str(e))
	except EOFError:
	    raise StopIteration

