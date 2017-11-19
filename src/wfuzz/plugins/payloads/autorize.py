fn = "user_5_local_admin_member.state"
import re
import base64



import cPickle as pickle
import gzip

from wfuzz.exception import FuzzExceptBadFile
from wfuzz.fuzzobjects import FuzzResult
from wfuzz.fuzzobjects import FuzzRequest
from wfuzz.plugin_api.base import BasePayload
from wfuzz.externals.moduleman.plugin import moduleman_plugin

@moduleman_plugin
class autorize(BasePayload):
    name = "autorize"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = ("Reads burp extension autorize states",)
    summary = "Returns fuzz results' from autororize."
    category = ["default"]
    priority = 99

    parameters = (
        ("fn", "", True, "Filename of a valid autorize state file."),
        ("attr", None, False, "Attribute of fuzzresult to return. If not specified the whole object is returned."),
    )

    default_parameter = "fn"

    def __init__(self, params):
        BasePayload.__init__(self, params)

	self.__max = -1
        self.attr = self.params["attr"]
	self._it = self._gen_wfuzz(self.params["fn"])

    def __iter__(self):
	return self

    def count(self):
	return self.__max

    def next(self):
	next_item = self._it.next()

        return next_item if not self.attr else next_item.get_field(self.attr)

    def _gen_wfuzz(self, output_fn):
	try:

            with open(self.find_file(output_fn), 'r') as f:
                for url1, port1, schema1, req1, resp1, url2, port2, schema2, req2, resp2, url3, port3, schema3, req3, resp3, res1, res2 in map(lambda x: re.split(r'\t+', x), f.readlines()):
                    raw_req1 = base64.decodestring(req2)
                    raw_res1 = base64.decodestring(res2)

                    item = FuzzResult()
                    item.history = FuzzRequest()
                    item.history.update_from_raw_http(raw_req1, schema1)

                    item.type = FuzzResult.result

		    yield item
	except IOError, e:
	    raise FuzzExceptBadFile("Error opening wfuzz payload file. %s" % str(e))
	except EOFError:
	    raise StopIteration

