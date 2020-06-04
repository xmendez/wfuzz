import re
import base64

from wfuzz.exception import FuzzExceptBadFile
from wfuzz.fuzzobjects import FuzzResult, FuzzWordType
from wfuzz.fuzzrequest import FuzzRequest
from wfuzz.plugin_api.base import BasePayload
from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.helpers.obj_dyn import rgetattr


@moduleman_plugin
class autorize(BasePayload):
    name = "autorize"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.2"
    description = ("Reads burp extension autorize states",)
    summary = "Returns fuzz results' from autorize."
    category = ["default"]
    priority = 99

    parameters = (
        ("fn", "", True, "Filename of a valid autorize state file."),
        (
            "attr",
            None,
            False,
            "Attribute of fuzzresult to return. If not specified the whole object is returned.",
        ),
    )

    default_parameter = "fn"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        self.__max = -1
        self.attr = self.params["attr"]
        self._it = self._gen_wfuzz(self.params["fn"])

    def count(self):
        return self.__max

    def get_next(self):
        next_item = next(self._it)

        return next_item if not self.attr else rgetattr(next_item, self.attr)

    def get_type(self):
        return FuzzWordType.WORD

    def _gen_wfuzz(self, output_fn):
        try:

            with open(self.find_file(output_fn), "r") as f:
                for (
                    url1,
                    port1,
                    schema1,
                    req1,
                    resp1,
                    url2,
                    port2,
                    schema2,
                    req2,
                    resp2,
                    url3,
                    port3,
                    schema3,
                    req3,
                    resp3,
                    res1,
                    res2,
                ) in [re.split(r"\t+", x) for x in f.readlines()]:
                    raw_req1 = base64.decodestring(req2)
                    # raw_res1 = base64.decodestring(res2)

                    item = FuzzResult()
                    item.history = FuzzRequest()
                    item.history.update_from_raw_http(raw_req1, schema1)

                    yield item
        except IOError as e:
            raise FuzzExceptBadFile("Error opening wfuzz payload file. %s" % str(e))
        except EOFError:
            raise StopIteration
