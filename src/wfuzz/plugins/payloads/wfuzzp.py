import pickle as pickle
import gzip

from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptBadFile
from wfuzz.fuzzobjects import FuzzResult
from wfuzz.plugin_api.base import BasePayload
from wfuzz.utils import rgetattr


@moduleman_plugin
class wfuzzp(BasePayload):
    name = "wfuzzp"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = (
        "This payload uses pickle.",
        "Warning: The pickle module is not intended to be secure against erroneous or maliciously constructed data.",
        "Never unpickle data received from an untrusted or unauthenticated source.",
        "See: https://blog.nelhage.com/2011/03/exploiting-pickle/",
    )
    summary = "Returns fuzz results' URL from a previous stored wfuzz session."
    category = ["default"]
    priority = 99

    parameters = (
        ("fn", "", True, "Filename of a valid wfuzz result file."),
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

    def __next__(self):
        next_item = next(self._it)

        return next_item if not self.attr else rgetattr(next_item, self.attr)

    def _gen_wfuzz(self, output_fn):
        try:
            with gzip.open(self.find_file(output_fn), 'r+b') as output:
                while 1:
                    item = pickle.load(output)
                    if not isinstance(item, FuzzResult):
                        raise FuzzExceptBadFile("Wrong wfuzz payload format, the object read is not a valid fuzz result.")

                    yield item
        except IOError as e:
            raise FuzzExceptBadFile("Error opening wfuzz payload file. %s" % str(e))
        except EOFError:
            return
