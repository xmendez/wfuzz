from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptBadFile
from wfuzz.fuzzobjects import FuzzResult, FuzzWordType
from wfuzz.fuzzrequest import FuzzRequest
from wfuzz.plugin_api.base import BasePayload
from wfuzz.helpers.obj_dyn import rgetattr
import xml.etree.cElementTree as ET
from base64 import b64decode


@moduleman_plugin
class burpitem(BasePayload):
    name = "burpitem"
    author = ("Bendegúz Nagy (@PaperTsar)",)
    version = "0.1"
    description = (
        "This payload loads request/response from items saved from Burpsuite.",
    )
    summary = "This payload loads request/response from items saved from Burpsuite."
    category = ["default"]
    priority = 99

    parameters = (
        ("fn", "", True, "Filename of a valid Burp item file."),
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
        self._it = self._gen_burpitem(self.params["fn"])

    def count(self):
        return self.__max

    def get_next(self):
        next_item = next(self._it)

        return next_item if not self.attr else rgetattr(next_item, self.attr)

    def get_type(self):
        return FuzzWordType.FUZZRES if not self.attr else FuzzWordType.WORD

    def _gen_burpitem(self, output_fn):
        try:
            tree = ET.parse(self.find_file(output_fn))
            for item in tree.getroot().iter("item"):
                fr = FuzzRequest()
                fr.update_from_raw_http(
                    raw=b64decode(item.find("request").text or "").decode("utf-8"),
                    scheme=item.find("protocol").text,
                    raw_response=b64decode(item.find("response").text or ""),
                )
                fr.wf_ip = {
                    "ip": item.find("host").attrib.get("ip", None)
                    or item.find("host").text,
                    "port": item.find("port").text,
                }
                frr = FuzzResult(history=fr)

                yield frr.update()
            return
        except IOError as e:
            raise FuzzExceptBadFile(
                "Error opening Burp items payload file. %s" % str(e)
            )
        except EOFError:
            return
