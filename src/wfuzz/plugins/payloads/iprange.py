from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptPluginBadParams, FuzzExceptBadInstall
from wfuzz.plugin_api.base import BasePayload
from wfuzz.fuzzobjects import FuzzWordType


@moduleman_plugin
class iprange(BasePayload):
    name = "iprange"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = (
        "ie. 192.168.1.0-192.168.1.12",
        "Requires: netaddr module",
    )
    summary = "Returns list of IP addresses of a given IP range."
    category = ["default"]
    priority = 99

    parameters = (
        ("iprange", "", True, "IP address range int the form 192.168.1.0-192.168.1.12"),
    )

    default_parameter = "iprange"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        try:
            from netaddr import IPRange
            from netaddr.core import AddrFormatError

            ran = self.params["iprange"].split("-")
            net = IPRange(ran[0], ran[1])
            self.f = iter(net)
            self.__count = net.size
        except ImportError:
            raise FuzzExceptBadInstall(
                "ipnet plugin requires netaddr module. Please install it using pip."
            )
        except AddrFormatError:
            raise FuzzExceptPluginBadParams(
                "The specified network range has an incorrect format."
            )
        except IndexError:
            raise FuzzExceptPluginBadParams(
                "The specified network range has an incorrect format."
            )

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        return str(next(self.f))

    def count(self):
        return self.__count
