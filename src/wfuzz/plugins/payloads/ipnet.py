from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptPluginBadParams, FuzzExceptBadInstall
from wfuzz.plugin_api.base import BasePayload
from wfuzz.fuzzobjects import FuzzWordType


@moduleman_plugin
class ipnet(BasePayload):
    name = "ipnet"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = ("ie. 192.168.1.0/24", "Requires: netaddr module")
    summary = "Returns list of IP addresses of a network."
    category = ["default"]
    priority = 99

    parameters = (("net", "", True, "Network range in the form ip/mask."),)

    default_parameter = "net"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        try:
            from netaddr import IPNetwork
            from netaddr.core import AddrFormatError

            net = IPNetwork("%s" % self.params["net"])
            self.f = net.iter_hosts()
            self.__count = net.size - 2

            if self.__count <= 0:
                raise FuzzExceptPluginBadParams(
                    "There are not hosts in the specified network"
                )

        except ValueError:
            raise FuzzExceptPluginBadParams(
                "The specified network has an incorrect format."
            )
        except ImportError:
            raise FuzzExceptBadInstall(
                "ipnet plugin requires netaddr module. Please install it using pip."
            )
        except AddrFormatError:
            raise FuzzExceptPluginBadParams(
                "The specified network has an incorrect format."
            )

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        return str(next(self.f))

    def count(self):
        return self.__count
