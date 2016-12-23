from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.exception import FuzzException
from wfuzz.plugin_api.base import BasePayload

@wfuzz_iterator
class ipnet(BasePayload):
    name = "ipnet"
    author = "Xavi Mendez (@xmendez)"
    version = "0.1"
    description = ("ie. 192.168.1.0/24", "Requires: netaddr module")
    summary = "Returns list of IP addresses of a network."
    category = ["default"]
    priority = 99

    parameters = (
        ("net", "", True, "Network range in the form ip/mask."),
    )

    default_parameter = "net"

    def __init__(self, params):
        BasePayload.__init__(self, params)

	try:
            from netaddr import IPNetwork
            from netaddr.core import AddrFormatError

            net = IPNetwork(u'%s' % self.params["net"])
            self.f = net.iter_hosts()
            self.__count = net.size - 2

            if self.__count <= 0:
                raise FuzzException(FuzzException.FATAL, "There are not hosts in the specified network")

	except AddrFormatError:
	    raise FuzzException(FuzzException.FATAL, "The specified network has an incorrect format.")
	except ValueError:
	    raise FuzzException(FuzzException.FATAL, "The specified network has an incorrect format.")
	except ImportError:
	    raise FuzzException(FuzzException.FATAL, "ipnet plugin requires netaddr module. Please install it using pip.")

    def next(self):
	return str(self.f.next())

    def count(self):
	return self.__count

    def __iter__ (self):
	return self
