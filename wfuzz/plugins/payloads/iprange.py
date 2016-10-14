from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.exception import FuzzException
from wfuzz.plugin_api.base import BasePayload

@wfuzz_iterator
class iprange(BasePayload):
    name = "iprange"
    author = "Xavi Mendez (@xmendez)"
    version = "0.1"
    description = ("ie. 192.168.1.0-192.168.1.12", "Requires: netaddr module",)
    summary = "Returns list of IP addresses of a given range."
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
	except AddrFormatError:
	    raise FuzzException(FuzzException.FATAL, "The specified network range has an incorrect format.")
	except IndexError:
	    raise FuzzException(FuzzException.FATAL, "The specified network range has an incorrect format.")
	except ImportError:
	    raise FuzzException(FuzzException.FATAL, "ipnet plugin requires netaddr module. Please install it using pip.")

    def next(self):
	return str(self.f.next())

    def count(self):
	return self.__count

    def __iter__ (self):
	return self

