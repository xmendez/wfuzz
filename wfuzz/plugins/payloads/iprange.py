from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.facade import FuzzException

@wfuzz_iterator
class iprange:
    name = "iprange"
    description = "Returns list of IP addresses of a given range. ie. 192.168.1.0-192.168.1.12"
    category = ["default"]
    priority = 99

    def __init__(self, whatrange, extra):
	try:
            from netaddr import IPRange

            ran = whatrange.split("-")
            net = IPRange(ran[0], ran[1])
            self.f = iter(net)
            self.__count = net.size
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

