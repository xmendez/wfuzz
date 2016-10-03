from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.exception import FuzzException

@wfuzz_iterator
class ipnet:
    name = "ipnet"
    description = "Returns a list of IP addresses of a given network. ie. 192.168.1.0/24"
    category = ["default"]
    priority = 99

    def __init__(self, network, extra):
	try:
            from netaddr import IPNetwork

            net = IPNetwork(u'%s' % network)
            self.f = net.iter_hosts()
            self.__count = net.size - 2

            if self.__count <= 0:
                raise FuzzException(FuzzException.FATAL, "There are not hosts in the specified network")

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
