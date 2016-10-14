from wfuzz.exception import FuzzException
from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.plugin_api.base import BasePayload

@wfuzz_iterator
class file(BasePayload):
    name = "file"
    author = ("Carlos del Ojo", "Christian Martorella", "Adapted to newer versions Xavi Mendez (@xmendez)")
    version = "0.1"
    description = ()
    summary = "Returns each word from a file."
    category = ["default"]
    priority = 99

    parameters = (
        ("fn", "", True, "Filename of a valid dictionary"),
    )

    default_parameter = "fn"

    def __init__(self, params):
        BasePayload.__init__(self, params)

	try:
	    self.f = open(self.params["fn"],"r")
	except IOError, e:
	    raise FuzzException(FuzzException.FATAL, "Error opening file. %s" % str(e))

	self.__count = len(self.f.readlines())
	self.f.seek(0)

    def next (self):
	return self.f.next().strip()

    def count(self):
	return self.__count

    def __iter__(self):
	return self

