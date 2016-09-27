from wfuzz.facade import FuzzException
from wfuzz.plugin_api.base import wfuzz_iterator

@wfuzz_iterator
class file:
    name = "file"
    description = "Returns each word from a file."
    category = ["default"]
    priority = 99

    def __init__(self, filename, extra):
	try:
	    self.f = open(filename,"r")
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

