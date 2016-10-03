from wfuzz.exception import FuzzException
from wfuzz.plugin_api.base import wfuzz_iterator

@wfuzz_iterator
class range:
    name = "range"
    description = "Returns each number of the given range. ie. 0-10"
    category = ["default"]
    priority = 99

    def __init__(self, whatrange, extra):    ## range example --> "23-56"
	try:
	    ran = whatrange.split("-")
	    self.minimum = int(ran[0])
	    self.maximum = int(ran[1])
	    self.__count = self.maximum - self.minimum + 1
	    self.width = len(ran[0])
	    self.current = self.minimum
	except:
	    raise FuzzException(FuzzException.FATAL, "Bad range format (eg. \"23-56\")")
		
    def next(self):
	if self.current>self.maximum:
	    raise StopIteration
	else:
	    if self.width:
		payl = "%0"+ str(self.width) + "d"
		payl = payl % (self.current)
	    else:
		payl = str(self.current)

	    self.current += 1
	    return payl

    def count(self):
	return self.__count

    def __iter__(self):
	return self

