from wfuzz.plugin_api.base import wfuzz_iterator

@wfuzz_iterator
class hexrange:
    name = "hexrange"
    description = "Returns each hex number of the given hex range. ie. 00-ff"
    category = ["default"]
    priority = 99

    def __init__(self, prange, extra):    ## range example --> "0-ffa"
	try:
	    ran = prange.split("-")
	    self.minimum = int(ran[0],16)
	    self.maximum = int(ran[1],16)
	    self.__count = self.maximum - self.minimum + 1
	    self.current = self.minimum
	except:
	    raise Exception, "Bad range format (eg. \"0-ffa\")"
	    
    def __iter__(self):
	return self

    def count(self):
	return self.__count
	    
    def next(self):
	if self.current > self.maximum:
	    raise StopIteration
	
	lgth=len(hex(self.maximum).replace("0x",""))
	pl="%"+str(lgth)+"s"
	num=hex(self.current).replace("0x","")	
	pl= pl % (num)
	payl=pl.replace(" ","0")
	
	self.current+=1

	return payl

