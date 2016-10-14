from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.plugin_api.base import BasePayload

@wfuzz_iterator
class hexrange(BasePayload):
    name = "hexrange"
    description = "Returns each hex number of the given hex range. ie. 00-ff"
    category = ["default"]
    priority = 99

    parameters = (
        ("range", "", True, "Range of hex numbers to generate in the form of 00-ff."),
    )

    default_parameter = "range"

    def __init__(self, params):
        BasePayload.__init__(self, params)

	try:
	    ran = self.params["range"].split("-")
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

