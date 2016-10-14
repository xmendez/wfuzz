from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.plugin_api.base import BasePayload

import random

@wfuzz_iterator
class hexrand(BasePayload):
    name = "hexrand"
    description = "Returns random hex numbers."
    category = ["default"]
    priority = 99

    parameters = (
        ("range", "", True, "Range of hex numbers to randomly generate in the form of 00-ff."),
    )

    default_parameter = "range"

    def __init__(self, params):
        BasePayload.__init__(self, params)

	try:
	    ran = self.params["range"].split("-")
	    self.minimum = int(ran[0],16)
	    self.maximum = int(ran[1],16)
	    self.__count = -1
	except:
	    raise Exception, "Bad range format (eg. \"0-ffa\")"
	    
    def __iter__ (self):
	return self

    def count(self):
	return self.__count

    def next (self):
	self.current = random.SystemRandom().randint(self.minimum,self.maximum)
	
	lgth = len(hex(self.maximum).replace("0x",""))
	pl="%"+str(lgth)+"s"
	num = hex(self.current).replace("0x","")	
	pl = pl % (num)
	payl =pl.replace(" ","0")
	
	return payl

