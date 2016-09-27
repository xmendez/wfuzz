from wfuzz.plugin_api.base import wfuzz_iterator

import random

@wfuzz_iterator
class hexrand:
    name = "hexrand"
    description = "Returns random hex numbers."
    category = ["default"]
    priority = 99

    def __init__(self, prange, extra):    ## range example --> "0-ffa"
	try:
	    ran = prange.split("-")
	    self.minimum=int(ran[0],16)
	    self.maximum=int(ran[1],16)
	    self.__count=-1
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

