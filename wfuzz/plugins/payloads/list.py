from wfuzz.plugin_api.base import wfuzz_iterator

@wfuzz_iterator
class list:
    name = "list"
    description = "Returns each element of the given word list separated by -. ie word1-word2"
    category = ["default"]
    priority = 99

    def __init__(self, l, extra):   
	if l.find("\\") >= 0:
	    l = l.replace("\\-", "$SEP$")
	    l = l.replace("\\\\", "$SCAP$")

	    self.l = l.split("-")

	    for i in range(len(self.l)):
		self.l[i] = self.l[i].replace("$SEP$", "-")
		self.l[i] = self.l[i].replace("$SCAP$", "\\")
	else:
	    self.l = l.split("-")
	    
	self.__count = len(self.l)
	self.current = 0

    def __iter__ (self):
	return self

    def count(self):
	return self.__count

    def next (self):
	if self.current >= self.__count:
	    raise StopIteration
	else:
	    elem = self.l[self.current]
	    self.current += 1
	    return elem

