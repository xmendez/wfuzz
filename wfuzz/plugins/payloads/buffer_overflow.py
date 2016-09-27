from wfuzz.plugin_api.base import wfuzz_iterator

@wfuzz_iterator
class buffer_overflow:
    name = "buffer_overflow"
    description = "Returns a string using the following pattern A * given number."
    category = ["default"]
    priority = 99

    def __init__(self, n, extra):   
	self.l = ['A' * int(n)]
	self.current = 0

    def __iter__(self):
	return self

    def count(self):
	return 1

    def next (self):
	if self.current == 0:
	    elem = self.l[self.current]
	    self.current+=1
	    return elem
	else:
	    raise StopIteration

