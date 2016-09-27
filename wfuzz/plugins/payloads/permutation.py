from wfuzz.plugin_api.base import wfuzz_iterator

import sys

@wfuzz_iterator
class permutation:
    name = "permutation"
    description = "Returns permutations of the given charset and length. ie. abc-2"
    category = ["default"]
    priority = 99

    def __init__(self, prange, extra):    ## range example --> "abcdef-4"
	self.charset = []

	try:
	    ran = prange.split("-")
	    self.charset = ran[0]
	    self.width = int(ran[1])
	except:
	    raise Exception, "Bad range format (eg. \"abfdeg-3\")"

	pset = []
	for x in self.charset:
	    pset.append(x)

	words = self.xcombinations(pset, self.width)
	self.lista = []
	for x in words:
	    self.lista.append(''.join(x))

	self.__count = len(self.lista)

    def __iter__ (self):
	return self

    def count(self):
	return self.__count

    def next (self):
	if self.lista != []:
	    payl=self.lista.pop()
	    return payl
	else:
	    raise StopIteration

    def xcombinations(self, items, n):
	if n == 0:
	    yield []
	else:
	    try:
		for i in xrange(len(items)):
		    for cc in self.xcombinations(items[:i] + items[i:], n - 1):
			yield [items[i]] + cc
	    except:
		print "Interrupted Permutation calculations"
		sys.exit()

