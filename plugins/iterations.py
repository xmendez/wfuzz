from externals.moduleman.plugin import moduleman_plugin

import itertools

class piterator_void:
    text="void"

    def count(self):
	return self.__count

    def __init__(self, *i):
	self._dic = i
	self.__count = max(map(lambda x:x.count(), i))
	self.it = self._dic[0]

    def next(self):
	return (self.it.next(),)

    def restart(self):
	for dic in self._dic: 
	    dic.restart()
	self.it = self._dic[0]

    def __iter__(self):
	self.restart()
	return self

@moduleman_plugin("restart", "count", "next", "__iter__")
class zip:
    name = "zip"
    description = "Returns an iterator that aggregates elements from each of the iterables."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
	self._dic = i
	self.it = itertools.izip(*self._dic)
	self.__count = max(map(lambda x:x.count(), i))

    def count(self):
	return self.__count

    def restart(self):
	for dic in self._dic: 
	    dic.restart()
	self.it = itertools.izip.__init__(self, *self._dic)

    def next(self):
	return self.it.next()

    def __iter__(self):
	self.restart()
	return self

@moduleman_plugin("restart", "count", "next", "__iter__")
class product:
    name = "product"
    description = "Returns an iterator cartesian product of input iterables."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
	self._dic = i
	self.it = itertools.product(*self._dic)
	self.__count = reduce(lambda x,y:x*y.count(), i[1:], i[0].count())

    def restart(self):
	for dic in self._dic: 
	    dic.restart()
	self.it = itertools.product(*self._dic)

    def count(self):
	return self.__count

    def next(self):
	return self.it.next()

    def __iter__(self):
	self.restart()
	return self

@moduleman_plugin("restart", "count", "next", "__iter__")
class chain:
    name = "chain"
    description = "Returns an iterator returns elements from the first iterable until it is exhausted, then proceeds to the next iterable, until all of the iterables are exhausted."
    category = ["default"]
    priority = 99

    def count(self):
	return self.__count

    def __init__(self, *i):
	self.__count = sum(map(lambda x:x.count(), i))
	self._dic = i
	self.it = itertools.chain(*i)

    def restart(self):
	for dic in self._dic: 
	    dic.restart()
	self.it = itertools.chain(*self._dic)

    def next(self):
	return (self.it.next(),)

    def __iter__(self):
	self.restart()
	return self
