from externals.moduleman.plugin import moduleman_plugin

import itertools

class piterator_void:
    def count(self):
	return self.__count

    def __init__(self, *i):
	self._dic = i
	self.restart()

    def next(self):
	return (self.it.next(),)

    def restart(self):
	self.__count = self._dic[0].count()

	self._dic[0].restart()
	self.it = self._dic[0]

    def __iter__(self):
	return self

@moduleman_plugin("restart", "count", "next", "__iter__")
class zip:
    name = "zip"
    description = "Returns an iterator that aggregates elements from each of the iterables."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
	self._dic = i
	self.restart()

    def count(self):
	return self.__count

    def restart(self):
	self.__count = max(map(lambda x:x.count(), self._dic))
	self.it = itertools.izip(*self._dic)

    def next(self):
	return self.it.next()

    def __iter__(self):
	return self

@moduleman_plugin("restart", "count", "next", "__iter__")
class product:
    name = "product"
    description = "Returns an iterator cartesian product of input iterables."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
	self._dic = i
	self.restart()

    def restart(self):
	self.it = itertools.product(*self._dic)
	self.__count = reduce(lambda x,y:x*y.count(), self._dic[1:], self._dic[0].count())

    def count(self):
	return self.__count

    def next(self):
	return self.it.next()

    def __iter__(self):
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
	self._dic = i
	self.restart()

    def restart(self):
	self.__count = sum(map(lambda x:x.count(), self._dic))
	self.it = itertools.chain(*self._dic)

    def next(self):
	return (self.it.next(),)

    def __iter__(self):
	return self
