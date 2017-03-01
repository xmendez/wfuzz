from wfuzz.externals.moduleman.plugin import moduleman_plugin

import itertools

@moduleman_plugin
class zip:
    name = "zip"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Returns an iterator that aggregates elements from each of the iterables."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
	self.__count = max(map(lambda x:x.count(), i))
	self.it = itertools.izip(*i)

    def count(self):
	return self.__count

    def next(self):
	return self.it.next()

    def __iter__(self):
	return self

@moduleman_plugin
class product:
    name = "product"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Returns an iterator cartesian product of input iterables."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
	self.it = itertools.product(*i)
	self.__count = reduce(lambda x,y:x*y.count(), i[1:], i[0].count())

    def count(self):
	return self.__count

    def next(self):
	return self.it.next()

    def __iter__(self):
	return self

@moduleman_plugin
class chain:
    name = "chain"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Returns an iterator returns elements from the first iterable until it is exhausted, then proceeds to the next iterable, until all of the iterables are exhausted."
    category = ["default"]
    priority = 99

    def count(self):
	return self.__count

    def __init__(self, *i):
	self.__count = sum(map(lambda x:x.count(), i))
	self.it = itertools.chain(*i)

    def next(self):
	return (self.it.next(),)

    def __iter__(self):
	return self
