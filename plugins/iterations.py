from framework.externals.moduleman.plugin import moduleman_plugin
from framework.fuzzer.base import wfuzz_iterator

import itertools

@wfuzz_iterator
class zip:
    name = "zip"
    description = "Returns an iterator that aggregates elements from each of the iterables."
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

@wfuzz_iterator
class product:
    name = "product"
    description = "Returns an iterator cartesian product of input iterables."
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

@wfuzz_iterator
class chain:
    name = "chain"
    description = "Returns an iterator returns elements from the first iterable until it is exhausted, then proceeds to the next iterable, until all of the iterables are exhausted."
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
