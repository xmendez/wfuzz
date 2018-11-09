from wfuzz.externals.moduleman.plugin import moduleman_plugin

import itertools
from functools import reduce

# python 2 and 3: iterator
from builtins import object

from builtins import zip as builtinzip


@moduleman_plugin
class zip(object):
    name = "zip"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Returns an iterator that aggregates elements from each of the iterables."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
        self.__count = min([x.count() for x in i])
        self.it = builtinzip(*i)

    def count(self):
        return self.__count

    def __next__(self):
        return next(self.it)

    def __iter__(self):
        return self


@moduleman_plugin
class product(object):
    name = "product"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Returns an iterator cartesian product of input iterables."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
        self.__count = reduce(lambda x, y: x * y.count(), i[1:], i[0].count())
        self.it = itertools.product(*i)

    def count(self):
        return self.__count

    def __next__(self):
        return next(self.it)

    def __iter__(self):
        return self


@moduleman_plugin
class chain(object):
    name = "chain"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Returns an iterator returns elements from the first iterable until it is exhausted, then proceeds to the next iterable, until all of the iterables are exhausted."
    category = ["default"]
    priority = 99

    def count(self):
        return self.__count

    def __init__(self, *i):
        self.__count = sum([x.count() for x in i])
        self.it = itertools.chain(*i)

    def __next__(self):
        return (next(self.it),)

    def __iter__(self):
        return self
