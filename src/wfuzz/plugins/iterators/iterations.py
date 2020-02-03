from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.dictionaries import BaseIterator

import itertools
from functools import reduce

from builtins import zip as builtinzip


@moduleman_plugin
class zip(BaseIterator):
    name = "zip"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Returns an iterator that aggregates elements from each of the iterables."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
        self._payload_list = i
        self.__width = len(i)
        self.__count = min([x.count() for x in i])
        self.it = builtinzip(*i)

    def count(self):
        return self.__count

    def width(self):
        return self.__width

    def payloads(self):
        return self._payload_list

    def __next__(self):
        return next(self.it)

    def __iter__(self):
        return self


@moduleman_plugin
class product(BaseIterator):
    name = "product"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Returns an iterator cartesian product of input iterables."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
        self._payload_list = i
        self.__width = len(i)
        self.__count = reduce(lambda x, y: x * y.count(), i[1:], i[0].count())
        self.it = itertools.product(*i)

    def count(self):
        return self.__count

    def width(self):
        return self.__width

    def payloads(self):
        return self._payload_list

    def __next__(self):
        return next(self.it)

    def __iter__(self):
        return self


@moduleman_plugin
class chain(BaseIterator):
    name = "chain"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Returns an iterator returns elements from the first iterable until it is exhausted, then proceeds to the next iterable, until all of the iterables are exhausted."
    category = ["default"]
    priority = 99

    def __init__(self, *i):
        self._payload_list = i
        self.__count = sum([x.count() for x in i])
        self.it = itertools.chain(*i)

    def count(self):
        return self.__count

    def width(self):
        return 1

    def payloads(self):
        return self._payload_list

    def __next__(self):
        return (next(self.it),)

    def __iter__(self):
        return self
