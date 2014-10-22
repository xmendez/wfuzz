import itertools

class iterator_zip(itertools.izip):
    text="zip"

    def __init__(self, *i):
	itertools.izip.__init__(self, *i)
	self.__count = max(map(lambda x:x.count(), i))

    def count(self):
	return self.__count

class iterator_product(itertools.product):
    text="product"

    def __init__(self, *i):
	itertools.product.__init__(self, *i)
	self.__count = reduce(lambda x,y:x*y.count(), i[1:], i[0].count())

    def count(self):
	return self.__count

class iterator_chain:
    text="chain"

    def count(self):
	return self.__count

    def __init__(self, *i):
	self.__count = sum(map(lambda x:x.count(), i))
	self.it = itertools.chain(*i)

    def next(self):
	return (self.it.next(),)

    def __iter__(self):
	return self
