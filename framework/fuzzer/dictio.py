from framework.fuzzer.fuzzobjects import FuzzRequest
from framework.fuzzer.fuzzobjects import FuzzStats

class dictionary:
	def __init__(self, payload, encoders):
	    self.__payload = payload
	    self.__encoder = encoders
	    self.__generator = None

	def count (self):
	    return self.__payload.count() * len(self.__encoder)

	def restart(self):
	    self.__payload.restart()
	    self.__generator = self.gen()

	def __iter__(self):
	    self.restart()
	    return self

	def gen(self):
	    while 1:
		pl = self.__payload.next()
		for encode in self.__encoder:
		    yield encode(pl)

	def next(self):
	    return self.__generator.next()

class requestGenerator:
	def __init__(self, seed, dictio):
	    self.seed = seed
	    self._baseline = FuzzRequest.from_baseline(seed)
	    self.dictio = dictio

	    self.stats = FuzzStats.from_requestGenerator(self)

	    if self.seed.wf_allvars is not None:
		self._allvar_gen = self.__allvars_gen(self.dictio)
	    else:
		self._allvar_gen = None
		

	def stop(self):
	    self.stats.cancelled = True

	def restart(self, seed):
	    self.seed = seed
	    self.dictio.restart()

	def count(self):
	    v = self.dictio.count()
	    if self.seed.wf_allvars is not None:
		v *= self.seed.wf_allvars_len()

	    if self._baseline: v += 1

	    return v

	def __iter__(self):
	    return self

	def __allvars_gen(self, dic):
	    for payload in dic:
		for r in FuzzRequest.from_all_fuzz_request(self.seed, payload):
		    yield r

	def next(self):
	    if self.stats.cancelled:
		raise StopIteration

	    if self.seed.wf_allvars is not None:
		return self._allvar_gen.next()
	    else:
		return FuzzRequest.from_seed(self.seed, self.dictio.next())

	def get_baseline(self):
	    return self._baseline
