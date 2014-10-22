from framework.fuzzer.fuzzobjects import FuzzRequest

class PluginResult:
    def __init__(self):
	self.source = ""
	self.issue = ""

class PluginRequest():
    def __init__(self):
	self.source = ""
	self.request = None
	self.rlevel = 0

    @staticmethod
    def from_fuzzRes(res, url, source):
	fr = FuzzRequest.from_fuzzRes(res, str(url))
	fr.wf_description = fr.path
	fr.rlevel = res.rlevel + 1

	plreq = PluginRequest()
	plreq.source = source
	plreq.request = fr
	plreq.rlevel = res.rlevel + 1

	return plreq

