from framework.fuzzer.fuzzobjects import FuzzRequestFactory

class PluginItem:
    undefined, result, backfeed = range(3)

    def __init__(self, ptype):
	self.source = ""
        self.plugintype = ptype

class PluginResult(PluginItem):
    def __init__(self):
        PluginItem.__init__(self, PluginItem.result)

	self.issue = ""

class PluginRequest(PluginItem):
    def __init__(self):
        PluginItem.__init__(self, PluginItem.backfeed)

	self.request = None
        self.rlevel = 0

    @staticmethod
    def from_fuzzRes(res, url, source):
	fr = FuzzRequestFactory.from_fuzzRes(res, str(url))
	fr.wf_description = fr.path
	fr.rlevel = res.rlevel + 1

	plreq = PluginRequest()
	plreq.source = source
	plreq.request = fr
	plreq.rlevel = res.rlevel + 1

	return plreq

