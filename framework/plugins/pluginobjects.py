from framework.fuzzer.fuzzobjects import FuzzItemType

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

	self.fuzzitem = None

    @staticmethod
    def from_fuzzRes(res, url, source):
        fr = res.from_soft_copy()
        fr.history.url = str(url)
	fr.description = fr.history.path
	fr.rlevel = res.rlevel + 1
        fr.type = FuzzItemType.backfeed

	plreq = PluginRequest()
	plreq.source = source
	plreq.fuzzitem = fr

	return plreq

