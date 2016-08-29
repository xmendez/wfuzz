from framework.fuzzobjects import FuzzResult

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
	plreq = PluginRequest()
	plreq.source = source
	plreq.fuzzitem = res.to_new_url(url)

	return plreq

