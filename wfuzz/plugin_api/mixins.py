# Plugins specializations with common methods useful for their own type

class DiscoveryPluginMixin:
    def __init__(self):
	BasePlugin.__init__(self)

    def queue_url(self, url):
	if not parse_url(url).bllist:
	    BasePlugin.queue_url(self, url)
	    return True
	return False



