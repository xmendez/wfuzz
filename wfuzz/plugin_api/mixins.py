# Plugins specializations with common methods useful for their own type

class DiscoveryPluginMixin:
    def __init__(self):
	BasePlugin.__init__(self)
	self.black_list = self.kbase["discovery.blacklist"][0].split("-")

    def blacklisted_extension(self, url):
	return parse_url(url).fext in self.black_list

    def queue_url(self, url):
	if not self.blacklisted_extension(url):
	    BasePlugin.queue_url(self, url)
	    return True
	return False



