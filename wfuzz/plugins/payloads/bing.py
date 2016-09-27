from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.plugin_api.payloadtools import BingIter

@wfuzz_iterator
class bing:
    '''
    Some examples of bing hacking:
    - http://www.elladodelmal.com/2010/02/un-poco-de-bing-hacking-i-de-iii.html
    '''
    name = "bing"
    description = "Returns URL results of a given bing API search (needs api key). ie, intitle:\"JBoss JMX Management Console\"-10"
    category = ["default"]
    priority = 99
    def __init__(self, default_param, extra):
	offset = 0
	limit = 0

	if extra:
	    if extra.has_key("offset"):
		offset = int(extra["offset"])

	    if extra.has_key("limit"):
		limit = int(extra["limit"])

	self._it = BingIter(default_param, offset, limit)

    def __iter__(self):
	return self

    def count(self):
	return self._it.max_count

    def next(self):
	return self._it.next()
