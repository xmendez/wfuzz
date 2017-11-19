from wfuzz.exception import FuzzExceptMissingAPIKey, FuzzExceptResourceParseError

import urllib2
import json

class BingIter:
    def __init__(self, dork, offset = 0, limit = 0, key = None):
	if key is None:
	    key = Facade().sett.get('plugins', 'bing_apikey')

	if not key:
	    raise FuzzExceptMissingAPIKey("An api Bing key is needed. Please chek wfuzz.ini.")

	self._key = key
	self._dork = dork

	self.max_count = 0
	self.current = 0
	self._index = 0
	self._retrieved = 0
	self._results = []

	# first bing request to get estimated total count (it does not take into consideration offset).
	if limit > 0 and limit < 50:
	    total_results, self._retrieved, self._results = self._do_search(offset, limit)
	else:
	    total_results, self._retrieved, self._results = self._do_search(offset)

	# offset not over the results
	if offset > total_results:
	    self._offset = total_results
	else:
	    self._offset = offset

	self.max_count = total_results - self._offset

	# no more than limit results
	if self.max_count > limit and limit > 0:
	    self.max_count = limit

    def _do_search(self, offset = 0, limit = 50):
	# some code taken from http://www.securitybydefault.com/2014/07/search2auditpy-deja-que-bing-haga-el.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SecurityByDefault+%28Security+By+Default%29
	# api doc http://go.microsoft.com/fwlink/?LinkID=248077
	user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)'
	creds = (':%s' % self._key).encode('base64')[:-1]
	auth = 'Basic %s' % creds

	result = None

	try:
	    urlstr = 'https://api.datamarket.azure.com/Data.ashx/Bing/Search/Composite?Sources=%27web%27&Query=%27'+ self._dork +'%27&$format=json'
	    if limit != 50:
		urlstr += "&$top=%d" % limit
	    if offset != 0:
		urlstr += "&$skip=%d" % offset

	    request = urllib2.Request(urlstr)

	    request.add_header('Authorization', auth)
	    request.add_header('User-Agent', user_agent)
	    requestor = urllib2.build_opener()
	    result = requestor.open(request)
	except Exception, e:
	    raise FuzzExceptResourceParseError("Error when retrieving Bing API results: %s." % str(e))

	results = json.loads(result.read())

	# WebTotal is not reliable, it is usually much bigger than the actual results, therefore
	# if your offset increases over the real number of results, you get a dict
	# without values and counters to ''. It gets updated when you are close to that limit though.
	if results['d']['results'][0]["WebTotal"]:
	    res_total = int(results['d']['results'][0]["WebTotal"])
	    res_list = results['d']['results'][0]['Web']

	    return res_total, len(res_list), res_list
	else:
	    return 0, 0, 0

    def __iter__(self):
	return self

    def next(self):
	if self.current >= self.max_count:
	    raise StopIteration
	
	# Result buffer already consumed
	if self._index >= self._retrieved:
	    realcount, self._retrieved, self._results = self._do_search(self.current + self._offset)

	    self._index = 0

	    # update real count
	    if self.max_count > realcount:
		self.max_count = realcount

	elem = self._results[self._index]['Url'].strip()

	self.current += 1
	self._index += 1

	# pycurl does not like unicode
	if isinstance(elem, unicode):
	    return elem.encode('utf-8')
	else:
	    return elem

