from framework.plugins.pluginobjects import PluginResult
from framework.plugins.pluginobjects import PluginRequest
from framework.core.myexception import FuzzException
from framework.core.facade import Facade

import os
import urlparse
import urllib2
import json

# Util methods when processing fuzz results 

def url_filename(fuzzresult):
    u = urlparse.urlsplit(fuzzresult.url).path.split('/')[-1:][0]

    return u

def url_same_domain(url1, url2):
    return url_domain(url1) == url_domain(url2)

def url_domain(url):
    return '.'.join(urlparse.urlparse(url).netloc.split(".")[-2:])

def url_filename_ext(url):
    path = urlparse.urlparse(url).path
    ext = os.path.splitext(path)[1]

    return ext

# Util methods for accessing search results
def search_bing(dork, key = None, raw = False):
    if key is None:
	key = Facade().sett.get('plugins', 'bing_apikey')

    if not key:
	raise FuzzException(FuzzException.FATAL, "An api Bing key is needed. Please chek wfuzz.ini.")
    
    # some code taken from http://www.securitybydefault.com/2014/07/search2auditpy-deja-que-bing-haga-el.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SecurityByDefault+%28Security+By+Default%29
    user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)'
    creds = (':%s' % key).encode('base64')[:-1]
    auth = 'Basic %s' % creds

    # temporary solution, wf should have a process performing http requests. even plugins might need this.
    
    try:
	request = urllib2.Request('https://api.datamarket.azure.com/Data.ashx/Bing/Search/Composite?Sources=%27web%27&Query=%27'+dork+'%27&$format=json')
	request.add_header('Authorization', auth)
	request.add_header('User-Agent', user_agent)
	requestor = urllib2.build_opener()
	result = requestor.open(request)
    except Exception, e:
	raise FuzzException(FuzzException.FATAL, "Error when retrieving Bing API results: %s." % e.msg)
    
    results = json.loads(result.read())
    #test results = {u'd': {u'results': [{u'Web': [{u'Description': u'Diario de informaci\xf3n general de USA, noticias de \xfaltima hora de USA, el mundo, local, deportes, noticias curiosas y m\xe1s', u'Title': u'20minutos.com - El medio social - \xdaltima hora en USA y el ...', u'Url': u'http://www.20minutos.com/', u'__metadata': {u'type': u'WebResult', u'uri': u"https://api.datamarket.azure.com/Data.ashx/Bing/Search/ExpandableSearchResultSet(guid'b670a6b6-6ae7-4830-ad6f-83b525d6266d')/Web?$skip=0&$top=1"}, u'DisplayUrl': u'www.20minutos.com', u'ID': u'546995b5-587a-4618-984d-93bc5041e067'}, {u'Description': u'Informaci\xf3n, noticias y resultados de deportes: F\xfatbol, Baloncesto, NBA, Beisbol, F\xf3rmula 1, MotoGP, Tenis y m\xe1s en 20minutos.com', u'Title': u'Noticias deportivas - 20minutos.com', u'Url': u'http://www.20minutos.com/deportes/', u'__metadata': {u'type': u'WebResult', u'uri': u"https://api.datamarket.azure.com/Data.ashx/Bing/Search/ExpandableSearchResultSet(guid'b670a6b6-6ae7-4830-ad6f-83b525d6266d')/Web?$skip=1&$top=1"}, u'DisplayUrl': u'www.20minutos.com/deportes', u'ID': u'2ff2cd36-eece-4810-9b00-cba7d5ecfa47'}], u'VideoTotal': u'', u'RelatedSearch': [], u'Image': [], u'__metadata': {u'type': u'ExpandableSearchResult', u'uri': u"https://api.datamarket.azure.com/Data.ashx/Bing/Search/Composite?Sources='web'&Query='ip:193.148.34.26'&$skip=0&$top=1"}, u'ImageOffset': u'', u'AlterationOverrideQuery': u'', u'ImageTotal': u'', u'WebTotal': u'20', u'SpellingSuggestionsTotal': u'', u'WebOffset': u'0', u'Video': [], u'News': [], u'AlteredQuery': u'', u'SpellingSuggestions': [], u'VideoOffset': u'', u'NewsTotal': u'', u'ID': u'b670a6b6-6ae7-4830-ad6f-83b525d6266d', u'NewsOffset': u''}]}}

    if raw:
	return results
    else:
	return results['d']['results'][0]['Web']

class BasePlugin():
    def __init__(self):
	self.results_queue = None
	self.base_fuzz_res = None

    def run(self, fuzzresult, control_queue, results_queue):
	try:
	    self.results_queue = results_queue
	    self.base_fuzz_res = fuzzresult
	    self.process(fuzzresult)
	except Exception, e:
	    plres = PluginResult()
	    plres.source = "$$exception$$"
	    plres.issue = "Exception within plugin %s: %s" % (self.name, str(e))
	    results_queue.put(plres)
	finally:
	    control_queue.get()
	    control_queue.task_done()
	    return

    def process(self, fuzzresult):
	'''
	This is were the plugin processing is done. Any wfuzz plugin must implement this method, do its job with the fuzzresult received and:
	- queue_url: if it is a discovery plugin enqueing more HTTP request that at some point will generate more results
	- add_result: Add information about the obtained results after the processing with an accurate description

	A kbase (get_kbase, has_kbase, add_kbase) is shared between all plugins. this can be used to store and retrieve relevant "collaborative" information.
	'''
	raise NotImplemented

    def add_result(self, issue):
	plres = PluginResult()
	plres.source = self.name
	plres.issue = issue

	self.results_queue.put(plres)

    def queue_raw_request(self, raw):
	self.results_queue.put(raw)

    def queue_url(self, url):
	self.results_queue.put(PluginRequest.from_fuzzRes(self.base_fuzz_res, url, self.name))

    def get_kbase(self, key):
	v = self.kbase.get(key)
	if not v:
	    raise FuzzException(FuzzException.FATAL, "Key not in kbase")
	return v

    def has_kbase(self, key):
	return self.kbase.has(key)

    def add_kbase(self, key, value):
	self.kbase.add(key, value)

# Plugins specializations with common methods useful for their own type

class DiscoveryPlugin(BasePlugin):
    def __init__(self):
	self.black_list = Facade().sett.get('plugins', 'file_bl').split(",")

	if self.has_kbase("discovery.bl"):
	    self.black_list = self.get_kbase("discovery.bl")[0].split("-")

    def blacklisted_extension(self, url):
	return url_filename_ext(url) in self.black_list
