from wfuzz.exception import (
    FuzzExceptMissingAPIKey,
    FuzzExceptResourceParseError,
    FuzzExceptPluginLoadError,
)
from wfuzz.facade import Facade
from wfuzz.helpers.utils import MyCounter


# Python 2 and 3: alternative 4
try:
    from urllib.request import Request
    from urllib.request import build_opener
except ImportError:
    from urllib2 import Request
    from urllib2 import build_opener

import json

# python 2 and 3: iterator
from builtins import object
from threading import Thread
from queue import Queue

IMPORTED_SHODAN = True
try:
    import shodan
except ImportError:
    IMPORTED_SHODAN = False

m = {
    "matches": [
        {
            "_shodan": {
                "id": "54e0ae62-9e22-404b-91b4-92f99e89c987",
                "options": {},
                "ptr": True,
                "module": "auto",
                "crawler": "62861a86c4e4b71dceed5113ce9593b98431f89a",
            },
            "hash": -1355923443,
            "os": None,
            "ip": 1240853908,
            "isp": "Comcast Cable",
            "http": {
                "html_hash": -2142469325,
                "robots_hash": None,
                "redirects": [],
                "securitytxt": None,
                "title": "400 Bad Request",
                "sitemap_hash": None,
                "robots": None,
                "favicon": None,
                "host": "73.245.237.148",
                "html": '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<title>400 Bad Request</title>\n</head><body>\n<h1>Bad Request</h1>\n<p>Your browser sent a request that this server could not understand.<br />\nReason: You\'re speaking plain HTTP to an SSL-enabled server port.<br />\n Instead use the HTTPS scheme to access this URL, please.<br />\n</p>\n<p>Additionally, a 404 Not Found\nerror was encountered while trying to use an ErrorDocument to handle the request.</p>\n</body></html>\n',
                "location": "/",
                "components": {},
                "server": "Apache",
                "sitemap": None,
                "securitytxt_hash": None,
            },
            "port": 9445,
            "hostnames": ["c-73-245-237-148.hsd1.fl.comcast.net"],
            "location": {
                "city": "Fort Lauderdale",
                "region_code": "FL",
                "area_code": 954,
                "longitude": -80.3704,
                "country_code3": "USA",
                "country_name": "United States",
                "postal_code": "33331",
                "dma_code": 528,
                "country_code": "US",
                "latitude": 26.065200000000004,
            },
            "timestamp": "2019-04-10T10:30:48.297701",
            "domains": ["comcast.net"],
            "org": "Comcast Cable",
            "data": "HTTP/1.1 400 Bad Request\r\nDate: Wed, 10 Apr 2019 10:19:07 GMT\r\nServer: Apache\r\nContent-Length: 481\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n",
            "asn": "AS7922",
            "transport": "tcp",
            "ip_str": "73.245.237.148",
        },
        {
            "_shodan": {
                "id": "4ace6fd1-8295-4aea-a086-2280598ca9e7",
                "options": {},
                "ptr": True,
                "module": "auto",
                "crawler": "62861a86c4e4b71dceed5113ce9593b98431f89a",
            },
            "product": "Apache httpd",
            "hash": 370611044,
            "os": None,
            "ip": 35226500,
            "isp": "EE High Speed Internet",
            "http": {
                "html_$ ash": -163723763,
                "robots_hash": None,
                "redirects": [],
                "securitytxt": None,
                "title": "401 Authorization Required",
                "sitemap_hash": None,
                "robots": None,
                "favicon": None,
                "host": "2.25.131.132",
                "html": "<HEAD><TITLE>401 Authorization Required</TITLE></HEAD>\n<BODY><H1>401 Authoriza$ ion Required</H1>\nBrowser not authentication-capable or authentication failed.\n</BODY>\n",
                "location": "/",
                "components": {},
                "server": "Apache",
                "sitemap": None,
                "securitytxt_hash": None,
            },
            "cpe": ["cpe:/a:apache:http_server"],
            "port": 8085,
            "hostnames": [],
            "location": {
                "city": "$ helmsford",
                "region_code": "E4",
                "area_code": None,
                "longitude": 0.48330000000001405,
                "country_code3": "GBR",
                "country_name": "United Kingdom",
                "postal_code": "CM2",
                "dma_code": None,
                "country_code": "GB",
                "latitude": 51.733300000000014,
            },
            "timestamp": "2019-04-10T11:03:59.955967",
            "$ omains": [],
            "org": "EE High Speed Internet",
            "data": 'HTTP/1.1 401 Unauthorized\r\nServer: Apache\r\nConnection: Close\r\nContent-type: text/html\r\nWWW-Authenticate: Digest realm="DSLForum CPE Management", algorithm=MD5, qop=auth, stale=FALSE, nonce="3d7a3f71e72e095dba31fd77d4db74$5", opaque="5ccc069c403ebaf9f0171e9517f40e41"\r\n\r\n',
            "asn": "AS12576",
            "transport": "tcp",
            "ip_str": "2.25.131.132",
        },
    ]
}


class BingIter(object):
    def __init__(self, dork, offset=0, limit=0, key=None):
        if key is None:
            key = Facade().sett.get("plugins", "bing_apikey")

        if not key:
            raise FuzzExceptMissingAPIKey(
                "An api Bing key is needed. Please chek wfuzz.ini."
            )

        self._key = key
        self._dork = dork

        self.max_count = 0
        self.current = 0
        self._index = 0
        self._retrieved = 0
        self._results = []

        # first bing request to get estimated total count (it does not take into consideration offset).
        if limit > 0 and limit < 50:
            total_results, self._retrieved, self._results = self._do_search(
                offset, limit
            )
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

    def _do_search(self, offset=0, limit=50):
        # some code taken from http://www.securitybydefault.com/2014/07/search2auditpy-deja-que-bing-haga-el.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SecurityByDefault+%28Security+By+Default%29
        # api doc http://go.microsoft.com/fwlink/?LinkID=248077
        user_agent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)"
        creds = (":%s" % self._key).encode("base64")[:-1]
        auth = "Basic %s" % creds

        result = None

        try:
            urlstr = (
                "https://api.datamarket.azure.com/Data.ashx/Bing/Search/Composite?Sources=%27web%27&Query=%27"
                + self._dork
                + "%27&$format=json"
            )
            if limit != 50:
                urlstr += "&$top=%d" % limit
            if offset != 0:
                urlstr += "&$skip=%d" % offset

            request = Request(urlstr)

            request.add_header("Authorization", auth)
            request.add_header("User-Agent", user_agent)
            requestor = build_opener()
            result = requestor.open(request)
        except Exception as e:
            raise FuzzExceptResourceParseError(
                "Error when retrieving Bing API results: %s." % str(e)
            )

        results = json.loads(result.read())

        # WebTotal is not reliable, it is usually much bigger than the actual results, therefore
        # if your offset increases over the real number of results, you get a dict
        # without values and counters to ''. It gets updated when you are close to that limit though.
        if results["d"]["results"][0]["WebTotal"]:
            res_total = int(results["d"]["results"][0]["WebTotal"])
            res_list = results["d"]["results"][0]["Web"]

            return res_total, len(res_list), res_list
        else:
            return 0, 0, 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.current >= self.max_count:
            raise StopIteration

        # Result buffer already consumed
        if self._index >= self._retrieved:
            realcount, self._retrieved, self._results = self._do_search(
                self.current + self._offset
            )

            self._index = 0

            # update real count
            if self.max_count > realcount:
                self.max_count = realcount

        elem = self._results[self._index]["Url"].strip()

        self.current += 1
        self._index += 1

        # pycurl does not like unicode
        if isinstance(elem, str):
            return elem.encode("utf-8")
        else:
            return elem


class ShodanIter:
    SHODAN_RES_PER_PAGE = 100
    MAX_ENQUEUED_RES = SHODAN_RES_PER_PAGE + 1
    NUM_OF_WORKERS = 1
    SLOW_START = True

    def __init__(self, dork, page, limit):
        if IMPORTED_SHODAN is False:
            raise FuzzExceptPluginLoadError(
                "shodan module not imported. Please, install shodan using pip"
            )

        key = Facade().sett.get("plugins", "shodan_apikey")
        if not key:
            raise FuzzExceptMissingAPIKey(
                "A Shodan api key is needed. Please check ~/.wfuzz/wfuzz.ini"
            )

        self.api = shodan.Shodan(key)
        self._dork = dork
        self._page = MyCounter(page)
        self._page_limit = self._page() + limit if limit > 0 else -1

        self.results_queue = Queue(self.MAX_ENQUEUED_RES)
        self.page_queue = Queue()

        self._threads = []

        self._started = False
        self._cancel_job = False

    def _do_search(self):
        while 1:
            page = self.page_queue.get()
            if page is None:
                self.page_queue.task_done()
                break

            if self._cancel_job:
                self.page_queue.task_done()
                continue

            if self._page_limit > 0 and page >= self._page_limit:
                self.page_queue.task_done()
                self.results_queue.put(None)
                continue

            try:
                results = self.api.search(self._dork, page=page)
                for item in results["matches"]:
                    if not self._cancel_job:
                        self.results_queue.put(item)

                self.page_queue.task_done()
                if not self._cancel_job:
                    self.page_queue.put(self._page.inc())
            except shodan.APIError as e:
                self.page_queue.task_done()
                if "Invalid page size" in str(e):
                    self.results_queue.put(None)
                elif "Insufficient query credits" in str(e):
                    self.results_queue.put(None)
                else:
                    self.results_queue.put(e)
                continue

    def __iter__(self):
        return self

    def _start(self):
        for th_n in range(self.NUM_OF_WORKERS):
            worker = Thread(target=self._do_search)
            worker.setName("_do_search_{}".format(str(th_n)))
            self._threads.append(worker)
            worker.start()

        self.page_queue.put(self._page())
        if not self.SLOW_START:
            for _ in range(self.NUM_OF_WORKERS - 1):
                self.page_queue.put(self._page.inc())

    def _stop(self):
        self._cancel_job = True

        for th in self._threads:
            self.page_queue.put(None)

        self.page_queue.join()

        for th in self._threads:
            th.join()

        self._threads = []

        self.results_queue.put(None)

    def __next__(self):
        if not self._started:
            self._start()
            self._started = True

        res = self.results_queue.get()
        self.results_queue.task_done()

        if res is None:
            self._stop()
            self._cancel_job = False
            self._started = False
            raise StopIteration
        elif isinstance(res, Exception):
            self._stop()
            raise res

        return res
