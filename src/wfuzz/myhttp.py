import pycurl
from io import BytesIO
from threading import Thread, Lock
import itertools
from queue import Queue
import collections

from .exception import FuzzExceptBadOptions, FuzzExceptNetError

from .factories.reqresp_factory import ReqRespRequestFactory

# See https://curl.haxx.se/libcurl/c/libcurl-errors.html
UNRECOVERABLE_PYCURL_EXCEPTIONS = [
    28,  # Operation timeout. The specified time-out period was reached according to the conditions.
    7,  # Failed to connect() to host or proxy.
    6,  # Couldn't resolve host. The given remote host was not resolved.
    5,  # Couldn't resolve proxy. The given proxy host could not be resolved.
]

# Other common pycurl exceptions:
# Exception in perform (35, 'error:0B07C065:x509 certificate routines:X509_STORE_add_cert:cert already in hash table')
# Exception in perform (18, 'SSL read: error:0B07C065:x509 certificate routines:X509_STORE_add_cert:cert already in hash table, errno 11')


class HttpPool:
    HTTPAUTH_BASIC, HTTPAUTH_NTLM, HTTPAUTH_DIGEST = ("basic", "ntlm", "digest")
    newid = itertools.count(0)

    def __init__(self, options):
        self.processed = 0

        self.exit_job = False
        self.mutex_stats = Lock()

        self.m = None
        self.curlh_freelist = []
        self._request_list = collections.deque()
        self.handles = []

        self.ths = None

        self.pool_map = {}

        self.options = options

        self._registered = 0

    def _initialize(self):
        # pycurl Connection pool
        self.m = pycurl.CurlMulti()
        self.handles = []

        for i in range(self.options.get("concurrent")):
            curl_h = pycurl.Curl()
            self.handles.append(curl_h)
            self.curlh_freelist.append(curl_h)

        # create threads
        self.ths = []

        for fn in ("_read_multi_stack",):
            th = Thread(target=getattr(self, fn))
            th.setName(fn)
            self.ths.append(th)
            th.start()

    def job_stats(self):
        with self.mutex_stats:
            dic = {
                "http_processed": self.processed,
                "http_registered": len(self._registered),
            }
        return dic

    # internal http pool control

    def iter_results(self, poolid):
        item = self.pool_map[poolid]["queue"].get()

        if not item:
            return

        yield item

    def _new_pool(self):
        poolid = next(self.newid)
        self.pool_map[poolid] = {}
        self.pool_map[poolid]["queue"] = Queue()
        self.pool_map[poolid]["proxy"] = None

        if self.options.get("proxies"):
            self.pool_map[poolid]["proxy"] = self._get_next_proxy(
                self.options.get("proxies")
            )

        return poolid

    def _prepare_curl_h(self, curl_h, fuzzres, poolid):
        new_curl_h = ReqRespRequestFactory.to_http_object(
            self.options, fuzzres.history, curl_h
        )
        new_curl_h = self._set_extra_options(new_curl_h, fuzzres, poolid)

        new_curl_h.response_queue = (BytesIO(), BytesIO(), fuzzres, poolid)
        new_curl_h.setopt(pycurl.WRITEFUNCTION, new_curl_h.response_queue[0].write)
        new_curl_h.setopt(pycurl.HEADERFUNCTION, new_curl_h.response_queue[1].write)

        return new_curl_h

    def enqueue(self, fuzzres, poolid):
        if self.exit_job:
            return

        self._request_list.append((fuzzres, poolid))

    def _stop_to_pools(self):
        for p in list(self.pool_map.keys()):
            self.pool_map[p]["queue"].put(None)

    def cleanup(self):
        self.exit_job = True
        for th in self.ths:
            th.join()

    def register(self):
        with self.mutex_stats:
            self._registered += 1

        if not self.pool_map:
            self._initialize()

        return self._new_pool()

    def deregister(self):
        with self.mutex_stats:
            self._registered -= 1

            if self._registered <= 0:
                self.cleanup()

    def _get_next_proxy(self, proxy_list):
        i = 0
        while 1:
            yield proxy_list[i]
            i += 1
            i = i % len(proxy_list)

    def _set_extra_options(self, c, fuzzres, poolid):
        if self.pool_map[poolid]["proxy"]:
            ip, port, ptype = next(self.pool_map[poolid]["proxy"])

            fuzzres.history.wf_proxy = (("%s:%s" % (ip, port)), ptype)

            if ptype == "SOCKS5":
                c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
                c.setopt(pycurl.PROXY, "%s:%s" % (ip, port))
            elif ptype == "SOCKS4":
                c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS4)
                c.setopt(pycurl.PROXY, "%s:%s" % (ip, port))
            elif ptype == "HTTP":
                c.setopt(pycurl.PROXY, "%s:%s" % (ip, port))
            else:
                raise FuzzExceptBadOptions(
                    "Bad proxy type specified, correct values are HTTP, SOCKS4 or SOCKS5."
                )
        else:
            c.setopt(pycurl.PROXY, "")

        mdelay = self.options.get("req_delay")
        if mdelay is not None:
            c.setopt(pycurl.TIMEOUT, mdelay)

        cdelay = self.options.get("conn_delay")
        if cdelay is not None:
            c.setopt(pycurl.CONNECTTIMEOUT, cdelay)

        return c

    def _process_curl_handle(self, curl_h):
        buff_body, buff_header, res, poolid = curl_h.response_queue

        try:
            ReqRespRequestFactory.from_http_object(
                self.options,
                res.history,
                curl_h,
                buff_header.getvalue(),
                buff_body.getvalue(),
            )
        except Exception as e:
            self.pool_map[poolid]["queue"].put(res.update(exception=e))
        else:
            # reset type to result otherwise backfeed items will enter an infinite loop
            self.pool_map[poolid]["queue"].put(res.update())

        with self.mutex_stats:
            self.processed += 1

    def _process_curl_should_retry(self, res, errno, poolid):
        if errno not in UNRECOVERABLE_PYCURL_EXCEPTIONS:
            res.history.wf_retries += 1

            if res.history.wf_retries < self.options.get("retries"):
                self._request_list.append((res, poolid))
                return True

        return False

    def _process_curl_handle_error(self, res, errno, errmsg, poolid):
        e = FuzzExceptNetError("Pycurl error %d: %s" % (errno, errmsg))
        res.history.totaltime = 0
        self.pool_map[poolid]["queue"].put(res.update(exception=e))

        with self.mutex_stats:
            self.processed += 1

    def _read_multi_stack(self):
        # Check for curl objects which have terminated, and add them to the curlh_freelist
        while not self.exit_job:
            while not self.exit_job:
                ret, num_handles = self.m.perform()
                if ret != pycurl.E_CALL_MULTI_PERFORM:
                    break

            num_q, ok_list, err_list = self.m.info_read()
            for curl_h in ok_list:
                self._process_curl_handle(curl_h)
                self.m.remove_handle(curl_h)
                self.curlh_freelist.append(curl_h)

            for curl_h, errno, errmsg in err_list:
                buff_body, buff_header, res, poolid = curl_h.response_queue

                if not self._process_curl_should_retry(res, errno, poolid):
                    self._process_curl_handle_error(res, errno, errmsg, poolid)

                self.m.remove_handle(curl_h)
                self.curlh_freelist.append(curl_h)

            while self.curlh_freelist and self._request_list:
                curl_h = self.curlh_freelist.pop()
                fuzzres, poolid = self._request_list.popleft()

                self.m.add_handle(self._prepare_curl_h(curl_h, fuzzres, poolid))

        self._stop_to_pools()

        # cleanup multi stack
        for c in self.handles:
            c.close()
            self.curlh_freelist.append(c)
        self.m.close()
