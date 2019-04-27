import pycurl
from io import BytesIO
from threading import Thread, Lock
import itertools
from queue import Queue

from .exception import FuzzExceptBadOptions, FuzzExceptNetError


class HttpPool:
    HTTPAUTH_BASIC, HTTPAUTH_NTLM, HTTPAUTH_DIGEST = ('basic', 'ntlm', 'digest')
    newid = itertools.count(0)

    def __init__(self, options):
        self.processed = 0

        self.exit_job = False
        self.mutex_multi = Lock()
        self.mutex_stats = Lock()
        self.mutex_reg = Lock()

        self.m = None
        self.freelist = Queue()
        self.retrylist = Queue()

        self.ths = None

        self.pool_map = {}
        self.default_poolid = 0

        self.options = options

        self._registered = 0

    def _initialize(self):
        # pycurl Connection pool
        self._create_pool(self.options.get("concurrent"))

        # internal pool
        self.default_poolid = self._new_pool()

        # create threads
        self.ths = []

        for fn in ("_read_multi_stack", "_read_retry_queue"):
            th = Thread(target=getattr(self, fn))
            th.setName(fn)
            self.ths.append(th)
            th.start()

    def job_stats(self):
        with self.mutex_stats:
            dic = {
                "http_Processed": self.processed,
                "http_Idle Workers": self.freelist.qsize()
            }
        return dic

    # internal http pool control

    def perform(self, fuzzreq):
        poolid = self._new_pool()
        self.enqueue(fuzzreq, poolid)
        item = self.pool_map[poolid]["queue"].get()
        return item

    def iter_results(self, poolid=None):
        item = self.pool_map[self.default_poolid if not poolid else poolid]["queue"].get()

        if not item:
            return

        yield item

    def _new_pool(self):
        poolid = next(self.newid)
        self.pool_map[poolid] = {}
        self.pool_map[poolid]["queue"] = Queue()
        self.pool_map[poolid]["proxy"] = None

        if self.options.get("proxies"):
            self.pool_map[poolid]["proxy"] = self._get_next_proxy(self.options.get("proxies"))

        return poolid

    def enqueue(self, fuzzres, poolid=None):
        c = fuzzres.history.to_http_object(self.freelist.get())
        c = self._set_extra_options(c, fuzzres, self.default_poolid if not poolid else poolid)

        if self.exit_job:
            return

        c.response_queue = ((BytesIO(), BytesIO(), fuzzres, self.default_poolid if not poolid else poolid))
        c.setopt(pycurl.WRITEFUNCTION, c.response_queue[0].write)
        c.setopt(pycurl.HEADERFUNCTION, c.response_queue[1].write)

        with self.mutex_multi:
            self.m.add_handle(c)

    def _stop_to_pools(self):
        for p in list(self.pool_map.keys()):
            self.pool_map[p]["queue"].put(None)

    # Pycurl management
    def _create_pool(self, num_conn):
        # Pre-allocate a list of curl objects
        self.m = pycurl.CurlMulti()
        self.m.handles = []

        for i in range(num_conn):
            c = pycurl.Curl()
            self.m.handles.append(c)
            self.freelist.put(c)

    def cleanup(self):
        self.exit_job = True
        for th in self.ths:
            th.join()

    def register(self):
        with self.mutex_reg:
            self._registered += 1

            if not self.pool_map:
                self._initialize()
                return self.default_poolid
            else:
                return self._new_pool()

    def deregister(self):
        with self.mutex_reg:
            self._registered -= 1

        if self._registered <= 0:
            self.cleanup()

    def _get_next_proxy(self, proxy_list):
        i = 0
        while 1:
            yield proxy_list[i]
            i += 1
            i = i % len(proxy_list)

    def _set_extra_options(self, c, freq, poolid):
        if self.pool_map[poolid]["proxy"]:
            ip, port, ptype = next(self.pool_map[poolid]["proxy"])

            freq.wf_proxy = (("%s:%s" % (ip, port)), ptype)

            c.setopt(pycurl.PROXY, "%s:%s" % (ip, port))
            if ptype == "SOCKS5":
                c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
            elif ptype == "SOCKS4":
                c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS4)
            elif ptype == "HTTP":
                pass
            else:
                raise FuzzExceptBadOptions("Bad proxy type specified, correct values are HTTP, SOCKS4 or SOCKS5.")
        else:
            c.setopt(pycurl.PROXY, "")

        mdelay = self.options.get("req_delay")
        if mdelay is not None:
            c.setopt(pycurl.TIMEOUT, mdelay)

        cdelay = self.options.get("conn_delay")
        if cdelay is not None:
            c.setopt(pycurl.CONNECTTIMEOUT, cdelay)

        return c

    def _read_retry_queue(self):
        while not self.exit_job:
            res, poolid = self.retrylist.get()

            if res is None:
                break

            self.enqueue(res, poolid)

    def _read_multi_stack(self):
        # Check for curl objects which have terminated, and add them to the freelist
        while not self.exit_job:
            with self.mutex_multi:
                while not self.exit_job:
                    ret, num_handles = self.m.perform()
                    if ret != pycurl.E_CALL_MULTI_PERFORM:
                        break

            num_q, ok_list, err_list = self.m.info_read()
            for c in ok_list:
                # Parse response
                buff_body, buff_header, res, poolid = c.response_queue

                try:
                    res.history.from_http_object(c, buff_header.getvalue(), buff_body.getvalue())
                except Exception as e:
                    self.pool_map[poolid]["queue"].put(res.update(exception=e))
                else:
                    # reset type to result otherwise backfeed items will enter an infinite loop
                    self.pool_map[poolid]["queue"].put(res.update())

                self.m.remove_handle(c)
                self.freelist.put(c)

                with self.mutex_stats:
                    self.processed += 1

            for c, errno, errmsg in err_list:
                buff_body, buff_header, res, poolid = c.response_queue

                res.history.totaltime = 0
                self.m.remove_handle(c)
                self.freelist.put(c)

                # Usual suspects:

                # Exception in perform (35, 'error:0B07C065:x509 certificate routines:X509_STORE_add_cert:cert already in hash table')
                # Exception in perform (18, 'SSL read: error:0B07C065:x509 certificate routines:X509_STORE_add_cert:cert already in hash table, errno 11')
                # Exception in perform (28, 'Connection time-out')
                # Exception in perform (7, "couldn't connect to host")
                # Exception in perform (6, "Couldn't resolve host 'www.xxx.com'")
                # (28, 'Operation timed out after 20000 milliseconds with 0 bytes received')
                # Exception in perform (28, 'SSL connection timeout')
                # 5 Couldn't resolve proxy 'aaa'

                # retry requests with recoverable errors
                if errno not in [28, 7, 6, 5]:
                    res.history.wf_retries += 1

                    if res.history.wf_retries < self.options.get("retries"):
                        self.retrylist.put((res, poolid))
                        continue

                e = FuzzExceptNetError("Pycurl error %d: %s" % (errno, errmsg))
                self.pool_map[poolid]["queue"].put(res.update(exception=e))

                with self.mutex_stats:
                    self.processed += 1

        self._stop_to_pools()
        self.retrylist.put((None, None))
        # cleanup multi stack
        for c in self.m.handles:
            c.close()
            self.freelist.put(c)
        self.m.close()
