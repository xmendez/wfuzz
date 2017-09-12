import sys
import os
import unittest
import SocketServer
import SimpleHTTPServer
import urllib2
import requests
import multiprocessing
from miproxy.proxy import AsyncMitmProxy 

sys.path.insert(0, os.path.abspath('..'))
import wfuzz

LOCAL_DOMAIN = "http://localhost"
URL_LOCAL = "%s:8000/dir" % (LOCAL_DOMAIN)
HTTPD_PORT = 8000


simple_filter_tests = [
    # simple filter
    ("test_codes_HC", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(hc=[404]), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c')], None),
    ("test_codes_SC", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(sc=[200]), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c')], None),
    ("test_codes_HL", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(hl=[4]), [(200, '/dir/b')], None),
    ("test_codes_SL", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(sl=[4]), [(200, '/dir/a'), (200, '/dir/c')], None),
    ("test_codes_HW", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(hw=[11]), [(200, '/dir/a'), (200, '/dir/b')], None),
    ("test_codes_SW", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(sw=[11]), [(200, '/dir/c')], None),
    ("test_codes_HH", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(hh=[28]), [(200, '/dir/b'), (200, '/dir/c')], None),
    ("test_codes_SH", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(sh=[28]), [(200, '/dir/a')], None),
]

test_list = [
    ## basic test
    ("test_basic", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c')], None),

    ## combining simple filters
    ("test_hchlhhhw","%s/FUZZ" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(hc=[404], hl=[4], hh=[300]), [(200, '/dir/b')], None),
    ("test_shsw", "%s/FUZZ" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(sh=[28], sw=[6]), [(200, '/dir/a')], None),

    ##regex filter
    ("test_ss", "%s/FUZZ" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(ss="one"), [(200, '/dir/a'), (200, '/dir/b')], None),
    ("test_hs", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(hs="one"), [(200, '/dir/c')], None),
    ("test_regex_sc", "%s/FUZZ" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(sc=[200], ss="one"), [(200, '/dir/a'), (200, '/dir/b')], None),
    ("test_regex_hc", "%s/FUZZ" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(hc=[200], ss="one"), [], None),

    ## complex filter
    ("test_filter_clh", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(filter="c!=404 and l!=4 and h!=300 and w!=6"), [(200, '/dir/b')], None),
    ("test_filter_hw", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(filter="h=28 or w=6"), [(200, '/dir/a')], None),
    ("test_filter_intext", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(filter="content~'one'"), [(200, '/dir/a'), (200, '/dir/b')], None),
    ("test_filter_intext2", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(filter="content!~'one'"), [(200, '/dir/c')], None),

    ## baseline
    ("test_baseline", "%s/FUZZ{notthere}" % URL_LOCAL, [["a","b","c"]], dict(), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c'),(404, "/dir/notthere")], None),
    ("test_baseline2", "%s/FUZZ{notthere}" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(hc=["BBB"]), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c')] + [(404, '/dir/notthere')], None),
    ("test_baseline3", "%s/FUZZ{notthere}" % URL_LOCAL, [["a","b","c"]], dict(hc=[200]), [(404, "/dir/notthere")], None),

    # iterators
    ("test_product", "%s:8000/iterators/FUZZFUZ2Z" % LOCAL_DOMAIN, [["a","b"],["c"]], dict(iterator="product"), [(200, '/iterators/ac'),(404, '/iterators/bc')], None),
    ("test_zip", "%s:8000/iterators/FUZZFUZ2Z" % LOCAL_DOMAIN, [["a","b"],["c"]], dict(iterator="zip"), [(200, '/iterators/ac')], None),
    ("test_chain", "%s/FUZZ" % URL_LOCAL, [["a","b"],["c"]], dict(iterator="chain"), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c')], None),
]

conn_tests = [
    # conn errors
    ("test_scanmode", "%s:666/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(scanmode=True), [(-1, '/a'), (-1, '/b'), (-1, '/c')], None),
    ("test_scanmode_sc", "%s:666/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(scanmode=True, sc=[-1]), [(-1, '/a'), (-1, '/b'), (-1, '/c')], None),
    ("test_scanmode_sc_xxx", "%s:666/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(scanmode=True, sc=["XXX"]), [(-1, '/a'), (-1, '/b'), (-1, '/c')], None),
    ("test_scanmode_hc", "%s:666/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(scanmode=True, hc=[-1]), [], None),
    ("test_scanmode_hc_xxx", "%s:666/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(scanmode=True, hc=["XXX"]), [], None),
    ("test_scanmode_sc_baseline", "%s{FUZZ}" % LOCAL_DOMAIN, [[8000,6666]], dict(scanmode=True, sc=["XXX"]), [(-1, '/a'), (-1, '/b'), (-1, '/c')], None),
]

recursive_tests = [
    ("test_rlevel_1", "%s:8000/recursive_dir/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(sc=[301],rlevel=1), [(301, '/recursive_dir/a'), (301, '/recursive_dir/a/b')], None),
    ("test_rlevel_2", "%s:8000/recursive_dir/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(sc=[301],rlevel=2), [(301, '/recursive_dir/a'), (301, '/recursive_dir/a/b'), (301, '/recursive_dir/a/b/c')], None),
]

plugins_tests = [
    ("test_robots", "%s:8000/plugins/FUZZ" % LOCAL_DOMAIN, [["robots.txt"]], dict(script="robots"), [(404, '/cal_endar/'), (404, '/crawlsnags/'), (404, '/osrun/'), (200, '/plugins/robots.txt'), (200, '/static/')], None),
    ("test_robots_hc", "%s:8000/plugins/FUZZ" % LOCAL_DOMAIN, [["robots.txt"]], dict(hc=[404], script="robots"), [(200, '/plugins/robots.txt'), (200, '/static/')], None),
]


# errors
error_tests = [
    ("test_bad_port", "%s:6666/FUZZ" % LOCAL_DOMAIN, [range(1)], dict(), [], 'Failed to connect to localhost port 6666'),
    ("test_bad_num_payloads", "%s:8000/FUZZ" % LOCAL_DOMAIN, [range(1), range(1)], dict(), [], 'FUZZ words and number of payloads do not match'),
    ("test_bad_proxy", "%s:8000/FUZZ" % LOCAL_DOMAIN, [range(1)], dict(proxies=[("localhost", 888, "HTML")]), [], 'Failed to connect to localhost port 888'),
    ("test_bad_num_dic", "%s:8000/iterators/FUZZ" % LOCAL_DOMAIN, [range(1)], dict(iterator="zip"), [], 'Several dictionaries must be used when specifying an iterator'),
]

class DynamicTests(unittest.TestCase):
    """
    Dummy class that will be populated dynamically with all the tests
    """
    pass

def wfuzz_me_test_generator(url, payloads, params, expected_list, extra_params):
    def test(self):
        # Wfuzz results
        with wfuzz.FuzzSession(url=url) as s :
            fuzzed = s.get_payloads(payloads).fuzz(**params)
            ret_list = map(lambda x: (x.code, x.history.urlparse.path), fuzzed)

        # repeat test with extra params if specified and check against 
        if extra_params:
            with wfuzz.FuzzSession(url=url) as s :
                same_list = map(lambda x: (x.code, x.history.urlparse.path), s.get_payloads(payloads).fuzz(**extra_params))

            self.assertEqual(sorted(ret_list), sorted(same_list))
        else:
            self.assertEqual(sorted(ret_list), sorted(expected_list))

    return test

def wfuzz_me_test_generator_exception(fn, exception_string):
    def test_exception(self):
        with self.assertRaises(Exception) as context:
            fn(None)
            setattr(DynamicTests, new_test, test_fn)

        self.assertTrue(exception_string in str(context.exception))

    return test_exception


def create_tests_from_list(test_list):
    """
    Creates tests cases where wfuzz using the indicated url, params results are checked against expected_res
    """
    for test_name, url, payloads, params, expected_res, exception_str in test_list:
        test_fn = wfuzz_me_test_generator(url, payloads, params, expected_res, None)
        if exception_str:
            test_fn_exc = wfuzz_me_test_generator_exception(test_fn, exception_str)
            setattr(DynamicTests, test_name, test_fn_exc)
        else:
            setattr(DynamicTests, test_name, test_fn)

def duplicate_tests_diff_params(test_list, group, extra_params):
    """
    Ignores expected_res and generates wfuzz tests that run 2 times with different params, expecting same results.

    """
    for test_name, url, payloads, params, expected_res, exception_str in test_list:
        extra = dict(params.items() + extra_params.items())
        new_test = "%s_%s" % (test_name, group)

        test_fn = wfuzz_me_test_generator(url, payloads, params, None, extra)
        setattr(DynamicTests, new_test, test_fn)

def create_tests():
    """
    Creates all dynamic tests

    """
    # Bad options tests
    create_tests_from_list(error_tests)

    # this are the basics
    basic_functioning_tests = [simple_filter_tests, test_list, plugins_tests, recursive_tests]

    for t in basic_functioning_tests:
        create_tests_from_list(t)

    # duplicate tests with proxy
    for t in basic_functioning_tests:
        duplicate_tests_diff_params(t, "_proxy_", dict(proxies=[("localhost", 8080, "HTML")] ))

    # TODO:
    # baseline duplicated with single filters
    # chain iterator duplicated with everything
    # duplicate with recipes
    # bad params
    # slice, prefilter
    # test if headers, cookies, etc. are set
    # test if variables are set
    # methods
    # auths are set
    # http://httpbin.org/headers

if __name__ == '__main__':

    httpd = None
    proxyd = None
    httpd_server_process = None
    server_process = None

    try:
        # Setup simple HTTP sever
        os.chdir("server_dir")
        Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
        httpd = SocketServer.TCPServer(("", HTTPD_PORT), Handler)

        httpd.allow_reuse_address = True

        httpd_server_process = multiprocessing.Process(target=httpd.serve_forever)
        httpd_server_process.daemon = True
        httpd_server_process.start()

        # HTTP proxy
        proxyd = AsyncMitmProxy() 

        server_process = multiprocessing.Process(target=proxyd.serve_forever)
        server_process.daemon = True
        server_process.start()

        create_tests()
        unittest.main()
    finally:
        if httpd: httpd.server_close()
        if proxyd: proxyd.server_close()
        if server_process: server_process.terminate()
        if httpd_server_process: httpd_server_process.terminate()
