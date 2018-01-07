import sys
import os
import unittest
import multiprocessing
import tempfile
from miproxy.proxy import AsyncMitmProxy 

from simple_server import GetHandler
from BaseHTTPServer import HTTPServer

sys.path.insert(0, os.path.abspath('../src'))
import wfuzz

LOCAL_DOMAIN = "http://localhost"
URL_LOCAL = "%s:8000/dir" % (LOCAL_DOMAIN)
HTTPD_PORT = 8000

ECHO_URL = "%s:8000/echo" % (LOCAL_DOMAIN)

# IDEAS:
#
# baseline duplicated with single filters
# chain iterator duplicated with everything
# bad params
# duplicate with post instead of get
# conn delays?
# script args

testing_tests = [
]

basic_tests = [
    # set static HTTP values
    ("test_static_strquery_set", "%s:8000/FUZZ?var=1&var=2" % LOCAL_DOMAIN, [["echo"]], dict(filter="content~'query=var=1&var=2'"), [(200, '/echo')], None),
    ("test_static_postdata_set", "%s:8000/FUZZ" % LOCAL_DOMAIN, [["echo"]], dict(postdata="a=2", filter="content~'POST_DATA=a=2'"), [(200, '/echo')], None),
    ("test_static_postdata2_set", "%s:8000/FUZZ" % LOCAL_DOMAIN, [["echo"]], dict(postdata="2", filter="content~'POST_DATA=2'"), [(200, '/echo')], None),
    ("test_static_method_set", "%s/FUZZ" % URL_LOCAL, [["dir"]], dict(method="OPTIONS", filter="content~'Message: Unsupported method (\\\'OPTIONS\\\')'"), [(501, '/dir/dir')], None),
    ("test_static_header_set", "%s:8000/FUZZ" % LOCAL_DOMAIN, [["echo"]], dict(headers=[("myheader", "isset")], filter="content~'Myheader: isset'"), [(200, '/echo')], None),
    ("test_static_cookie_set", "%s:8000/FUZZ" % LOCAL_DOMAIN, [["echo"]], dict(cookie=["cookie1=value1",], filter="content~'Cookie: cookie1=value1'"), [(200, '/echo')], None),
    ("test_static_basic_auth_set", "%s:8000/FUZZ" % LOCAL_DOMAIN, [["echo"]], dict(auth=("basic","user:pass"), filter="content~'Authorization: Basic dXNlcjpwYXNz'"), [(200, '/echo')], None),
    ("test_static_ntlm_auth_set", "%s:8000/FUZZ" % LOCAL_DOMAIN, [["echo"]], dict(auth=("ntlm","user:pass"), filter="content~'Authorization: NTLM TlRMTVNTUAABAAAABoIIAAAAAAAAAAAAAAAAAAAAAAA='"), [(200, '/echo')], None),

    # fuzzing HTTP values
    ("test_basic_path_fuzz", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c')], None),
    ("test_multi_path_fuzz", "%s/FUZZ/FUZ2Z/FUZ3Z" % ECHO_URL, [["a"],["b"],["c"]], dict(filter="content~'path=/echo/a/b/c'"), [(200, '/echo/a/b/c')], None),
    ("test_basic_method_fuzz", "%s" % URL_LOCAL, [["OPTIONS", "PUT"]], dict(method="FUZZ", filter="content~'Unsupported method' and content~FUZZ"), [(501, '/dir'), (501, '/dir')], None),
    ("test_basic_postdata_fuzz", "%s" % ECHO_URL, [["onevalue", "twovalue"]], dict(postdata="a=FUZZ", filter="content~FUZZ and content~'POST_DATA=a='"), [(200, '/echo'), (200, '/echo')], None),
    ("test_basic_postdata2_fuzz", "%s" % ECHO_URL, [["onevalue", "twovalue"]], dict(postdata="FUZZ=1234", filter="content~'POST_DATA=twovalue=1234' or content~'POST_DATA=onevalue=1234'"), [(200, '/echo'), (200, '/echo')], None),
    ("test_basic_postdata3_fuzz", "%s" % ECHO_URL, [["onevalue", "twovalue"]], dict(postdata="FUZZ", filter="content~'POST_DATA=twovalue' or content~'POST_DATA=onevalue'"), [(200, '/echo'), (200, '/echo')], None),
    ("test_basic_header_fuzz", "%s" % ECHO_URL, [["onevalue", "twovalue"]], dict(headers=[("myheader", "FUZZ")], filter="content~'Myheader:' and content~FUZZ"), [(200, '/echo'), (200, '/echo')], None),
    ("test_basic_header_name_fuzz", "%s" % ECHO_URL, [["onevalue", "twovalue"]], dict(headers=[("FUZZ", "myheadervalue")], filter="content~': myheadervalue' and content~FUZZ"), [(200, '/echo'), (200, '/echo')], None),
    ("test_static_strquery_fuzz", "%s:8000/echo?var=FUZZ" % LOCAL_DOMAIN, [["value1"]], dict(filter="content~'query=var=value1'"), [(200, '/echo')], None),
    ("test_static_strquery2_fuzz", "%s:8000/echo?FUZZ=value1" % LOCAL_DOMAIN, [["var"]], dict(filter="content~'query=var=value1'"), [(200, '/echo')], None),

    # url fuzzing
    ("test_url_not_normalized_by_lib", "http://localhost:8000/echo/FUZZ", [["../../etc/pass"]], dict(), [(200, '/echo/../../etc/pass')], None),
    ("test_url_port_fuzz", "%s:FUZZ/dir/a" % LOCAL_DOMAIN, [["8000"]], dict(), [(200, '/dir/a')], None),
    ("test_url_hostname_fuzz", "http://FUZZ:8000/dir/a", [["localhost"]], dict(), [(200, '/dir/a')], None),
    ("test_url_hostname2_fuzz", "http://FUZZ/dir/a", [["localhost:8000"]], dict(), [(200, '/dir/a')], None),
    ("test_url_schema_fuzz", "FUZZ://localhost:8000/dir/a", [["http"]], dict(), [(200, '/dir/a')], None),
    ("test_url_all_url_fuzz", "FUZZ", [["http://localhost:8000/dir/a"]], dict(), [(200, '/dir/a')], None),
    ("test_url_all_url_fuzz2", "FUZZ", [["http://webscantest.com/datastore/search_get_by_name.php?name=Rake"]], dict(), [(200, '/datastore/search_get_by_name.php')], None),

    # edge cases
    ("test_vhost_fuzz", "%s" % ECHO_URL, [["onevalue", "twovalue"]], dict(headers=[("Host", "FUZZ")], filter="content~'Host:' and content~FUZZ"), [(200, '/echo'), (200, '/echo')], None),

    # payload encoder tests
    ("test_encoding", "%s:8000/echo?var=FUZZ" % LOCAL_DOMAIN, None, dict(payloads=[("list", dict(values="value1", encoder=["md5"]))], filter="content~'path=/echo?var=9946687e5fa0dab5993ededddb398d2e'"), [(200, '/echo')], None),
    ("test_nested_encoding", "%s:8000/echo?var=FUZZ" % LOCAL_DOMAIN, None, dict(payloads=[("list", dict(values="value1", encoder=["none@md5"]))], filter="content~'path=/echo?var=9946687e5fa0dab5993ededddb398d2e'"), [(200, '/echo')], None),
    ("test_cat_encoding", "%s:8000/echo?var=FUZZ" % LOCAL_DOMAIN, None, dict(payloads=[("list", dict(values="value1", encoder=["default"]))], filter="content~'path=/echo?var=' and (content~'9946687e5fa0dab5993ededddb398d2e' or content~'value1')"), [(200, '/echo'), (200, '/echo')], None),

    # prefilter, slice
    ("test_prefilter", "%s/FUZZ" % URL_LOCAL, [["a","a","a","a","a","a"]], dict(prefilter="FUZZ|u()",ss="one"), [(200, '/dir/a')], None),
    ("test_slice", "%s/FUZZ" % URL_LOCAL, None, dict(payloads=[("list", dict(default="a-a-a-a-a"), "FUZZ|u()")], ss="one"), [(200, '/dir/a')], None),

    # follow
    ("test_follow", "%s:8000/FUZZ" % LOCAL_DOMAIN, [["redirect"]], dict(follow=True, filter="content~'path=/echo'"), [(200, '/echo')], None),

    # all params
    ("test_all_params_get", "%s:8000/echo?var=1&var2=2" % LOCAL_DOMAIN, [["avalue"]], dict(allvars="allvars", filter="content~'query=var=avalue&var2=2' or content~'var=1&var2=avalue'"), [(200, '/echo'), (200, '/echo')], None),
    ("test_all_params_post", "%s" % ECHO_URL, [["onevalue"]], dict(allvars="allpost", postdata="a=1&b=2", filter="content~'POST_DATA=a=onevalue&b=2' or content~'POST_DATA=a=1&b=onevalue'"), [(200, '/echo'), (200, '/echo')], None),

    # simple filter
    ("test_codes_HC", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(hc=[404]), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c')], None),
    ("test_codes_SC", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(sc=[200]), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c')], None),
    ("test_codes_HL", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(hl=[4]), [(200, '/dir/b')], None),
    ("test_codes_SL", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(sl=[4]), [(200, '/dir/a'), (200, '/dir/c')], None),
    ("test_codes_HW", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(hw=[11]), [(200, '/dir/a'), (200, '/dir/b')], None),
    ("test_codes_SW", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(sw=[11]), [(200, '/dir/c')], None),
    ("test_codes_HH", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(hh=[28]), [(200, '/dir/b'), (200, '/dir/c')], None),
    ("test_codes_SH", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(sh=[28]), [(200, '/dir/a')], None),

    # combining simple filters
    ("test_hchlhhhw","%s/FUZZ" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(hc=[404], hl=[4], hh=[300]), [(200, '/dir/b')], None),
    ("test_shsw", "%s/FUZZ" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(sh=[28], sw=[6]), [(200, '/dir/a')], None),

    # regex filter
    ("test_ss", "%s/FUZZ" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(ss="one"), [(200, '/dir/a'), (200, '/dir/b')], None),
    ("test_hs", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(hs="one"), [(200, '/dir/c')], None),
    ("test_regex_sc", "%s/FUZZ" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(sc=[200], ss="one"), [(200, '/dir/a'), (200, '/dir/b')], None),
    ("test_regex_hc", "%s/FUZZ" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(hc=[200], ss="one"), [], None),

    # complex filter
    ("test_filter_clh", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(filter="c!=404 and l!=4 and h!=300 and w!=6"), [(200, '/dir/b')], None),
    ("test_filter_hw", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(filter="h=28 or w=6"), [(200, '/dir/a')], None),
    ("test_filter_intext", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(filter="content~'one'"), [(200, '/dir/a'), (200, '/dir/b')], None),
    ("test_filter_intext2", "%s/FUZZ" % URL_LOCAL, [["a","b","c"]], dict(filter="content!~'one'"), [(200, '/dir/c')], None),

    # baseline
    ("test_baseline", "%s/FUZZ{notthere}" % URL_LOCAL, [["a","b","c"]], dict(), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c'),(404, "/dir/notthere")], None),
    ("test_baseline2", "%s/FUZZ{notthere}" % URL_LOCAL, [["a","b","c","d","e","f"]], dict(hc=["BBB"]), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c')] + [(404, '/dir/notthere')], None),
    ("test_baseline3", "%s/FUZZ{notthere}" % URL_LOCAL, [["a","b","c"]], dict(hc=[200]), [(404, "/dir/notthere")], None),
    #XXX("test_scheme_baseline_fuzz", "FUZZ{HTTP}://localhost:8000/dir/a", [["https"]], dict(), [(200, '/dir/a')], None),

    # iterators
    ("test_product", "%s:8000/iterators/FUZZFUZ2Z" % LOCAL_DOMAIN, [["a","b"],["c"]], dict(iterator="product"), [(200, '/iterators/ac'),(404, '/iterators/bc')], None),
    ("test_zip", "%s:8000/iterators/FUZZFUZ2Z" % LOCAL_DOMAIN, [["a","b"],["c"]], dict(iterator="zip"), [(200, '/iterators/ac')], None),
    ("test_chain", "%s/FUZZ" % URL_LOCAL, [["a","b"],["c"]], dict(iterator="chain"), [(200, '/dir/a'), (200, '/dir/b'), (200, '/dir/c')], None),

    # recursive
    ("test_rlevel_1", "%s:8000/recursive_dir/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(sc=[301],rlevel=1), [(301, '/recursive_dir/a'), (301, '/recursive_dir/a/b')], None),
    ("test_rlevel_2", "%s:8000/recursive_dir/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(sc=[301],rlevel=2), [(301, '/recursive_dir/a'), (301, '/recursive_dir/a/b'), (301, '/recursive_dir/a/b/c')], None),
    ("test_rlevel_1_post", "%s:8000/echo/FUZZ/" % LOCAL_DOMAIN, [["a"]], dict(filter="content~'command=POST' and content~'POST_DATA=a=1'", postdata="a=1", rlevel=1), [(200, '/echo/a/'), (200, '/echo/a/a')], None),

    # plugins
    ("test_robots", "%s:8000/plugins/FUZZ" % LOCAL_DOMAIN, [["robots.txt"]], dict(script="robots"), [(404, '/cal_endar/'), (404, '/crawlsnags/'), (404, '/osrun/'), (200, '/plugins/robots.txt'), (200, '/static/')], None),
    ("test_robots_hc", "%s:8000/plugins/FUZZ" % LOCAL_DOMAIN, [["robots.txt"]], dict(hc=[404], script="robots"), [(200, '/plugins/robots.txt'), (200, '/static/')], None),
]

scanmode_tests = [
    ("test_scanmode", "%s:666/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(scanmode=True), [(-1, '/a'), (-1, '/b'), (-1, '/c')], None),
    ("test_scanmode_sc", "%s:666/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(scanmode=True, sc=[-1]), [(-1, '/a'), (-1, '/b'), (-1, '/c')], None),
    ("test_scanmode_sc_xxx", "%s:666/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(scanmode=True, sc=["XXX"]), [(-1, '/a'), (-1, '/b'), (-1, '/c')], None),
    ("test_scanmode_hc", "%s:666/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(scanmode=True, hc=[-1]), [], None),
    ("test_scanmode_hc_xxx", "%s:666/FUZZ" % LOCAL_DOMAIN, [["a","b","c"]], dict(scanmode=True, hc=["XXX"]), [], None),
]

error_tests = [
    ("test_url_schema_error_fuzz", "FUZZ://localhost:8000/dir/a", [["https"]], dict(), [(200, '/dir/a')], "Pycurl error 35"),
    ("test_all_params_fuzz_error", "%s:8000/echo?var=FUZZ&var2=2" % LOCAL_DOMAIN, [["avalue"]], dict(allvars="allvars", filter="content~'query=var=avalue&var2=2' or content~'var=1&var2=avalue'"), [(200, '/echo'), (200, '/echo')], "FUZZ words not allowed when using all parameters brute forcing"),
    ("test_all_params_no_var", "%s:8000/echo" % LOCAL_DOMAIN, [["avalue"]], dict(allvars="allvars", filter="content~'query=var=avalue&var2=2' or content~'var=1&var2=avalue'"), [(200, '/echo'), (200, '/echo')], "No variables on specified variable set"),
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
        with wfuzz.FuzzSession(url=url, **params) as s :
            if payloads == None:
                fuzzed = s.fuzz()
            else:
                fuzzed = s.get_payloads(payloads).fuzz()

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

def wfuzz_me_test_generator_saveres(url, payloads, params, expected_list):
    def test(self):
        if not expected_list: return
        temp_name = next(tempfile._get_candidate_names())
        defult_tmp_dir = tempfile._get_default_tempdir()

        filename = os.path.join(defult_tmp_dir, temp_name)

        # Wfuzz results
        with wfuzz.FuzzSession(url=url, **dict(params.items() + dict(save=filename).items())) as s :
            if payloads == None:
                fuzzed = s.fuzz()
            else:
                fuzzed = s.get_payloads(payloads).fuzz()

            ret_list = map(lambda x: (x.code, x.history.urlparse.path), fuzzed)

        # repeat test with performaing same saved request
        with wfuzz.FuzzSession(payloads=[("wfuzzp", dict(fn=filename))], url="FUZZ") as s :
            same_list = map(lambda x: (x.code, x.history.urlparse.path), s.fuzz())

        self.assertEqual(sorted(ret_list), sorted(same_list))

        # repeat test with performaing FUZZ[url] saved request
        with wfuzz.FuzzSession(payloads=[("wfuzzp", dict(fn=filename))], url="FUZZ[url]") as s :
            print filename
            same_list = map(lambda x: (x.code, x.history.urlparse.path), s.fuzz())

        self.assertEqual(sorted(ret_list), sorted(same_list))

    return test


def wfuzz_me_test_generator_recipe(url, payloads, params, expected_list):
    def test(self):
        temp_name = next(tempfile._get_candidate_names())
        defult_tmp_dir = tempfile._get_default_tempdir()

        filename = os.path.join(defult_tmp_dir, temp_name)

        # Wfuzz results
        with wfuzz.FuzzSession(url=url, **params) as s :
            s.export_to_file(filename)

            if payloads == None:
                fuzzed = s.fuzz()
            else:
                fuzzed = s.get_payloads(payloads).fuzz()

            ret_list = map(lambda x: (x.code, x.history.urlparse.path), fuzzed)

        # repeat test with recipe as only parameter
        with wfuzz.FuzzSession(recipe=filename) as s :
            if payloads == None:
                same_list = map(lambda x: (x.code, x.history.urlparse.path), s.fuzz())
            else:
                same_list = map(lambda x: (x.code, x.history.urlparse.path), s.get_payloads(payloads).fuzz())

        self.assertEqual(sorted(ret_list), sorted(same_list))

    return test


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

def duplicate_tests_diff_params(test_list, group, next_extra_params, previous_extra_params):
    """
    Ignores expected_res and generates wfuzz tests that run 2 times with different params, expecting same results.

    """
    for test_name, url, payloads, params, expected_res, exception_str in test_list:
        next_extra = dict(params.items() + next_extra_params.items())
        new_test = "%s_%s" % (test_name, group)

        prev_extra = params
        if previous_extra_params:
            prev_extra = dict(params.items() + previous_extra_params.items())

        test_fn = wfuzz_me_test_generator(url, payloads, prev_extra, None, next_extra)
        setattr(DynamicTests, new_test, test_fn)


def duplicate_tests(test_list, group, test_gen_fun):
    """
    generates wfuzz tests that run 2 times with recipe input, expecting same results.

    """
    for test_name, url, payloads, params, expected_res, exception_str in test_list:
        new_test = "%s_%s" % (test_name, group)

        test_fn = test_gen_fun(url, payloads, params, None)
        setattr(DynamicTests, new_test, test_fn)

def create_tests():
    """
    Creates all dynamic tests

    """
    if testing_tests:
        create_tests_from_list(testing_tests)
        duplicate_tests(testing_tests, "recipe", wfuzz_me_test_generator_recipe)
        duplicate_tests(testing_tests, "saveres", wfuzz_me_test_generator_saveres)
        duplicate_tests_diff_params(testing_tests, "_proxy_", dict(proxies=[("localhost", 8080, "HTML")]), None)
    else:
        # this are the basics
        basic_functioning_tests = [error_tests, scanmode_tests, basic_tests]

        for t in basic_functioning_tests:
            create_tests_from_list(t)

        # duplicate tests with recipe
        duplicate_tests(basic_tests, "recipe", wfuzz_me_test_generator_recipe)

        # duplicate tests with save results
        duplicate_tests(basic_tests, "saveres", wfuzz_me_test_generator_saveres)

        # duplicate tests with proxy
        duplicate_tests_diff_params(basic_tests, "_proxy_", dict(proxies=[("localhost", 8080, "HTML")]), None)

if __name__ == '__main__':

    httpd = None
    proxyd = None
    httpd_server_process = None
    server_process = None

    try:
        # Setup simple HTTP sever
        os.chdir("server_dir")
        httpd = HTTPServer(('localhost', HTTPD_PORT), GetHandler)

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
