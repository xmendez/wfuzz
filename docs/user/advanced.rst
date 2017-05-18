Advanced Usage
===============

Wfuzz global options
--------------------

Wfuzz global options can be tweaked by modifying the "wfuzz.ini" at the user's home direcory::

    ~/.wfuzz$ cat wfuzz.ini 

    [connection]
    concurrent = 10
    conn_delay = 90
    req_delay = 90
    retries = 3
    user-agent = Wfuzz/2.2

    [general]
    default_printer = raw
    cancel_on_plugin_except = 1
    concurrent_plugins = 3
    encode_space = 1
    lookup_dirs = .,/home/xxx/tools/fuzzdb


A useful option is "lookup_dirs". This option will indicate Wfuzz, which directories to look for files, avoiding to specify a full path in the command line. For example, when fuzzing using a dictionary.

Iterators: Combining payloads
-----------------------------

Payloads can be combined by using the -m parameter, in wfuzz this functionality is provided by what is called iterators, the following types are provided by default::

    $ python wfuzz.py -e iterators

    Available iterators:

    Name    | Summary                                                                           
    ----------------------------------------------------------------------------------------------
    product | Returns an iterator cartesian product of input iterables.                         
    zip     | Returns an iterator that aggregates elements from each of the iterables.          
    chain   | Returns an iterator returns elements from the first iterable until it is exhaust  
            | ed, then proceeds to the next iterable, until all of the iterables are exhausted  


Below are shown some examples using two different payloads containing the elements a,b,c and 1,2,3 respectively and how they can be combined using the existing iterators.

* zip::

    wfuzz.py -z list,a-b-c -z list,1-2-3 -m zip http://google.com/FUZZ/FUZ2Z

    00001:  C=404      9 L        32 W          276 Ch        "a - 1"
    00002:  C=404      9 L        32 W          276 Ch        "c - 3"
    00003:  C=404      9 L        32 W          276 Ch        "b - 2"

* chain::

    wfuzz.py -z list,a-b-c -z list,1-2-3 -m chain http://google.com/FUZZ

    00001:  C=404      9 L        32 W          280 Ch        "b"
    00002:  C=404      9 L        32 W          280 Ch        "a"
    00003:  C=404      9 L        32 W          280 Ch        "c"
    00004:  C=404      9 L        32 W          280 Ch        "1"
    00006:  C=404      9 L        32 W          280 Ch        "3"
    00005:  C=404      9 L        32 W          280 Ch        "2"

* product::

    wfuzz.py -z list,a-b-c -z list,1-2-3 http://mysite.com/FUZZ/FUZ2Z

    00001:  C=404      9 L        32 W          276 Ch        "a - 2"
    00002:  C=404      9 L        32 W          276 Ch        "a - 1"
    00005:  C=404      9 L        32 W          276 Ch        "b - 2"
    00004:  C=404      9 L        32 W          276 Ch        "a - 3"
    00008:  C=404      9 L        32 W          276 Ch        "c - 2"
    00003:  C=404      9 L        32 W          276 Ch        "b - 1"
    00007:  C=404      9 L        32 W          276 Ch        "c - 1"
    00006:  C=404      9 L        32 W          276 Ch        "b - 3"
    00009:  C=404      9 L        32 W          276 Ch        "c - 3"

Encoders
--------

In Wfuzz, a encoder is a transformation of a payload from one format to another. A list of the available encoders can be obtained using the following command::

    $ python wfuzz.py -e encoders

Specifying an encoder
^^^^^^^^^^^^^^^^^^^^^^

Encoders are specified as a payload parameter. There are two equivalent ways of specifying an encoder within a payload:

* The long way::

    $ python wfuzz.py -z file --zP fn=wordlist/general/common.txt,encoder=md5  http://testphp.vulnweb.com/FUZZ
    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://testphp.vulnweb.com/FUZZ
    Total requests: 950

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00002:  C=404      7 L        12 W          168 Ch        "b4b147bc522828731f1a016bfa72c073"
    00003:  C=404      7 L        12 W          168 Ch        "96a3be3cf272e017046d1b2674a52bd3"
    00004:  C=404      7 L        12 W          168 Ch        "a2ef406e2c2351e0b9e80029c909242d"
    ...

* The not so long way::

    $ wfuzz -z file,wordlist/general/common.txt,md5 http://testphp.vulnweb.com/FUZZ

Specifying multiple encoders
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Several encoders can be specified at once, using "-" as a separator::

    $ python wfuzz.py -z list,1-2-3,md5-sha1-none http://webscantest.com/FUZZ
    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://webscantest.com/FUZZ
    Total requests: 9

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00000:  C=200     38 L       121 W         1486 Ch        "da4b9237bacccdf19c0760cab7aec4a8359010b0"
    00001:  C=200     38 L       121 W         1486 Ch        "c4ca4238a0b923820dcc509a6f75849b"
    00002:  C=200     38 L       121 W         1486 Ch        "3"
    00003:  C=200     38 L       121 W         1486 Ch        "77de68daecd823babbb58edb1c8e14d7106e83bb"
    00004:  C=200     38 L       121 W         1486 Ch        "1"
    00005:  C=200     38 L       121 W         1486 Ch        "356a192b7913b04c54574d18c28d46e6395428ab"
    00006:  C=200     38 L       121 W         1486 Ch        "eccbc87e4b5ce2fe28308fd9f2a7baf3"
    00007:  C=200     38 L       121 W         1486 Ch        "2"
    00008:  C=200     38 L       121 W         1486 Ch        "c81e728d9d4c2f636f067f89cc14862c"

    Total time: 0.428943
    Processed Requests: 9
    Filtered Requests: 0
    Requests/sec.: 20.98180

* Encoders can also be chained using the "@" char::

    $ python wfuzz.py -z list,1-2-3,sha1-sha1@none http://webscantest.com/FUZZ
    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://webscantest.com/FUZZ
    Total requests: 6

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00000:  C=200     38 L       121 W         1486 Ch        "356a192b7913b04c54574d18c28d46e6395428ab"
    00001:  C=200     38 L       121 W         1486 Ch        "356a192b7913b04c54574d18c28d46e6395428ab"
    00002:  C=200     38 L       121 W         1486 Ch        "77de68daecd823babbb58edb1c8e14d7106e83bb"
    00003:  C=200     38 L       121 W         1486 Ch        "da4b9237bacccdf19c0760cab7aec4a8359010b0"
    00004:  C=200     38 L       121 W         1486 Ch        "da4b9237bacccdf19c0760cab7aec4a8359010b0"
    00005:  C=200     38 L       121 W         1486 Ch        "77de68daecd823babbb58edb1c8e14d7106e83bb"

The above "sha1@none" parameter specification will encode the payload using the sha1 encoder and the result will be encoded again using the none encoder.

* Encoders are grouped by categories. This allows to select several encoders by category, for example::

    $ python wfuzz.py -z list,1-2-3,hashes http://webscantest.com/FUZZ

    00000:  C=200     38 L       121 W         1486 Ch        "Mw=="
    00001:  C=200     38 L       121 W         1486 Ch        "c81e728d9d4c2f636f067f89cc14862c"
    00002:  C=200     38 L       121 W         1486 Ch        "77de68daecd823babbb58edb1c8e14d7106e83bb"
    00003:  C=200     38 L       121 W         1486 Ch        "da4b9237bacccdf19c0760cab7aec4a8359010b0"
    00004:  C=200     38 L       121 W         1486 Ch        "c4ca4238a0b923820dcc509a6f75849b"
    00005:  C=200     38 L       121 W         1486 Ch        "356a192b7913b04c54574d18c28d46e6395428ab"
    00006:  C=200     38 L       121 W         1486 Ch        "MQ=="
    00007:  C=200     38 L       121 W         1486 Ch        "Mg=="
    00008:  C=200     38 L       121 W         1486 Ch        "eccbc87e4b5ce2fe28308fd9f2a7baf3"

Scan/Parse Plugins
------------------

Wfuzz is more than a Web Content Scanner. Wfuzz could help you to secure your web applications by finding and exploiting web application vulnerabilities.

Wfuzz's web application vulnerability scanner is supported by plugins. A list of scanning plugins can be obtained using the following command::

    $ python wfuzz.py -e scripts

Scripts are grouped in categories. A script could belong to several categories at the same time.

Thre are two general categories:

* passive: Passive scripts analyze existing requests and responses without performing new requests.
* active: Active scripts perform new requests to the application to probe it for vulnerabilities.

Additional categories are:

* discovery: Discovery plugins help crawling a website by automatically enqueuing discovered content to wfuzz request's pool.

The default category groups the plugins that are run by default.

Scanning mode is indicated when using the --script parameter followed by the selected plugins. Plugins could be selected by category or name, wildcards can also be used.

The -A switch is an alias for --script=default.

Script's detailed information can be obtained using --scrip-help, for example::

    $ python wfuzz.py --script-help=default

An example, parsing a "robots.txt" file is shown below::

    $ python wfuzz.py --script=robots -z list,robots.txt http://www.webscantest.com/FUZZ
    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://www.webscantest.com/FUZZ
    Total requests: 1

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00001:  C=200      6 L        10 W          101 Ch        "robots.txt"
    |_ Plugin robots enqueued 4 more requests (rlevel=1)
    00002:  C=200     40 L       117 W         1528 Ch        "/osrun/"
    00003:  C=200     55 L       132 W         1849 Ch        "/cal_endar/"
    00004:  C=200     40 L       123 W         1611 Ch        "/crawlsnags/"
    00005:  C=200     85 L       197 W         3486 Ch        "/static/"

    Total time: 0
    Processed Requests: 5 (1 + 4)
    Filtered Requests: 0
    Requests/sec.: 0

Custom scripts
^^^^^^^^^^^^^^

If you would like to create customs scripts, place them in your home directory. In order to leverage this feature, a directory named "scripts" must be created underneath the ".wfuzz" directory.


Recipes
-------

You could save Wfuzz command line options to a file for later execution or for easy distribution. 

To create a recipe, execute the following::

    $ python wfuzz.py --script=robots -z list,robots.txt --dump-recipe /tmp/recipe http://www.webscantest.com/FUZZ

Then, execute Wfuzz using the stored options by using the "--recipe" option::

    $ python wfuzz.py --recipe /tmp/recipe 
    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://www.webscantest.com/FUZZ
    Total requests: 1

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00001:  C=200      6 L        10 W          101 Ch        "robots.txt"
    |_ Plugin robots enqueued 4 more requests (rlevel=1)
    00002:  C=200     40 L       117 W         1528 Ch        "/osrun/"
    00003:  C=200     55 L       132 W         1849 Ch        "/cal_endar/"
    00004:  C=200     40 L       123 W         1611 Ch        "/crawlsnags/"
    00005:  C=200     85 L       197 W         3486 Ch        "/static/"

    Total time: 1.341176
    Processed Requests: 5 (1 + 4)
    Filtered Requests: 0
    Requests/sec.: 3.728071

You can combine a recipe with additional command line options, for example::

    $ python wfuzz.py --recipe /tmp/recipe -b cookie1=value

In case of repeated options, command line options have precedence over options included in the recipe.

Scan Mode: Ignore Errors and Exceptions
---------------------------------------

In the event of a network problem (e.g. DNS failure, refused connection, etc), Wfuzz will raise an exception and stop execution as shown below::

    $ python wfuzz.py -z list,support-web-none http://FUZZ.google.com/
    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://FUZZ.google.com/
    Total requests: 3

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================


    Fatal exception: Pycurl error 6: Could not resolve host: none.google.com


You can tell Wfuzz to continue execution, ignoring errors by supplying the -Z switch. The latter command in scan mode will get the following results::

    $ python wfuzz.py -z list,support-web-none -Z http://FUZZ.google.com/
    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://FUZZ.google.com/
    Total requests: 3

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00002:  C=404     11 L        72 W         1561 Ch        "web"
    00003:  C=XXX      0 L         0 W            0 Ch        "none! Pycurl error 6: Could not resolve host: none.google.com"
    00001:  C=301      6 L        14 W          224 Ch        "support"

    Total time: 1.064229
    Processed Requests: 3
    Filtered Requests: 0
    Requests/sec.: 2.818939

Errors are shown as a result with the XXX code, the payload used followed by an exclamation mark and the companion exception message. Error codes can be filtered using the "XXX" expression. For example::

    $ python wfuzz.py -z list,support-web-none -Z --hc XXX http://FUZZ.google.com/
    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://FUZZ.google.com/
    Total requests: 3

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00002:  C=404     11 L        72 W         1561 Ch        "web"
    00001:  C=301      6 L        14 W          224 Ch        "support"

    Total time: 0.288635
    Processed Requests: 3
    Filtered Requests: 1
    Requests/sec.: 10.39374

When Wfuzz is used in scan mode, HTTP requests will take longer time due to network error timeouts. These can be tweaked using the --req-delay and --conn-delay command line parameters.

Timeouts
^^^^^^^^

You can tell Wfuzz to stop waiting for server to response a connection request after a given number of seconds --conn-delay and also the maximum number of seconds that the response is allowed to take using --req-delay parameter.

These timeouts are really handy when you are using Wfuzz to bruteforce resources behind a proxy, ports, hostnames, virtual hosts, etc.

Filter Language
---------------

Wfuzz's filter language grammar is build using `pyparsing <http://pyparsing.wikispaces.com/>`_, therefore it must be installed before using the command line parameters "--filter, --prefilter, --slice".

A filter expression must be built using the following symbols and operators:

* Boolean Operators

"and", "or" and "not" operators could be used to build conditional expressions.

Additionally, the following boolean operators are also supported:

============= ============= =============================================
Name          Short version Description
============= ============= =============================================
hasquery                    True when the URL contains a query string.
ispath                      True when the URL path refers to a directory.
bllist                      True when the URL file extension is included in the configuration discovery's blacklist
unique(value) u(value)      Returns True if a value is unique.
============= ============= =============================================

* Expression Operators

Expressions operators such as "= != < > >= <=" could be used to check values. Additionally, the following for matching text are available:

============ ====================================================================
Operator     Description
============ ====================================================================
=~           True when the regular expression specified matches the value.
!~           True when the regular expression specified does not match the value.
~            Equivalent to Python's "str1" in "str2" (case insensitive)
============ ====================================================================

Where values could be:

* Basic primitives:

============ ====================
Long Name    Description
============ ====================
'string'     Quoted string
0..9+        Integer values
XXX          HTTP request error code
BBB          Baseline
============ ====================

* Values can also be modified using the following operators:

================================ ======================= =============================================
Name                             Short version           Description
================================ ======================= =============================================
value|unquote()                  value|u()               Unquotes the value
value|lower()                    value|l()               lowercase of the value
value|upper()                                            uppercase of the value
value|encode('encoder', 'value') value|e('enc', 'val')   Returns encoder.encode(value)
value|decode('decoder', 'value') value|d('dec', 'val')   Returns encoder.decode(value)
value|replace('what', 'with')    value|r('what', 'with') Returns value replacing what for with
================================ ======================= =============================================

* When a FuzzResult is available, you could perform runtime introspection of the objects using the following symbols

============ ============== =============================================
Name         Short version  Description
============ ============== =============================================
description                 Wfuzz's result description
nres                        Wfuzz's result identifier
code         c              HTTP response's code
chars        h              Wfuzz's result HTTP response chars
lines        l              Wfuzz's result HTTP response lines
words        w              Wfuzz's result HTTP response words
md5                         Wfuzz's result HTTP response md5 hash
============ ============== =============================================

Or FuzzRequest object's attribute such as:

============================ =============================================
Name                         Description
============================ =============================================
url                          HTTP request's value
method                       HTTP request's verb
scheme                       HTTP request's scheme
host                         HTTP request's host
content                      HTTP response's content
raw_content                  HTTP response's content including headers
cookies.request              HTTP request cookie
cookies.response             HTTP response cookie
cookies.request.<<name>>              HTTP request cookie
cookies.response.<<name>>             HTTP response cookie
headers.request              All HTTP request headers
headers.response             All HTTP response headers
headers.request.<<name>>     HTTP request given header
headers.response.<<name>>    HTTP response given header
parameters                   All HTTP request GET and POST parameters
parameters.get               All HTTP request GET parameters
parameters.post              All HTTP request POST parameters
parameters.get/post.<<name>> A given HTTP request GET/POST parameter
============================ =============================================

URL field is broken in smaller parts using the urlparse Python's module, which parses a URL into: scheme://netloc/path;parameters?query#fragment.

For example, for the "http://www.google.com/dir/test.php?id=1" URL you can get the following values:

=================== =============================================
Name                Value
=================== =============================================
url.scheme          http
url.netloc          www.google.com
url.path            /dir/test.php
url.params
url.query           id=1
url.fragment      
url.domain          google.com
url.ffname          test.php
url.fext            .php
url.fname           test
url.pstrip          Returns a hash of the request using the parameter's names without values (useful for unique operations)
=================== =============================================

Payload instrospection can also be performed by using the keyword FUZZ:

============ ==============================================
Name         Description
============ ==============================================
FUZnZ        Allows to access the Nth payload string
FUZnZ[field] Allows to access the Nth payload attributes
============ ==============================================

Where field is one of the described above.

Filtering results
^^^^^^^^^^^^^^^^^

The --filter command line parameter in conjuntion with the described filter language allows you to peform more complex result triage than the standard filter switches such as "--hc/hl/hw/hh", "--sc/sl/sw/sh" and "-ss/hs".

An example below::

    $ python wfuzz.py -z range,0-10 --filter "c=200 and l>97" http://testphp.vulnweb.com/listproducts.php?cat=FUZZ
    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://testphp.vulnweb.com/listproducts.php?cat=FUZZ
    Total requests: 11

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00003:  C=200     99 L       302 W         4442 Ch        "2"
    00002:  C=200    102 L       434 W         7011 Ch        "1"

    Total time: 1.452705
    Processed Requests: 11
    Filtered Requests: 9
    Requests/sec.: 7.572076

Using result and payload instrospection to look for specific content returned in the response::

    $ python wfuzz.py -z list,echoedback -d searchFor=FUZZ --filter "content~FUZZ" http://testphp.vulnweb.com/search.php?test=query

Which is equivalent to::

    $ python wfuzz.py -z list,echoedback -d searchFor=FUZZ --ss "echoedback" http://testphp.vulnweb.com/search.php?test=query

A more interesting variation of the above examples could be::

    $ python wfuzz-cli.py -w fuzzdb/attack/xss/xss-rsnake.txt -d searchFor=FUZZ --filter "intext~FUZZ" http://testphp.vulnweb.com/search.php?test=query

Filtering a payload
^^^^^^^^^^^^^^^^^^^^^^^^^^

Slice
"""""""

The --slice command line parameter in conjuntion with the described filter language allows you to filter a payload.
The specific payload to filter, specified by the -z switch must preceed --slice.

An example is shown below::

    $ python wfuzz-cli.py -z list,one-two-one-one --slice "u(FUZZ)" http://localhost:9000/FUZZ

    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://localhost:9000/FUZZ
    Total requests: <<unknown>>

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00001:  C=404      9 L        32 W          277 Ch        "one"
    00002:  C=404      9 L        32 W          277 Ch        "two"

    Total time: 0.031817
    Processed Requests: 2
    Filtered Requests: 0
    Requests/sec.: 62.85908
    
It is worth noting that the type of payload dictates the available language symbols. For example, a dictionary payload such as the one in the example
above does not have a full FuzzResult object context and therefore object fields cannot be used.

Prefilter
""""""""

The --prefilter command line parameter is similar to --slice but is not associated to any payload. The filtering is
performed just before any HTTP request is done. 

In this context you are filtering the FuzzResult which is built as a result of combining all the input payloads.

Reutilising previous results
--------------------------------------

Previously performed HTTP requests/responses contain a treasure trove of data. Wfuzz payloads and object instrospection (explained in the filter grammar section) exposes a Python object interface to requests/responses recorded by Wfuzz or other tools.

This allows you to perform manual and semi-automatic tests with full context and understanding of your actions, without relying on a web application scanner underlying implementation.

Some ideas:

* Replaying individual requests as-is
* Replaying sequences of requests (such as a login or a checkout operation)
* Comparing two proxy logs, returning a diff output of the URLs and parameters submitted
* Fuzzing requests (creating a Burp object) and appending them to the original's replayed list
* Comparing response bodies and headers of fuzzed requests against their original
* Using difflib module in Python standard library to return a diff-formatted HTML output of two response bodies

wfuzzp payload
^^^^^^^^^^^^^^

Wfuzz results can be stored using the --oF option as illustrated below::

$ python wfuzz.py --oF /tmp/session -z range,0-10 http://www.google.com/dir/test.php?id=FUZZ

Then you can reutilise those results by using the wfuzzp payload.

For example, to perform the same exact HTTP requests::

$ python wfuzz.py -z wfuzzp,/tmp/session FUZZ

* Accessing specific HTTP object fields can be achieved by using the attr payload's parameter::

    $ python wfuzz.py -z wfuzzp,/tmp/session --zP attr=url  FUZZ

* Or by specyfing the FUZZ keyword and a field name in the form of FUZZ[field]::

    $ python wfuzz.py -z wfuzzp,/tmp/session  --dry-run FUZZ[url]

This could be used, for example, to perform new requests based on stored values::

    $ python wfuzz.py -z wfuzzp,/tmp/session -p localhost:8080 http://testphp.vulnweb.com/FUZZ[url.path]?FUZZ[url.query]
    00001:  C=200     25 L       155 W         1362 Ch        "/dir/test.php - id=0"
    ...
    00002:  C=200     25 L       155 W         1362 Ch        "/dir/test.php - id=1"

The above command will generate HTTP requests such as the following::

    GET /dir/test.php?id=10 HTTP/1.1
    Host: testphp.vulnweb.com
    Accept: */*
    Content-Type:  application/x-www-form-urlencoded
    User-Agent:  Wfuzz/2.2
    Connection: close

You can filter the payload using the filter grammar as described before.

burpstate and burplog payloads
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Wfuzz can read burp's log or saved states. This allows to filter or reutilise burp proxy requests and responses.

For example, the following will return a unique list of HTTP requests including the authtoken as a GET parameter::

    $ python wfpayload -z burplog,a_burp_log.log --slice "parameters.get~'authtoken' and u(url.pstrip)"

Authtoken is the parameter used by BEA WebLogic Commerce Servers (TM) as a CSRF token, and thefore the above will find all the requests exposing the CSRF token in the URL.
