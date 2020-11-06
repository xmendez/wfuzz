Advanced Usage
===============

Wfuzz global options
--------------------

Wfuzz global options can be tweaked by modifying the "wfuzz.ini" at the user's home directory::

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

    $ wfuzz -e iterators

    Available iterators:

    Name    | Summary                                                                           
    ----------------------------------------------------------------------------------------------
    product | Returns an iterator cartesian product of input iterables.                         
    zip     | Returns an iterator that aggregates elements from each of the iterables.          
    chain   | Returns an iterator returns elements from the first iterable until it is exhaust  
            | ed, then proceeds to the next iterable, until all of the iterables are exhausted  


Below are shown some examples using two different payloads containing the elements a,b,c and 1,2,3 respectively and how they can be combined using the existing iterators.

* zip::

    wfuzz -z list,a-b-c -z list,1-2-3 -m zip http://google.com/FUZZ/FUZ2Z

    00001:  C=404      9 L        32 W          276 Ch        "a - 1"
    00002:  C=404      9 L        32 W          276 Ch        "c - 3"
    00003:  C=404      9 L        32 W          276 Ch        "b - 2"

* chain::

    wfuzz -z list,a-b-c -z list,1-2-3 -m chain http://google.com/FUZZ

    00001:  C=404      9 L        32 W          280 Ch        "b"
    00002:  C=404      9 L        32 W          280 Ch        "a"
    00003:  C=404      9 L        32 W          280 Ch        "c"
    00004:  C=404      9 L        32 W          280 Ch        "1"
    00006:  C=404      9 L        32 W          280 Ch        "3"
    00005:  C=404      9 L        32 W          280 Ch        "2"

* product::

    wfuzz -z list,a-b-c -z list,1-2-3 http://mysite.com/FUZZ/FUZ2Z

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

    $ wfuzz -e encoders

Specifying an encoder
^^^^^^^^^^^^^^^^^^^^^^

Encoders are specified as a payload parameter. There are two equivalent ways of specifying an encoder within a payload:

* The long way::

    $ wfuzz -z file --zP fn=wordlist/general/common.txt,encoder=md5  http://testphp.vulnweb.com/FUZZ
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
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

* The not so long way using the zE command line switch::

    $ wfuzz -z file --zD wordlist/general/common.txt --zE md5 http://testphp.vulnweb.com/FUZZ

* The not so long way::

    $ wfuzz -z file,wordlist/general/common.txt,md5 http://testphp.vulnweb.com/FUZZ

Specifying multiple encoders
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Several encoders can be specified at once, using "-" as a separator::

    $ wfuzz -z list,1-2-3,md5-sha1-none http://webscantest.com/FUZZ
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
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

    $ wfuzz -z list,1-2-3,sha1-sha1@none http://webscantest.com/FUZZ
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
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

    $ wfuzz -z list,1-2-3,hashes http://webscantest.com/FUZZ

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

    $ wfuzz -e scripts

Scripts are grouped in categories. A script could belong to several categories at the same time.

There are two general categories:

* passive: Passive scripts analyse existing requests and responses without performing new requests.
* active: Active scripts perform new requests to the application to probe it for vulnerabilities.

Additional categories are:

* discovery: Discovery plugins help crawling a website by automatically enqueuing discovered content to wfuzz request's pool.

The default category groups the plugins that are run by default.

Scanning mode is indicated when using the --script parameter followed by the selected plugins. Plugins could be selected by category or name, wildcards can also be used.

The -A switch is an alias for --script=default.

Script's detailed information can be obtained using --scrip-help, for example::

    $ wfuzz --script-help=default

An example, parsing a "robots.txt" file is shown below::

    $ wfuzz --script=robots -z list,robots.txt http://www.webscantest.com/FUZZ
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
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

In order to not scan the same requests (with the same parameters) over an over again, there is a cache,the cache can be disabled with the --no-cache flag.

For example, if we target a web server with the same URL but different parameter values, we get::

    $ wfuzz -z range --zD 0-3 -z list --zD "'" -u http://testphp.vulnweb.com/artists.php?artist=FUZZFUZ2Z -A

    000000004:   0.195s       200        101 L    287 W    3986 Ch     nginx/1.4.1                                                       "3 - '"                                                                                                                                    
    |_  Error identified: Warning: mysql_fetch_array()
    000000001:   0.198s       200        101 L    287 W    3986 Ch     nginx/1.4.1                                                       "0 - '"                                                                                                                                    
    000000002:   0.198s       200        101 L    287 W    3986 Ch     nginx/1.4.1                                                       "1 - '"                                                                                                                                    
    000000003:   0.198s       200        101 L    287 W    3986 Ch     nginx/1.4.1                                                       "2 - '"                                                                                                                                    

But, if we do the same but disabling the cache::

    $ wfuzz -z range --zD 0-3 -z list --zD "'" -u http://testphp.vulnweb.com/artists.php?artist=FUZZFUZ2Z -A --no-cache

    000000004:   1.170s       200        101 L    287 W    3986 Ch     nginx/1.4.1                                                       "3 - '"                                                                                                                                    
    |_  Error identified: Warning: mysql_fetch_array()
    000000002:   1.173s       200        101 L    287 W    3986 Ch     nginx/1.4.1                                                       "1 - '"                                                                                                                                    
    |_  Error identified: Warning: mysql_fetch_array()
    000000001:   1.174s       200        101 L    287 W    3986 Ch     nginx/1.4.1                                                       "0 - '"                                                                                                                                    
    |_  Error identified: Warning: mysql_fetch_array()
    000000003:   1.173s       200        101 L    287 W    3986 Ch     nginx/1.4.1                                                       "2 - '"                                                                                                                                    
    |_  Error identified: Warning: mysql_fetch_array()

Custom scripts
^^^^^^^^^^^^^^

If you would like to create customs scripts, place them in your home directory. In order to leverage this feature, a directory named "scripts" must be created underneath the ".wfuzz" directory.


Recipes
-------

You could save Wfuzz command line options to a file for later execution or for easy distribution. 

To create a recipe, execute the following::

    $ wfuzz --script=robots -z list,robots.txt --dump-recipe /tmp/recipe http://www.webscantest.com/FUZZ

Then, execute Wfuzz using the stored options by using the "--recipe" option::

    $ wfuzz --recipe /tmp/recipe 
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
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

    $ wfuzz --recipe /tmp/recipe -b cookie1=value

Several recipes can also be combined::

    $ wfuzz --recipe /tmp/recipe --recipe /tmp/recipe2

In case of repeated options, command line options have precedence over options included in the recipe. Last recipe has precedence.

Connect to an specific host
---------------------------------------

The --ip option can be used to connect to a specific host and port instead of the URL's host and port::

    $ wfuzz -z range,1-1 --ip 127.0.0.1 http://www.google.com/anything/FUZZ

This useful, for example, to test if a reverse proxy can be manipulated into misrouting requests to a destination of our choice.


Scan Mode: Ignore Errors and Exceptions
---------------------------------------

In the event of a network problem (e.g. DNS failure, refused connection, etc.), Wfuzz will raise an exception and stop execution as shown below::

    $ wfuzz -z list,support-web-none http://FUZZ.google.com/
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
    ********************************************************

    Target: http://FUZZ.google.com/
    Total requests: 3

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================


    Fatal exception: Pycurl error 6: Could not resolve host: none.google.com


You can tell Wfuzz to continue execution, ignoring errors by supplying the -Z switch. The latter command in scan mode will get the following results::

    $ wfuzz -z list,support-web-none -Z http://FUZZ.google.com/
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
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

    $ wfuzz -z list,support-web-none -Z --hc XXX http://FUZZ.google.com/
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
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

These timeouts are really handy when you are using Wfuzz to brute force resources behind a proxy, ports, hostnames, virtual hosts, etc.

Filter Language
---------------

Wfuzz's filter language grammar is build using `pyparsing <http://pyparsing.wikispaces.com/>`_, therefore it must be installed before using the command line parameters "--filter, --prefilter, --slice, --field and --efield".

The information about the filter language can be also obtained executing::

    wfuzz --filter-help

A filter expression must be built using the following symbols and operators:

* Boolean Operators

"and", "or" and "not" operators could be used to build conditional expressions.

* Expression Operators

Expressions operators such as "= != < > >= <=" could be used to check values. Additionally, the following operators for matching text are available:

============ ====================================================================
Operator     Description
============ ====================================================================
=~           True when the regular expression specified matches the value.
~            Equivalent to Python's "str2" in "str1" (case insensitive)
!~           Equivalent to Python's "str2" not in "str1" (case insensitive)
============ ====================================================================

Also, assignment operators:

============ ====================================================================
Operator     Description
============ ====================================================================
:=           Assigns a value
=+           Concatenates value at the left
=-           Concatenates value at the right
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
value|unquote()                  value|un()              Unquotes the value
value|lower()                    value|l()               lower-case of the value
value|upper()                                            upper-case of the value
value|encode('encoder', 'value') value|e('enc', 'val')   Returns encoder.encode(value)
value|decode('decoder', 'value') value|d('dec', 'val')   Returns encoder.decode(value)
value|replace('what', 'with')    value|r('what', 'with') Returns value replacing what for with
value|unique()                   value|u()               Returns True if a value is unique.
value|startswith('value')        value|sw('value')       Returns true if the value string starts with param
value|gregex('expression')       value|gre('exp')        Returns first regex group that matches in value
value|diff(expression)                                   Returns diff comparison between value and expression
================================ ======================= =============================================

* When a FuzzResult is available, you could perform runtime introspection of the objects using the following symbols

============ ============== =============================================
Name         Short version  Description
============ ============== =============================================
url                         Wfuzz's result HTTP request url
description                 Wfuzz's result description
nres                        Wfuzz's result identifier
code         c              Wfuzz's result HTTP response's code
chars        h              Wfuzz's result HTTP response chars
lines        l              Wfuzz's result HTTP response lines
words        w              Wfuzz's result HTTP response words
md5                         Wfuzz's result HTTP response md5 hash
history      r              Wfuzz's result associated FuzzRequest object
plugins                     Wfuzz's plugins scan results 
============ ============== =============================================

FuzzRequest object's attribute (you need to use the r. prefix) such as:

============================ =============================================
Name                         Description
============================ =============================================
url                          HTTP request's url
urlp                         HTTP request's parsed url (see section below).
method                       HTTP request's verb
scheme                       HTTP request's scheme
host                         HTTP request's host
content                      HTTP response's content
raw_content                  HTTP response's content including headers
cookies.all                  All HTTP request and response cookies
cookies.request              HTTP requests cookieS
cookies.response             HTTP response cookies
cookies.request.<<name>>     Specified HTTP request cookie
cookies.response.<<name>>    Specified HTTP response cookie
headers.all                  All HTTP request and response headers
headers.request              HTTP request headers
headers.response             HTTP response headers
headers.request.<<name>>     Specified HTTP request header case insensitive
headers.response.<<name>>    Specified HTTP response header insensitive
params.all                   All HTTP request GET and POST parameters
params.get                   All HTTP request GET parameters
params.post                  HTTP request POST parameters in returned as a dictionary
params.raw_post              HTTP request POST parameters payload
params.get.<<name>>          Spcified HTTP request GET parameter
params.post.<<name>>         Spcified HTTP request POST parameter
pstrip                       Returns a signature of the HTTP request using the parameter's names without values (useful for unique operations)
is_path                      Returns true when the HTTP request path refers to a directory.
reqtime                      Returns the total time that HTTP request took to be retrieved
============================ =============================================

It is worth noting that Wfuzz will try to parse the POST parameters according to the specified content type header. Currently, application/x-www-form-urlencoded, multipart/form-dat and application/json are supported. This is prone to error depending on the data format, raw_post will not try to do any processing.

FuzzRequest URL field is broken in smaller (read only) parts using the urlparse Python's module in the urlp attribute.

Urlparse parses a URL into: scheme://netloc/path;parameters?query#fragment. For example, for the "http://www.google.com/dir/test.php?id=1" URL you can get the following values:

=================== =============================================
Name                Value
=================== =============================================
urlp.scheme          http
urlp.netloc          www.google.com
urlp.path            /dir/test.php
urlp.params
urlp.query           id=1
urlp.fragment      
urlp.ffname          test.php
urlp.fext            .php
urlp.fname           test
urlp.hasquery        Returns true when the URL contains a query string.
urlp.isbllist        Returns true when the URL file extension is included in the configuration discovery's blacklist
=================== =============================================

Payload introspection can also be performed by using the keyword FUZZ:

============ ==============================================
Name         Description
============ ==============================================
FUZnZ        Allows to access the Nth payload string
FUZnZ[field] Allows to access the Nth payload attributes
============ ==============================================

Where field is one of the described above.

Filtering results
^^^^^^^^^^^^^^^^^

The --filter command line parameter in conjunction with the described filter language allows you to perform more complex result triage than the standard filter switches such as "--hc/hl/hw/hh", "--sc/sl/sw/sh" and "-ss/hs".

An example below::

    $ wfuzz -z range,0-10 --filter "c=200 and l>97" http://testphp.vulnweb.com/listproducts.php?cat=FUZZ
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
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

Using result and payload introspection to look for specific content returned in the response::

    $ wfuzz -z list,echoedback -d searchFor=FUZZ --filter "content~FUZZ" http://testphp.vulnweb.com/search.php?test=query

Which is equivalent to::

    $ wfuzz -z list,echoedback -d searchFor=FUZZ --ss "echoedback" http://testphp.vulnweb.com/search.php?test=query

A more interesting variation of the above examples could be::

    $ wfuzz -w fuzzdb/attack/xss/xss-rsnake.txt -d searchFor=FUZZ --filter "content~FUZZ" http://testphp.vulnweb.com/search.php?test=query

You can use the fields as boolean values as well. For example, this filter will show only the requests with parameters::

    $ wfuzz -z range --zD 0-1 -u http://testphp.vulnweb.com/artists.php?artist=FUZZ --filter 'r.params.all'

Results with plugin issues can be filter as well::

    $ wfuzz -z list --zD index -u http://testphp.vulnweb.com/FUZZ.php --script headers --filter "plugins~'nginx'"

Payload mangling
^^^^^^^^^^^^^^^^^^^^^^^^^^

Slicing a payload
"""""""

The --slice command line parameter in conjunction with the described language allows you to filter a payload.
The payload to filter, specified by the -z switch must precede --slice command line parameter.

The specified expression must return a boolean value, an example, using the unique operator is shown below::

    $ wfuzz -z list --zD one-two-one-one --slice "FUZZ|u()" http://localhost:9000/FUZZ

    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
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
    
It is worth noting that, the type of payload dictates the available language symbols. For example, a dictionary payload such as in the example
above does not have a full FuzzResult object context and therefore object fields cannot be used.

When slicing a FuzzResult payload, you are accessing the FuzzResult directly, therefore given a previous session such as::

    $ wfuzz -z range --zD 0-0 -u http://www.google.com/FUZZ --oF /tmp/test1
    ...
    000000001:   404        11 L     72 W       1558 Ch     "0"                                                                                                                                                 
    ...

this can be used to filter the payload::

    $ wfpayload -z wfuzzp --zD /tmp/test1 --slice "c=404"
    ...
    000000001:   404        11 L     72 W       1558 Ch     "0"                                                                                                                                                 
    ...

    $ wfpayload -z wfuzzp --zD /tmp/test1 --slice "c!=404"
    ...
    wfuzz.py:168: UserWarning:Fatal exception: Empty dictionary! Please check payload or filter.
    ...

In fact, in this situation, FUZZ refers to the previous result (if any)::

    $ wfuzz -z wfuzzp --zD /tmp/test1 -u FUZZ --oF /tmp/test2
    ...
    000000001:   404        11 L     72 W       1558 Ch     "http://www.google.com/0"                                                                                                                           
    ...

    $ wfpayload -z wfuzzp --zD /tmp/test2 --efield r.headers.response.date --efield FUZZ[r.headers.response.date]
    ...
    000000001:   404        11 L     72 W       1558 Ch     "http://www.google.com/0 | Mon, 02 Nov 2020 19:29:03 GMT | Mon, 02 Nov 2020 19:27:27 GMT"                                                           
    ...

Re-writing a payload
"""""""

The slice command parameter also allows to re-write a payload. Any value, other than a boolean, returned by the
specified expression will be interpreted not to filter the source payload but to change its value.

For example::

    $ ./wfuzz -z list --zD one-two-three --slice "FUZZ|upper()" -u https://www.wfuzz.io/FUZZ
    000000001:   404        11 L     72 W     1560 Ch     "ONE"
    000000003:   404        11 L     72 W     1562 Ch     "THREE"
    000000002:   404        11 L     72 W     1560 Ch     "TWO"

Prefilter
"""""""""

The --prefilter command line parameter is similar to --slice but is not associated to any payload. It is a general filtering 
performed just before any HTTP request is done. 

In this context you are filtering a FuzzResult object, which is the result of combining all the input payloads, that is has not been updated with the result of performing its associated HTTP request yet and therefore lacking some information.

The --prefilter command cannot be used to re-write a payload. The assignment operators can be used to modify the FuzzResult object's fields but expressions other booleans will be ignored.

Reutilising previous results
--------------------------------------

Previously performed HTTP requests/responses contain a treasure trove of data. Wfuzz payloads and object introspection (explained in the filter grammar section) exposes a Python object interface to requests/responses recorded by Wfuzz or other tools.

This allows you to perform manual and semi-automatic tests with full context and understanding of your actions, without relying on a web application scanner underlying implementation.

Some ideas:

* Replaying individual requests as-is
* Comparing response bodies and headers of fuzzed requests against their original
* Looking for requests with the CSRF token exposed in the URL
* Looking for responses with JSON content with an incorrect content type

To reutilise previous results, a payload that generates a full FuzzResult object context should be used.

* wfuzzp payload:

Wfuzz results can be stored using the --oF option as illustrated below::

$ wfuzz --oF /tmp/session -z range,0-10 http://www.google.com/dir/test.php?id=FUZZ

* burpstate and burplog payloads:

Wfuzz can read burp's (TM) log or saved states. This allows to filter or reutilise burp proxy requests and responses.

Then, you can reutilise those results by using the denoted payloads. To repeat a request exactly how it was stored, you must use the FUZZ keyword on the command line::

    $ wfuzz -z burpstate,a_burp_state.burp FUZZ

    $ wfuzz -z burplog,a_burp_log.burp FUZZ

    $ wfuzz -z wfuzzp,/tmp/session FUZZ

Previous requests can also be modified by using the usual command line switches. Some examples below:

* Adding a new header::

    $ wfuzz -z burpstate,a_burp_state.burp -H "addme: header" FUZZ

* Using new cookies specified by another payload::

    $ wfuzz -z burpstate,a_burp_state.burp -z list,1-2-3 -b "cookie=FUZ2Z" FUZZ

* The stored HTTP requests can be printed using the --prev flag for comparing old vs new results::

    $ wfuzz -z burpstate,testphp.burp --slice "cookies.request and url|u()" --filter "c!=FUZZ[c]" -b "" --prev FUZZ  
    ...
    000076:  C=302      0 L        3 W           14 Ch        "http://testphp.vulnweb.com/userinfo.php"
      |__    C=200    114 L      373 W         5347 Ch        "http://testphp.vulnweb.com/userinfo.php"


* Same request against another URL::

    $ wfuzz -z burpstate,a_burp_state.burp -H "addme: header" -u http://www.otherhost.com FUZZ

If you do not want to use the full saved request:

* Accessing specific HTTP object fields can be achieved by using the attr payload's parameter::

    $ wfuzz -z wfuzzp,/tmp/session --zP attr=url FUZZ

* Or by specifying the FUZZ keyword and a field name in the form of FUZZ[field]::

    $ wfuzz -z wfuzzp,/tmp/session FUZZ[url]

This could be used, for example, to perform new requests based on stored values::

    $ wfuzz -z wfuzzp,/tmp/session -p localhost:8080 http://testphp.vulnweb.com/FUZZ[url.path]?FUZZ[url.query]
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

Reutilising previous results
--------------------------------------

Plugins results contain a treasure trove of data. Wfuzz payloads and object introspection (explained in the filter grammar section) exposes a Python object interface to plugins results.
This allows you to perform semi-automatic tests based on plugins results or compile a set of results to be used in another tool.

Request mangling
^^^^^^^^^

The assignment operators can be used to modify previous requests, for example, let's add a quote to every string parameter prior of performing the HTTP request::

    $ wfuzz -z range,1-5 --oF /tmp/session http://testphp.vulnweb.com/artists.php?artist=FUZZ
    000003:  C=200    118 L      455 W         5326 Ch        "3"
    ...
    000004:  C=200     99 L      272 W         3868 Ch        "4"

    $ wfuzz -z wfuzzp,/tmp/session --prefilter "r.params.get=+'\''" -A FUZZ
    00010:  0.161s   C=200  101 L  287 W    3986 Ch    nginx/1.4.1  "http://testphp.vulnweb.com/artists.php?artist=1'"
    |_  Error identified: Warning: mysql_fetch_array()
    ...


The above command looks for simple SQL injection issues.
