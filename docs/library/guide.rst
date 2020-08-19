Python library
===============

Wfuzz's Python library allows to automate tasks and integrate Wfuzz into new tools or scripts.

Library Options
---------------

All options that are available within the Wfuzz command line interface are available as library options:

======================== =====================================================================================
CLI Option               Library Option
======================== =====================================================================================
<URL>                    url="url"
--recipe <filename>      recipe=["filename"]
--oF <filename>          save="filename"
-f filename,printer      printer=("filename", "printer")
--dry-run                transport="dryrun"
-p addr                  proxies=[("ip","port","type")]
-t N                     concurrent=N
-s N                     delay=0.0
-R depth                 rleve=depth
--follow                 follow=True
-Z                       scanmode=True
--req-delay N            req_delay=0
--conn-delay N           conn_delay=0.0
--no-cache               no_cache=True
--script=<plugins>       script="plugins"
--script-args n1=v1,...  script_args={n1: v1}
-m iterator              iterator="iterator"
-z payload               payloads=[("name",{default="",encoder=["md5"]},slice=""),]
-V alltype               allvars="alltype"
-X method                method="method"
--hc/hl/hw/hh N[,N]+     hc/hl/hw/hh=[N,N]
--sc/sl/sw/sh N[,N]+     sc/sl/sw/sh=[N,N]
--ss/hs regex            ss/hs="regex"
--filter <filter>        filter="filter exp"
--prefilter <filter>     prefilter=["prefilter exp"]
-b cookie                cookie=["cookie1=value1",]
-d postdata              postdata="postdata"
-H header                headers=[("header1", "value1"),]
--basic/ntlm/digest auth auth=("basic", "user:pass")
======================== =====================================================================================

These options can be used in the main library interfaces: fuzz, payload or session indistinctly.

Fuzzing a URL
-------------

Fuzzing a URL with wfuzz library is very simple. Firstly, import the wfuzz module::

>>> import wfuzz

Now, let's try to fuzz a web page to look for hidden content, such as directories. For this example, let's use Acunetix's testphp (http://testphp.vulnweb.com/)::

    >>> import wfuzz
    >>> for r in wfuzz.fuzz(url="http://testphp.vulnweb.com/FUZZ", hc=[404], payloads=[("file",dict(fn="wordlist/general/common.txt"))]):
    ...     print r
    ... 
    00060:  C=301      7 L        12 W          184 Ch        "admin"
    00183:  C=403     10 L        29 W          263 Ch        "cgi-bin"
    00429:  C=301      7 L        12 W          184 Ch        "images"
    ...


Now, we have a FuzzResult object called r. We can get all the information we need from this object.

FuzzSession object
------------------

A FuzzSession object has all the methods of the main wfuzz API.

The FuzzSession object allows you to persist certain parameters across fuzzing sessions::

    >>> import wfuzz
    >>> s = wfuzz.FuzzSession(url="http://testphp.vulnweb.com/FUZZ")
    >>> for r in s.fuzz(hc=[404], payloads=[("file",dict(fn="wordlist/general/common.txt"))]):
    ...     print r
    ... 
    00060:  C=301      7 L        12 W          184 Ch        "admin"
    00183:  C=403     10 L        29 W          263 Ch        "cgi-bin"
    ...

FuzzSession can also be used as context manager::

    >>> with wfuzz.FuzzSession(url="http://testphp.vulnweb.com/FUZZ", hc=[404], payloads=[("file",dict(fn="wordlist/general/common.txt"))]) as s:
    ...     for r in s.fuzz():
    ...             print r
    ... 
    00295:  C=301      7 L        12 W          184 Ch        "admin"
    00418:  C=403     10 L        29 W          263 Ch        "cgi-bin"


Get payload
-----------

The get_payload function generates a Wfuzz payload from a Python iterable. It is a quick and flexible way of getting a payload programmatically without using Wfuzz payloads plugins.

Generating a new payload and start fuzzing is really simple::

    >>> import wfuzz
    >>> s = wfuzz.get_payload(range(5))
    >>> for r in s.fuzz(url="http://testphp.vulnweb.com/FUZZ"):
    ...     print r
    ... 
    00012:  C=404      7 L        12 W          168 Ch        "0"
    00013:  C=404      7 L        12 W          168 Ch        "1"
    00014:  C=404      7 L        12 W          168 Ch        "2"
    00015:  C=404      7 L        12 W          168 Ch        "3"
    00016:  C=404      7 L        12 W          168 Ch        "4"

The get_payloads method can be used when various payloads are needed::

    >>> import wfuzz
    >>> s = wfuzz.get_payloads([range(5), ["a","b"]])
    >>> for r in s.fuzz(url="http://testphp.vulnweb.com/FUZZ/FUZ2Z"):
    ...     print r
    ... 
    00028:  C=404      7 L        12 W          168 Ch        "4 - b"
    00027:  C=404      7 L        12 W          168 Ch        "4 - a"
    00024:  C=404      7 L        12 W          168 Ch        "2 - b"
    00026:  C=404      7 L        12 W          168 Ch        "3 - b"
    00025:  C=404      7 L        12 W          168 Ch        "3 - a"
    00022:  C=404      7 L        12 W          168 Ch        "1 - b"
    00021:  C=404      7 L        12 W          168 Ch        "1 - a"
    00020:  C=404      7 L        12 W          168 Ch        "0 - b"
    00023:  C=404      7 L        12 W          168 Ch        "2 - a"
    00019:  C=404      7 L        12 W          168 Ch        "0 - a"

Get session
-----------

The get_session function generates a Wfuzz session object from the specified command line. It is a quick way of getting a payload programmatically from a string representing CLI options::

    $ python
    >>> import wfuzz
    >>> s = wfuzz.get_session("-z range,0-10 http://testphp.vulnweb.com/FUZZ")
    >>> for r in s.fuzz():
    ...     print r
    ... 
    00002:  C=404      7 L        12 W          168 Ch        "1"
    00011:  C=404      7 L        12 W          168 Ch        "10"
    00008:  C=404      7 L        12 W          168 Ch        "7"
    00001:  C=404      7 L        12 W          168 Ch        "0"
    00003:  C=404      7 L        12 W          168 Ch        "2"
    00004:  C=404      7 L        12 W          168 Ch        "3"
    00005:  C=404      7 L        12 W          168 Ch        "4"
    00006:  C=404      7 L        12 W          168 Ch        "5"
    00007:  C=404      7 L        12 W          168 Ch        "6"
    00009:  C=404      7 L        12 W          168 Ch        "8"
    00010:  C=404      7 L        12 W          168 Ch        "9"

Interacting with the results
----------------------------

Once a Wfuzz result is available the grammar defined in the filter language can be used to work with the results' values. For example::

    $ python
    >>> import wfuzz

    >>> with wfuzz.get_session("-z list --zD test -u http://testphp.vulnweb.com/userinfo.php -d uname=FUZZ&pass=FUZZ") as s:
    ...     for r in s.fuzz():
    ...             print(r.history.cookies.response)
    ...             print(r.history.params.all)
    ...             print(r.history.params.post)
    ...             print(r.history.params.post.uname)
    ...             print(r.history.params.post['pass'])
    {'login': 'test%2Ftest'}
    {'uname': 'test', 'pass': 'test'}
    {'uname': 'test', 'pass': 'test'}
    test
    test
    >>>

The result object has also a method to evaluate a language expression::

    >> print(r.eval("r.cookies.response"))
    login=test%2Ftest
