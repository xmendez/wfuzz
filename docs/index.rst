.. Wfuzz documentation master file, created by
   sphinx-quickstart on Thu Mar  2 13:44:00 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Wfuzz: The Web fuzzer
==================================

.. image:: https://img.shields.io/pypi/v/wfuzz.svg
    :target: https://pypi.org/project/wfuzz/

.. image:: https://img.shields.io/pypi/l/wfuzz.svg
    :target: https://pypi.org/project/wfuzz/

.. image:: https://img.shields.io/pypi/pyversions/wfuzz.svg
    :target: https://pypi.org/project/wfuzz/

.. image:: https://codecov.io/github/xmendez/wfuzz/coverage.svg?branch=master
    :target: https://codecov.io/github/xmendez/wfuzz

Wfuzz supports Python 3. The use of **Python 3** is preferred (and faster) over Python 2. 

See Wfuzz in action:

* Wfuzz cli::

    $ wfuzz -w wordlist/general/common.txt --hc 404 http://testphp.vulnweb.com/FUZZ                                                                                              
    ********************************************************
    * Wfuzz 2.2 - The Web Bruteforcer                      *
    ********************************************************

    Target: http://testphp.vulnweb.com/FUZZ
    Total requests: 950

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00022:  C=301      7 L        12 W          184 Ch        "admin"
    00130:  C=403     10 L        29 W          263 Ch        "cgi-bin"
    00378:  C=301      7 L        12 W          184 Ch        "images"
    00690:  C=301      7 L        12 W          184 Ch        "secured"
    00938:  C=301      7 L        12 W          184 Ch        "CVS"

    Total time: 5.519253
    Processed Requests: 950
    Filtered Requests: 945
    Requests/sec.: 172.1247

* Wfuzz library::

    >>> import wfuzz
    >>> for r in wfuzz.get_payload(range(100)).fuzz(hl=[97], url="http://testphp.vulnweb.com/listproducts.php?cat=FUZZ"):
    ...     print r
    ... 
    00125:  C=200    102 L       434 W         7011 Ch        "1"
    00126:  C=200     99 L       302 W         4442 Ch        "2"

other tools included in the wfuzz framework.

* Wfuzz payload generator::

    $ wfpayload -z range,0-10
    0
    1
    2
    3
    4
    5
    6
    7
    8
    9
    10

* Wfuzz encoder/decoder::
    
    $ wfencode -e md5 test
    098f6bcd4621d373cade4e832627b4f6

Wfuzz has been created to facilitate the task in web applications assessments and it is based on a simple concept: it replaces any reference to the FUZZ keyword by the value of a given payload.

A payload in Wfuzz is a source of data.

This simple concept allows any input to be injected in any field of an HTTP request, allowing to perform complex web security attacks in different web application components such as: parameters, authentication, forms, directories/files, headers, etc.

Wfuzz is more than a web content scanner:

- Wfuzz could help you to secure your web applications by finding and exploiting web application vulnerabilities. Wfuzz's web application vulnerability scanner is supported by plugins.
- Wfuzz is a completely modular framework and makes it easy for even the newest of Python developers to contribute. Building plugins is simple and takes little more than a few minutes.
- Wfuzz exposes a simple language interface to the previous HTTP requests/responses performed using Wfuzz or other tools, such as Burp. This allows you to perform manual and semi-automatic tests with full context and understanding of your actions, without relying on a web application scanner underlying implementation.

User Guide
==================

.. toctree::
   :maxdepth: 2

   user/installation
   user/getting
   user/basicusage
   user/advanced

Library Guide
==================

.. toctree::
   :maxdepth: 2

   library/guide
