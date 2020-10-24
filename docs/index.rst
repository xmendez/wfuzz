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

Wfuzz provides a framework to automate web applications security assessments and could help you to secure your web applications by finding and exploiting web application vulnerabilities.

See Wfuzz in action
-------------------

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

* You can also run wfuzz from the official docker image::

    $ docker run -v $(pwd)/wordlist:/wordlist/ -it ghcr.io/xmendez/wfuzz wfuzz
    ********************************************************
    * Wfuzz 3.0.3 - The Web Fuzzer                         *
    *                                                      *
    * Version up to 1.4c coded by:                         *
    * Christian Martorella (cmartorella@edge-security.com) *
    * Carlos del ojo (deepbit@gmail.com)                   *
    *                                                      *
    * Version 1.4d to 3.0.3 coded by:                      *
    * Xavier Mendez (xmendez@edge-security.com)            *
    ********************************************************

    Usage:  wfuzz [options] -z payload,params <url>

            FUZZ, ..., FUZnZ  wherever you put these keywords wfuzz will replace them with the values of the specified payload.
            FUZZ{baseline_value} FUZZ will be replaced by baseline_value. It will be the first request performed and could be used as a base for filtering.


    Examples:
            wfuzz -c -z file,users.txt -z file,pass.txt --sc 200 http://www.site.com/log.asp?user=FUZZ&pass=FUZ2Z
            wfuzz -c -z range,1-10 --hc=BBB http://www.site.com/FUZZ{something not there}
            wfuzz --script=robots -z list,robots.txt http://www.webscantest.com/FUZZ

    Type wfuzz -h for further information or --help for advanced usage.


How it works
------------

Wfuzz it is based on a simple concept: it replaces any reference to the FUZZ keyword by the value of a given payload.

A payload in Wfuzz is a source of data.

This simple concept allows any input to be injected in any field of an HTTP request, allowing to perform complex web security attacks in different web application components such as: parameters, authentication, forms, directories/files, headers, etc.

Wfuzz is more than a web brute forcer:

- Wfuzz's web application vulnerability scanner is supported by plugins.
- Wfuzz is a completely modular framework and makes it easy for even the newest of Python developers to contribute. Building plugins is simple and takes little more than a few minutes.
- Wfuzz exposes a simple language interface to the previous HTTP requests/responses performed using Wfuzz or other tools, such as Burp. This allows you to perform manual and semi-automatic tests with full context and understanding of your actions, without relying on a web application scanner underlying implementation.

Installation Guide
==================

.. toctree::	
   :maxdepth: 4

   user/installation
   user/breaking

User Guide
==================

.. toctree::
   :maxdepth: 4

   user/getting
   user/basicusage
   user/advanced
   user/wfpayload

Library Guide	
==================	

.. toctree::	
   :maxdepth: 4

   library/guide
