********************************************************
* Wfuzz  2.0 - The Web Bruteforcer                     *
* Coded by:                                            *
* Christian Martorella (cmartorella@edge-security.com) *
* Carlos del ojo (deepbit@gmail.com)                   *
* Xavier Mendez aka Javi (xmendez@edge-security.com)   *
********************************************************

What is this?
-------------

Wfuzz is a tool designed to  brutefore web applications, it's very flexible, it supports:
	
	-Recursion (When doing directory discovery)
	-Post data bruteforcing
	-Header bruteforcing
	-Output to HTML (easy for just clicking the links and checking the page, even with postdata!)
	-Colored output 
	-Hide results by return code, word numbers, line numbers, etc.
	-Url encoding
	-Cookies
	-Multithreading
	-Proxy support 
	-All parameter fuzzing

It was created to facilitate the task in web applications assessments, it's a tool by pentesters for pentesters ;)

How does it works?
------------------

The tool is based on dictionaries or ranges, then you choose where you want to bruteforce just by replacing the value by the word FUZZ.

Examples:

	- wfuzz.py -c -z file,wordlists/commons.txt --hc 404 -o html http://www.mysite.com/FUZZ 2> results.html

	 This will bruteforce the site http://www.mysyte.com/FUZZ in search of resources i
	 (directories, scripts, files,etc), it will hide from the output the return code 404 
	 (for easy reading results), it will use the dictionary commons.txt for the bruteforce
	 , and also will output the results to the results.html file (with a cool format to work).

	- wfuzz.py -c -z range,1-100 --hc 404 http://www.mysite.com/list.asp?id=FUZZ
	  In this example instead of using a file as dictionary, it will use a range from 1-100,
	  and will bruteforce the parameter "id".

	- wfuzz.py -c -z file,wordlists/commons.txt --hc 404 --html -d "id=1&catalogue=FUZZ" 
	   http://www.mysite.com/check.asp 2> results.html 
	   Here you can see the use of POST data, with the option "-d".

	- wfuzz.py -c -z file, wordlists/commons.txt --hc 404 -R 2 http://www.mysite.com/FUZZ
	  Example of path discovery, using a recursive level of 2 paths.

	- wfuzz.py -z file,wordlists/http_methods.txt -X http://testphp.vulnweb.com/
	  HTTP method scanning example

	- wfuzz.py -z file,wordlists/http_methods.txt -z file,wordlists/commons.txt -X http://testphp.vulnweb.com/FUZ2Z/
	  HTTP method scanning example in several paths

	- wfuzz.py -z list,TRACE -X http://testphp.vulnweb.com/
	  Scanning for TRACE method using a list payload

	- wfuzz.py -c -z file,wordlists/methods.txt --hc 404 -v --follow http://www.mysite.com/FUZZ
	  Bruteforce following HTTP redirects

	- wfuzz.py -c -z file,wordlists/commons.txt --hc 404 -I http://www.mysite.com/FUZZ
	  Bruteforce using HEAD HTTP method 

	- wfuzz.py -z list,http://mysite.com -z list,dir-dir2-dir3  FUZZ/FUZ2Z
	  Bruteforce using URL as payload and a list of directories.

	- wfuzz.py -z list,..,double_nibble_hexa@second_nibble_hexa@uri_double_hexadecimal@uri_hexadecimal@first_nibble_hexa@none http://mysite.com/FUZZ/jmx-console
	  Bruteforce using multiple encodings per payload.

	- wfuzz.py -z list,dir1-dir2 -z file,wordlist/general/common.txt -z list,jsp-php-asp -z range,1-40  http://localhost/FUZZ/FUZ2Z.FUZ3Z?id=FUZ4Z
	  Fuzzing using 4 payloads

	- wfuzz.py -z -c -z range,1-10 --hc=BBB http://mysite.com/FUZZ{directory}
	  Baseline support, Bruteforcing and hiding the response codes that are equal to http://mysite.com/directory

	- Combining payloads using iterators:

	zip

	    - wfuzz.py -z list,a-b-c -z list,1-2-3 -m zip http://mysite.com/FUZZ/FUZ2Z

	    Target: http://mysite.com/FUZZ/FUZ2Z
	    Payload type: list,a-b-c; list,1-2-3

	    Total requests: 3
	    ==================================================================
	    ID      Response   Lines      Word         Chars          Request    
	    ==================================================================

	    00001:  C=404      9 L        32 W          276 Ch        "a - 1"
	    00002:  C=404      9 L        32 W          276 Ch        "c - 3"
	    00003:  C=404      9 L        32 W          276 Ch        "b - 2"


	chain

	    - wfuzz.py -z list,a-b-c -z list,1-2-3 -m chain http://mysite.com/FUZZ/FUZ2Z

	    Target: http://mysite.com/FUZZ/FUZ2Z
	    Payload type: list,a-b-c; list,1-2-3

	    Total requests: 6
	    ==================================================================
	    ID      Response   Lines      Word         Chars          Request    
	    ==================================================================

	    00001:  C=404      9 L        32 W          280 Ch        "b"
	    00002:  C=404      9 L        32 W          280 Ch        "a"
	    00003:  C=404      9 L        32 W          280 Ch        "c"
	    00004:  C=404      9 L        32 W          280 Ch        "1"
	    00006:  C=404      9 L        32 W          280 Ch        "3"
	    00005:  C=404      9 L        32 W          280 Ch        "2"


	product

	    - wfuzz.py -z list,a-b-c -z list,1-2-3 http://mysite.com/FUZZ/FUZ2Z

	    Target: http://mysite.com/FUZZ/FUZ2Z
	    Payload type: list,a-b-c; list,1-2-3

	    Total requests: 9
	    ==================================================================
	    ID      Response   Lines      Word         Chars          Request    
	    ==================================================================

	    00001:  C=404      9 L        32 W          276 Ch        "a - 2"
	    00002:  C=404      9 L        32 W          276 Ch        "a - 1"
	    00005:  C=404      9 L        32 W          276 Ch        "b - 2"
	    00004:  C=404      9 L        32 W          276 Ch        "a - 3"
	    00008:  C=404      9 L        32 W          276 Ch        "c - 2"
	    00003:  C=404      9 L        32 W          276 Ch        "b - 1"
	    00007:  C=404      9 L        32 W          276 Ch        "c - 1"
	    00006:  C=404      9 L        32 W          276 Ch        "b - 3"
	    00009:  C=404      9 L        32 W          276 Ch        "c - 3"


Platforms:
----------

wfuzz was tested on Linux, Os X and Windows.
On windows the colored output doesn't work, we are working towards fixing this problem.


Dependencies:
------------

On *nix systems, need pycurl to work.
On Windows just run the wfuzz.exe

Thanks:
-------

Shouts goes to: Trompeti an all the S21sec Team. (www.s21sec.com)

Special thanks to DarkRaver for the tool Dirb, part of wfuzz is based on the functionallity of dirb. (www.open-labs.org) and most of the wordlist are from his tool.

Andres Andreu, all Injection payloads are taken from wsFuzzer (www.neurofuzz.com)

FuzzDB project, the all database is included in the wordlist directory.

Stay tunned for the GUI it rocks..

FuzzDB
------

The wordlist directory includes FuzzDB project:

Attack and Discovery Pattern Database for Application Fuzz Testing

http://code.google.com/p/fuzzdb/

Copyright (c) 2010, Adam Muntner
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
Neither the name of fuzzdb  nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Licensed under Creative Commons - By Attribution

Changelog 2.0:
==============

- Dynamic output printers
- Dynamic payloads
- Multiple payload support (FUZZ, FUZ2Z, ... , FUZnZ)
- Combine payloads using dynamic iterators (zip, chain, product)
- Added list payload
- Added encoder_uri_double_hex
- Added encoder_first_nibble_hex
- Added encoder_second_nibble_hex
- Added encoder_none
- Multiple encodings per payload
- Fixed to FUZZ completely in the URL without hostname or IP or schema (i.e. FUZZ/FUZ2Z)
- Fixed to FUZZ mixing all payload's positions (auth, http method, URL, data)
- Added baseline request functionality
- Added fuzzdb (Attack and Discovery Pattern Database for Application Fuzz Testing)

Changelog 1.4d:
==============
-Using _ in encoders names
-Added HEAD method scanning
-Added magictree support
-Fuzzing in HTTP methods
-Hide responses by regex
-Bash auto completion script (modify and then copy wfuzz_bash_completion into /etc/bash_completion.d)
-Verbose output including server header and redirect location
-Added follow HTTP redirects option (this functionality was already provided by reqresp)
-Fixed HTML output, thanks to Christophe De La Fuente
-Fixed terminal colour, thanks to opensource@till.name

Changelog 1.4c:
==============
-Fixed Headers parsing, thanks to Osama
-Fixed encoding naming problems, thanks to Osama
-Added support to Hexa-Random payload (hexa-rand), thanks to Kaerast

Changelog 1.4:
==============
-More encodings:
-Performance improving
-Some bugs fixed

Changelog 1.3:
=========
-Creada funcion select_encoding
-Multiple encoding, it's possible to encode both dictionries with different encodings.
-Hidecode XXX (cuando da muchos errores, pero puede servir)
-Word count fixed
-More encoders (binascii,md5,sha1)
