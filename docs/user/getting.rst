Getting Started
===============

A typical Wfuzz command line execution, specifying a dictionary payload and a URL, looks like this::

    $ wfuzz -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ


The obtained output is shown below::

    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
    ********************************************************

    Target: http://testphp.vulnweb.com/FUZZ
    Total requests: 950

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00006:  C=301      7 L        12 W          184 Ch        "admin"
    00135:  C=403     10 L        29 W          263 Ch        "cgi-bin"
    00379:  C=301      7 L        12 W          184 Ch        "images"
    00686:  C=301      7 L        12 W          184 Ch        "secured"
    ...
    00935:  C=301      7 L        12 W          184 Ch        "CVS"

    Total time: 4.214460
    Processed Requests: 950
    Filtered Requests: 0
    Requests/sec.: 225.4143

Wfuzz output allows to analyse the web server responses and filter the desired results based on the HTTP response message obtained, for example, response codes, response length, etc.

Each line provides the following information:

- ID: The request number in the order that it was performed.
- Response: Shows the HTTP response code.
- Lines: Shows the number of lines in the HTTP response.
- Word: Shows the number of words in the HTTP response.
- Chars: Shows the number of characters in the HTTP response.
- Payload: Shows the payload used.

Getting help
------------

Use the --h and --help switch to get basic and advanced help usage respectively.

Wfuzz is a completely modular framework, you can check the available modules by using the -e <<category>> switch::

    $ wfuzz -e iterators

    Available iterators:

    Name    | Summary                                                                           
    ----------------------------------------------------------------------------------------------
    product | Returns an iterator cartesian product of input iterables.                         
    zip     | Returns an iterator that aggregates elements from each of the iterables.          
    chain   | Returns an iterator returns elements from the first iterable until it is exhaust  
            | ed, then proceeds to the next iterable, until all of the iterables are exhausted  
            | .                                                                                 


Valid categories are: payloads, encoders, iterators, printers or scripts.

Payloads
--------

Wfuzz is based on a simple concept: it replaces any reference to the keyword FUZZ by the value of a given payload. A payload in Wfuzz is a source of input data.

The available payloads can be listed by executing::

    $ wfuzz -e payloads

Detailed information about payloads could be obtained by executing::

    $ wfuzz -z help

The latter can be filtered using the --slice parameter::

    $ wfuzz -z help --slice "dirwalk"

    Name: dirwalk 0.1
    Categories: default
    Summary: Returns filename's recursively from a local directory.
    Description:
       Returns all the file paths found in the specified directory.
       Handy if you want to check a directory structure against a webserver,
       for example, because you have previously downloaded a specific version
       of what is supposed to be on-line.
    Parameters:
       + dir: Directory path to walk and generate payload from.


Specifying a payload:
^^^^^^^^^^^^^^^^^^^^^

Each FUZZ keyword must have its corresponding payload. There are several equivalent ways of specifying a payload:

* The long way explicitly defining the payload's parameter name through the command line::

    $ wfuzz -z file --zP fn=wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ

* The not so long way explicitly defining the payload's default parameter through the --zD command line option::

    $ wfuzz -z file --zD wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ

* The not so long way defining only the value of the payload's default parameter::

    $ wfuzz -z file,wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ

* The short way when using the file payload alias::

    $ wfuzz -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ


The stdin payload could be used when using a external wordlist generator::

    $ crunch 2 2 ab | wfuzz -z stdin http://testphp.vulnweb.com/FUZZ
    Crunch will now generate the following amount of data: 12 bytes
    0 MB
    0 GB
    0 TB
    0 PB
    Crunch will now generate the following number of lines: 4 
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
    ********************************************************

    Target: http://testphp.vulnweb.com/FUZZ
    Total requests: <<unknown>>

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00002:  C=404      7 L        12 W          168 Ch        "ab"
    00001:  C=404      7 L        12 W          168 Ch        "aa"
    00003:  C=404      7 L        12 W          168 Ch        "ba"
    00004:  C=404      7 L        12 W          168 Ch        "bb"

    Total time: 3.643738
    Processed Requests: 4
    Filtered Requests: 0
    Requests/sec.: 1.097773


Multiple payloads
^^^^^^^^^^^^^^^^^

Several payloads can be used by specifying several -z or -w parameters and the corresponding FUZZ, ... , FUZnZ keyword where n is the payload number. The following example, brute forces files, extension files and directories at the same time::

    $ wfuzz -w wordlist/general/common.txt -w wordlist/general/common.txt -w wordlist/general/extensions_common.txt --hc 404 http://testphp.vulnweb.com/FUZZ/FUZ2ZFUZ3Z  

Filters
-------


Filtering results in Wfuzz is paramount:

* Big dictionaries could generate a great amount of output and can easily drown out legitimate valid results. 
* Triaging HTTP responses is key to perform some attacks, for example, in order to check for the presence of a SQL injection vulnerability we need to distinguish a legitimate response from the one that generates an error or different data.

Wfuzz allows to filter based on the HTTP responses code and the length of the received information (in the form of words, characters or lines). Regular expressions can also be used. Two approaches can be taken: showing or hiding results matching a given filter.

Hiding responses
^^^^^^^^^^^^^^^^

The following command line parameters can be used to hide certain HTTP responses "--hc, --hl, --hw, --hh". For example, the following command filters the web resources unknown by the web server (http://en.wikipedia.org/wiki/HTTP_404)::

    wfuzz -w wordlist/general/common.txt --hc 404 http://testphp.vulnweb.com/FUZZ    

Multiple values can be specified, for example, the following wfuzz execution adds the forbidden resources to the filter::

    wfuzz -w wordlist/general/common.txt --hc 404,403 http://testphp.vulnweb.com/FUZZ    

Lines, words or chars are handy when we are looking for resources with the same HTTP status code. For example, it is a common behaviour (sometimes due to misconfiguration) that web servers return a custom error page with a 200 response code, this is known as soft 404.

Below is shown an example::

    $ wfuzz -w wordlist/general/common.txt --hc 404 http://datalayer.io/FUZZ  
    ********************************************************
    * Wfuzz 2.2 - The Web Fuzzer                           *
    ********************************************************

    Target: http://datalayer.io/FUZZ
    Total requests: 950

    ==================================================================
    ID      Response   Lines      Word         Chars          Request    
    ==================================================================

    00000:  C=200    279 L       635 W         8972 Ch        "W3SVC3"
    00001:  C=200    279 L       635 W         8972 Ch        "Log"
    00002:  C=200    279 L       635 W         8972 Ch        "10"
    00003:  C=200    279 L       635 W         8972 Ch        "02"
    00004:  C=200    279 L       635 W         8972 Ch        "2005"
    ...
    00024:  C=200    301 L       776 W         9042 Ch        "about"
    ...

Looking carefully at the above results, is easy to ascertain that all the "not found" resources have a common patter of 279 lines, 635 words and 8972 chars.
Thus, we can improve our "--hc 404" filter by using this information (various filters can be combined)::

    $ wfuzz -w wordlist/general/common.txt --hc 404 --hh 8972  http://datalayer.io/FUZZ  

    00022:  C=200    301 L       776 W         9042 Ch        "about"
    00084:  C=302      0 L         0 W            0 Ch        "blog"
    00192:  C=302      0 L         0 W            0 Ch        "css"
    ...
    00696:  C=200    456 L      1295 W        15119 Ch        "service"
    00751:  C=200    238 L       512 W         6191 Ch        "store"
    00788:  C=302      0 L         0 W            0 Ch        "text"
    00913:  C=302      0 L         0 W            0 Ch        "template"

Showing responses
^^^^^^^^^^^^^^^^^

Showing results works the same way but using the command line parameters preceded by an "s": "--sc, --sl, --sw, --sh".

Using the baseline
^^^^^^^^^^^^^^^^^^

Filters can be built against a reference HTTP response, called the "baseline". For example, the previous command for filtering "not found" resources using the --hh switch could have be done with the following command::

    $ wfuzz -w wordlist/general/common.txt --hh BBB  http://datalayer.io/FUZZ{notthere}
    ...
    00000:  C=200    279 L       635 W         8972 Ch        "notthere"
    00001:  C=200    301 L       776 W         9042 Ch        "about"
    00004:  C=200    456 L      1295 W        15119 Ch        "service"
    ...

Here the {} defines the value of the FUZZ word for this first HTTP request, and then the response can be used specifying "BBB" as a filter value. 

Regex filters
^^^^^^^^^^^^^

The command line parameters "--ss" and "--hs" allow to filter the responses using a regular expression against the returned content. For example, the following allows to find web servers vulnerable to "shellshock" (see http://edge-security.blogspot.co.uk/2014/10/scan-for-shellshock-with-wfuzz.html for more information)::

    $ wfuzz -H "User-Agent: () { :;}; echo; echo vulnerable" --ss vulnerable -w cgis.txt http://localhost:8000/FUZZ     

A valid python regex should be used within these switches or an error will be prompted::

    $ wfuzz -w wordlist/general/common.txt --hs "error)"  http://testphp.vulnweb.com/FUZZ

    Fatal exception: Invalid regex expression: unbalanced parenthesis
