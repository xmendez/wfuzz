wfpayload
=========

wfpayload uses the same motor as wfuzz but instead of performing HTTP requests, uses wfuzz's payload plugins to generate new content or analyse saved sessions.

Generating new dictionaries
-------------------

You can use wfpayload to create new dictionaries::

    $ wfpayload -z range --zD 0-10
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

The same wfuzz's syntax can be used, for example::

    $ wfpayload -z range --zD 0-10 --filter "FUZZ<3"
    0
    1
    2


Analysing saved sessions
------------------

Previously performed HTTP requests/responses contain a treasure trove of data. You can use wfpayload to filter and analyse previously saved sessions. Wfpayload can also read sessions from external tools, such as burp.

This allows you to look for new vulnerabilities or understand the underlying target without performing new HTTP requests.

For example, the following will return a unique list of HTTP requests including the authtoken parameter as a GET parameter::

    $ wfpayload -z burplog,a_burp_log.log --slice "params.get~'authtoken'"

Authtoken is the parameter used by BEA WebLogic Commerce Servers (TM) as a CSRF token, and therefore the above will find all the requests exposing the CSRF token in the URL.

You can also look for specific parameters or headers, for example, the following will look for HTTP responses accepting any CORS origin::

    $ wfpayload -z burplog --zD burp_log_05032020.log --prefilter "r.headers.response.Access-Control-Allow-Origin='*'" 

It is worth noting that, if the header is not present in the response it will be return an empty value, not raising any error.

You can also select the fields to show with --efield and --field, for example::

    $ wfpayload -z wfuzzp --zD /tmp/session --field r.params.get
    artist=5
    ...

Or::

    $ wfpayload -z wfuzzp --zD /tmp/session --efield r.params.get
    000000006:   200        99 L     272 W    3868 Ch     "5 | artist=5"
    ...

Running plugins against saved sessions
-------------------

Plugins can be run against a saved session. For example::

    $ ./wfpayload -z burplog --zD ./burp_log_05032020.log  --script=headers --filter "plugins~'akamai'"
    ...
    000000124:   302        0 L      0 W      0 Ch        "https://trial-eum-clientnsv4-s.akamaihd.net/eum/getdns.txt?c=pjq71x1r7"                                                                            
    |_  New Server header - AkamaiGHost
    000000913:   200        10 L     6571 W   289832 Ch   "https://assets.adobedtm.com/2eed2bf00c8bca0c98d97ffee50a306922bc8c98/satelliteLib-27b81756e778cc85cc1a2f067764cd3abf072aa9.js"                     
    |_  New Server header - AkamaiNetStorage
    ...

Re-writing saved sessions
-------------------

The content of a saved session can be re-written. For example, let's say there is a session with a bunch of 404/400 results that you want to remove::

    $ wfpayload -z burplog --zD ./burp_log_05032020.log  --hc 404 --oF /tmp/no404

and then::

    $ wfpayload -z wfuzzp --zD /tmp/no404
