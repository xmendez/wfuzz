import sys
from wfuzz import __version__ as version
import os
if os.name == "nt":
    import WConio


examples_banner = '''Examples:\n\twfuzz -c -z file,users.txt -z file,pass.txt --sc 200 http://www.site.com/log.asp?user=FUZZ&pass=FUZ2Z
\twfuzz -c -z range,1-10 --hc=BBB http://www.site.com/FUZZ{something not there}
\twfuzz --script=robots -z list,robots.txt http://www.webscantest.com/FUZZ
\n\tMore examples in the README.'''

exec_banner = '''********************************************************\r
* Wfuzz %s - The Web Fuzzer                           *\r
********************************************************\r\n''' % version

help_banner = '''********************************************************
* Wfuzz %s - The Web Fuzzer                           *
*                                                      *
* Version up to 1.4c coded by:                         *
* Christian Martorella (cmartorella@edge-security.com) *
* Carlos del ojo (deepbit@gmail.com)                   *
*                                                      *
* Version 1.4d to %s coded by:                        *
* Xavier Mendez (xmendez@edge-security.com)            *
********************************************************\r\n''' % (version, version)

header_usage ='''Usage:\twfuzz [options] -z payload,params <url>\r\n
\tFUZZ, ..., FUZnZ  wherever you put these keywords wfuzz will replace them with the values of the specified payload. 
\tFUZZ{baseline_value} FUZZ will be replaced by baseline_value. It will be the first request performed and could be used as a base for filtering.
'''

brief_usage ='''%s\n\n%s\n\nType wfuzz -h for further information or --help for advanced usage.''' % (header_usage, examples_banner)

usage ='''%s\n\nOptions:
\t-h      		    : This help
\t--help			    : Advanced help
\t--version		    : Wfuzz version details
\t-e <type>		    : List of available encoders/payloads/iterators/printers/scripts
\t
\t-c			    : Output with colors
\t-v			    : Verbose information.
\t--interact		    : (beta) If selected,all key presses are captured. This allows you to interact with the program.
\t
\t-p addr			    : Use Proxy in format ip:port:type or ip:port:type-...-ip:port:type for using various proxies.
\t			      Where type could be SOCKS4,SOCKS5 or HTTP if omitted.
\t
\t-t N			    : Specify the number of concurrent connections (10 default)
\t-s N			    : Specify time delay between requests (0 default)
\t-R depth		    : Recursive path discovery being depth the maximum recursion level.
\t-L, --follow        	    : Follow HTTP redirections
\t
\t-u url                      : Specify a URL for the request.
\t-z payload		    : Specify a payload for each FUZZ keyword used in the form of type,parameters,encoder.
\t			      A list of encoders can be used, ie. md5-sha1. Encoders can be chained, ie. md5@sha1.
\t			      Encoders category can be used. ie. url
\t                              Use help as a payload to show payload plugin's details (you can filter using --slice)
\t-w wordlist		    : Specify a wordlist file (alias for -z file,wordlist).
\t-V alltype		    : All parameters bruteforcing (allvars and allpost). No need for FUZZ keyword.
\t-X method		    : Specify an HTTP method for the request, ie. HEAD or FUZZ
\t
\t-b cookie		    : Specify a cookie for the requests
\t-d postdata 		    : Use post data (ex: "id=FUZZ&catalogue=1")
\t-H header  		    : Use header (ex:"Cookie:id=1312321&user=FUZZ")
\t--basic/ntlm/digest auth    : in format "user:pass" or "FUZZ:FUZZ" or "domain\FUZ2Z:FUZZ"
\t
\t--hc/hl/hw/hh N[,N]+	    : Hide responses with the specified code/lines/words/chars (Use BBB for taking values from baseline)
\t--sc/sl/sw/sh N[,N]+	    : Show responses with the specified code/lines/words/chars (Use BBB for taking values from baseline)
\t--ss/hs regex		    : Show/Hide responses with the specified regex within the content
''' % (header_usage)

verbose_usage ='''%s\n\nOptions:
\t-h/--help		    : This help
\t--help			    : Advanced help
\t--version		    : Wfuzz version details
\t-e <type>		    : List of available encoders/payloads/iterators/printers/scripts
\t
\t--recipe <filename>	    : Reads options from a recipe
\t--dump-recipe <filename>    : Prints current options as a recipe
\t--oF <filename>	            : Saves fuzz results to a file. These can be consumed later using the wfuzz payload.
\t
\t-c			    : Output with colors
\t-v			    : Verbose information.
\t-o filename,printer         : Store results in the output file using the specified printer (raw printer if omitted).
\t--interact		    : (beta) If selected,all key presses are captured. This allows you to interact with the program.
\t--dry-run		    : Print the results of applying the requests without actually making any HTTP request.
\t
\t-p addr			    : Use Proxy in format ip:port:type. Repeat option for using various proxies.
\t			      Where type could be SOCKS4,SOCKS5 or HTTP if omitted.
\t
\t-t N			    : Specify the number of concurrent connections (10 default)
\t-s N			    : Specify time delay between requests (0 default)
\t-R depth		    : Recursive path discovery being depth the maximum recursion level.
\t-L,--follow		    : Follow HTTP redirections
\t-Z			    : Scan mode (Connection errors will be ignored).
\t--req-delay N		    : Sets the maximum time in seconds the request is allowed to take (CURLOPT_TIMEOUT). Default 90.
\t--conn-delay N              : Sets the maximum time in seconds the connection phase to the server to take (CURLOPT_CONNECTTIMEOUT). Default 90.
\t
\t-A			    : Alias for --script=default -v -c
\t--script=		    : Equivalent to --script=default
\t--script=<plugins>	    : Runs script's scan. <plugins> is a comma separated list of plugin-files or plugin-categories
\t--script-help=<plugins>	    : Show help about scripts.
\t--script-args n1=v1,...     : Provide arguments to scripts. ie. --script-args grep.regex=\"<A href=\\\"(.*?)\\\">\"
\t
\t-u url                      : Specify a URL for the request.
\t-m iterator		    : Specify an iterator for combining payloads (product by default)
\t-z payload		    : Specify a payload for each FUZZ keyword used in the form of name[,parameter][,encoder].
\t			      A list of encoders can be used, ie. md5-sha1. Encoders can be chained, ie. md5@sha1.
\t			      Encoders category can be used. ie. url
\t                              Use help as a payload to show payload plugin's details (you can filter using --slice)
\t--zP <params>		    : Arguments for the specified payload (it must be preceded by -z or -w).
\t--slice <filter>	    : Filter payload\'s elements using the specified expression (Use BBB for taking values from baseline). It must be preceded by -z. 
\t			      It should be composed of: c,l,w,h,index,intext,inurl,site,inheader,filetype,ispath,hasquery;not,and,or;=,<,>,!=,<=,>=")
\t-w wordlist		    : Specify a wordlist file (alias for -z file,wordlist).
\t-V alltype		    : All parameters bruteforcing (allvars and allpost). No need for FUZZ keyword.
\t-X method		    : Specify an HTTP method for the request, ie. HEAD or FUZZ
\t
\t-b cookie		    : Specify a cookie for the requests. Repeat option for various cookies.
\t-d postdata 		    : Use post data (ex: "id=FUZZ&catalogue=1")
\t-H header  		    : Use header (ex:"Cookie:id=1312321&user=FUZZ"). Repeat option for various headers.
\t--basic/ntlm/digest auth    : in format "user:pass" or "FUZZ:FUZZ" or "domain\FUZ2Z:FUZZ"
\t
\t--hc/hl/hw/hh N[,N]+	    : Hide responses with the specified code/lines/words/chars (Use BBB for taking values from baseline)
\t--sc/sl/sw/sh N[,N]+	    : Show responses with the specified code/lines/words/chars (Use BBB for taking values from baseline)
\t--ss/hs regex		    : Show/hide responses with the specified regex within the content
\t--filter <filter>	    : Show/hide responses using the specified filter expression (Use BBB for taking values from baseline)
\t--prefilter <filter>	    : Filter items before fuzzing using the specified expression (Use BBB for taking values from baseline)
\t			      It should be composed of: c,l,w,h,index,intext,inurl,site,inheader,filetype,ispath,hasquery;not,and,or;=,<,>,!=,<=,>=")
''' % (header_usage)

class Term:
    reset = "\x1b[0m"
    bright = "\x1b[1m"
    dim = "\x1b[2m"
    underscore = "\x1b[4m"
    blink = "\x1b[5m"
    reverse = "\x1b[7m"
    hidden = "\x1b[8m"

    delete = "\x1b[0K"
    oneup = "\033[1A"

    fgBlack = "\x1b[30m"
    fgRed = "\x1b[31m"
    fgGreen = "\x1b[32m"
    fgYellow = "\x1b[33m"
    fgBlue = "\x1b[34m"
    fgMagenta = "\x1b[35m"
    fgCyan = "\x1b[36m"
    fgWhite = "\x1b[37m"

    bgBlack = "\x1b[40m"
    bgRed = "\x1b[41m"
    bgGreen = "\x1b[42m"
    bgYellow = "\x1b[43m"
    bgBlue = "\x1b[44m"
    bgMagenta = "\x1b[45m"
    bgCyan = "\x1b[46m"
    bgWhite = "\x1b[47m"


    def get_colour(self, code):
	if code == 0:
	    cc = Term.fgYellow
	    wc = 12
	elif code >= 400 and code < 500:
	    cc = Term.fgRed
	    wc = 12
	elif code >= 300 and code < 400:
	    cc = Term.fgBlue
	    wc = 11
	elif code >= 200 and code < 300:
	    cc = Term.fgGreen
	    wc = 10
	else:
	    cc = Term.fgMagenta
	    wc = 1

	return (cc, wc)

    def delete_line(self):
        if os.name != 'nt':
            sys.stdout.write("\r" + Term.delete)
        else:
            WConio.clreol()

    def set_colour(self, colour):
	cc, wc = colour

        if os.name != 'nt':
            sys.stdout.write(cc)
        else:
            WConio.textcolor(wc)

    def write(self, string, colour):
	cc, wc = colour

        if os.name != 'nt':
            sys.stdout.write(cc + string + Term.reset)
        else:
            WConio.textcolor(wc)
            sys.stdout.write(string)
            WConio.textcolor(8)

    def go_up(self, lines):
        sys.stdout.write("\033["+str(lines)+"A")

    def erase_lines(self, lines):
        for i in range(lines):
            sys.stdout.write("\r" + Term.delete)
            sys.stdout.write(Term.oneup)







