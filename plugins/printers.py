import socket
import sys
import json as jjson
from xml.dom import minidom

from externals.moduleman.plugin import moduleman_plugin
from framework.ui.console.output import getTerminalSize
from framework.ui.console.common import exec_banner, Term
from framework.core.myexception import FuzzException

@moduleman_plugin("header", "footer", "result")
class magictree:
    name = "magictree"
    description = "Prints results in magictree format"
    category = ["default"]
    priority = 99

    def __init__(self):
	self.node_mt = None
	self.node_service = None

    def __create_xml_element(self, parent, caption, text):
	# Create a <xxx> element
	doc = minidom.Document()
	el = doc.createElement(caption)
	parent.appendChild(el)

	# Give the <xxx> element some text
	ptext = doc.createTextNode(text)

	el.appendChild(ptext)
	return el

    def header(self, summary):
	doc = minidom.Document()

	#<magictree class="MtBranchObject">
	self.node_mt = doc.createElement("magictree")
	self.node_mt.setAttribute("class", "MtBranchObject")

	#<testdata class="MtBranchObject">
	node_td = doc.createElement("testdata")
	node_td.setAttribute("class", "MtBranchObject")
	self.node_mt.appendChild(node_td)

	#<host>209.85.146.105
	host = summary.seed.history.host
	if host.find(":") > 0:
	    host, port = host.split(":")
	else:
	    port = 80
	    if summary.seed.history.scheme.lower() == "https":
		port = 443

	try:
	    resolving = socket.gethostbyname(host)
	    node_h = self.__create_xml_element(node_td, "host", str(resolving))
	except socket.gaierror:
	    node_h = self.__create_xml_element(node_td, "host", str(host))

	#<ipproto>tcp
	node_ipr = self.__create_xml_element(node_h, "ipproto", "tcp")

	#<port>80<state>open</state><service>http
	node_port = self.__create_xml_element(node_ipr, "port", str(port))
	self.__create_xml_element(node_port, "state", "open")
	if summary.seed.history.scheme.lower() == "https":
	    node_port = self.__create_xml_element(node_port, "tunnel", "ssl")

	self.node_service = self.__create_xml_element(node_port, "service", "http")

    def result(self, fuzz_result):
	node_url = self.__create_xml_element(self.node_service, "url", str(fuzz_result.url))

	if 'Server' in fuzz_result.history.headers.response:
	    self.__create_xml_element(node_url, "HTTPServer", fuzz_result.history.headers.response['Server'])

	location = ""
	if 'Location' in fuzz_result.history.headers.response:
	    location = fuzz_result.history.headers.response['Location']

	if fuzz_result.code == 301 or fuzz_result.code == 302 and location:
	    self.__create_xml_element(node_url, "RedirectLocation", location)

	self.__create_xml_element(node_url, "ResponseCode", str(fuzz_result.code))
	self.__create_xml_element(node_url, "source", "WFuzz")

    def footer(self, summary):
	sys.stderr.write(self.node_mt.toxml())

@moduleman_plugin("header", "footer", "result")
class html:
    name = "html"
    description = "Prints results in html format"
    category = ["default"]
    priority = 99

    def header(self, summary):
	url = summary.url

	sys.stderr.write("<html><head></head><body bgcolor=#000000 text=#FFFFFF><h1>Fuzzing %s</h1>\r\n<table border=\"1\">\r\n<tr><td>#request</td><td>Code</td><td>#lines</td><td>#words</td><td>Url</td></tr>\r\n" % (url) )

    def result(self, fuzz_result):
	htmlc="<font>"

	if fuzz_result.code >= 400 and fuzz_result.code < 500:
	    htmlc = "<font color=#FF0000>"
	elif fuzz_result.code>=300 and fuzz_result.code < 400:
	    htmlc = "<font color=#8888FF>"
	elif fuzz_result.code>=200 and fuzz_result.code < 300:
	    htmlc = "<font color=#00aa00>"

	if fuzz_result.history.method.lower() == "post":
	    inputs=""
	    for n, v in fuzz_result.history.parameters.post.items():
		inputs+="<input type=\"hidden\" name=\"%s\" value=\"%s\">" % (n, v)

	    sys.stderr.write ("\r\n<tr><td>%05d</td>\r\n<td>%s%d</font></td>\r\n<td>%4dL</td>\r\n<td>%5dW</td>\r\n<td><table><tr><td>%s</td><td><form method=\"post\" action=\"%s\">%s<input type=submit name=b value=\"send POST\"></form></td></tr></table></td>\r\n</tr>\r\n" %(fuzz_result.nres, htmlc, fuzz_result.code, fuzz_result.lines, fuzz_result.words, fuzz_result.description, fuzz_result.url, inputs))
	else:
	    sys.stderr.write("\r\n<tr><td>%05d</td><td>%s%d</font></td><td>%4dL</td><td>%5dW</td><td><a href=%s>%s</a></td></tr>\r\n" %(fuzz_result.nres, htmlc, fuzz_result.code, fuzz_result.lines, fuzz_result.words, fuzz_result.url, fuzz_result.url))

    def footer(self, summary):
	sys.stderr.write("</table></body></html><h5>Wfuzz by EdgeSecurity<h5>\r\n")
	sys.stdout.flush()

@moduleman_plugin("header", "footer", "result")
class default:
    name = "default"
    description = "Default output format"
    category = ["default"]
    priority = 99

    def __init__(self):
        self.colour = True if self.kbase.has("colour") else False
        self.verbose = True if self.kbase.has("verbose") else False

        self.term = Term()

    def _print_verbose(self, res):
	txt_colour = ("", 8) if not res.is_baseline or not self.colour else (Term.fgCyan, 8)

        self.term.set_colour(txt_colour)

	self.term.write("%05d:  " % (res.nres), txt_colour)
	self.term.write("%.3fs   C=" % (res.timer), txt_colour)

	location = ""
	if 'Location' in res.history.headers.response:
	    location = res.history.headers.response['Location']
	elif res.history.url != res.history.redirect_url:
	    location = "(*) %s" % res.history.url

	server = ""
	if 'Server' in res.history.headers.response:
	    server = res.history.headers.response['Server']

	if res.exception:
	    self.term.write("XXX", self.term.get_colour(res.code) if self.colour else ("",8))
	else:
	    self.term.write("%03d" % (res.code), self.term.get_colour(res.code) if self.colour else ("",8))

	self.term.write("   %4d L\t   %5d W\t  %5d Ch  %20.20s  %51.51s   \"%s\"" % (res.lines, res.words, res.chars, server[:17], location[:48], res.description), txt_colour)

	sys.stdout.flush()


    def _print(self, res):
	txt_colour = ("", 8) if not res.is_baseline or not self.colour else (Term.fgCyan, 8)

        self.term.set_colour(txt_colour)

        self.term.write("%05d:  C=" % (res.nres), txt_colour)
	if res.exception:
	    self.term.write("XXX", self.term.get_colour(res.code) if self.colour else ("",8))
	else:
	    self.term.write("%03d" % (res.code), self.term.get_colour(res.code) if self.colour else ("",8))
	self.term.write("   %4d L\t   %5d W\t  %5d Ch\t  \"%s\"" % (res.lines, res.words, res.chars, res.description), txt_colour)

	sys.stdout.flush()

    def header(self, summary):
	print exec_banner
	print "Target: %s\r" % summary.url
	#print "Payload type: " + payloadtype + "\n"
	#print "Total requests:aaaaaaa %d\r\n" % summary.total_req
	if summary.total_req > 0:
	    print "Total requests: %d\r\n" % summary.total_req
	else:
		print "Total requests: <<unknown>>\r\n"

        if self.verbose:
            print "==============================================================================================================================================\r"
            print "ID	C.Time   Response   Lines      Word         Chars                  Server                                             Redirect   Payload    \r"
            print "==============================================================================================================================================\r\n"
        else:
            print "==================================================================\r"
            print "ID	Response   Lines      Word         Chars          Request    \r"
            print "==================================================================\r\n"

    def result(self, res):
        self.term.delete_line()

        if self.verbose:
            self._print_verbose(res)
        else:
            self._print(res)

        if res.is_visible: 
            sys.stdout.write("\n\r")

            for i in res.plugins_res:
                print "  |_ %s\r" % i.issue

    def footer(self, summary):
        self.term.delete_line()
	sys.stdout.write("\r\n")

	print "Total time: %s\r" % str(summary.totaltime)[:8]

	if summary.backfeed > 0:
	    print "Processed Requests: %s (%d + %d)\r" % (str(summary.processed)[:8], (summary.processed - summary.backfeed), summary.backfeed)
	else:
	    print "Processed Requests: %s\r" % (str(summary.processed)[:8])
	print "Filtered Requests: %s\r" % (str(summary.filtered)[:8])
	print "Requests/sec.: %s\r\n" % str(summary.processed/summary.totaltime if summary.totaltime > 0 else 0)[:8]

@moduleman_plugin("header", "footer", "result")
class json:
    name = "json"
    description = "Results in json format"
    category = ["default"]
    priority = 99

    json_res = []

    def header(self, res):
        pass

    def result(self, res):
	server = ""
	if 'Server' in res.history.headers.response:
	    server = res.history.headers.response['Server']
	location = ""
	if 'Location' in res.history.headers.response:
	    location = res.history.headers.response['Location']
	elif res.history.url != res.history.redirect_url:
	    location = "(*) %s" % res.history.url
        post_data = {}
	if res.history.method.lower() == "post":
	    for n, v in res.history.parameters.post.items():
                post_data[n] = v

        res_entry = {"lines": res.lines, "words": res.words, "chars" : res.chars, "url":res.url, "description":res.description, "location" : location, "server" : server, "server" : server, "postdata" : post_data}
        self.json_res.append(res_entry)

    def noresult(self, res):
        pass
    def footer(self, summary):
        print jjson.dumps(self.json_res)



@moduleman_plugin("header", "footer", "result")
class raw:
    name = "raw"
    description = "Raw output format"
    category = ["default"]
    priority = 99

    def header(self, summary):
	print exec_banner
	print "Target: %s\r" % summary.url
	#print "Payload type: " + payloadtype + "\n"
	print "Total requests: %d\r\n" % summary.total_req
	print "==================================================================\r"
	print "ID	Response   Lines      Word         Chars          Payload    \r"
	print "==================================================================\r\n"

    def result(self, res):
	if res.exception:
	    sys.stdout.write("XXX")
	else:
	    sys.stdout.write("%05d:  C=%03d" % (res.nres, res.code))

	sys.stdout.write("   %4d L\t   %5d W\t  %5d Ch\t  \"%s\"\r\n" % (res.lines, res.words, res.chars, res.description))

	for i in res.plugins_res:
		print "  |_ %s\r" % i.issue


    def footer(self, summary):
	print "\r\n"

	print "Total time: %s\r" % str(summary.totaltime)[:8]

	if summary.backfeed > 0:
	    print "Processed Requests: %s (%d + %d)\r" % (str(summary.processed)[:8], (summary.processed - summary.backfeed), summary.backfeed)
	else:
	    print "Processed Requests: %s\r" % (str(summary.processed)[:8])
	print "Filtered Requests: %s\r" % (str(summary.filtered)[:8])
	print "Requests/sec.: %s\r\n" % str(summary.processed/summary.totaltime if summary.totaltime > 0 else 0)[:8]
