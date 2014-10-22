import socket
import sys
from xml.dom import minidom

class printer_magictree:
    text = "magictree"

    def __init__(self):
	self.node_mt = None
	self.node_service = None

    def create_xml_element(self, parent, caption, text):
	# Create a <xxx> element
	doc = minidom.Document()
	el = doc.createElement(caption)
	parent.appendChild(el)

	# Give the <xxx> element some text
	ptext = doc.createTextNode(text)

	el.appendChild(ptext)
	return el

    def header(self, request):
	doc = minidom.Document()

	#<magictree class="MtBranchObject">
	self.node_mt = doc.createElement("magictree") 
	self.node_mt.setAttribute("class", "MtBranchObject")

	#<testdata class="MtBranchObject">
	node_td = doc.createElement("testdata") 
	node_td.setAttribute("class", "MtBranchObject")
	self.node_mt.appendChild(node_td)

	#<host>209.85.146.105
	host = request["Host"]
	if host.find(":") > 0:
	    host, port = host.split(":")
	else:
	    port = 80
	    if request.schema.lower() == "https":
		port = 443

	try:
	    resolving = socket.gethostbyname(host)
	    node_h = self.create_xml_element(node_td, "host", str(resolving))
	except socket.gaierror:
	    node_h = self.create_xml_element(node_td, "host", str(host))

	#<ipproto>tcp
	node_ipr = self.create_xml_element(node_h, "ipproto", "tcp")

	#<port>80<state>open</state><service>http
	node_port = self.create_xml_element(node_ipr, "port", str(port))
	self.create_xml_element(node_port, "state", "open")
	if request.schema.lower() == "https":
	    node_port = self.create_xml_element(node_port, "tunnel", "ssl")

	self.node_service = self.create_xml_element(node_port, "service", "http")

    def result(self, nreq, fuzz_result, request):
	node_url = self.create_xml_element(self.node_service, "url", str(request.completeUrl))

	if fuzz_result.server:
	    self.create_xml_element(node_url, "HTTPServer", fuzz_result.server)

	if fuzz_result.code == 301 or fuzz_result.code == 302 and fuzz_result.location:
	    self.create_xml_element(node_url, "RedirectLocation", fuzz_result.location)

	self.create_xml_element(node_url, "ResponseCode", str(fuzz_result.code))
	self.create_xml_element(node_url, "source", "WFuzz")

    def footer(self):
	sys.stderr.write(self.node_mt.toxml())

    def error(self, nreq, request):
	pass

class printer_html:
    text = "html"

    def header(self, request):
	url = request.completeUrl

	sys.stderr.write("<html><head></head><body bgcolor=#000000 text=#FFFFFF><h1>Fuzzing %s</h1>\r\n<table border=\"1\">\r\n<tr><td>#request</td><td>Code</td><td>#lines</td><td>#words</td><td>Url</td></tr>\r\n" % (url) )

    def result(self, nreq, fuzz_result, request):
	htmlc="<font>"

	if fuzz_result.code >= 400 and fuzz_result.code < 500:
	    htmlc = "<font color=#FF0000>"
	elif fuzz_result.code>=300 and fuzz_result.code < 400:
	    htmlc = "<font color=#8888FF>"
	elif fuzz_result.code>=200 and fuzz_result.code < 300:
	    htmlc = "<font color=#00aa00>"

	if request.method.lower() == "get":
	    sys.stderr.write("\r\n<tr><td>%05d</td><td>%s%d</font></td><td>%4dL</td><td>%5dW</td><td><a href=%s>%s</a></td></tr>\r\n" %(nreq,htmlc,fuzz_result.code,fuzz_result.lines,fuzz_result.words,request.completeUrl,request.completeUrl))
	else:
	    inputs=""
	    postvars = request.variablesPOST()
	    for i in postvars:
		inputs+="<input type=\"hidden\" name=\"%s\" value=\"%s\">" % (i, request.getVariablePOST(i))

	    sys.stderr.write ("\r\n<tr><td>%05d</td>\r\n<td>%s%d</font></td>\r\n<td>%4dL</td>\r\n<td>%5dW</td>\r\n<td><table><tr><td>%s</td><td><form method=\"post\" action=\"%s\">%s<input type=submit name=b value=\"send POST\"></form></td></tr></table></td>\r\n</tr>\r\n" %(nreq,htmlc,fuzz_result.code,fuzz_result.lines,fuzz_result.words,request.description,request.completeUrl,inputs))

    def footer(self):
	sys.stderr.write("</table></body></html><h5>Wfuzz by EdgeSecurity<h5>\r\n")
	sys.stdout.flush()

    def error(self, nreq, request):
	sys.stderr.write ("\r\n<tr><td>%05d</td><td>XXX</td><td>%4dL</td><td>%5dW</td><td><a href=%s>%s</a></td></tr>\r\n" %(nreq,0,0,request.completeUrl,"Error in "+request.completeUrl))
