#!/usr/bin/python

#Covered by GPL V2.0

import copy
from reqresp import *
import binascii
import sys
import threading
import getopt
import time
import os
import iterations
import encoders
import payloads
import printers
from dictio import dictionary
import re
import hashlib
import random

from collections import defaultdict

ENCODERS_LIST={}
for i in dir(encoders):
	try:
		if i[:8]=='encoder_':
			ENCODERS_LIST[getattr(encoders,i).text.lower().replace(" ","_")] = i
	except:
		pass

ITERATORS_LIST={}
itera=dir(iterations)
for i in itera:
	try:
		if i[:9]=='iterator_':
			ITERATORS_LIST[getattr(iterations,i).text.lower().replace(" ","_")] = i
	except:
		pass

PAYLOADS_LIST={}
for i in dir(payloads):
	try:
		if i[:8]=='payload_':
			PAYLOADS_LIST[getattr(payloads,i).text.lower().replace(" ","_")] = i
	except:
		pass

PRINTER_LIST={}
for i in dir(printers):
	try:
		if i[:8]=='printer_':
			PRINTER_LIST[getattr(printers,i).text.lower().replace(" ","_")] = i
	except:
		pass

class requestGenerator:
	def __init__(self,reqresp,varsSet,dictio,proxy=None,proxytype=None):
		self.reqsgenerated=0

		self.request=reqresp
		self.proxy=proxy
		if self.proxy!=None:
			if proxy.count("-"):
				self.proxy=proxy.split("-")
			else:
				self.proxy=[proxy]
		self.proxytype=proxytype
		self.allvars=False
		self.allpost=False
		self.allheaders=False
		self.final=False
		self.child=None
		self.request, self.baseline = self.generate_baseline_request(reqresp)

		self.kk=varsSet
		if varsSet=="allvars":
			self.allvars=True
			self.varSET=self.request.variablesGET()
		elif varsSet=="allpost":
			self.allpost=True
			self.varSET=self.request.variablesPOST()
		elif varsSet=="allheaders":
			self.allheaders=True
			self.varSET=self.request.getHeaders()
		elif varsSet!="None":
			raise Exception,"Unknown variable set: "+varsSet


		#################### Importante aqui se guarda un nuevo diccionario, mediante el constructor por copia
		# Esto se hace para que cada diccionario de cada requestGenerator tenga su propio iterador! y no usen
		# todos el mismo :D
		####################

		#REPASAR
		#self.dictio = dictionary(dictio)
		self.dictio = dictio

		self.currentDictio1=None

		self.currentVarSet=0

	def count (self):
		sr=0
		if self.child:
			sr=self.child.count()
		if self.allvars or self.allpost or self.allheaders:
			return self.dictio.count()*len( self.varSET)+sr
		else:
		    return self.dictio.count()+sr

	def append (self,rg):
		if self.child:
			self.child.append(rg)
		else:
			self.child=rg

	def __iter__ (self):
		self.restart()
		return self

	def restart (self):
		self.dictio.restart()
		self.final=False

		if self.child:
			self.child.restart()

	def moreRequests (self):
		if not self.child:
			return not self.final
		else:
			return self.final or self.child.moreRequests()

	def generated(self):
		return self.reqsgenerated

	def next (self):
		try :
			if self.allvars or self.allpost or self.allheaders:
				if not self.varSET:
					raise StopIteration
			
				if not self.currentDictio1:
					self.currentDictio1=self.dictio.next()
	
				if self.currentVarSet>=len(self.varSET):
					self.currentDictio1=self.dictio.next()
					self.currentVarSet=0
				
				var=self.varSET[self.currentVarSet]
				self.currentVarSet+=1

				self.reqsgenerated+=1
				return self.generate_request(self.request,self.currentDictio1,var)
				
			else:
				self.reqsgenerated+=1
				return self.generate_request(self.request,self.dictio.next())
		except Exception,e:
			if self.child:
				return self.child.next()
			else:
				self.final=True
				raise e

	def generate_baseline_request(self, req):
	    schema = req.schema
	    rawReq = req.getAll()

	    baseline_marker = re.compile("FUZ\d*Z{(.*?)}",re.MULTILINE|re.DOTALL)
	    payload = baseline_marker.findall(rawReq)

	    if len(payload) == 0:
		return (req, None)

	    # it is not possible to specify baseline value for HTTP method!
	    if fuzzmethods:
		payload = ['GET'] + payload

	    for i in payload:
		rawReq = rawReq.replace("{" + i + "}", '')

	    base_req = Request()
	    base_req.parseRequest(rawReq,schema)
	    base_req.followLocation = req.followLocation
	    base_req.setProxy(self.proxy,self.proxytype)
	    method,userpass=req.getAuth()
	    if fuzzmethods:
		base_req.method = "FUZZ"
	    if method != 'None': base_req.setAuth(method,userpass)

	    return (base_req, self.generate_request(base_req, payload))

		

	def generate_request(self,req,payload,variable=""):
		if self.allvars==True:
			copycat=copy.deepcopy(req)
			copycat.setProxy(self.proxy,self.proxytype)
			copycat.addVariableGET(variable,payload)
			copycat.description=variable + "=" + payload
			return copycat
			
		elif self.allpost==True:
			copycat=copy.deepcopy(req)
			copycat.setProxy(self.proxy,self.proxytype)
			copycat.addVariablePOST(variable,payload)
			copycat.description=variable + "=" + payload
			return copycat

		elif self.allheaders==True:
			copycat=copy.deepcopy(req)
			copycat.setProxy(self.proxy,self.proxytype)
			copycat.addHeader(variable,payload)
			copycat.description=variable + "=" + payload
			return copycat

		else:
			rawReq = req.getAll()
			schema = req.schema
			method,userpass=req.getAuth()
			http_method = None

			newreq=Request()
			newreq.setUrl(req.completeUrl)
			newreq.setPostData(req.postdata)

			rawUrl = newreq.completeUrl

			if self.request.description:
			    newreq.description = self.request.description
			else:
			    newreq.description = ""

			for i, payload1 in enumerate(payload, start=1):
			    fuzz_word = "FUZZ"
			    if i > 1:
				fuzz_word = "FUZ" + str(i) + "Z"

			    if fuzzmethods and fuzz_word == "FUZZ":
				http_method = payload1
				newreq.description += " - " + payload1
			    elif method and (userpass.count(fuzz_word)):
				userpass=userpass.replace(fuzz_word,payload1)
				newreq.description += " - " + payload1
			    elif newreq.completeUrl.count(fuzz_word):
				rawUrl = rawUrl.replace(fuzz_word,payload1)
				newreq.description += " - " + payload1
			    elif rawReq.count(fuzz_word):
				rawReq=rawReq.replace(fuzz_word,payload1)
				newreq.description += " - " + payload1
			    else:
				req.description = "No %s word!" % fuzz_word
				return req

			newreq.parseRequest(rawReq,schema)
			newreq.setUrl(rawUrl)
			newreq.followLocation = req.followLocation
			if self.proxy!=None:
				random.shuffle(self.proxy)
				newreq.setProxy(self.proxy[0],self.proxytype)
			if http_method: newreq.method = http_method
			if method != 'None': newreq.setAuth(method,userpass)
			return newreq

				


class FuzzResult:

	def __init__(self,request,sleeper,saveMemory=True):

		global OS

		#######################################
		self.len=0
		self.lines=0
		self.words=0
		self.code=0
		self.md5=""
		self.sleeper=sleeper
		
		### Used only when saveMemory = False
		self.respHeaders=[]
		self.html=""
		self.rawrequest=""
		self.completeUrl=""
		self.descrip=request.description
		########################################
		request.setConnTimeout(10)
		request.setTotalTimeout(10)
		i=5
		x=True
		while i:
			try:
				time.sleep(self.sleeper)
				starttime=time.time()	
				request.perform()
				stoptime=time.time()	
				diff=stoptime-starttime	
				break
			except Exception,e:
				#print e
				i-=1
				x=False
		if not i:
			if __name__=="__main__":
				global nreq
				nreq+=1
				limpialinea()
				if "XXX" in hidecodes:
					pass
				else:
					sys.stdout.write ("%05d: C=XXX %4d L\t   %5d W\t %s\r\n" %(nreq,0,0,"Error in "+request.description[-50:]))
					sys.stdout.flush()

				if printer_tool: printer_tool.error(nreq, request)
				raise a
			return 


		if not saveMemory:
			self.completeUrl=request.completeUrl
			self.req=request
			self.respHeaders=request.response.getHeaders()
		self.len=len(request.response.getContent())
		self.lines=request.response.getContent().count("\n")
		self.words=len(re.findall("\S+",request.response.getContent()))
		self.code=int(request.response.code)
		self.timer=str(diff)[:8]
		self.timestamp=time.strftime('%X',time.gmtime(starttime))
		self.cookie=request.response.getCookie()
		if request.response.has_header('Location'):
			self.location=request.response['Location']
		elif request.followLocation and request.follow_url:
			self.location="(*) %s" % request.follow_url
		else:
			self.location=""

		if request.response.has_header("Server"):
			self.server = request.response["Server"]
		else:
			self.server = ""

		m=hashlib.md5()
		m.update(request.response.getContent())

		self.md5=m.hexdigest()

		if __name__=="__main__":
			if str(self.code) in hidecodes or str(self.lines) in hidelines or str(self.words) in hidewords or str(self.len) in hidechars \
			    or (hideregex and hideregex.search(request.response.getContent())):
				fl=""
			else:
				fl="\r\n"
				if printer_tool: printer_tool.result(nreq, self, request)

			nreq+=1
			self.imprimeResult(nreq,request.description[-50:],fl)

			del request

	def __getitem__ (self,key):
		for i,j in self.respHeaders:
			if key==i:
				return  j
		print "Error al obtener header!!!"


	def has_header (self,key):
		for i,j in self.respHeaders:
			if i==key:
				return True
		return False


	def imprimeResult(self, nreq,fuzzs,finalLine):
		global printMutex

		printMutex.acquire()
		
		limpialinea()
		sys.stdout.write ("%05d:  C=" % (nreq) ) 

		cc=""
		wc=8
		if self.code>=400 and self.code<500:
			if color:
				cc="\x1b[31m"
				wc=12
		elif self.code>=300 and self.code<400:
			if color:
				cc="\x1b[36m"
				wc=11
		elif self.code>=200 and self.code<300:
			if color:
				cc="\x1b[32m"
				wc=10
		else:
			if color:
				cc="\x1b[35m"
				wc=1
		if OS!='nt':
			sys.stdout.write (cc)
		else:
			WConio.textcolor(wc)


		sys.stdout.write ("%03d" % (self.code)) 
		
		if color:
		    if OS!='nt':
			    sys.stdout.write ("\x1b[37m")
		    else:
			    WConio.textcolor(8)
			
		if verbose:
		    sys.stdout.write ("   %4d L\t   %5d W\t  %5d Ch  %20.20s  %51.51s   \"%s\"%s" % (self.lines,self.words,self.len,self.server[:17],self.location[:48],fuzzs,finalLine))
		else:
		    sys.stdout.write ("   %4d L\t   %5d W\t  %5d Ch\t  \"%s\"%s" %(self.lines,self.words,self.len,fuzzs,finalLine))
		
		sys.stdout.flush()


		printMutex.release()

#####################################################################################################
#####################################################################################################
#####################################################################################################


class Fuzzer:
	def __init__(self,genreq,ignore,sleeper,threads=20):
		self.genReq=genreq
		self.results=[]
		self.threads=threads
		self.run=True
		self.threads_list=[]
		self.nres=0
		self.mutex=1
		self.Semaphore_Mutex=threading.BoundedSemaphore(value=self.mutex)
		self.ignore=ignore
		self.sleeper=sleeper

	def count (self):
		return self.genReq.count()

	def Launch (self):
		# baseline request
		rq=self.genReq.baseline
		if rq:
		    try:
			res=FuzzResult(rq,False)

			if "BBB" in hidelines:
			    hidelines.append(str(res.lines))
			if "BBB" in hidecodes:
			    hidecodes.append(str(res.code))
			if "BBB" in hidewords:
			    hidewords.append(str(res.words))
			if "BBB" in hidechars:
			    hidechars.append(str(res.len))
			self.agregaresultado(res)
		    except :
			    pass

		for i in range (0,self.threads):
			th=threading.Thread(target=self.attack, kwargs={})
			th.start()
			self.threads_list.append(th)

	def attack (self):
		rq=self.getNewReq()
		while rq and self.run:
			try :
				res=FuzzResult(rq,self.sleeper,False)
				#if (str(res.code) not in self.ignore):
				self.agregaresultado(res)
			except :
				pass
			rq=self.getNewReq()

	def agregaresultado (self,res):
		self.Semaphore_Mutex.acquire()
		self.results.append(res)
		self.nres+=1
		self.Semaphore_Mutex.release()

 	def numResults (self):
		nres=len(self.results)
		return self.nres
    
	def getResult(self,n):
		return self.results[n]

	def getResults(self):
		return self.results

	def getNewReq(self):
		self.Semaphore_Mutex.acquire()
		try:
			res=self.genReq.next()
		except :
			res=None
		self.Semaphore_Mutex.release()
		return res

	def cleanthreads(self):
		if self.genReq.moreRequests():
			return None
		for i in self.threads_list:
			i.join()
		return True

	def stop(self):
		self.run=False
		for i in self.threads_list:
			i.join()

	def resum(self):
		self.run=True
	
	def delete(self):
		del self.results
		self.results=[]
		


#############################################################################################################
#############################################################################################################
#################         INTERFACE CONOSLA                                              ####################
#############################################################################################################
#############################################################################################################


OS=os.name
if OS=="nt":
	import WConio

mutex=1
printMutex=threading.BoundedSemaphore(value=mutex)


def limpialinea():
	sys.stdout.write ("\r")
	if OS!='nt':
		sys.stdout.write ("\x1b[0K")
	else:
		WConio.clreol()

def select_payload(typ):
	typ=typ.lower()

	if not typ in PAYLOADS_LIST:
		print typ+" payload does not exists (-e payloads for a list of available payloads)" 
		sys.exit(-1)

	return getattr(payloads,PAYLOADS_LIST[typ])

def select_iteration(typ):
	typ=typ.lower()

	if not typ in ITERATORS_LIST:
		print typ+" iterator does not exists (-m iterators for a list of available iterators)" 
		sys.exit(-1)

	return getattr(iterations,ITERATORS_LIST[typ])

def select_encoding(typ):
	typ=typ.lower()

	if not typ in ENCODERS_LIST:
		print typ+" encoding does not exists (-e encodings for a list of available encodings)" 
		sys.exit(-1)

	return getattr(encoders,ENCODERS_LIST[typ])()

def select_printer(typ):
	typ=typ.lower()

	if not typ in PRINTER_LIST:
		print typ+" printer does not exists (-e printers for a list of available encodings)" 
		sys.exit(-1)

	return getattr(printers,PRINTER_LIST[typ])()


if __name__=="__main__":

	color=False
	verbose=False
	fuzzmethods=False
	hidecodes=[]
	hidewords=[]
	hidelines=[]
	hidechars=[]
	hideregex=None
	ths=20
	postdata=False
	postdata_data=""
	nreq=0
	sleeper=0

	rlevel=0
	current_depth=0

	banner='''
********************************************************
* Wfuzz  2.0 - The Web Bruteforcer                     *
* Blackhat Arsenal Release                             *
********************************************************
'''
	usage='''Usage: %s [options] <url>\r\n
Options:
-c			    : Output with colors
-v			    : Verbose information
-o printer		    : Output format by stderr

-p addr			    : use Proxy (ip:port or ip:port-ip:port-ip:port)
-x type			    : use SOCK proxy (SOCKS4,SOCKS5)
-t N			    : Specify the number of threads (20 default)
-s N			    : Specify time delay between requests (0 default)

-e <type>		    : List of available encodings/payloads/iterators/printers
-R depth		    : Recursive path discovery
-I			    : Use HTTP HEAD instead of GET method (No HTML body responses). 
--follow		    : Follow redirections

-m iterator		    : Specify iterator (product by default)
-z payload		    : Specify payload (type,parameters,encoding)
-V alltype		    : All parameters bruteforcing (allvars and allpost). No need for FUZZ keyword.

-X			    : Payload within HTTP methods (ex: "FUZZ HTTP/1.0"). No need for FUZZ keyword.
-b cookie		    : Specify a cookie for the requests
-d postdata 		    : Use post data (ex: "id=FUZZ&catalogue=1")
-H headers  		    : Use headers (ex:"Host:www.mysite.com,Cookie:id=1312321&user=FUZZ")

--basic/ntlm/digest auth    : in format "user:pass" or "FUZZ:FUZZ" or "domain\FUZ2Z:FUZZ"

--hc/hl/hw/hh N[,N]+	    : Hide resposnes with the specified[s] code/lines/words/chars (Use BBB for taking values from baseline)
--hs regex		    : Hide responses with the specified regex within the response

Keyword: FUZZ,FUZ2Z  wherever you put these words wfuzz will replace them by the payload selected. 

Example: - wfuzz.py -c -z file,commons.txt --hc 404 -o html http://www.site.com/FUZZ 2> res.html
	 - wfuzz.py -c -z file,users.txt -z file,pass.txt --hc 404 http://www.site.com/log.asp?user=FUZZ&pass=FUZ2Z
	 - wfuzz.py -c -z range,1-10 --hc=BBB http://www.site.com/FUZZ{something}

	   More examples in the README.
''' % (sys.argv[0])



	try:
		opts, args = getopt.getopt(sys.argv[1:], "IXvcx:b:e:R:d:z:r:f:t:w:V:H:m:o:s:p:",['hc=','hh=','hl=','hw=','hs=','ntlm=','basic=','digest=','follow'])
		optsd=defaultdict(list)
		for i,j in opts:
			optsd[i].append(j)

		if "-e" in optsd:
			if "payloads" in optsd["-e"]:
				print "Available payloads:"
				for i in PAYLOADS_LIST.keys():
					print " - "+i
				sys.exit(0)
			if "encodings" in optsd["-e"]:
				print "Available encodings:"
				for i in ENCODERS_LIST.keys():
					print " - "+i
				sys.exit(0)
			if "iterators" in optsd["-e"]:
				print "Available iterators:"
				for i in ITERATORS_LIST.keys():
					print " - "+i
				sys.exit(0)
			if "printers" in optsd["-e"]:
				print "Available printers:"
				for i in PRINTER_LIST.keys():
					print " - "+i
				sys.exit(0)
			else:
			    raise Exception
		if "-m" in optsd:
			if "help" in optsd["-m"]:
				print "Available iterators:"
				for i in ITERATORS_LIST.keys():
					print " - " + i
				sys.exit(0)
		url=args[0]
		if not "-z" in optsd.keys():
			raise Exception
	except Exception,qw: 
		if str(qw) == "0":
			sys.exit(-1)
		print banner
		print usage
		sys.exit(-1)
	
	if "-X" in optsd:
		fuzzmethods=True

	if "-v" in optsd:
		verbose=True

	if "-c" in optsd:
		color=True
	if "-s" in optsd:
		sleeper=float(optsd["-s"][0])
	if "--magictree" in optsd:
		magictree=True
	if "--html" in optsd:
		html=True
	if "--hc" in optsd:
		hidecodes=optsd["--hc"][0].split(",")
	if "--hw" in optsd:
		hidewords=optsd["--hw"][0].split(",")
	if "--hl" in optsd:
		hidelines=optsd["--hl"][0].split(",")
	if "--hh" in optsd:
		hidechars=optsd["--hh"][0].split(",")
	if "--hs" in optsd:
		hideregex=re.compile(optsd["--hs"][0],re.MULTILINE|re.DOTALL)

	payloadtype='; '.join(optsd["-z"])

	selected_dic = []
	if "-z" in optsd:
	    for i in optsd["-z"]:
		vals = i.split(",")
		t, par = vals[:2]
		p = select_payload(t)(par)

		d = dictionary()
		d.setpayload(p)
		if len(vals) == 3:
		    encoding = vals[2]
		    d.setencoder([select_encoding(i).encode for i in encoding.split("@")])

		selected_dic.append(d)

	printer_tool = None
	if "-o" in optsd:
	    printer_tool = select_printer(optsd['-o'][0])

	if "-m" in optsd:
	    iterat_tool = select_iteration(optsd['-m'][0])
	else:
	    iterat_tool = select_iteration('product')
	    
	dic = iterat_tool(*selected_dic)
		
	a=Request()
	a.setUrl(url)

	if "-I" in optsd:
	    a.method="HEAD"

	if "--basic" in optsd:
		a.setAuth("basic",optsd["--basic"][0])

	if "--digest" in optsd:
		a.setAuth("digest",optsd["--digest"][0])

	if "--ntlm" in optsd:
		a.setAuth("ntlm",optsd["--ntlm"][0])

	if "-d" in optsd:
		a.setPostData(optsd["-d"][0])

	if "--follow" in optsd:
		a.followLocation = True

	if "-b" in optsd:
		a.addHeader("Cookie",optsd["-b"][0])


	proxy=None
	proxytype=None
	if "-p" in optsd:
		proxy=optsd["-p"][0]
	if "-x" in optsd:
		proxytype=optsd["-x"][0]	
		if proxytype not in ("SOCKS5","SOCKS4"):
			print usage
			sys.exit()
	if "-t" in optsd:
		ths=int(optsd["-t"][0])

	if "-R" in optsd:
		rlevel=int(optsd["-R"][0])
	
	if "-V" in optsd:
		varset=str(optsd["-V"][0])
	else:
		varset="None"
	if "-H" in optsd:
		headers=str(optsd["-H"][0]).split(",")
		for x in headers:
			splitted=x.partition(":")
			a.addHeader(splitted[0],splitted[2])

	rh=requestGenerator(a,varset,dic,proxy,proxytype)
	
	if printer_tool:
	    printer_tool.header(a)

	fz=Fuzzer(rh,hidecodes,sleeper,ths)

	print banner
	print "Target: " + url
	print "Payload type: " + payloadtype + "\n"
	print "Total requests: " + str(rh.count())

	if verbose:
	    print "========================================================================================================================================="
	    print "ID	Response   Lines      Word         Chars                  Server                                             Redirect   Request    "
	    print "=========================================================================================================================================\r\n"
	else:
	    print "=================================================================="
	    print "ID	Response   Lines      Word         Chars          Request    "
	    print "==================================================================\r\n"
	fz.Launch()
	try:
		while True:
			if fz.cleanthreads():
				limpialinea()
				print "\r\n"
	
				if rlevel:
	
					current_depth+=1
					results=fz.results

					voidDicc=dictionary()
					rh2=requestGenerator(Request(),"None",voidDicc)

					# REPASAR
					for i in selected_dic:
					    i.restart() # pq no se llama iter() automaticamente
					dic=iterat_tool(*selected_dic)#dictionary()

					for i in results:
						if i.code==200 and i.req.completeUrl[-1]=='/':
							i.req.setUrl(i.req.completeUrl+"FUZZ")
							rhtemp=requestGenerator(i.req,"None",dic,proxy,proxytype)
							rh2.append(rhtemp)
						if i.code==200 and i.req.followLocation and i.req.follow_url and i.req.follow_url[-1]=='/':
							i.req.setUrl(i.req.follow_url+"FUZZ")
							rhtemp=requestGenerator(i.req,"None",dic,proxy,proxytype)
							rh2.append(rhtemp)
						elif i.code>=300 and i.code<400:
							if i.has_header("Location") and i["Location"][-1]=='/':
								i.req.setUrl(i["Location"]+"FUZZ")
								rhtemp=requestGenerator(i.req,"None",dic,proxy,proxytype)
								rh2.append(rhtemp)
						elif i.code==401:
							if i.req.completeUrl[-1]=='/':
								i.req.setUrl(i.req.completeUrl+"FUZZ")
							else:
								i.req.setUrl(i.req.completeUrl+"/FUZZ")
							rhtemp=requestGenerator(i.req,"None",dic,None,proxy,proxytype)
							rh2.append(rhtemp)
	
	
					if rh2.moreRequests:
						fz=Fuzzer(rh,hidecodes,sleeper,ths)
						print "-------------- Recursion level",current_depth,"---------------"
						print
						fz.Launch()
	
					rlevel-=1
					
					continue
	
				if printer_tool: printer_tool.footer()
				sys.exit(0)
	
			time.sleep(1)
	except KeyboardInterrupt:
		limpialinea()
		sys.stdout.write("Stopping...\r\n")
		
		fz.stop()

	if printer_tool: printer_tool.footer()
	limpialinea()
	sys.stdout.write("\r\n")
