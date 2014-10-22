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
from encoders import *
from payloads import *
from dictio import dictionary
import re
import hashlib

ENCODERS={}
encs=dir(encoders)
for i in encs:
	try:
		if i[:8]=='encoder_':
			ENCODERS[getattr(encoders,i).text.lower()]=i
	except:
		pass

# Generate_fuzz evolution
class requestGenerator:
	def __init__(self,reqresp,varsSet,dictio,dictio2=None,proxy=None):

		self.reqsgenerated=0

		self.request=reqresp
		self.proxy=proxy
		self.allvars=False
		self.allpost=False
		self.allheaders=False
		self.final=False
		self.child=None

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

		self.dictio=dictionary(dictio)
		if dictio2:
			self.dictio2=dictionary(dictio2)
		else:
			self.dictio2=None

		self.currentDictio1=None

		self.currentVarSet=0

	def count (self):
		sr=0
		if self.child:
			sr=self.child.count()
		if self.allvars or self.allpost or self.allheaders:
			return self.dictio.count()*len( self.varSET)+sr
		elif not self.dictio2:
			return self.dictio.count()+sr
		else:
			return self.dictio.count()*self.dictio2.count()+sr

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
		if self.dictio2:
			self.dictio2.restart()
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
			if self.dictio2:
				if not self.currentDictio1:
					self.currentDictio1=self.dictio.next()
				try:
					self.currentDictio2=self.dictio2.next()
				except :
					self.currentDictio1=self.dictio.next()
					self.dictio2.restart()
					self.currentDictio2=self.dictio2.next()
				self.reqsgenerated+=1
				return self.generate_request(self.request,self.currentDictio1,self.currentDictio2)
	
			elif self.allvars or self.allpost or self.allheaders:
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
				return self.generate_request(self.request,self.currentDictio1,"",var)
				
			else:
				self.reqsgenerated+=1
				return self.generate_request(self.request,self.dictio.next())
		except Exception,e:
			if self.child:
				return self.child.next()
			else:
				self.final=True
				raise e
		

	def generate_request(self,req,payload1,payload2="",variable=""):
		if self.allvars==True:
			copycat=copy.deepcopy(req)
			copycat.setProxy(self.proxy)
			copycat.addVariableGET(variable,payload1)
			copycat.description=variable + "=" + payload1
			return copycat
			
		elif self.allpost==True:
			copycat=copy.deepcopy(req)
			copycat.setProxy(self.proxy)
			copycat.addVariablePOST(variable,payload1)
			copycat.description=variable + "=" + payload1
			return copycat

		elif self.allheaders==True:
			copycat=copy.deepcopy(req)
			copycat.setProxy(self.proxy)
			copycat.addHeader(variable,payload1)
			copycat.description=variable + "=" + payload1
			return copycat

		else:
			rawReq=req.getAll()
			schema=req.schema
			method,userpass=req.getAuth()

			if rawReq.count('FUZZ'):
				a=Request()
				res=rawReq.replace("FUZZ",payload1)
				if rawReq.count('FUZ2Z'):
					res=res.replace("FUZ2Z",payload2)
				a.parseRequest(res,schema)
				temp=a.completeUrl
				#a.setUrl(temp.replace("FUZZ",payload1))
			#	a.completeUrl=self.request.completeUrl.replace("FUZZ",payload1)
				if self.request.completeUrl.count("FUZ2Z"):
					a.setUrl(temp.replace("FUZ2Z",payload2))
					#a.completeUrl=a.completeUrl.replace("FUZ2Z",payload2)

				if self.request.description:
					a.description=self.request.description+"/"+payload1
				else:
					a.description=payload1
				if rawReq.count('FUZ2Z'):
					a.description+=" - "+payload2
				if method != 'None':
					a.setAuth(method,userpass)
				a.setProxy(self.proxy)
				return a

			elif method and (userpass.count('FUZZ') ):
				copycat=copy.deepcopy(req)
				userpass=userpass.replace("FUZZ",payload1)
				if userpass.count('FUZ2Z'):
						userpass=userpass.replace("FUZ2Z",payload2)
				copycat.setAuth(method,userpass)
				copycat.description=userpass
				copycat.setProxy(self.proxy)
				return copycat
				
			else:
				return req


class FuzzResult:

	def __init__(self,request,saveMemory=True):

		global OS

		#######################################
		self.len=0
		self.lines=0
		self.words=0
		self.code=0
		self.md5=""
		
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
		import time
		while i:
			try:
			
				#time.sleep(0.1)
				starttime=time.time()	
				request.perform()
				stoptime=time.time()	
				diff=stoptime-starttime	
				break
			except :
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

				if html:
					sys.stderr.write ("\r\n<tr><td>%05d</td><td>XXX</td><td>%4dL</td><td>%5dW</td><td><a href=%s>%s</a></td></tr>\r\n" %(nreq,0,0,request.completeUrl,"Error in "+request.completeUrl))
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
		else:
			self.location=""
		m=hashlib.md5()
		m.update(request.response.getContent())

		self.md5=m.hexdigest()


		if __name__=="__main__":


			if str(self.code) in hidecodes or str(self.lines) in hidelines or str(self.words) in hidewords or str(self.len) in hidechars:
				fl=""
			else:
				fl="\r\n"
			nreq+=1
			
			imprimeResult (nreq,self.code,self.lines,self.words,request.description[-50:],fl,self.len)
			del request

			if html:
				if str(self.code) in hidecodes or str(self.lines) in hidelines or str(self.words) in hidewords or str(self.len) in hidechars:
					return
				imprimeResultHtml (nreq,self.code,self.lines,self.words,request,self.len)


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



#####################################################################################################
#####################################################################################################
#####################################################################################################


class Fuzzer:
	def __init__(self,genreq,ignore,threads=20):
		self.genReq=genreq
		self.results=[]
		self.threads=threads
		self.run=True
		self.threads_list=[]
		self.nres=0
		self.mutex=1
		self.Semaphore_Mutex=threading.BoundedSemaphore(value=self.mutex)
		self.ignore=ignore

	def count (self):
		return self.genReq.count()

	def Launch (self):
		for i in range (0,self.threads):
			th=threading.Thread(target=self.attack, kwargs={})
			th.start()
			self.threads_list.append(th)

	def attack (self):
		rq=self.getNewReq()
		while rq and self.run:
			try :
				res=FuzzResult(rq,False)
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


def imprimeResult (nreq,code,lines,words,fuzzs,finalLine,len):
	global printMutex

	printMutex.acquire()
	
	limpialinea()
	sys.stdout.write ("%05d:  C=" % (nreq) ) 

	cc=""
	wc=8
	if code>=400 and code<500:
		if color:
			cc="\x1b[31m"
			wc=12
	elif code>=300 and code<400:
		if color:
			cc="\x1b[36m"
			wc=11
	elif code>=200 and code<300:
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


	sys.stdout.write ("%03d" % (code)) 
	
	if OS!='nt':
		sys.stdout.write ("\x1b[37m")
	else:
		WConio.textcolor(8)
		
	sys.stdout.write ("   %4d L\t   %5d W\t  %5d Ch\t  \"%s\"%s" %(lines,words,len,fuzzs,finalLine))
	
	sys.stdout.flush()


	printMutex.release()

def limpialinea():
	sys.stdout.write ("\r")
	if OS!='nt':
		sys.stdout.write ("\x1b[0K")
	else:
		WConio.clreol()

def imprimeResultHtml (nreq,code,lines,words,req):
	
	htmlc="<font>"
	if code>=400 and code<500:
			htmlc="<font color=#FF0000>"
	elif code>=300 and code<400:
			htmlc="<font color=#8888FF>"
	elif code>=200 and code<300:
			htmlc="<font color=#00aa00>"

	if req.method.lower()=="get":
		sys.stderr.write ("\r\n<tr><td>%05d</td><td>%s%d</font></td><td>%4dL</td><td>%5dW</td><td><a href=%s>%s</a></td></tr>\r\n" %(nreq,htmlc,code,lines,words,req.completeUrl,req.completeUrl))
	else:
		inputs=""
		postvars=req.variablesPOST()
		for i in postvars:
			inputs+="<input type=\"hidden\" name=\"%s\" value=\"%s\">" % (i,req.getVariablePOST(i))

		sys.stderr.write ("\r\n<tr><td>%05d</td>\r\n<td>%s%d</font></td>\r\n<td>%4dL</td>\r\n<td>%5dW</td>\r\n<td><table><tr><td>%s</td><td><form method=\"post\" action=\"%s\">%s<input type=submit name=b value=\"send POST\"></form></td></tr></table></td>\r\n</tr>\r\n" %(nreq,htmlc,code,lines,words,req.description,req.completeUrl,inputs))



def select_encoding(typ):
	typ=typ.lower()

	if not typ in ENCODERS:
		print typ+" encoding does not exists (-e help for a list of available encodings)" 
		sys.exit(-1)

	return getattr (encoders,ENCODERS[typ])()


if __name__=="__main__":

	color=False
	hidecodes=[]
	hidewords=[]
	hidelines=[]
	hidechars=[]
	ths=20
	postdata=False
	html=False
	postdata_data=""
	nreq=0

	rlevel=0
	current_depth=0

	banner='''
*************************************
* Wfuzz  1.4c - The Web Bruteforcer *
* Coded by:                         *
* Christian Martorella              *
*   - cmartorella@edge-security.com *
* Carlos del ojo                    *
*   - deepbit@gmail.com             *
*************************************
'''
	usage='''
Usage: %s [options] <url>\r\n
Options:
-c	    : Output with colors
-x addr		: use Proxy (ip:port)
-d postdata 	: Use post data (ex: "id=FUZZ&catalogue=1")
-H headers  	: Use headers (ex:"Host:www.mysite.com,Cookie:id=1312321&user=FUZZ")
-z payload type : Specify type of payload (file,range,hexa-range,hexa-rand)
-r N1-N2    	: Specify range limits
-f path     	: Specify file path (comma sepparated, if multiple FUZZ vars)
-t N        	: Specify the number of threads (20 default)
-e encoding 	: Encoding for payload (-e help for a list of encodings)
-b cookie	: Specify a cookie for the requests
-R depth    	: Recursive path discovery
-V alltype  	: All parameters bruteforcing (allvars and allpost). No need for FUZZ keyword.

--basic auth  	: in format "user:pass" or "FUZZ:FUZZ"
--ntlm auth   	: in format "domain\user:pass" or "domain\FUZ2Z:FUZZ"
--digest auth 	: in format "user:pass" or "FUZZ:FUZZ"

--hc N[,N]+ 	: Hide resposnes with the specified[s] code
--hl N[,N]+ 	: Hide responses with the specified[s] number of lines
--hw N[,N]+ 	: Hide responses with the specified[s] number of words
--hh N[,N]+     : Hide responses with the specified[s] number of chars
--html      : Output in HTML format by stderr \r\n

Keyword: FUZZ,FUZ2Z  wherever you put these words wfuzz will replace them by the payload selected. 

Examples in the README.
''' % (sys.argv[0])



	try:
		opts, args = getopt.getopt(sys.argv[1:], "cx:b:e:R:d:z:r:f:t:w:V:H:",['hc=','hh=','hl=','hw=','ntlm=','basic=','digest=','html'])
		optsd=dict(opts)
		if "-e" in optsd:
			if optsd["-e"] == "help":
				print "Available encodings:"
				for i in ENCODERS.keys():
					print " - "+i
				sys.exit(0)
		url=args[0]
		if not "-z" in optsd:
			raise Exception
	except Exception,qw: 
		if str(qw) == "0":
			sys.exit(-1)
		print banner
		print usage
		sys.exit(-1)
	
	if "-c" in optsd:
		color=True

	if "--html" in optsd:
		html=True
	if "--hc" in optsd:
		hidecodes=optsd["--hc"].split(",")
	if "--hw" in optsd:
		hidewords=optsd["--hw"].split(",")
	if "--hl" in optsd:
		hidelines=optsd["--hl"].split(",")
	if "--hh" in optsd:
		hidechars=optsd["--hh"].split(",")

	payloadtype=optsd ["-z"]
	d2=None

	if optsd ["-z"].lower()=="file":
		try:
			list=optsd["-f"].split(",")
		except:
			print banner
			print usage
			print"You need to set the \"-f\" option"
			sys.exit()
		dic1=payload_file(list[0])
		if len (list)==2:
			dic2=payload_file(list[1])
			d2=dictionary()
			d2.setpayload(dic2)
			
	elif optsd ["-z"].lower()=="range":
		dic1=payload_range(optsd["-r"],len(optsd["-r"].split("-")[1]))
	elif optsd ["-z"].lower()=="hexa-range":
		dic1=payload_hexrange(optsd["-r"])
	elif optsd ["-z"].lower()=="hexa-rand":
		dic1=payload_hexrand(optsd["-r"])
	
	else:
		print "Bad argument: -z dicttype : Specify type od dictionary (file,range,hexa-range,hexa-rand)"
		sys.exit (-1)

	d1=dictionary()
	d1.setpayload(dic1)

		
	if "-e" in optsd:
		encodings=optsd["-e"].split(",")
		if len(encodings) == 2:
			
			if len(optsd["-f"].split(",")) == 2:	
				enc=select_encoding(encodings[0])
				print encodings[0] + list[0]
				d1.setencoder(enc)			
				enc=select_encoding(encodings[1])
				print encodings[1] + list[1]
				d2.setencoder(enc)			
			else:
				enc=select_encoding(encodings[0])
				d1.setencoder(enc)			
		elif len(encodings) ==1:	
			enc=select_encoding(encodings[0])
			d1.setencoder(enc)



	a=Request()
	a.setUrl(url)

	if "--basic" in optsd:
		a.setAuth("basic",optsd["--basic"])

	if "--digest" in optsd:
		a.setAuth("digest",optsd["--digest"])

	if "--ntlm" in optsd:
		a.setAuth("ntlm",optsd["--ntlm"])

	if "-d" in optsd:
		a.addPostdata(optsd["-d"])
		print "test"

	if "-b" in optsd:
		a.addHeader("Cookie",optsd["-b"])


	proxy=None
	if "-x" in optsd:
		proxy=optsd["-x"]

	if "-t" in optsd:
		ths=int(optsd["-t"])

	if "-R" in optsd:
		rlevel=int(optsd["-R"])
	
	if "-V" in optsd:
		varset=str(optsd["-V"])
	else:
		varset="None"
	if "-H" in optsd:
		headers=str(optsd["-H"]).split(",")
		for x in headers:
			splitted=x.partition(":")
			a.addHeader(splitted[0],splitted[2])

	rh=requestGenerator(a,varset,d1,d2,proxy)
	
	if html:
		sys.stderr.write("<html><head></head><body bgcolor=#000000 text=#FFFFFF><h1>Fuzzing %s</h1>\r\n<table border=\"1\">\r\n<tr><td>#request</td><td>Code</td><td>#lines</td><td>#words</td><td>Url</td></tr>\r\n" % (url) )

	fz=Fuzzer(rh,hidecodes,ths)

	print banner
	print "Target: " + url
	print "Payload type: " + payloadtype + "\n"
	print "Total requests: " + str(rh.count())

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
	
					for i in results:
						if i.code==200 and i.req.completeUrl[-1]=='/':
							i.req.setUrl(i.req.completeUrl+"FUZZ")
							rhtemp=requestGenerator(i.req,"None",d1,None,proxy)
							rh2.append(rhtemp)
						elif i.code>=300 and i.code<400:
							if i.has_header("Location") and i["Location"][-1]=='/':
								i.req.setUrl(i["Location"]+"FUZZ")
								print i.req
								rhtemp=requestGenerator(i.req,"None",d1,None,proxy)
								rh2.append(rhtemp)
						elif i.code==401:
							if i.req.completeUrl[-1]=='/':
								i.req.setUrl(i.req.completeUrl+"FUZZ")
							else:
								i.req.setUrl(i.req.completeUrl+"/FUZZ")
							rhtemp=requestGenerator(i.req,"None",d1,None,proxy)
							rh2.append(rhtemp)
	
	
					if rh2.moreRequests:
						fz=Fuzzer(rh2,ths)
						print "-------------- Recursion level",current_depth,"---------------"
						print
						fz.Launch()
	
					rlevel-=1
					
					continue
	
				if html:
					sys.stderr.write("</table></body></html><h5>Wfuzz by EdgeSecurity<h5>\r\n")
				sys.exit(0)
	
				
			time.sleep(1)
	except KeyboardInterrupt:
		limpialinea()
		sys.stdout.write("Stopping...\r\n")
		
		fz.stop()

	if html:
		sys.stderr.write("</table></body></html><h5>Wfuzz by EdgeSecurity<h5>\r\n")


	limpialinea()
	sys.stdout.write("\r\n")
