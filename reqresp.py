#Covered by GPL V2.0
#Coded by Carlos del Ojo Elias (deepbit@gmail.com)


from urlparse import *
from time import gmtime, strftime
import pycurl
import gzip
import StringIO
import string
import re
import threading
from time import localtime, strftime

from xml.dom.minidom import Document

try:
	from TextParser import *
except:
	pass

mutex=1
Semaphore_Mutex=threading.BoundedSemaphore(value=mutex)
REQLOG=False


class Request:

	def __init__ (self):

		self.__host=None	  		# www.google.com:80
		self.__path=None			# /index.php
		self.__params=None			# Mierdaza de index.php;lskjflkasjflkasjfdlkasdf?
		self.schema="http" 			# http

		##### Variables calculadas por getters NO SE PUEDEN MODIFICAR
		# self.urlWithoutPath                    # http://www.google.es
		# self.pathWithVariables    	         	# /index.php?a=b&c=d
		# self.urlWithoutVariables=None 	 		# http://www.google.es/index.php
		# self.completeUrl=""					# http://www.google.es/index.php?a=b
		# self.postdata=""		# Datos por POST, toto el string
		################

		self.ContentType="application/x-www-form-urlencoded"      # None es normal encoding 
		self.boundary="---------------------------D33PB1T0R3QR3SP0B0UND4RY2203"
		self.multiPOSThead={}

		self.__variablesGET={}
		self.__GETorder=[]

		self.__variablesPOST={}
		self.__headers={}		# diccionario, por ejemplo headers["Cookie"]
		
		self.response=None		# Apunta a la response que produce dicha request

		################### lo de debajo no se deberia acceder directamente

		self.time=None    		# 23:00:00
		self.ip=None	   		# 192.168.1.1
		self.method="GET" 		# GET o POST (EN MAYUSCULAS SI PUEDE SER)
		self.protocol="HTTP/1.1"	# HTTP/1.1
		self.__performHead=""
		self.__performBody=""

		self.__authMethod=None
		self.__userpass=""

		self.description=""     # For temporally store imformation

		self.__proxy=None
		self.__timeout=None
		self.__totaltimeout=None

		self.followLocation=False

	def __str__(self):
		str="[ URL: %s" % (self.completeUrl)
		if self.method=="POST":
			str+=" - POST: \"%s\"" % self.postdata
		if "Cookie" in self.__headers:
			str+=" - COOKIE: \"%s\"" % self.__headers["Cookie"]
		str+=" ]"
		return str

	def getXML(self,obj):
		r=obj.createElement("request")
		r.setAttribute("method",self.method)
		url=obj.createElement("URL")
		url.appendChild(obj.createTextNode(self.completeUrl))
		r.appendChild(url)
		if self.method=="POST":
			pd=obj.createElement("PostData")
			pd.appendChild(obj.createTextNode(self.postdata))
			r.appendChild(pd)
		if "Cookie" in self.__headers:
			ck=obj.createElement("Cookie")
			ck.appendChild(obj.createTextNode(self.__headers["Cookie"]))
			r.appendChild(ck)

		return r
		
	
	def __getattr__ (self,name):
		if name=="urlWithoutVariables":
			return urlunparse((self.schema,self.__host,self.__path,'','',''))
		elif name=="pathWithVariables":
			return urlunparse(('','',self.__path,'',self.getVARIABLESstring(self.__variablesGET,self.__GETorder),''))
		elif name=="completeUrl":
			return urlunparse((self.schema,self.__host,self.__path,self.__params,self.getVARIABLESstring(self.__variablesGET,self.__GETorder),''))
		elif name=="urlWithoutPath":
			return "%s://%s" % (self.schema,self.__headers["Host"])
		elif name=="path":
			return self.__path
		elif name=="postdata":
			if self.ContentType=="application/x-www-form-urlencoded":
				return self.getVARIABLESstring(self.__variablesPOST,None)
			elif self.ContentType=="multipart/form-data":
				pd=""
				for i,j in self.__variablesPOST.items():
					pd+="--"+self.boundary+"\r\n"
					pd+="%s\r\n\r\n%s\r\n" % ("\r\n".join(self.multiPOSThead[i]),j)
				pd+="--"+self.boundary+"--\r\n"
				return pd
			else:
				return self.__uknPostData
		else:
			raise AttributeError

	def getVARIABLESstring(self,vars,sort):
		str=[]

		if not sort:
			for i,j in vars.items():
				str.append(i+"="+j)
		else:
			for i in sort:
				str.append(i+"="+vars[i])

		return "&".join(str)


	def readUrlEncodedVariables(self,str):
		dicc=[]

		for i in str.split("&"):
			if i:
				list=i.split("=",1)
				if len (list)==1:
					dicc.append([list[0],""])
				elif len (list)==2:
					dicc.append([list[0],list[1]])



		return dicc

	def setUrl (self, urltmp):

		self.__variablesGET={}

		self.schema,self.__host,self.__path,self.__params,variables,f=urlparse(urltmp)

		self.__headers["Host"]=self.__host.lstrip()

		if len(variables)>0:
			dicc=self.readUrlEncodedVariables(variables)
			[self.addVariableGET(i,j) for i,j in dicc]
			

	def setProxy (self,prox):
		self.__proxy=prox

	def setFollowLocation(self,value):
		self.followLocation=value


	def setConnTimeout (self,time):
		self.__timeout=time

	def setTotalTimeout (self,time):
		self.__totaltimeout=time
############## Autenticacion ###########################
	def setAuth (self,method,string):
		self.__authMethod=method
		self.__userpass=string

	def getAuth (self):
		return self.__authMethod, self.__userpass

############## TRATAMIENTO VARIABLES GET & POST #########################

	def variablesGET(self):
		return self.__variablesGET.keys()

	def variablesPOST(self):
		return self.__variablesPOST.keys()

	def addVariablePOST (self,key,value):
		self.method="POST"
		self.__variablesPOST[key]=value
		self.__headers["Content-Length"]=str(len(self.postdata))

	def addVariableGET (self,key,value):
		if not key in self.__variablesGET:
			self.__GETorder.append(key)
		self.__variablesGET[key]=value

	def getVariableGET (self,key):
		if self.__variablesGET.has_key(str(key)):
			return self.__variablesGET[str(key)]
		else:
			return None

	def getVariablePOST (self,key):
		if self.__variablesPOST.has_key(str(key)):
			return self.__variablesPOST[str(key)]
		else:
			return None

	def setPostData (self,pd):
		self.__variablesPOST={}
		self.method="POST"
		self.parsePOSTDATA(pd)

	def addPostdata (self,str):
		self.method="POST"
		self.postdata=self.postdata+str
		variables=str.split("&")
		for i in variables:
			tmp=i.split("=",1)
			if len(tmp)==2:
				self.addVariablePOST(tmp[0],tmp[1])
			else:
				self.addVariablePOST(tmp[0],'')




############################################################################

	def addHeader (self,key,value):
		k=string.capwords(key,"-")
		if k!="Accept-Encoding":
			self.__headers[k]=value.strip()
	

	def __getitem__ (self,key):
		k=string.capwords(key,"-")
		if self.__headers.has_key(k):
			return self.__headers[k]
		else:
			return ""

	def __getHeaders (self):
		list=[]
		for i,j in self.__headers.items():
			list+=["%s: %s" % (i,j)]
		return list
	
	def getHeaders (self):
		list=[]
		for i,j in self.__headers.items():
			list+=["%s: %s" % (i,j)]
		return list



	def perform(self):
		global REQLOG
		if REQLOG:
			Semaphore_Mutex.acquire()
			f=open("/tmp/REQLOG","a")
			f.write( strftime("\r\n\r\n############################ %a, %d %b %Y %H:%M:%S\r\n", localtime()))
			f.write(self.getAll())
			f.close()
			Semaphore_Mutex.release()


		self.__performHead=""
		self.__performBody=""
		self.__headersSent=""

		conn=pycurl.Curl()
		conn.setopt(pycurl.SSL_VERIFYPEER,False)
		conn.setopt(pycurl.SSL_VERIFYHOST,1)
		conn.setopt(pycurl.URL,self.completeUrl)

		if self.__authMethod or self.__userpass:
			if self.__authMethod=="basic":
				conn.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
			elif self.__authMethod=="ntlm":
				conn.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
			elif self.__authMethod=="digest":
				conn.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_DIGEST)
			conn.setopt(pycurl.USERPWD, self.__userpass)

		if self.__timeout:
			conn.setopt(pycurl.CONNECTTIMEOUT, self.__timeout)
			conn.setopt(pycurl.NOSIGNAL, 1)

		if self.__totaltimeout:
			conn.setopt(pycurl.TIMEOUT, self.__totaltimeout)
			conn.setopt(pycurl.NOSIGNAL, 1)

		conn.setopt(pycurl.WRITEFUNCTION, self.body_callback)
		conn.setopt(pycurl.HEADERFUNCTION, self.header_callback)
		#conn.setopt(pycurl.DEBUGFUNCTION, self.sent_header_callback)
		#conn.setopt(pycurl.VERBOSE, 1)

		if self.__proxy!=None:
			conn.setopt(pycurl.PROXY,self.__proxy)
			if self.__headers.has_key("Proxy-Connection"):
				del self.__headers["Proxy-Connection"]

		conn.setopt(pycurl.HTTPHEADER,self.__getHeaders())
		if self.method=="POST":
			conn.setopt(pycurl.POSTFIELDS,self.postdata)
		conn.perform()

		rp=Response()
		rp.parseResponse(self.__performHead)
		rp.addContent(self.__performBody)

		if self.schema=="https" and self.__proxy:
			self.response=Response()
			self.response.parseResponse(rp.getContent())
		else:
			self.response=rp



		if self.followLocation:
			if self.response.getLocation():
				a=Request()
				url=urlparse(self.response.getLocation())
				if not url[0] or not url[1]:
					sc=url[0]
					h=url[1]
					if not sc:
						sc=self.schema
					if not h:
						h=self.__host
					a.setUrl(urlunparse((sc,h)+url[2:]))
				else:
					a.setUrl(self.response.getLocation())
				a.setProxy(self.__proxy)

				ck=""

				if "Cookie" in self.__headers:
					ck=self.__headers["Cookie"]
				if self.response.getCookie():
					if ck:
						ck+=";"+self.response.getCookie()
					else:
						ck=self.response.getCookie()

				if ck:
					self.addHeader("Cookie",ck)


				a.perform()
				self.response=a.response



	######### ESTE conjunto de funciones no es necesario para el uso habitual de la clase

	def getPostData (self):
		return self.postdata

	def getAll (self):
		"Devuelve el texto de la request completa (lo que escrbirias por telnet"
		pd=self.postdata
		string=str(self.method)+" "+str(self.pathWithVariables)+" "+str(self.protocol)+"\n"
		for i,j in self.__headers.items():
			string+=i+": "+j+"\n"
		string+="\n"+pd

		return string

	##########################################################################

	def sent_header_callback(self,type,data):
		if type==pycurl.INFOTYPE_HEADER_OUT:
			tp=TextParser()
			tp.setSource("string",data)

			while (tp.readUntil("^([^:]+): (.*)$")):
				self.addHeader(tp[0][0],tp[0][1])
		
		

	def header_callback(self,data):
		self.__performHead+=data

	def body_callback(self,data):
		self.__performBody+=data

	def Substitute(self,src,dst):
		a=self.getAll()
		rx=re.compile(src)
		b=rx.sub(dst,a)
		del rx
		self.parseRequest(b,self.schema)

	def parseRequest (self,rawRequest,prot="http"):
		''' Aun esta en fase BETA y por probar'''
		tp=TextParser()
		tp.setSource("string",rawRequest)

		self.__variablesPOST={}
		self.__headers={}		# diccionario, por ejemplo headers["Cookie"]


		tp.readLine()
		try:
			tp.search("(\w+) (.*) (HTTP\S*)")
			self.method=tp[0][0]
			self.protocol=tp[0][2]
		except Exception,a:
			print rawRequest
			raise a

		pathTMP=tp[0][1]
		pathTMP=('','')+urlparse(pathTMP)[2:]
		pathTMP=urlunparse(pathTMP)
	#	print pathTMP
	#	pathTMP=pathTMP.replace("//","/")
		self.time=strftime("%H:%M:%S", gmtime())

		while True:
			tp.readLine()
			if (tp.search("^([^:]+): (.*)$")):
				self.addHeader(tp[0][0],tp[0][1])
			else:
				break

		self.setUrl(prot+"://"+self.__headers["Host"]+pathTMP)

		if self.method.upper()=="POST":

			pd=""
			while tp.readLine(): 
				pd+=tp.lastFull_line


			if "Content-Type" in self.__headers:
				values=self.__headers["Content-Type"].split(";")
				if values[0].strip().lower()=="application/x-www-form-urlencoded":
					self.ContentType=values[0]
				elif values[0].strip().lower()=="multipart/form-data":
					self.ContentType=values[0]
					self.boundary=values[1].split("=")[1].strip()

			self.parsePOSTDATA(pd)


	def parsePOSTDATA(self,pd):

		if self.ContentType=="application/x-www-form-urlencoded":
			dicc=self.readUrlEncodedVariables(pd)
			[self.addVariablePOST(i,j) for i,j in dicc]

		elif self.ContentType=="multipart/form-data":
			self.multiPOSThead={}
			dicc={}
			tp=TextParser()
			tp.setSource("string",pd)
		#	print self.boundary
		#	print tp.readUntil("%s$" % (self.boundary))

			while True:
				headers=[]
				if not tp.readUntil("name=\"([^\"]+)\""):
					break
				var=tp[0][0]
				headers.append(tp.lastFull_line.strip())
				while True:
					tp.readLine()
					if tp.search("^([^:]+): (.*)$"):
						headers.append(tp.lastFull_line.strip())
					else:
						break

				value=""
				while True:
					tp.readLine()
					if not tp.search(self.boundary):
						value+=tp.lastFull_line
					else:
						break

				if value[-2:]=="\r\n":
					value=value[:-2]


				dicc[var]=value
				self.multiPOSThead[var]=headers

				if tp.search(self.boundary+"--"):
					break

			
			self.__variablesPOST.update(dicc)
#			print pd
#			print dicc
#			print self.__variablesPOST

		else:
			self.__uknPostData=pd

class Response:

	def __init__ (self,protocol="",code="",message=""):
		self.protocol=protocol         # HTTP/1.1
		self.code=code			# 200
		self.message=message		# OK
		self.__headers=[]		# bueno pues las cabeceras igual que en la request
		self.__content=""		# contenido de la response (si i solo si Content-Length existe)
		self.md5=""             # hash de los contenidos del resultado
		self.charlen=""         # Cantidad de caracteres de la respuesta

	def addHeader (self,key,value):
		k=string.capwords(key,"-")
		self.__headers+=[(k,value)]

	def delHeader (self,key):
		for i in self.__headers:
			if i[0].lower()==key.lower():
				self.__headers.remove(i)


	def addContent (self,text):
		self.__content=self.__content+text

	def __getitem__ (self,key):
		for i,j in self.__headers:
			if key==i:
				return  j
		print "Error al obtener header!!!"

	def getCookie (self):
		str=[]
		for i,j in self.__headers:
			if i.lower()=="set-cookie":
				str.append(j.split(";")[0])
		return  "; ".join(str)


	def has_header (self,key):
		for i,j in self.__headers:
			if i.lower()==key.lower():
				return True
		return False
	
	def getLocation (self):
		for i,j in self.__headers:
			if i.lower()=="location":
				return j
		return None

	def header_equal (self,header,value):
		for i,j in self.__headers:
			if i==header and j.lower()==value.lower():
				return True
		return False

	def getHeaders (self):
		return self.__headers


	def getContent (self):
		return self.__content

	def getAll (self):
		string=str(self.protocol)+" "+str(self.code)+" "+str(self.message)+"\r\n"
		for i,j in self.__headers:
			string+=i+": "+j+"\r\n"
		string+="\r\n"+self.getContent()
		return string

	def Substitute(self,src,dst):
		a=self.getAll()
		b=a.replace(src,dst)
		self.parseResponse(b)

	def getAll_wpost (self):
		string=str(self.protocol)+" "+str(self.code)+" "+str(self.message)+"\r\n"
		for i,j in self.__headers:
			string+=i+": "+j+"\r\n"
		return string


	def parseResponse (self,rawResponse,type="curl"):
		self.__content=""
		self.__headers=[]

		tp=TextParser()
		tp.setSource("string",rawResponse)

		while True:
			tp.readUntil("(HTTP\S*) ([0-9]+)")

			try:
				self.protocol=tp[0][0]
			except:
				self.protocol="unknown"

			try:
				self.code=tp[0][1]
			except:
				self.code="0"

			if self.code!="100":
				break


		self.code=int(self.code)

		while True:
			tp.readLine()
			if (tp.search("^([^:]+): ?(.*)$")):
				self.addHeader(tp[0][0],tp[0][1])
			else:
				break

		while tp.skip(1):
			self.addContent(tp.lastFull_line)

		if type=='curl':
			self.delHeader("Transfer-Encoding")

		if self.header_equal("Transfer-Encoding","chunked"):
			result=""
			content=StringIO.StringIO(self.__content)
			hexa=content.readline()	
			nchunk=int(hexa.strip(),16)
			
			while nchunk:
				result+=content.read(nchunk)
				content.readline()
				hexa=content.readline()	
				nchunk=int(hexa.strip(),16)

			self.__content=result

		if self.header_equal("Content-Encoding","gzip"):
			compressedstream = StringIO.StringIO(self.__content)
			gzipper = gzip.GzipFile(fileobj=compressedstream)
			body=gzipper.read()
			self.__content=body
			self.delHeader("Content-Encoding")



class ReqrespException(Exception):
	def __init__ (self,value):
		self.__value=value

	def __str__ (self):
		return self.GetError()

	def GetError(self):
		if self.__value==1:
			return "Attribute not modificable"
