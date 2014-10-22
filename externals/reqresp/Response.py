from urlparse import urlparse, urlunparse
import string
import re
import StringIO
import gzip

try:
    from TextParser import *
except:
    pass

class Response:

	def __init__ (self,protocol="",code="",message=""):
		self.protocol=protocol         # HTTP/1.1
		self.code=code			# 200
		self.message=message		# OK
		self._headers=[]		# bueno pues las cabeceras igual que en la request
		self.__content=""		# contenido de la response (si i solo si Content-Length existe)
		self.md5=""             # hash de los contenidos del resultado
		self.charlen=""         # Cantidad de caracteres de la respuesta

	def addHeader (self,key,value):
		k=string.capwords(key,"-")
		self._headers+=[(k,value)]

	def delHeader (self,key):
		for i in self._headers:
			if i[0].lower()==key.lower():
				self._headers.remove(i)


	def addContent (self,text):
		self.__content=self.__content+text

	def __getitem__ (self,key):
		for i,j in self._headers:
			if key==i:
				return  j
		print "Error al obtener header!!!"

	def getCookie (self):
		str=[]
		for i,j in self._headers:
			if i.lower()=="set-cookie":
				str.append(j.split(";")[0])
		return  "; ".join(str)


	def has_header (self,key):
		for i,j in self._headers:
			if i.lower()==key.lower():
				return True
		return False
	
	def getLocation (self):
		for i,j in self._headers:
			if i.lower()=="location":
				return j
		return None

	def header_equal (self,header,value):
		for i,j in self._headers:
			if i==header and j.lower()==value.lower():
				return True
		return False

	def getHeaders (self):
		return self._headers

	def getContent (self):
		return self.__content

	def getTextHeaders(self):
		string=str(self.protocol)+" "+str(self.code)+" "+str(self.message)+"\r\n"
		for i,j in self._headers:
			string+=i+": "+j+"\r\n"

		return string

	def getAll (self):
		string=self.getTextHeaders()+"\r\n"+self.getContent()
		return string

	def Substitute(self,src,dst):
		a=self.getAll()
		b=a.replace(src,dst)
		self.parseResponse(b)

	def getAll_wpost (self):
		string=str(self.protocol)+" "+str(self.code)+" "+str(self.message)+"\r\n"
		for i,j in self._headers:
			string+=i+": "+j+"\r\n"
		return string


	def parseResponse (self,rawResponse,type="curl"):
		self.__content=""
		self._headers=[]

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

