import urllib
import base64
import re
import binascii
import random
import hashlib


# SUPERCLASS

class encoder:
	def __init__(self):
		pass
	
	def encode (self,string):
		return string


#######################################################
######################################################
######## Inheritances
#######################################################
######################################################

class encoder_urlencode (encoder):
	text="urlencode"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		return urllib.quote(string)

	def decode(self,string):
         try:
		 	res=urllib.unquote(clear)	
			return res
         except:
			return 1

class encoder_double_urlencode (encoder):
	text="double urlencode"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		return urllib.quote(urllib.quote(string))

class encoder_base64 (encoder):
	text="base64"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		return base64.standard_b64encode(string)

	def decode(self,string):
		import base64
		try:
			res=base64.decodestring(string)
			return res
		except:
			return 1

class encoder_uri_hex (encoder):
	text="uri hexadecimal"
	def __init__(self):
		encoder.__init__(self)
	
	def encode(self,string):
		strt = ""
		con = "%%%02x"
		s=re.compile(r"/|;|=|:|&|@|\\|\?")	
		for c in string:
			if s.search(c):
				strt += c
				continue
			strt += con % ord(c)
		return strt


class encoder_random_upper (encoder):
	text="random Uppercase"
	def __init__(self):
		encoder.__init__(self)
	
	def encode(self,string):
		strt = ""
		for c in string:
			x = int(random.uniform(0,10))
			x = x % 2
			if x == 1:
				strt += c.upper()
			else:
				strt += c
		return strt   


class encoder_doble_nibble_hex (encoder):
	text="double nibble Hexa"
	def __init__(self):
		encoder.__init__(self)
	
	def encode(self,string):
		strt = ""
		fin = ""
		con = "%%%02x"
# first get it in straight hex
		s=re.compile(r"/|;|=|:|&|@|\\|\?")	
		enc=encoder_uri_hex()
		strt = enc.encode(string)
		for c in strt:
			if not c == "%":
				if s.search(c):
					fin += c
					continue
				fin += con % ord(c)
			else:
				fin += c
		return fin

class encoder_sha1 (encoder):
	text="sha1"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		s=hashlib.sha1()
		s.update(string)
		res =s.hexdigest()
		return res
		
class encoder_md5 (encoder):
	text="md5"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		m=hashlib.new('md5')
		m.update(string)
		res = m.hexdigest()
		return res
		
class encoder_binascii (encoder):
	text="binary Ascii"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		res = binascii.hexlify(string)		
		return res

	def decode(self,string):
		import binascii
		try:
			res = binascii.unhexlify(clear)
			return res
		except:
			return 1

class encoder_html (encoder):
	text="html encoder"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		res=string
		res=res.replace("<","&lt;")
		res=res.replace(">","&gt;")
		res=res.replace("\"","&quot;")
		res=res.replace("'","&apos;")
		#res=res.replace("&","&amp;")
		return res

class encoder_html_decimal (encoder):
	text="html encoder decimal"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		new=""
		for x in string:
			new+="&#"+str(ord(x))+";"
		return new

class encoder_html_hexadecimal (encoder):
	text="html encoder Hexa"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		new=""
		for x in string:
			val="%02x" % ord(x)
			new+="&#x"+str(val)+";"
		return new

class encoder_utf8_binary (encoder):
	text="utf8 binary"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		new=""
		for x in string:
			val="%02x" % ord(x)
			new+="\\x"+str(val)
		return new

class encoder_utf8 (encoder):
	text="utf8"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		new=""
		for x in string:
			val="%02x" % ord(x)
			if len(val)==2:
				new+="\\u00"+str(val)
			else:
				new+="\\u"+str(val)
		return new

class encoder_uri_unicode (encoder):
	text="uri unicode"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		new=""
		for x in string:
			val="%02x" % ord(x)
			if len(val)==2:
				new+="%u00"+str(val)
			else:
				new+="%u"+str(val)
		return new

class encoder_mysqlchar (encoder):
	text="mysql char"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		new="CHAR("
		for x in string:
			val=str(ord(x))
			new+=str(val)+","
		new=new.strip(",")
		new+=")"
		return new
	
	def decode(self,string):
		temp=string.strip("CHAR").strip("(").strip(")").split(",")
		new=""
		for x in temp:
			new+=chr(int(x))
		return new

class encoder_mssqlchar(encoder):
	text="mssql Char"
	def __init__(self):
		encoder.__init__(self)

	def encode(self,string):
		new=""
		for x in string:
			val=str(ord(x))
			new+="CHAR("+str(val)+")+"
		new=new.strip("+")
		return new
	
	def decode(self,string):
		new=""
		temp=string.split("+")
		for x in temp:
			x=x.strip("CHAR").strip(")").strip("(")
			new+= chr(int(x))
		return new 

class encoder_oraclechar(encoder):
	text="oracle Char"
	def __init__(self):
		encoder.__init__(self)
	def encode(self,string):
		new=""
		for x in string:
			val=str(ord(x))
			new+="chr("+val+")||"
		new=new.strip("||")
		return new

	def decode(self,string):
		new=""
		temp=string.split("||")
		for x in temp:
			x=x.strip("chr").strip(")").strip("(")
			new+= chr(int(x))
		return new 


