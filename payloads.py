import encoders
import copy
import random


####### SUPERCLASS

class payload:
	def __init__(self):
		self.__count=0
		pass

	def __iter__ (self):
		return payload_iterator()


	def count(self):
		return self.__count

class payload_iterator:
	def __init__(self):
		pass

	def next (self):
		raise StopIteration
	

######################################
######################################
######## Inheritances
######################################
######################################

class payload_file (payload):
	def __init__(self,file):
		payload.__init__(self)
		self.file=file
		f=open(file,"r")
		self.__count=len(f.readlines())
		f.close()


	def count(self):
		return self.__count

	def __iter__ (self):
		return file_iterator(self.file)

class file_iterator (payload_iterator):
	def __init__(self,file):
		payload_iterator.__init__(self)
		self.file=open (file,"r")
		
	def next (self):
		line=self.file.next().strip()

		return line

################### RANGE PAYLOAD


class payload_range (payload):
	def __init__(self,range,width=0):    ## range example --> "23-56"
		payload.__init__(self)
		try:
			ran=range.split("-")
			self.minimum=int(ran[0])
			self.maximum=int(ran[1])
			self.__count=self.maximum - self.minimum
			self.width=width
		except:
			raise Exception, "Bad range format (eg. \"23-56\")"
		

	def count(self):
		return self.__count

	def __iter__ (self):
		return range_iterator(self.minimum,self.maximum,self.width)


class range_iterator (payload_iterator):
	def __init__(self,min,max,width):
		payload_iterator.__init__(self)
		self.minimum=min
		self.maximum=max
		self.width=width
		self.current=self.minimum
		
	def next (self):
		if self.current>self.maximum:
			raise StopIteration
		if self.width:
			payl="%0"+str(self.width)+"d"
			payl=payl % (self.current)
		else:
			payl=str(self.current)

		self.current+=1
		return payl
	

################### HEXRANGE PAYLOAD


class payload_hexrange (payload):
	def __init__(self,range):    ## range example --> "0-ffa"
		payload.__init__(self)
		try:
			ran=range.split("-")
			self.minimum=int(ran[0],16)
			self.maximum=int(ran[1],16)
			self.__count=self.maximum - self.minimum
		except:
			raise Exception, "Bad range format (eg. \"0-ffa\")"
		
	def __iter__ (self):
		return hexrange_iterator(self.minimum,self.maximum)

	def count(self):
		return self.__count

class hexrange_iterator (payload_iterator):
	def __init__(self,min,max):
		payload_iterator.__init__(self)
		self.minimum=min
		self.maximum=max
		self.current=self.minimum
		
	def next (self):
		if self.current>self.maximum:
			raise StopIteration
		
		lgth=len(hex(self.maximum).replace("0x",""))
		pl="%"+str(lgth)+"s"
		num=hex(self.current).replace("0x","")	
		pl= pl % (num)
		payl=pl.replace(" ","0")
		
		self.current+=1

		return payl

class payload_hexrand (payload):
	def __init__(self,range):    ## range example --> "0-ffa"
		payload.__init__(self)
		try:
			ran=range.split("-")
			self.minimum=int(ran[0],16)
			self.maximum=int(ran[1],16)
			self.__count=self.maximum - self.minimum
		except:
			raise Exception, "Bad range format (eg. \"0-ffa\")"
		
	def __iter__ (self):
		return hexrand_iterator(self.minimum,self.maximum)

	def count(self):
		return self.__count



class hexrand_iterator (payload_iterator):
	def __init__(self,min,max):
		payload_iterator.__init__(self)
		self.minimum=min
		self.maximum=max
		self.current=self.minimum
		
	def next (self):
		self.current = random.SystemRandom().randint(self.minimum,self.maximum)
		
		lgth=len(hex(self.maximum).replace("0x",""))
		pl="%"+str(lgth)+"s"
		num=hex(self.current).replace("0x","")	
		pl= pl % (num)
		payl=pl.replace(" ","0")
		
		return payl

######################### PAYLOAD LIST


class payload_list (payload):
	def __init__(self,list):   
		payload.__init__(self)
		self.list=list
		self.__count=len(list)
		
	def __iter__ (self):
		return plist_iterator(self.list)

	def count(self):
		return self.__count


class plist_iterator (list):
	def __init__(self,list):
		self.list=list
		self.current=0
		
	def next (self):
		try:
			elem=self.list[self.current]
			self.current+=1
			return elem
		except:
			raise StopIteration
		
