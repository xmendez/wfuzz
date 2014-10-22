import encoders
import copy
import random


####### SUPERCLASS

class payload:
	def __init__(self):
		self.__count=0
		pass

	def __iter__ (self):
		return base_iterator()


	def count(self):
		return self.__count

class base_iterator:
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
	text = "file"
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

class file_iterator (base_iterator):
	def __init__(self,file):
		base_iterator.__init__(self)
		self.file=open (file,"r")
		
	def next (self):
		line=self.file.next().strip()

		return line

################### RANGE PAYLOAD


class payload_range (payload):
	text = "range"
	def __init__(self,range):    ## range example --> "23-56"
		payload.__init__(self)
		try:
			ran=range.split("-")
			self.minimum=int(ran[0])
			self.maximum=int(ran[1])
			self.__count=self.maximum - self.minimum + 1
			self.width=len(ran[0])
		except:
			raise Exception, "Bad range format (eg. \"23-56\")"
		

	def count(self):
		return self.__count

	def __iter__ (self):
		return range_iterator(self.minimum,self.maximum,self.width)


class range_iterator (base_iterator):
	def __init__(self,min,max,width):
		base_iterator.__init__(self)
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


class payload_hexrange(payload):
	text="hexrange"
	def __init__(self,range):    ## range example --> "0-ffa"
		payload.__init__(self)
		try:
			ran=range.split("-")
			self.minimum=int(ran[0],16)
			self.maximum=int(ran[1],16)
			self.__count=self.maximum - self.minimum + 1
		except:
			raise Exception, "Bad range format (eg. \"0-ffa\")"
		
	def __iter__ (self):
		return hexrange_iterator(self.minimum,self.maximum)

	def count(self):
		return self.__count

class hexrange_iterator (base_iterator):
	def __init__(self,min,max):
		base_iterator.__init__(self)
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

class payload_hexrand(payload):
	text="hexrand"
	def __init__(self,range):    ## range example --> "0-ffa"
		payload.__init__(self)
		try:
			ran=range.split("-")
			self.minimum=int(ran[0],16)
			self.maximum=int(ran[1],16)
			self.__count=self.maximum - self.minimum + 1
		except:
			raise Exception, "Bad range format (eg. \"0-ffa\")"
		
	def __iter__ (self):
		return hexrand_iterator(self.minimum,self.maximum)

	def count(self):
		return self.__count



class hexrand_iterator (base_iterator):
	def __init__(self,min,max):
		base_iterator.__init__(self)
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
	text="list"
	separator="-"
	def __init__(self,l):   
		payload.__init__(self)
		self.l=l.split(self.separator)
		self.__count=len(self.l)

	def __iter__ (self):
		return plist_iterator(self.l)

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

class payload_names(payload):
	text="names"
	def __init__(self,startnames):
		self.startnames=startnames
		payload.__init__(self)
		from sets import Set
		possibleusernames=[]
		name=""
		list=self.startnames.split("-")
		for x in list:
			if name=="":
				name=name+x
			else:
				name=name+" "+x
		if " " in name:
			parts=name.split()
			possibleusernames.append(parts[0])
			possibleusernames.append(parts[0]+"."+parts[1])
			possibleusernames.append(parts[0]+parts[1])
			possibleusernames.append(parts[0]+"."+parts[1][0])
			possibleusernames.append(parts[0][0]+"."+parts[1])
			possibleusernames.append(parts[0]+parts[1][0])
			possibleusernames.append(parts[0][0]+parts[1])
			str1=""
			str2=""
			str3=""
			str4=""
			for i in range(0,len(parts)-1):
				str1=str1+parts[i]+"."
				str2=str2+parts[i]
				str3=str3+parts[i][0]+"."
				str4=str4+parts[i][0]
			str5=str1+parts[-1]
			str6=str2+parts[-1]
			str7=str4+parts[-1]
			str8=str3+parts[-1]
			str9=str2+parts[-1][0]
			str10=str4+parts[-1][0]
			possibleusernames.append(str5)
			possibleusernames.append(str6)
			possibleusernames.append(str7)
			possibleusernames.append(str8)
			possibleusernames.append(str9)
			possibleusernames.append(str10)
			possibleusernames.append(parts[-1])
			possibleusernames.append(parts[0]+"."+parts[-1])
			possibleusernames.append(parts[0]+parts[-1])
			possibleusernames.append(parts[0]+"."+parts[-1][0])
			possibleusernames.append(parts[0][0]+"."+parts[-1])
			possibleusernames.append(parts[0]+parts[-1][0])
			possibleusernames.append(parts[0][0]+parts[-1])
			self.creatednames=possibleusernames
		else:
			possibleusernames.append(name)
			self.creatednames=possibleusernames
		self.__count=len(possibleusernames)
		
	def count(self):
		return self.__count

	def __iter__(self):
		return name_iterator(self.creatednames)	

class name_iterator(list):
	def __init__(self,list):
		self.list=list

	def next(self):
		if self.list != []:
			payl=self.list.pop()
			return payl
		else:
			raise StopIteration
