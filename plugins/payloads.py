import random
import sys
import __builtin__

from externals.moduleman.plugin import moduleman_plugin
from framework.core.myexception import FuzzException
from framework.fuzzer.base import wfuzz_iterator
from framework.plugins.api import search_bing

@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class ipnet:
    name = "ipnet"
    description = "Returns list of IP addresses of a given network. ie. 192.168.1.0/24"
    category = ["default"]
    priority = 99

    def __init__(self, network):
	try:
            import ipaddress

            net = ipaddress.ip_network(u'%s' % network)
            self.f = net.hosts()
            self.__count = net.num_addresses - 2

            if self.__count <= 0:
                raise FuzzException(FuzzException.FATAL, "There are not hosts in the specified network")

	except ValueError:
	    raise FuzzException(FuzzException.FATAL, "The specified network has an incorrect format.")
	except ImportError:
	    raise FuzzException(FuzzException.FATAL, "ipnet plugin requires ipaddress module. Please install it using pip.")

    def next(self):
	return str(self.f.next())

    def count(self):
	return self.__count

    def __iter__ (self):
	return self

@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class file:
    name = "file"
    description = "Returns each word from a file."
    category = ["default"]
    priority = 99

    def __init__(self, filename):
	try:
	    self.f = open(filename,"r")
	except IOError:
	    raise FuzzException(FuzzException.FATAL, "Error opening file")

	self.__count = len(self.f.readlines())
	self.f.seek(0)

    def next (self):
	return self.f.next().strip()

    def count(self):
	return self.__count

    def __iter__ (self):
	return self

@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class range:
    name = "range"
    description = "Returns each number of the given range. ie. 0-10"
    category = ["default"]
    priority = 99

    def __init__(self, whatrange):    ## range example --> "23-56"
	try:
	    ran = whatrange.split("-")
	    self.minimum = int(ran[0])
	    self.maximum = int(ran[1])
	    self.__count = self.maximum - self.minimum + 1
	    self.width = len(ran[0])
	    self.current = self.minimum
	except:
	    raise FuzzException(FuzzException.FATAL, "Bad range format (eg. \"23-56\")")
		
    def next(self):
	if self.current>self.maximum:
	    raise StopIteration
	else:
	    if self.width:
		payl = "%0"+ str(self.width) + "d"
		payl = payl % (self.current)
	    else:
		payl = str(self.current)

	    self.current += 1
	    return payl

    def count(self):
	return self.__count

    def __iter__(self):
	return self

@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class hexrange:
    name = "hexrange"
    description = "Returns each hex number of the given hex range. ie. 00-ff"
    category = ["default"]
    priority = 99

    def __init__(self, prange):    ## range example --> "0-ffa"
	try:
	    ran = prange.split("-")
	    self.minimum = int(ran[0],16)
	    self.maximum = int(ran[1],16)
	    self.__count = self.maximum - self.minimum + 1
	    self.current = self.minimum
	except:
	    raise Exception, "Bad range format (eg. \"0-ffa\")"
	    
    def __iter__(self):
	return self

    def count(self):
	return self.__count
	    
    def next(self):
	if self.current > self.maximum:
	    raise StopIteration
	
	lgth=len(hex(self.maximum).replace("0x",""))
	pl="%"+str(lgth)+"s"
	num=hex(self.current).replace("0x","")	
	pl= pl % (num)
	payl=pl.replace(" ","0")
	
	self.current+=1

	return payl

@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class hexrand:
    name = "hexrand"
    description = "Returns random hex numbers."
    category = ["default"]
    priority = 99

    def __init__(self, prange):    ## range example --> "0-ffa"
	try:
	    ran = prange.split("-")
	    self.minimum=int(ran[0],16)
	    self.maximum=int(ran[1],16)
	    self.__count=-1
	except:
	    raise Exception, "Bad range format (eg. \"0-ffa\")"
	    
    def __iter__ (self):
	return self

    def count(self):
	return self.__count

    def next (self):
	self.current = random.SystemRandom().randint(self.minimum,self.maximum)
	
	lgth = len(hex(self.maximum).replace("0x",""))
	pl="%"+str(lgth)+"s"
	num = hex(self.current).replace("0x","")	
	pl = pl % (num)
	payl =pl.replace(" ","0")
	
	return payl


@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class buffer_overflow:
    name = "buffer_overflow"
    description = "Returns a string using the following pattern A * given number."
    category = ["default"]
    priority = 99

    def __init__(self, n):   
	self.l = ['A' * int(n)]
	self.current = 0

    def __iter__(self):
	return self

    def count(self):
	return 1

    def next (self):
	if self.current == 0:
	    elem = self.l[self.current]
	    self.current+=1
	    return elem
	else:
	    raise StopIteration

@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class list:
    name = "list"
    description = "Returns each element of the given word list separated by -. ie word1-word2"
    category = ["default"]
    priority = 99

    def __init__(self, l):   
	if l.find("\\") >= 0:
	    l = l.replace("\\-", "$SEP$")
	    l = l.replace("\\\\", "$SCAP$")

	    self.l = l.split("-")

	    for i in __builtin__.range(len(self.l)):
		self.l[i] = self.l[i].replace("$SEP$", "-")
		self.l[i] = self.l[i].replace("$SCAP$", "\\")
	else:
	    self.l = l.split("-")
	    
	self.__count = len(self.l)
	self.current = 0

    def __iter__ (self):
	return self

    def count(self):
	return self.__count

    def next (self):
	if self.current >= self.__count:
	    raise StopIteration
	else:
	    elem = self.l[self.current]
	    self.current += 1
	    return elem

@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class stdin:
    name = "stdin"
    description = "Returns each item read from stdin."
    category = ["default"]
    priority = 99

    def __init__(self, deprecated):
	# stdin is unseekable
	self.__count = -1
	#self.__count=len(sys.stdin.readlines())
	#sys.stdin.seek(0)

    def count(self):
	return self.__count

    def __iter__ (self):
	return self

    def next (self):
	#line=sys.stdin.next().strip().split(':')
	line = sys.stdin.next().strip()

	return line

@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class names:
    name = "names"
    description = "Returns possible usernames by mixing the given words, separated by -, using known typical constructions. ie. jon-smith"
    category = ["default"]
    priority = 99

    def __init__(self, startnames):
	self.startnames = startnames
	from sets import Set
	possibleusernames = []
	name = ""
	llist = self.startnames.split("-")

	for x in llist:
	    if name == "":
		name = name + x
	    else:
		name = name + " " + x

	    if " " in name:
		parts = name.split()
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
		for i in __builtin__.range(0,len(parts)-1):
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
	    else:
		possibleusernames.append(name)

	    self.creatednames=possibleusernames
	    self.__count=len(possibleusernames)
	    
    def count(self):
	return self.__count

    def __iter__(self):
	return self

    def next(self):
	if self.creatednames:
	    payl = self.creatednames.pop()
	    return payl
	else:
	    raise StopIteration
		
@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class permutation:
    name = "permutation"
    description = "Returns permutations of the given charset and length. ie. abc-2"
    category = ["default"]
    priority = 99

    def __init__(self, prange):    ## range example --> "abcdef-4"
	self.charset = []

	try:
	    ran = prange.split("-")
	    self.charset = ran[0]
	    self.width = int(ran[1])
	except:
	    raise Exception, "Bad range format (eg. \"abfdeg-3\")"

	pset = []
	for x in self.charset:
	    pset.append(x)

	words = self.xcombinations(pset, self.width)
	self.lista = []
	for x in words:
	    self.lista.append(''.join(x))

	self.__count = len(self.lista)

    def __iter__ (self):
	return self

    def count(self):
	return self.__count

    def next (self):
	if self.lista != []:
	    payl=self.lista.pop()
	    return payl
	else:
	    raise StopIteration

    def xcombinations(self, items, n):
	if n == 0:
	    yield []
	else:
	    try:
		for i in xrange(len(items)):
		    for cc in self.xcombinations(items[:i] + items[i:], n - 1):
			yield [items[i]] + cc
	    except:
		print "Interrupted Permutation calculations"
		sys.exit()

@wfuzz_iterator
@moduleman_plugin("count", "next", "__iter__")
class bing:
    '''
    Some examples of bing hacking:
    - http://www.elladodelmal.com/2010/02/un-poco-de-bing-hacking-i-de-iii.html
    '''
    name = "bing"
    description = "Returns URL results of a given bing API search (needs api key). ie, intitle:\"JBoss JMX Management Console\"-10"
    category = ["default"]
    priority = 99

    def __init__(self, dork):   
	self.l = search_bing(dork)
	self.__count = len(self.l)
	self.current = 0

    def __iter__ (self):
	return self

    def count(self):
	return self.__count

    def next (self):
	if self.current >= self.__count:
	    raise StopIteration
	else:
	    elem = self.l[self.current]['Url']
	    self.current += 1
	    return str(elem.strip())
