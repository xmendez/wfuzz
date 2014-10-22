#!/usr/bin/python

#Covered by GPL V2.0

from encoders import *
from payloads import *

# generate_dictio evolution		
class dictionary:
	def __init__(self,dicc=None):
		if dicc:
			self.__payload=dicc.getpayload()
			self.__encoder=dicc.getencoder()
		else:	
			self.__payload=payload()
			self.__encoder=encoder()
		self.iter=self.__payload.__iter__()

	def count (self):
		return self.__payload.count()

	def setpayload(self,payl):
		self.__payload=payl
		self.iter=self.__payload.__iter__()

	def setencoder(self,encd):
		self.__encoder=encd

	def getpayload (self):
		return self.__payload
	
	def getencoder (self):
		return self.__encoder

	def generate_all(self):
		dicc=[]
		for i in self.__payload:
			dicc.append(self.__encoder.encode(i))
		return dicc

	def __iter__(self):
		self.restart()
		return self

	def next(self):
		pl=self.iter.next()
		return self.__encoder.encode(pl)

	def restart(self):
		self.iter=self.__payload.__iter__()

