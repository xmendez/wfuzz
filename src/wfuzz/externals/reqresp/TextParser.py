# Covered by GPL V2.0
# Coded by Carlos del Ojo Elias (deepbit@gmail.com)

import sys
import re

# python 2 and 3: iterator
from builtins import object


class TextParser(object):
    def __init__(self):
        self.string = ""
        self.oldindex = 0
        self.newindex = 0
        self.type = ""
        self.lastFull_line = None
        self.lastline = None

        self.actualIndex = 0

    def __del__(self):
        if self.type == "file":
            self.fd.close()

    def __str__(self):
        return str(self.matches)

    def __iter__(self):
        self.actualIndex = 0
        return self

    def __next__(self):
        try:
            value = self.matches[self.actualIndex]
            self.actualIndex += 1
            return value
        except Exception:
            raise StopIteration

    def setSource(self, t, *args):
        """Se especifica el tipo de entrada. Puede ser fichero o entrada estandard

        Ejemplos: setSource("file","/tmp/file")
                    setSource("stdin")\n"""

        if t == "file":
            self.type = t
            self.fd = open(args[0], "r")
        elif t == "stdin":
            if self.type == "file":
                self.fd.close()
            self.type = t
        elif t == "string":
            if self.type == "file":
                self.fd.close()
            self.type = t
            self.string = args[0]
            self.oldindex = 0
            self.newindex = 0
        else:
            print("Bad argument -- TextParser.setSource()\n")
            sys.exit(-1)

    def seekinit(self):
        self.oldindex = 0
        self.newindex = 0

    def readUntil(self, pattern, caseSens=True):
        "Lee lineas hasta que el patron (pattern) conincide en alguna linea"

        while True:
            if self.readLine() == 0:
                return False
            if self.search(pattern, caseSens) is True:
                break

        return True

    def search(self, pattern, caseSens=True, debug=0):
        "Intenta hacer Matching entre el pattern pasado por parametro y la ultima linea leida"

        if not caseSens:
            self.regexp = re.compile(pattern, re.IGNORECASE)
        else:
            self.regexp = re.compile(pattern)
        self.matches = self.regexp.findall(self.lastline)
        j = 0
        for i in self.matches:
            if not isinstance(i, tuple):
                self.matches[j] = tuple([self.matches[j]])
            j += 1

        #               DEBUG PARA MATCHING
        if debug == 1:
            print(("[", self.lastline, "-", pattern, "]"))
            print((len(self.matches)))
            print((self.matches))

        if len(self.matches) == 0:
            return False
        else:
            return True

    def __getitem__(self, key):
        "Para acceder a cada uno de los patrones que coinciden, esta preparado paragrupos de patrones, no para solo un patron"

        return self.matches[key]

    def skip(self, lines):
        "Salta las lines que se indiquen en el parametro"

        for i in range(lines):
            if self.readLine() == 0:
                return False

        return True

    def readLine(self):
        "Lee la siguiente linea eliminando retornos de carro"

        if self.type == "file":
            self.lastFull_line = self.fd.readline()
        elif self.type == "stdin":
            self.lastFull_line = input()
        elif self.type == "string":
            if self.newindex == -1:
                return 0

            if self.oldindex >= 0:
                self.newindex = self.string.find("\n", self.oldindex, len(self.string))
                if self.newindex == -1:
                    self.lastFull_line = self.string[self.oldindex : len(self.string)]
                else:
                    self.lastFull_line = self.string[self.oldindex : self.newindex + 1]

                self.oldindex = self.newindex + 1
            else:
                self.lastFull_line = ""

        bytes_read = len(self.lastFull_line)

        s = self.lastFull_line
        self.lastline = s

        if s[-2:] == "\r\n":
            self.lastline = s[:-2]
        elif s[-1:] == "\r" or s[-1:] == "\n":
            self.lastline = s[:-1]

        return bytes_read
