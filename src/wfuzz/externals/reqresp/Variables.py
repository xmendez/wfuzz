from .TextParser import TextParser
import json


class Variable:
    def __init__(self, name, value="", extraInfo=""):
        self.name = name
        self.value = value
        self.initValue = value
        self.extraInfo = extraInfo

    def restore(self):
        self.value = self.initValue

    def change(self, newval):
        self.initValue = self.value = newval

    def update(self, val):
        self.value = val

    def append(self, val):
        self.value += val

    def __str__(self):
        return "[ %s : %s ]" % (self.name, self.value)


class VariablesSet:
    def __init__(self):
        self.variables = []
        self.boundary = None

    def names(self):
        dicc = []
        for i in self.variables:
            dicc.append(i.name)

        return dicc

    def existsVar(self, name):
        return name in self.names()

    def addVariable(self, name, value="", extraInfo=""):
        self.variables.append(Variable(name, value, extraInfo))

    def getVariable(self, name):
        dicc = []
        for i in self.variables:
            if i.name == name:
                dicc.append(i)

        if len(dicc) > 1:
            raise Exception("Variable exists more than one time!!! :D" % (name))

        if not dicc:
            var = Variable(name)
            self.variables.append(var)
            return var

        return dicc[0]

    def urlEncoded(self):
        return "&".join(
            [
                "=".join([i.name, i.value]) if i.value is not None else i.name
                for i in self.variables
            ]
        )

    def json_encoded(self):
        dicc = {i.name: i.value for i in self.variables}

        return json.dumps(dicc)

    def parse_json_encoded(self, cad):
        dicc = []

        for key, value in json.loads(cad).items():
            dicc.append(Variable(key, value))

        self.variables = dicc

    def parseUrlEncoded(self, cad):
        dicc = []

        if cad == "":
            dicc.append(Variable("", None))

        for i in cad.split("&"):
            if i:
                var_list = i.split("=", 1)
                if len(var_list) == 1:
                    dicc.append(Variable(var_list[0], None))
                elif len(var_list) == 2:
                    dicc.append(Variable(var_list[0], var_list[1]))

        self.variables = dicc

    def multipartEncoded(self):
        if not self.boundary:
            self.boundary = "---------------------------D33PB1T0R3QR3SP0B0UND4RY2203"
        pd = ""
        for i in self.variables:
            pd += "--" + self.boundary + "\r\n"
            pd += "%s\r\n\r\n%s\r\n" % ("\r\n".join(i.extraInfo), i.value)
        pd += "--" + self.boundary + "--\r\n"
        return pd

    def parseMultipart(self, cad, boundary):
        self.boundary = boundary
        dicc = []
        tp = TextParser()
        tp.setSource("string", cad)

        while True:
            headers = []
            if not tp.readUntil('name="([^"]+)"'):
                break
            var = tp[0][0]
            headers.append(tp.lastFull_line.strip())
            while True:
                tp.readLine()
                if tp.search("^([^:]+): (.*)$"):
                    headers.append(tp.lastFull_line.strip())
                else:
                    break

            value = ""
            while True:
                tp.readLine()
                if not tp.search(boundary):
                    value += tp.lastFull_line
                else:
                    break

            if value[-2:] == "\r\n":
                value = value[:-2]

            dicc.append(Variable(var, value.strip(), headers))

        self.variables = dicc
