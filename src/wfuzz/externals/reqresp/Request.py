# Covered by GPL V2.0
# Coded by Carlos del Ojo Elias (deepbit@gmail.com)
# Lately maintained by Xavi Mendez (xmendez@edge-security.com)

# Python 2 and 3
import sys

if sys.version_info >= (3, 0):
    from urllib.parse import urlparse
    from urllib.parse import urlunparse
else:
    from urlparse import urlparse
    from urlparse import urlunparse

import re
import pycurl

from .Variables import VariablesSet
from .exceptions import ReqRespException
from .Response import Response

from wfuzz.helpers.str_func import python2_3_convert_to_unicode
from wfuzz.helpers.obj_dic import CaseInsensitiveDict

from .TextParser import TextParser


PYCURL_PATH_AS_IS = True
if not hasattr(pycurl, "PATH_AS_IS"):
    PYCURL_PATH_AS_IS = False


class Request:
    def __init__(self):
        self.__host = None  # www.google.com:80
        self.__path = None  # /index.php
        self.__params = None  # Mierdaza de index.php;lskjflkasjflkasjfdlkasdf?
        self.schema = "http"  # http

        # #### Variables calculadas por getters NO SE PUEDEN MODIFICAR
        # self.urlWithoutPath                    # http://www.google.es
        # self.pathWithVariables                        # /index.php?a=b&c=d
        # self.urlWithoutVariables=None                         # http://www.google.es/index.php
        # self.completeUrl=""                                   # http://www.google.es/index.php?a=b
        # self.finalUrl=""                                      # Url despues de hacer el FollowLocation
        # self.redirectUrl=""                                   # Url redirected
        # self.postdata=""              # Datos por POST, toto el string
        # ###############

        self.ContentType = (
            "application/x-www-form-urlencoded"  # None es normal encoding
        )
        self.multiPOSThead = {}

        self.__variablesGET = VariablesSet()
        self._variablesPOST = VariablesSet()
        self._non_parsed_post = None

        # diccionario, por ejemplo headers["Cookie"]
        self._headers = CaseInsensitiveDict(
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1)",
            }
        )

        self.response = None  # Apunta a la response que produce dicha request

        # ################## lo de debajo no se deberia acceder directamente

        self.time = None  # 23:00:00
        self.ip = None  # 192.168.1.1
        self._method = None
        self.protocol = "HTTP/1.1"  # HTTP/1.1
        self.__performHead = ""
        self.__performBody = ""

        self.__authMethod = None
        self.__userpass = ""

        self.description = ""  # For temporally store imformation

        self.__proxy = None
        self.proxytype = None
        self.__timeout = None
        self.__totaltimeout = None
        self.__finalurl = ""

        self.followLocation = False
        self.__userpass = ""

        self.totaltime = None

    @property
    def method(self):
        if self._method is None:
            return "POST" if self._non_parsed_post is not None else "GET"

        return self._method

    @method.setter
    def method(self, value):
        if value == "None":
            value = None

        self._method = value

    def setFinalUrl(self, fu):
        self.__finalurl = fu

    def __str__(self):
        str = "[ URL: %s" % (self.completeUrl)
        if self.postdata:
            str += ' - {}: "{}"'.format(self.method, self.postdata)
        if "Cookie" in self._headers:
            str += ' - COOKIE: "%s"' % self._headers["Cookie"]
        str += " ]"
        return str

    def getHost(self):
        return self.__host

    def getXML(self, obj):
        r = obj.createElement("request")
        r.setAttribute("method", self.method)
        url = obj.createElement("URL")
        url.appendChild(obj.createTextNode(self.completeUrl))
        r.appendChild(url)
        if self.postdata:
            pd = obj.createElement("PostData")
            pd.appendChild(obj.createTextNode(self.postdata))
            r.appendChild(pd)
        if "Cookie" in self._headers:
            ck = obj.createElement("Cookie")
            ck.appendChild(obj.createTextNode(self._headers["Cookie"]))
            r.appendChild(ck)

        return r

    def __getattr__(self, name):
        if name == "urlWithoutVariables":
            return urlunparse((self.schema, self.__host, self.__path, "", "", ""))
        elif name == "pathWithVariables":
            return urlunparse(
                ("", "", self.__path, "", self.__variablesGET.urlEncoded(), "")
            )
        elif name == "completeUrl":
            return urlunparse(
                (
                    self.schema,
                    self.__host,
                    self.__path,
                    self.__params,
                    self.__variablesGET.urlEncoded(),
                    "",
                )
            )
        elif name == "finalUrl":
            if self.__finalurl:
                return self.__finalurl
            return self.completeUrl
        elif name == "urlWithoutPath":
            return "%s://%s" % (self.schema, self._headers["Host"])
        elif name == "path":
            return self.__path
        elif name == "postdata":
            if self.ContentType == "application/x-www-form-urlencoded":
                return self._variablesPOST.urlEncoded()
            elif self.ContentType == "multipart/form-data":
                return self._variablesPOST.multipartEncoded()
            elif self.ContentType == "application/json":
                return self._variablesPOST.json_encoded()
            else:
                return self._variablesPOST.urlEncoded()
        else:
            raise AttributeError

    def setUrl(self, urltmp):
        self.__variablesGET = VariablesSet()
        self.schema, self.__host, self.__path, self.__params, variables, f = urlparse(
            urltmp
        )
        if "Host" not in self._headers or (not self._headers["Host"]):
            self._headers["Host"] = self.__host

        if variables:
            self.__variablesGET.parseUrlEncoded(variables)

    # ############## PROXY ##################################
    def getProxy(self):
        return self.__proxy

    def setProxy(self, prox, ptype):
        self.__proxy = prox
        self.proxytype = ptype

    # ############## FOLLOW LOCATION ########################
    def setFollowLocation(self, value):
        self.followLocation = value

    # ############# TIMEOUTS ################################
    def setConnTimeout(self, time):
        self.__timeout = time

    def getConnTimeout(self):
        return self.__timeout

    def setTotalTimeout(self, time):
        self.__totaltimeout = time

    def getTotalTimeout(self):
        return self.__totaltimeout

    # ############# Autenticacion ###########################
    def setAuth(self, method, string):
        self.__authMethod = method
        self.__userpass = string

    def getAuth(self):
        return self.__authMethod, self.__userpass

    # ############# TRATAMIENTO VARIABLES GET & POST #########################

    def existsGETVar(self, key):
        return self.__variablesGET.existsVar(key)

    def existPOSTVar(self, key):
        return self._variablesPOST.existsVar(key)

    def setVariablePOST(self, key, value):
        v = self._variablesPOST.getVariable(key)
        v.update(value)

    #       self._headers["Content-Length"] = str(len(self.postdata))

    def setVariableGET(self, key, value):
        v = self.__variablesGET.getVariable(key)
        v.update(value)

    def getGETVars(self):
        return self.__variablesGET.variables

    def getPOSTVars(self):
        return self._variablesPOST.variables

    def setPostData(self, pd, boundary=None):
        self._non_parsed_post = pd
        self._variablesPOST = VariablesSet()

        try:
            if self.ContentType == "multipart/form-data":
                self._variablesPOST.parseMultipart(pd, boundary)
            elif self.ContentType == "application/json":
                self._variablesPOST.parse_json_encoded(pd)
            else:
                self._variablesPOST.parseUrlEncoded(pd)
        except Exception:
            try:
                self._variablesPOST.parseUrlEncoded(pd)
            except Exception:
                print("Warning: POST parameters not parsed")
                pass

    ############################################################################

    def addHeader(self, key, value):
        self._headers[key] = value

    def delHeader(self, key):
        if key in self._headers:
            del self._headers[key]

    def __getitem__(self, key):
        if key in self._headers:
            return self._headers[key]
        else:
            return ""

    def getHeaders(self):
        header_list = []
        for i, j in self._headers.items():
            header_list += ["%s: %s" % (i, j)]
        return header_list

    def head(self):
        conn = pycurl.Curl()
        conn.setopt(pycurl.SSL_VERIFYPEER, False)
        conn.setopt(pycurl.SSL_VERIFYHOST, 0)
        conn.setopt(pycurl.URL, self.completeUrl)

        conn.setopt(pycurl.NOBODY, True)  # para hacer un pedido HEAD

        conn.setopt(pycurl.WRITEFUNCTION, self.header_callback)
        conn.perform()

        rp = Response()
        rp.parseResponse(self.__performHead)
        self.response = rp

    def createPath(self, newpath):
        """Creates new url from a location header || Hecho para el followLocation=true"""
        if "http" in newpath[:4].lower():
            return newpath

        parts = urlparse(self.completeUrl)
        if "/" != newpath[0]:
            newpath = "/".join(parts[2].split("/")[:-1]) + "/" + newpath

        return urlunparse([parts[0], parts[1], newpath, "", "", ""])

    # pycurl - reqresp conversions
    @staticmethod
    def to_pycurl_object(c, req):

        c.setopt(pycurl.MAXREDIRS, 5)

        c.setopt(pycurl.WRITEFUNCTION, req.body_callback)
        c.setopt(pycurl.HEADERFUNCTION, req.header_callback)

        c.setopt(pycurl.NOSIGNAL, 1)
        c.setopt(pycurl.SSL_VERIFYPEER, False)
        c.setopt(pycurl.SSL_VERIFYHOST, 0)

        if PYCURL_PATH_AS_IS:
            c.setopt(pycurl.PATH_AS_IS, 1)

        c.setopt(pycurl.URL, python2_3_convert_to_unicode(req.completeUrl))

        if req.getConnTimeout():
            c.setopt(pycurl.CONNECTTIMEOUT, req.getConnTimeout())

        if req.getTotalTimeout():
            c.setopt(pycurl.TIMEOUT, req.getTotalTimeout())

        authMethod, userpass = req.getAuth()
        if authMethod or userpass:
            if authMethod == "basic":
                c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
            elif authMethod == "ntlm":
                c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
            elif authMethod == "digest":
                c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_DIGEST)
            c.setopt(pycurl.USERPWD, python2_3_convert_to_unicode(userpass))
        else:
            c.unsetopt(pycurl.USERPWD)

        c.setopt(pycurl.HTTPHEADER, python2_3_convert_to_unicode(req.getHeaders()))

        curl_options = {
            "GET": pycurl.HTTPGET,
            "POST": pycurl.POST,
            "PATCH": pycurl.UPLOAD,
            "HEAD": pycurl.NOBODY,
        }

        for o in curl_options.values():
            c.setopt(o, False)

        if req.method in curl_options:
            c.unsetopt(pycurl.CUSTOMREQUEST)
            c.setopt(curl_options[req.method], True)
        else:
            c.setopt(pycurl.CUSTOMREQUEST, req.method)

        if req._non_parsed_post is not None:
            c.setopt(
                pycurl.POSTFIELDS, python2_3_convert_to_unicode(req._non_parsed_post)
            )

        c.setopt(pycurl.FOLLOWLOCATION, 1 if req.followLocation else 0)

        # proxy = req.getProxy()
        # if proxy is not None:
        #     c.setopt(pycurl.PROXY, python2_3_convert_to_unicode(proxy))
        #     if req.proxytype == "SOCKS5":
        #         c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
        #     elif req.proxytype == "SOCKS4":
        #         c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS4)
        #     req.delHeader("Proxy-Connection")
        # else:
        #     c.setopt(pycurl.PROXY, "")

        return c

    def response_from_conn_object(self, conn, header, body):
        # followlocation
        if conn.getinfo(pycurl.EFFECTIVE_URL) != self.completeUrl:
            self.setFinalUrl(conn.getinfo(pycurl.EFFECTIVE_URL))

        self.totaltime = conn.getinfo(pycurl.TOTAL_TIME)

        self.response = Response()
        self.response.parseResponse(header, rawbody=body)

        return self.response

    def perform(self):
        self.__performHead = ""
        self.__performBody = ""
        self.__headersSent = ""

        try:
            conn = Request.to_pycurl_object(pycurl.Curl(), self)
            conn.perform()
            self.response_from_conn_object(conn, self.__performHead, self.__performBody)
        except pycurl.error as error:
            errno, errstr = error
            raise ReqRespException(ReqRespException.FATAL, errstr)
        finally:
            conn.close()

    # ######## ESTE conjunto de funciones no es necesario para el uso habitual de la clase

    def getAll(self):
        pd = self._non_parsed_post if self._non_parsed_post else ""
        string = (
            str(self.method)
            + " "
            + str(self.pathWithVariables)
            + " "
            + str(self.protocol)
            + "\n"
        )
        for i, j in self._headers.items():
            string += i + ": " + j + "\n"
        string += "\n" + pd

        return string

    # #########################################################################

    def header_callback(self, data):
        self.__performHead += data

    def body_callback(self, data):
        self.__performBody += data

    def Substitute(self, src, dst):
        a = self.getAll()
        rx = re.compile(src)
        b = rx.sub(dst, a)
        del rx
        self.parseRequest(b, self.schema)

    def parseRequest(self, rawRequest, prot="http"):
        """ Aun esta en fase BETA y por probar"""
        tp = TextParser()
        tp.setSource("string", rawRequest)

        self._variablesPOST = VariablesSet()
        self._headers = {}  # diccionario, por ejemplo headers["Cookie"]

        tp.readLine()
        try:
            tp.search(r"^(\S+) (.*) (HTTP\S*)$")
            self.method = tp[0][0]
            self.protocol = tp[0][2]
        except Exception as a:
            print(rawRequest)
            raise a

        pathTMP = tp[0][1].replace(" ", "%20")
        pathTMP = ("", "") + urlparse(pathTMP)[2:]
        pathTMP = urlunparse(pathTMP)

        while True:
            tp.readLine()
            if tp.search("^([^:]+): (.*)$"):
                self.addHeader(tp[0][0], tp[0][1])
            else:
                break

        self.setUrl(prot + "://" + self._headers["Host"] + pathTMP)

        # ignore CRLFs until request line
        while tp.lastline == "" and tp.readLine():
            pass

        # TODO: hacky, might need to change tp.readline returning read bytes instead
        pd = ""
        if tp.lastFull_line:
            pd += tp.lastFull_line

        while tp.readLine():
            pd += tp.lastFull_line

        if pd:
            boundary = None
            if "Content-Type" in self._headers:
                values = self._headers["Content-Type"].split(";")
                self.ContentType = values[0].strip().lower()
                if self.ContentType == "multipart/form-data":
                    boundary = values[1].split("=")[1].strip()

            self.setPostData(pd, boundary)
