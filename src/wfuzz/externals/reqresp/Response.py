import re
import cgi

from io import BytesIO
import gzip
import zlib

from .TextParser import TextParser

from wfuzz.helpers.str_func import python2_3_convert_from_unicode


def get_encoding_from_headers(headers):
    """Returns encodings from given HTTP Header Dict.

    :param headers: dictionary to extract encoding from.
    :rtype: str
    """

    content_type = headers.get("Content-Type")

    if not content_type:
        return None

    content_type, params = cgi.parse_header(content_type)

    if "charset" in params:
        return params["charset"].strip("'\"")

    if "text" in content_type:
        return "ISO-8859-1"

    if "image" in content_type:
        return "utf-8"

    if "application/json" in content_type:
        return "utf-8"


def get_encodings_from_content(content):
    """Returns encodings from given content string.

    :param content: bytestring to extract encodings from.
    """
    charset_re = re.compile(r'<meta.*?charset=["\']*(.+?)["\'>]', flags=re.I)
    pragma_re = re.compile(r'<meta.*?content=["\']*;?charset=(.+?)["\'>]', flags=re.I)
    xml_re = re.compile(r'^<\?xml.*?encoding=["\']*(.+?)["\'>]')

    return (
        charset_re.findall(content)
        + pragma_re.findall(content)
        + xml_re.findall(content)
    )


class Response:
    def __init__(self, protocol="", code="", message=""):
        self.protocol = protocol  # HTTP/1.1
        self.code = code  # 200
        self.message = message  # OK
        self._headers = []  # bueno pues las cabeceras igual que en la request
        self.__content = (
            ""  # contenido de la response (si i solo si Content-Length existe)
        )
        self.md5 = ""  # hash de los contenidos del resultado
        self.charlen = ""  # Cantidad de caracteres de la respuesta

    def addHeader(self, key, value):
        self._headers += [(key, value)]

    def delHeader(self, key):
        for i in self._headers:
            if i[0].lower() == key.lower():
                self._headers.remove(i)

    def addContent(self, text):
        self.__content = self.__content + text

    def __getitem__(self, key):
        for i, j in self._headers:
            if key == i:
                return j
        print("Error al obtener header!!!")

    def getCookie(self):
        str = []
        for i, j in self._headers:
            if i.lower() == "set-cookie":
                str.append(j.split(";")[0])
        return "; ".join(str)

    def has_header(self, key):
        for i, j in self._headers:
            if i.lower() == key.lower():
                return True
        return False

    def getLocation(self):
        for i, j in self._headers:
            if i.lower() == "location":
                return j
        return None

    def header_equal(self, header, value):
        for i, j in self._headers:
            if i == header and j.lower() == value.lower():
                return True
        return False

    def getHeaders(self):
        return self._headers

    def getContent(self):
        return self.__content

    def getTextHeaders(self):
        string = (
            str(self.protocol) + " " + str(self.code) + " " + str(self.message) + "\r\n"
        )
        for i, j in self._headers:
            string += i + ": " + j + "\r\n"

        return string

    def getAll(self):
        string = self.getTextHeaders() + "\r\n" + self.getContent()
        return string

    def Substitute(self, src, dst):
        a = self.getAll()
        b = a.replace(src, dst)
        self.parseResponse(b)

    def getAll_wpost(self):
        string = (
            str(self.protocol) + " " + str(self.code) + " " + str(self.message) + "\r\n"
        )
        for i, j in self._headers:
            string += i + ": " + j + "\r\n"
        return string

    def parseResponse(self, rawheader, rawbody=None, type="curl"):
        self.__content = ""
        self._headers = []

        tp = TextParser()
        tp.setSource("string", rawheader)

        tp.readUntil(r"(HTTP\S*) ([0-9]+)")
        while True:
            while True:
                try:
                    self.protocol = tp[0][0]
                except Exception:
                    self.protocol = "unknown"

                try:
                    self.code = tp[0][1]
                except Exception:
                    self.code = "0"

                if self.code != "100":
                    break
                else:
                    tp.readUntil(r"(HTTP\S*) ([0-9]+)")

            self.code = int(self.code)

            while True:
                tp.readLine()
                if tp.search("^([^:]+): ?(.*)$"):
                    self.addHeader(tp[0][0], tp[0][1])
                else:
                    break

            # curl sometimes sends two headers when using follow, 302 and the final header
            # also when using proxies
            tp.readLine()
            if not tp.search(r"(HTTP\S*) ([0-9]+)"):
                break
            else:
                self._headers = []

        # ignore CRLFs until request line
        while tp.lastline == "" and tp.readLine():
            pass

        # TODO: this should be added to rawbody not directly to __content
        if tp.lastFull_line:
            self.addContent(tp.lastFull_line)

        while tp.skip(1):
            self.addContent(tp.lastFull_line)

        if type == "curl":
            self.delHeader("Transfer-Encoding")

        if self.header_equal("Transfer-Encoding", "chunked"):
            result = ""
            content = BytesIO(rawbody)
            hexa = content.readline()
            nchunk = int(hexa.strip(), 16)

            while nchunk:
                result += content.read(nchunk)
                content.readline()
                hexa = content.readline()
                nchunk = int(hexa.strip(), 16)

            rawbody = result

        if self.header_equal("Content-Encoding", "gzip"):
            compressedstream = BytesIO(rawbody)
            gzipper = gzip.GzipFile(fileobj=compressedstream)
            rawbody = gzipper.read()
            self.delHeader("Content-Encoding")
        elif self.header_equal("Content-Encoding", "deflate"):
            deflated_data = None
            try:
                deflater = zlib.decompressobj()
                deflated_data = deflater.decompress(rawbody)
                deflated_data += deflater.flush()
            except zlib.error:
                try:
                    deflater = zlib.decompressobj(-zlib.MAX_WBITS)
                    deflated_data = deflater.decompress(rawbody)
                    deflated_data += deflater.flush()
                except zlib.error:
                    deflated_data = ""
            rawbody = deflated_data
            self.delHeader("Content-Encoding")

        if rawbody is not None:
            # Try to get charset encoding from headers
            content_encoding = get_encoding_from_headers(dict(self.getHeaders()))

            # fallback to default encoding
            if content_encoding is None:
                content_encoding = "utf-8"

            self.__content = python2_3_convert_from_unicode(
                rawbody.decode(content_encoding, errors="replace")
            )
