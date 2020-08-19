from wfuzz.externals.moduleman.plugin import moduleman_plugin

# Python 2 and 3
try:
    from urllib.parse import quote
    from urllib.parse import unquote
except ImportError:
    from urllib import quote
    from urllib import unquote

# Python 2 and 3
try:
    from base64 import decodebytes as b64decode
    from base64 import standard_b64encode
except ImportError:
    from base64 import decodestring as b64decode
    from base64 import standard_b64encode

import re
import binascii
import random
import hashlib
import html


@moduleman_plugin("encode")
class none:
    name = "none"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Returns string without changes"
    category = ["default"]
    priority = 99

    def encode(self, string):
        return string

    def decode(self, string):
        return string


@moduleman_plugin("encode")
class urlencode:
    name = "urlencode"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Replace special characters in string using the %xx escape. Letters, digits, and the characters '_.-' are never quoted."
    category = ["url_safe", "url"]
    priority = 99

    def encode(self, string):
        return quote(string)

    def decode(self, string):
        return unquote(string)


@moduleman_plugin("encode")
class double_urlencode:
    name = "double urlencode"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Applies a double encode to special characters in string using the %25xx escape. Letters, digits, and the characters '_.-' are never quoted."
    category = ["url_safe", "url"]
    priority = 99

    def encode(self, string):
        return quote(quote(string))

    def decode(self, string):
        return unquote(unquote(string))


@moduleman_plugin("encode")
class base64:
    name = "base64"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Encodes the given string using base64"
    category = ["hashes"]
    priority = 99

    def encode(self, string):
        return standard_b64encode(string.encode("utf-8")).decode("utf-8")

    def decode(self, string):
        return b64decode(string.encode("utf-8")).decode("utf-8")


@moduleman_plugin("encode")
class uri_triple_hex:
    name = "uri_triple_hex"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Encodes ALL charachers using the %25%xx%xx escape."
    category = ["url"]
    priority = 99

    def encode(self, string):
        strt = ""
        s = re.compile(r"/|;|=|:|&|@|\\|\?")
        for c in string:
            if s.search(c):
                strt += c
                continue
            temp = hex(ord(c))[2:]
            strt += "%%25%%%02x%%%02x" % (ord(temp[:1]), ord(temp[1:]))
        return strt


@moduleman_plugin("encode")
class uri_double_hex:
    name = "uri_double_hex"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Encodes ALL charachers using the %25xx escape."
    category = ["url"]
    priority = 99

    def encode(self, string):
        strt = ""
        con = "%%25%02x"
        s = re.compile(r"/|;|=|:|&|@|\\|\?")
        for c in string:
            if s.search(c):
                strt += c
                continue
            strt += con % ord(c)
        return strt


@moduleman_plugin("encode")
class uri_hex:
    name = "uri_hex"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Encodes ALL charachers using the %xx escape."
    category = ["url"]
    priority = 99

    def encode(self, string):
        strt = ""
        con = "%%%02x"
        s = re.compile(r"/|;|=|:|&|@|\\|\?")
        for c in string:
            if s.search(c):
                strt += c
                continue
            strt += con % ord(c)
        return strt


@moduleman_plugin("encode")
class random_upper:
    name = "random_upper"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Replaces random characters in string with its capitals letters"
    category = ["default"]
    priority = 99

    def encode(self, string):
        strt = ""
        for c in string:
            x = int(random.uniform(0, 10))
            x = x % 2
            if x == 1:
                strt += c.upper()
            else:
                strt += c
        return strt


@moduleman_plugin("encode")
class second_nibble_hex:
    name = "second_nibble_hex"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Replaces ALL characters in string using the %?%dd escape"
    category = ["url"]
    priority = 99

    def encode(self, string):
        strt = ""
        s = re.compile(r"/|;|=|:|&|@|\\|\?")
        for c in string:
            if s.search(c):
                strt += c
                continue
            temp = hex(ord(c))[2:]
            strt += "%%%s%%%02x" % (str(temp[:1]), ord(temp[1:]))
        return strt


@moduleman_plugin("encode")
class first_nibble_hex:
    name = "first_nibble_hex"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Replaces ALL characters in string using the %%dd? escape"
    category = ["url"]
    priority = 99

    def encode(self, string):
        strt = ""
        s = re.compile(r"/|;|=|:|&|@|\\|\?")
        for c in string:
            if s.search(c):
                strt += c
                continue
            temp = hex(ord(c))[2:]
            strt += "%%%%%02x%s" % (ord(temp[:1]), str(temp[1:]))
        return strt


@moduleman_plugin("encode")
class doble_nibble_hex:
    name = "doble_nibble_hex"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Replaces ALL characters in string using the %%dd%dd escape"
    category = ["url"]
    priority = 99

    def encode(self, string):
        strt = ""
        fin = ""
        con = "%%%02x"
        s = re.compile(r"/|;|=|:|&|@|\\|\?")
        enc = uri_hex()
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


@moduleman_plugin("encode")
class sha1:
    name = "sha1"
    summary = "Applies a sha1 hash to the given string"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    category = ["hashes"]
    priority = 99

    def encode(self, string):
        s = hashlib.sha1()
        s.update(string.encode("utf-8"))
        res = s.hexdigest()
        return res


@moduleman_plugin("encode")
class md5:
    name = "md5"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Applies a md5 hash to the given string"
    category = ["hashes"]
    priority = 99

    def encode(self, string):
        m = hashlib.new("md5")
        m.update(string.encode("utf-8"))
        res = m.hexdigest()
        return res


@moduleman_plugin("encode")
class hexlify:
    name = "hexlify"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Every byte of data is converted into the corresponding 2-digit hex representation."
    category = ["default"]
    priority = 99

    def encode(self, string):
        return binascii.hexlify(string.encode("utf-8")).decode("utf-8")

    def decode(self, string):
        return binascii.unhexlify(string.encode("utf-8")).decode("utf-8")


@moduleman_plugin("encode")
class html_escape:
    name = "html_escape"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = 'Convert the characters &<>" in string to HTML-safe sequences.'
    category = ["html"]
    priority = 99

    def encode(self, string):
        return html.escape(string, quote=True)


@moduleman_plugin("encode")
class html_decimal:
    name = "html_decimal"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Replaces ALL characters in string using the &#dd; escape"
    category = ["html"]
    priority = 99

    def encode(self, string):
        new = ""
        for x in string:
            new += "&#" + str(ord(x)) + ";"
        return new


@moduleman_plugin("encode")
class html_hexadecimal:
    name = "html_hexadecimal"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Replaces ALL characters in string using the &#xx; escape"
    category = ["html"]
    priority = 99

    def encode(self, string):
        new = ""
        for x in string:
            val = "%02x" % ord(x)
            new += "&#x" + str(val) + ";"
        return new


@moduleman_plugin("encode")
class utf8_binary:
    name = "utf8_binary"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Replaces ALL characters in string using the \\uxx escape"
    category = ["url"]
    priority = 99

    def encode(self, string):
        new = ""
        for x in string:
            val = "%02x" % ord(x)
            new += "\\x" + str(val)
        return new


@moduleman_plugin("encode")
class utf8:
    name = "utf8"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Replaces ALL characters in string using the \\u00xx escape"
    category = ["url"]
    priority = 99

    def encode(self, string):
        new = ""
        for x in string:
            val = "%02x" % ord(x)
            if len(val) == 2:
                new += "\\u00" + str(val)
            else:
                new += "\\u" + str(val)
        return new


@moduleman_plugin("encode")
class uri_unicode:
    name = "uri_unicode"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Replaces ALL characters in string using the %u00xx escape"
    category = ["url"]
    priority = 99

    def encode(self, string):
        new = ""
        for x in string:
            val = "%02x" % ord(x)
            if len(val) == 2:
                new += "%u00" + str(val)
            else:
                new += "%u" + str(val)
        return new


@moduleman_plugin("encode")
class mysql_char:
    name = "mysql_char"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Converts ALL characters to MySQL's char(xx)"
    category = ["db"]
    priority = 99

    def encode(self, string):
        new = "CHAR("
        for x in string:
            val = str(ord(x))
            new += str(val) + ","
        new = new.strip(",")
        new += ")"
        return new

    def decode(self, string):
        temp = string.strip("CHAR").strip("(").strip(")").split(",")
        new = ""
        for x in temp:
            new += chr(int(x))
        return new


@moduleman_plugin("encode")
class mssql_char:
    name = "mssql_char"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Converts ALL characters to MsSQL's char(xx)"
    category = ["db"]
    priority = 99

    def encode(self, string):
        new = ""
        for x in string:
            val = str(ord(x))
            new += "CHAR(" + str(val) + ")+"
        new = new.strip("+")
        return new

    def decode(self, string):
        new = ""
        temp = string.split("+")
        for x in temp:
            x = x.strip("CHAR").strip(")").strip("(")
            new += chr(int(x))
        return new


@moduleman_plugin("encode")
class oracle_char:
    name = "oracle_char"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    summary = "Converts ALL characters to Oracle's chr(xx)"
    category = ["db"]
    priority = 99

    def encode(self, string):
        new = ""
        for x in string:
            val = str(ord(x))
            new += "chr(" + val + ")||"
        new = new.strip("||")
        return new

    def decode(self, string):
        new = ""
        temp = string.split("||")
        for x in temp:
            x = x.strip("chr").strip(")").strip("(")
            new += chr(int(x))
        return new
