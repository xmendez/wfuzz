from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptBadFile, FuzzExceptBadOptions
from wfuzz.fuzzobjects import FuzzResult
from wfuzz.fuzzrequest import FuzzRequest
from wfuzz.plugin_api.base import BasePayload
from wfuzz.helpers.obj_dyn import rgetattr
from wfuzz.fuzzobjects import FuzzWordType


import datetime
import string
import re
import struct
import zipfile

TAG = re.compile(r"</?(\w*)>", re.M)  # Match a XML tag
nvprint = string.printable.replace("\x0b", "").replace("\x0c", "")  # Printables


@moduleman_plugin
class burpstate(BasePayload):
    name = "burpstate"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = (
        "*ALERT*: https://portswigger.net/blog/goodbye-state-files-we-wont-miss-you",
        "",
        "Returns fuzz results' from a Burp saved state file. This payload's code is based on burp2xml.py:",
        "Developed by Paul Haas, <phaas AT redspin DOT com> under Redspin. Inc.",
        "Licensed under the GNU Public License version 3.0 (2008-2009)",
        "Process Burp Suite Professional's output into a well-formed XML document.",
        "",
        "Currently, the whole burp state file is read, in the future this needs to be changed to be more memory efficient.",
    )
    summary = "Returns fuzz results from a Burp state."
    category = ["default"]
    priority = 99

    parameters = (
        ("fn", "", True, "Filename of a valid Burp state file."),
        (
            "attr",
            None,
            False,
            "Fuzzresult attribute to return. If not specified the whole object is returned.",
        ),
        (
            "source",
            "proxy, target",
            False,
            "A list of separated Burp sources to get the HTTP requests and responses from. It could be proxy or target tool.",
        ),
        (
            "checkversion",
            False,
            False,
            "If the Burp log file version is unknown an exception will be raised and execution will fail. Checked with burp state file version 65, 67.",
        ),
    )

    default_parameter = "fn"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        self.__max = -1
        self.attr = self.params["attr"]
        self._it = self.burp_to_xml(self.params["fn"])

        if any(i not in ["proxy", "target"] for i in self.params["source"].split(",")):
            raise FuzzExceptBadOptions("Unknown burp source parameter")

        self.request_tags = []
        self.response_tags = []

        if "proxy" in self.params["source"]:
            self.request_tags.append("</originalRequest>")
            self.response_tags.append("</originalResponse>")

        if "target" in self.params["source"]:
            self.request_tags.append("</request>")
            self.response_tags.append("</response>")

    def __iter__(self):
        return self

    def count(self):
        return self.__max

    def get_type(self):
        return FuzzWordType.FUZZRES if not self.attr else FuzzWordType.WORD

    def get_next(self):
        next_item = next(self._it)

        return next_item if not self.attr else rgetattr(next_item, self.attr)

    def milliseconds_to_date(self, milliseconds):
        """Convert milliseconds since Epoch (from Java) to Python date structure:
        See: http://java.sun.com/j2se/1.4.2/docs/api/java/util/Date.html

        There is no direct way to convert milliseconds since Epoch to Python object
        So we convert the milliseconds to seconds first as a POSIX timestamp which
        can be used to get a valid date, and then use the parsed values from that
        object along with converting mili -> micro seconds in a new date object."""
        try:
            d = datetime.datetime.fromtimestamp(milliseconds / 1000)
            date = datetime.datetime(
                d.year,
                d.month,
                d.day,
                d.hour,
                d.minute,
                d.second,
                (milliseconds % 1000) * 1000,
            )
        except ValueError:  # Bad date, just return the milliseconds
            date = str(milliseconds)
            return None
        return date

    def burp_binary_field(self, field, i):
        """Strip Burp Suite's binary format characters types from our data.
        The first character after the leading tag describes the type of the data."""
        if len(field) <= i:
            return None, -1
        elif field[i] == "\x00":  # 4 byte integer value
            return str(struct.unpack(">I", field[i + 1 : i + 5])[0]), 5
        elif field[i] == "\x01":  # Two possible unsigned long long types
            if field[i + 1] == "\x00":  # (64bit) 8 Byte Java Date
                ms = struct.unpack(">Q", field[i + 1 : i + 9])[0]
                date = self.milliseconds_to_date(ms)
                value = (
                    date.ctime() if date else 0
                )  # Use the ctime string format for date
            else:  # Serial Number only used ocasionally in Burp
                value = str(struct.unpack(">Q", field[i + 1 : i + 9])[0])
            return value, 9
        elif field[i] == "\x02":  # Boolean Object True/False
            return str(struct.unpack("?", field[i + 1 : i + 2])[0]), 2
        elif field[i] == "\x03" or field[i] == "\x04":  # 4 byte length + string
            length = struct.unpack(">I", field[i + 1 : i + 5])[0]
            # print "Saw string of length", length, "at", i + 5, i + 5+length
            value = field[i + 5 : i + 5 + length]
            if "<" in value or ">" in value or "&" in value:  # Sanatize HTML w/CDATA
                value = "<![CDATA[" + value.replace("]]>", "]]><![CDATA[") + "]]>"
            value = "".join(c for c in value if c in nvprint)  # Remove nonprintables
            return value, 5 + length  # ** TODO: Verify length by matching end tag **
        print("Unknown binary format", repr(field[i]))
        return None, -1

    def strip_cdata(self, data):
        if data.startswith("<![CDATA["):
            data = data[9:]

        if data.endswith("]]>"):
            data = data[:-3]

        return data

    def burp_to_xml(self, filename):
        """Unzip Burp's file, remove non-printable characters, CDATA any HTML,
        include a valid XML header and trailer, and return a valid XML string."""

        z = zipfile.ZipFile(self.find_file(filename))  # Open Burp's zip file
        burp = z.read("burp", "rb")  # Read-in the main burp file
        m = TAG.match(burp, 0)  # Match a tag at the start of the string
        while m:
            index = m.end()
            etag = m.group().replace("<", "</")  # Matching tag

            m = TAG.match(burp, index)  # Attempt to get the next tag
            if not m:  # Data folows
                # Read the type of data using Burp's binary data headers
                value, length = self.burp_binary_field(burp, index)
                if value is None:
                    break

                index += length + len(etag)  # Point our index to the next tag
                m = TAG.match(burp, index)  # And retrieve it

                if (
                    self.params["checkversion"]
                    and etag == "</version>"
                    and value not in ["65", "67"]
                ):
                    raise FuzzExceptBadFile("Unknown burp log version %s" % value)

                if etag == "</https>":
                    https_tag = value == "True"

                if etag in self.request_tags:
                    raw_request = self.strip_cdata(value)

                if etag in self.response_tags:
                    fr = FuzzRequest()
                    fr.update_from_raw_http(
                        raw_request,
                        "http" if not https_tag else "https",
                        self.strip_cdata(value),
                    )
                    frr = FuzzResult(history=fr)

                    raw_request = ""
                    https_tag = ""

                    yield frr.update()
