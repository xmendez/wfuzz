from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptBadFile
from wfuzz.fuzzobjects import FuzzResult, FuzzRequest
from wfuzz.plugin_api.base import BasePayload

import datetime
import logging
import os
import re

CRLF = "\r\n"
DELIMITER = "%s%s" % ('=' * 54, CRLF)
CRLF_DELIMITER = CRLF + DELIMITER
HEADER = re.compile('(\d{1,2}:\d{2}:\d{2} (AM|PM|))[ \t]+(\S+)([ \t]+\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|unknown host)\])?')

@moduleman_plugin
class burplog(BasePayload):
    name = "burplog"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = ("Returns fuzz results' URL from a Burp log.",
    )
    summary = "Returns fuzz results from a Burp log."
    category = ["default"]
    priority = 99

    parameters = (
        ("fn", "", True, "Filename of a valid Burp log file."),
        ("attr", None, False, "Attribute of fuzzresult to return. If not specified the whole object is returned."),
    )

    default_parameter = "fn"

    def __init__(self, params):
        BasePayload.__init__(self, params)

	self.__max = -1
        self.attr = self.params["attr"]
        self._it = self.parse(self.open_burp_log(self.params["fn"]))

    def __iter__(self):
	return self

    def count(self):
	return self.__max

    def next(self):
	next_item = self._it.next()

        return next_item if not self.attr else next_item.get_field(self.attr)

    def open_burp_log(self, burp_log):
        burp_file = None

        try:
            burp_file = open(self.find_file(burp_log), 'rb')
            buf = burp_file.read()

        except IOError, e:
            raise FuzzExceptBadFile("Error opening burp log file. %s" % str(e))
        finally:
            if burp_file is not None:
                burp_file.close()

        return buf

    def forward_buffer(self, buf, pos, n, token):
        """
        Advance buf from current position by n bytes while buf is not equal
        to token.

        @param buffer: String
        @param pos: Integer of current position in buffer.
        @param n: Length of token string.
        @param token: Token to advance current buffer position to.
        @return: Position of buffer at token.
        @rtype: int
        """
        while buf[pos:pos + n] != token:
            pos += 1

        return pos

    def parse(self, buf):
        """
        Parses a Burp Suite log file.  Returns a list of Burp objects
        in the order in which they were written.

        @param burp_log: A filename or string of a Burp Suite log.
        @return: list of gds.burp.Burp objects.
        @rtype: list
        """

        parsed = []
        history = 'START'

        pos = 0
        req = 0

        buf_len = len(buf)

        while pos < buf_len + 1:
            try:
                if history == "START":
                    if buf[pos:pos + 56] == DELIMITER:
                        history = "HEADER"
                    else:
                        pos += 1

                # Parse the header lines
                if history == "HEADER":
                    start = pos

                    # First check to make sure we've got a header block
                    pos += 56
                    pos = self.forward_buffer(buf, pos, 2, CRLF)

                    header = buf[start + 56:pos]

                    # Advance over CRLF
                    pos += 2

                    if buf[start:start + 56] == DELIMITER and \
                        buf[pos:pos + 56] == DELIMITER:

                        # we are positive this is a header and not just a
                        # coincidence that the delimiter was in the body.

                        matched = HEADER.match(header)
                        ctime, host, ip_address = matched.group(1, 3, 5)
                        history = "REQUEST"
                    else:
                        history = "START"

                elif history == "REQUEST":
                    start = pos
                    pos += 56
                    start2 = pos
                    pos = self.forward_buffer(buf, pos, 2, CRLF)


                    pos = self.forward_buffer(buf, pos, 4, CRLF + CRLF)

                    # Advance over CRLF
                    pos += 4
                    start = pos
                    pos = self.forward_buffer(buf, pos, 56, DELIMITER)

                    # at this point, we're right at the delimiter, so -2 bytes
                    # to account for that last CRLF.
                    raw_request = buf[start2:pos - 2]

                    # we got the body, now advance over the delimiter
                    pos += 56

                    history = "RESPONSE"

                if history == "RESPONSE":
                    start = pos

                    pos = self.forward_buffer(buf, pos, 2, CRLF)

                    # slice buf from index of current position + 3 CRLF
                    # to current position + 3 CRLF + delimiter length (= 62)
                    if buf[pos + 6:pos + 62] != DELIMITER:

                        pos = self.forward_buffer(buf, pos, 4, CRLF + CRLF)

                        # Advance over CRLF
                        pos += 4

                        while buf[pos - 2:pos + 56] != CRLF_DELIMITER and \
                            pos < buf_len - 2:
                            pos += 1

                        raw_response = buf[start:pos]

                        pos += 56

                    else:
                        raw_response = ""

                    fr = FuzzRequest()
                    fr.update_from_raw_http(raw_request, "http", raw_response)
                    frr = FuzzResult(history=fr)
                    

                    yield frr.update()

                    history = "START"

            # The most likely cause for an exception to get raised is if
            # modifications were made to the main Burp class and weren't handled
            # correctly.  Check your source!
            #
            # If this is a legit exception due to incorrect parsing, please send
            # labs@gdssecurity.com an email with the error message and if possible
            # a sanitized proxy log.
            except Exception, e:
                print e
                pos += 1
