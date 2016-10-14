from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.plugin_api.base import BasePayload

import sys

@wfuzz_iterator
class stdin(BasePayload):
    name = "stdin"
    description = "Returns each item read from stdin."
    category = ["default"]
    priority = 99

    parameters = (
    )

    default_parameter = ""

    def __init__(self, params):
        BasePayload.__init__(self, params)

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

