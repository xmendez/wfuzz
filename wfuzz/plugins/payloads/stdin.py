from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload

import sys

@moduleman_plugin
class stdin(BasePayload):
    name = "stdin"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = ()
    summary = "Returns each item read from stdin."
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

