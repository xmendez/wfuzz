from wfuzz.plugin_api.base import wfuzz_iterator

import sys

@wfuzz_iterator
class stdin:
    name = "stdin"
    description = "Returns each item read from stdin."
    category = ["default"]
    priority = 99

    def __init__(self, deprecated, extra):
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

