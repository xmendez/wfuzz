from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.plugin_api.base import BasePayload

@wfuzz_iterator
class buffer_overflow(BasePayload):
    name = "buffer_overflow"
    description = "Returns a string using the following pattern A * given number."
    category = ["default"]
    priority = 99

    parameters = (
        ("size", "", True, "Size of the overflow string."),
    )

    default_parameter = "size"

    def __init__(self, params):
        BasePayload.__init__(self, params)

	self.l = ['A' * int(self.params["size"])]
	self.current = 0

    def __iter__(self):
	return self

    def count(self):
	return 1

    def next (self):
	if self.current == 0:
	    elem = self.l[self.current]
	    self.current+=1
	    return elem
	else:
	    raise StopIteration

