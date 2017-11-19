from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload

@moduleman_plugin
class list(BasePayload):
    name = "list"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = ("ie word1-word2",)
    summary = "Returns each element of the given word list separated by -."
    category = ["default"]
    priority = 99

    parameters = (
        ("values", "", True, "Values separated by - to return as a dictionary."),
    )

    default_parameter = "values"

    def __init__(self, params):
        BasePayload.__init__(self, params)

	if self.params["values"].find("\\") >= 0:
            self.params["values"] = self.params["values"].replace("\\-", "$SEP$")
	    self.params["values"] = self.params["values"].replace("\\\\", "$SCAP$")

	    self.l = self.params["values"].split("-")

	    for i in range(len(self.l)):
		self.l[i] = self.l[i].replace("$SEP$", "-")
		self.l[i] = self.l[i].replace("$SCAP$", "\\")
	else:
	    self.l = self.params["values"].split("-")
	    
	self.__count = len(self.l)
	self.current = 0

    def __iter__ (self):
	return self

    def count(self):
	return self.__count

    def next (self):
	if self.current >= self.__count:
	    raise StopIteration
	else:
	    elem = self.l[self.current]
	    self.current += 1
	    return elem

