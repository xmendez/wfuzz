from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptBadFile
from wfuzz.plugin_api.base import BasePayload

@moduleman_plugin
class file(BasePayload):
    name = "file"
    author = ("Carlos del Ojo", "Christian Martorella", "Adapted to newer versions Xavi Mendez (@xmendez)")
    version = "0.1"
    description = (
        "Returns the contents of a dictionary file line by line.",
    )
    summary = "Returns each word from a file."
    category = ["default"]
    priority = 99

    parameters = (
        ("fn", "", True, "Filename of a valid dictionary"),
    )

    default_parameter = "fn"

    def __init__(self, params):
        BasePayload.__init__(self, params)

	try:
	    self.f = open(self.find_file(self.params["fn"]), "r")
	except IOError, e:
	    raise FuzzExceptBadFile("Error opening file. %s" % str(e))

	self.__count = len(self.f.readlines())
	self.f.seek(0)

    def next (self):
	return self.f.next().strip()

    def count(self):
	return self.__count

    def __iter__(self):
	return self

