from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptBadFile
from wfuzz.plugin_api.base import BasePayload
from wfuzz.utils import open_file_detect_encoding


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
            self.f = open_file_detect_encoding(self.find_file(self.params["fn"]))
        except IOError as e:
            raise FuzzExceptBadFile("Error opening file. %s" % str(e))

        self.__count = None

    def __next__(self):
        line = self.f.readline()
        if not line:
            self.f.close()
            raise StopIteration
        return line.strip()

    def count(self):
        if self.__count is None:
            self.__count = len(self.f.readlines())
            self.f.seek(0)

        return self.__count

    def __iter__(self):
        return self
