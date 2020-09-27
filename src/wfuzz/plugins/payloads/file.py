from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptBadFile
from wfuzz.plugin_api.base import BasePayload
from wfuzz.helpers.file_func import FileDetOpener
from wfuzz.fuzzobjects import FuzzWordType


@moduleman_plugin
class file(BasePayload):
    name = "file"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.2"
    description = ("Returns the contents of a dictionary file line by line.",)
    summary = "Returns each word from a file."
    category = ["default"]
    priority = 99

    parameters = (
        ("fn", "", True, "Filename of a valid dictionary"),
        (
            "count",
            "True",
            False,
            "Indicates if the number of words in the file should be counted.",
        ),
        ("encoding", "Auto", False, "Indicates the file encoding."),
    )

    default_parameter = "fn"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        try:
            encoding = (
                self.params["encoding"]
                if self.params["encoding"].lower() != "auto"
                else None
            )
            self.f = FileDetOpener(self.find_file(self.params["fn"]), encoding)
        except IOError as e:
            raise FuzzExceptBadFile("Error opening file. %s" % str(e))

        self.__count = None

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        line = next(self.f)
        if not line:
            self.f.close()
            raise StopIteration
        return line.strip()

    def count(self):
        if self.params["count"].lower() == "false":
            return -1

        if self.__count is None:
            self.__count = len(list(self.f))
            self.f.reset()

        return self.__count
