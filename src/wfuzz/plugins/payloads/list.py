from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload
from wfuzz.fuzzobjects import FuzzWordType


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

            self.value_list = self.params["values"].split("-")

            for i in range(len(self.value_list)):
                self.value_list[i] = self.value_list[i].replace("$SEP$", "-")
                self.value_list[i] = self.value_list[i].replace("$SCAP$", "\\")
        else:
            self.value_list = self.params["values"].split("-")

        self.__count = len(self.value_list)
        self.current = 0

    def count(self):
        return self.__count

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        if self.current >= self.__count:
            raise StopIteration
        else:
            elem = self.value_list[self.current]
            self.current += 1
            return elem
