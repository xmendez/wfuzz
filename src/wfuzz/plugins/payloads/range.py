from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.exception import FuzzExceptPluginBadParams
from wfuzz.plugin_api.base import BasePayload
from wfuzz.fuzzobjects import FuzzWordType


@moduleman_plugin
class range(BasePayload):
    name = "range"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    description = ("ie. 0-10",)
    summary = "Returns each number of the given range."
    category = ["default"]
    priority = 99

    parameters = (("range", "", True, "Range of numbers in the form 0-10."),)

    default_parameter = "range"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        try:
            ran = self.params["range"].split("-")
            self.minimum = int(ran[0])
            self.maximum = int(ran[1])
            self.__count = self.maximum - self.minimum + 1
            self.width = len(ran[0])
            self.current = self.minimum
        except ValueError:
            raise FuzzExceptPluginBadParams('Bad range format (eg. "23-56")')

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        if self.current > self.maximum:
            raise StopIteration
        else:
            if self.width:
                payl = "%0" + str(self.width) + "d"
                payl = payl % (self.current)
            else:
                payl = str(self.current)

            self.current += 1
            return payl

    def count(self):
        return self.__count

    def __iter__(self):
        return self
