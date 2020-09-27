from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload
from wfuzz.exception import FuzzExceptBadOptions
from wfuzz.fuzzobjects import FuzzWordType


@moduleman_plugin
class hexrange(BasePayload):
    name = "hexrange"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    description = ()
    summary = "Returns each hex number of the given hex range."
    category = ["default"]
    priority = 99

    parameters = (
        ("range", "", True, "Range of hex numbers to generate in the form of 00-ff."),
    )

    default_parameter = "range"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        try:
            ran = self.params["range"].split("-")
            self.minimum = int(ran[0], 16)
            self.maximum = int(ran[1], 16)
            self.__count = self.maximum - self.minimum + 1
            self.current = self.minimum
            self.lgth = max(
                len(ran[0]), len(ran[1]), len(hex(self.maximum).replace("0x", ""))
            )
        except ValueError:
            raise FuzzExceptBadOptions('Bad range format (eg. "0-ffa")')

    def count(self):
        return self.__count

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        if self.current > self.maximum:
            raise StopIteration

        pl = "%" + str(self.lgth) + "s"
        num = hex(self.current).replace("0x", "")
        pl = pl % (num)
        payl = pl.replace(" ", "0")

        self.current += 1

        return payl
