from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload
from wfuzz.exception import FuzzExceptPluginBadParams
from wfuzz.fuzzobjects import FuzzWordType

import random


@moduleman_plugin
class hexrand(BasePayload):
    name = "hexrand"
    author = (
        "Carlos del Ojo",
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    description = ()
    summary = "Returns random hex numbers from the given range."
    category = ["default"]
    priority = 99

    parameters = (
        (
            "range",
            "",
            True,
            "Range of hex numbers to randomly generate in the form of 00-ff.",
        ),
    )

    default_parameter = "range"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        try:
            ran = self.params["range"].split("-")
            self.minimum = int(ran[0], 16)
            self.maximum = int(ran[1], 16)
            self.__count = -1
        except ValueError:
            raise FuzzExceptPluginBadParams('Bad range format (eg. "0-ffa")')

    def __iter__(self):
        return self

    def count(self):
        return self.__count

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        self.current = random.SystemRandom().randint(self.minimum, self.maximum)

        lgth = len(hex(self.maximum).replace("0x", ""))
        pl = "%" + str(lgth) + "s"
        num = hex(self.current).replace("0x", "")
        pl = pl % (num)
        payl = pl.replace(" ", "0")

        return payl
