from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload
from wfuzz.fuzzobjects import FuzzWordType

import sys


@moduleman_plugin
class stdin(BasePayload):
    name = "stdin"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = ()
    summary = "Returns each item read from stdin."
    category = ["default"]
    priority = 99

    parameters = ()

    default_parameter = ""

    def __init__(self, params):
        BasePayload.__init__(self, params)
        self.__count = -1

    def count(self):
        return self.__count

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        line = next(sys.stdin).strip()

        return line
