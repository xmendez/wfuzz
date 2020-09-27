from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload
from wfuzz.exception import FuzzExceptBadOptions
from wfuzz.fuzzobjects import FuzzWordType


@moduleman_plugin
class permutation(BasePayload):
    name = "permutation"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = ()
    summary = "Returns permutations of the given charset and length."
    category = ["default"]
    priority = 99

    parameters = (("ch", "", True, "Charset and len to permute in the form of abc-2."),)

    default_parameter = "ch"

    def __init__(self, params):
        BasePayload.__init__(self, params)
        self.charset = []

        try:
            ran = self.params["ch"].split("-")
            self.charset = ran[0]
            self.width = int(ran[1])
        except ValueError:
            raise FuzzExceptBadOptions('Bad range format (eg. "0-ffa")')

        pset = []
        for x in self.charset:
            pset.append(x)

        words = self.xcombinations(pset, self.width)
        self.lista = []
        for x in words:
            self.lista.append("".join(x))

        self.__count = len(self.lista)

    def count(self):
        return self.__count

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        if self.lista != []:
            payl = self.lista.pop()
            return payl
        else:
            raise StopIteration

    def xcombinations(self, items, n):
        if n == 0:
            yield []
        else:
            for i in range(len(items)):
                for cc in self.xcombinations(items[:i] + items[i:], n - 1):
                    yield [items[i]] + cc
