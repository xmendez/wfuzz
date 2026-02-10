from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload
from wfuzz.exception import FuzzExceptBadOptions
from wfuzz.fuzzobjects import FuzzWordType


@moduleman_plugin
class permutation(BasePayload):
    name = "permutation"
    author = ("Xavi Mendez (@xmendez)", "@n0kovo@infosec.exchange")
    version = "0.2"
    description = ()
    summary = "Returns permutations of the given charset and length."
    category = ["default"]
    priority = 99

    parameters = (("ch", "", True, "Charset and min/max len to permute, in the form of abc-1-8."),)

    default_parameter = "ch"

    def __init__(self, params):
        BasePayload.__init__(self, params)
        self.charset = []

        try:
            ran = self.params["ch"].split("-")
            self.charset = ran[0]
            self.min_length = int(ran[1])
            self.max_length = int(ran[2])
        except ValueError:
            raise FuzzExceptBadOptions('Bad range format (eg. "1-4-ffa")')

        pset = []
        for x in self.charset:
            pset.append(x)

        words = self.xcombinations(pset, self.min_length, self.max_length)
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

    def xcombinations(self, charset, min_length, max_length):
        def product(pool, repeat):
            n = len(pool)
            indices = [0] * repeat
            current_perm = [pool[0]] * repeat
            while True:
                yield ''.join(current_perm)
                for i in reversed(range(repeat)):
                    indices[i] += 1
                    if indices[i] < n:
                        current_perm[i] = pool[indices[i]]
                        break
                    indices[i] = 0
                    current_perm[i] = pool[0]
                else:
                    return

        for length in range(min_length, max_length + 1):
            for perm in product(charset, length):
                yield perm
