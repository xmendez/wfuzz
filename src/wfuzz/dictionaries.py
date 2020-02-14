from .exception import (
    FuzzExceptNoPluginError
)
from .facade import Facade
from .filter import FuzzResFilterSlice
from .fuzzobjects import FuzzWord, FuzzWordType


class BaseIterator:
    def count(self):
        raise NotImplementedError

    def width(self):
        raise NotImplementedError

    def payloads(self):
        raise NotImplementedError

    def cleanup(self):
        for payload in self.payloads():
            payload.close()


class BaseDictionary:
    def count(self):
        raise NotImplementedError

    def next_word(self):
        raise NotImplementedError

    def __next__(self):
        return self.next_word()

    def __iter__(self):
        return self

    def close(self):
        pass


class EncodeIt(BaseDictionary):
    def __init__(self, parent, encoders_list):
        self.parent = parent
        self.encoders = encoders_list
        self.__generator = self._gen()

    def count(self):
        return self.parent.count() * len(self.encoders)

    def concatenate(self, encoder_name, payload_word):
        string = payload_word.content
        for plugin_name in reversed(encoder_name.split("@")):
            string = Facade().encoders.get_plugin(plugin_name)().encode(string)

        return FuzzWord(string, FuzzWordType.WORD)

    def encode(self, encoder_name, payload_word):
        plugin_list = Facade().encoders.get_plugins(encoder_name)
        if not plugin_list:
            raise FuzzExceptNoPluginError(encoder_name + " encoder does not exists (-e encodings for a list of available encoders)")

        for plugin_class in plugin_list:
            yield FuzzWord(plugin_class().encode(payload_word.content), FuzzWordType.WORD)

    def next_word(self):
        return next(self.__generator)

    def _gen(self):
        while 1:
            try:
                payload_word = next(self.parent)
            except StopIteration:
                return

            for encoder_name in self.encoders:
                if encoder_name.find('@') > 0:
                    yield self.concatenate(encoder_name, payload_word)
                else:
                    for string in self.encode(encoder_name, payload_word):
                        yield string

    def __next__(self):
        return next(self.__generator)


class TupleIt(BaseDictionary, BaseIterator):
    def __init__(self, parent):
        self.parent = parent

    def count(self):
        return self.parent.count()

    def width(self):
        return 1

    def payloads(self):
        return [self.parent]

    def next_word(self):
        return (next(self.parent),)


class WrapperIt(BaseDictionary):
    def __init__(self, iterator):
        self._it = iter(iterator)

    def count(self):
        return -1

    def next_word(self):
        return FuzzWord(str(next(self._it)), FuzzWordType.WORD)


class SliceIt(BaseDictionary):
    def __init__(self, payload, slicestr):
        self.ffilter = FuzzResFilterSlice(filter_string=slicestr)
        self.payload = payload

    def count(self):
        return -1

    def next_word(self):
        item = next(self.payload)
        while not self.ffilter.is_visible(item.content):
            item = next(self.payload)

        return item


class AllVarDictio(BaseDictionary, BaseIterator):
    def __init__(self, iterator, allvar_len):
        self._it = iter(iterator)
        self._count = allvar_len

    def count(self):
        return self._count

    def width(self):
        return 0

    def payloads(self):
        return []

    def next_word(self):
        var_name, fuzz_word = next(self._it)
        return (FuzzWord(var_name, FuzzWordType.WORD), fuzz_word)
