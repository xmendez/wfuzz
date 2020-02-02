# Python 2 and 3: zip_longest
try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest

from ..utils import ObjectFactory
from ..exception import (
    FuzzExceptBadOptions,
    FuzzExceptNoPluginError
)
from ..facade import Facade
from ..filter import FuzzResFilterSlice


class Dictionary(object):
    def __init__(self, payload, encoders_list):
        self.__payload = payload
        self.__encoders = encoders_list
        self.__generator = self._gen() if self.__encoders else None

    def count(self):
        return (self.__payload.count() * len(self.__encoders)) if self.__encoders else self.__payload.count()

    def __iter__(self):
        return self

    def _gen(self):
        while 1:
            try:
                payload_list = next(self.__payload)
            except StopIteration:
                return

            for name in self.__encoders:
                if name.find('@') > 0:
                    string = payload_list
                    for i in reversed(name.split("@")):
                        string = Facade().encoders.get_plugin(i)().encode(string)
                    yield string
                else:
                    plugin_list = Facade().encoders.get_plugins(name)
                    if not plugin_list:
                        raise FuzzExceptNoPluginError(name + " encoder does not exists (-e encodings for a list of available encoders)")

                    for e in plugin_list:
                        yield e().encode(payload_list)

    def __next__(self):
        return next(self.__generator) if self.__encoders else next(self.__payload)


class TupleIt(object):
    def __init__(self, parent):
        self.parent = parent

    def count(self):
        return self.parent.count()

    def __next__(self):
        return (next(self.parent),)

    def __iter__(self):
        return self


class WrapperIt(object):
    def __init__(self, iterator):
        self._it = iter(iterator)

    def __iter__(self):
        return self

    def count(self):
        return -1

    def __next__(self):
        return str(next(self._it))


class SliceIt(object):
    def __init__(self, payload, slicestr):
        self.ffilter = FuzzResFilterSlice(filter_string=slicestr)
        self.payload = payload

    def __iter__(self):
        return self

    def count(self):
        return -1

    def __next__(self):
        item = next(self.payload)
        while not self.ffilter.is_visible(item):
            item = next(self.payload)

        return item


class DictionaryFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(self, {
            'dictio_from_iterable': DictioFromIterableBuilder(),
            'dictio_from_payload': DictioFromPayloadBuilder(),
        })


class BaseDictioBuilder:
    @staticmethod
    def validate(options, selected_dic):
        if not selected_dic:
            raise FuzzExceptBadOptions("Empty dictionary! Check payload and filter")

        if len(selected_dic) == 1 and options["iterator"]:
            raise FuzzExceptBadOptions("Several dictionaries must be used when specifying an iterator")

    @staticmethod
    def get_dictio(options, selected_dic):
        if len(selected_dic) == 1:
            return TupleIt(selected_dic[0])
        elif options["iterator"]:
            return Facade().iterators.get_plugin(options["iterator"])(*selected_dic)
        else:
            return Facade().iterators.get_plugin("product")(*selected_dic)


class DictioFromIterableBuilder(BaseDictioBuilder):
    def __call__(self, options):
        selected_dic = []
        self._payload_list = []

        for d in [WrapperIt(x) for x in options["dictio"]]:
            selected_dic.append(d)

        self.validate(options, selected_dic)

        return self.get_dictio(options, selected_dic)


class DictioFromPayloadBuilder(BaseDictioBuilder):
    def __call__(self, options):
        selected_dic = []
        self._payload_list = []

        for payload in options["payloads"]:
            try:
                name, params, slicestr = [x[0] for x in zip_longest(payload, (None, None, None))]
            except ValueError:
                raise FuzzExceptBadOptions("You must supply a list of payloads in the form of [(name, {params}), ... ]")

            if not params:
                raise FuzzExceptBadOptions("You must supply a list of payloads in the form of [(name, {params}), ... ]")

            p = Facade().payloads.get_plugin(name)(params)
            self._payload_list.append(p)
            pp = Dictionary(p, params["encoder"]) if "encoder" in params else p
            selected_dic.append(SliceIt(pp, slicestr) if slicestr else pp)

        self.validate(options, selected_dic)

        return self.get_dictio(options, selected_dic)


dictionary_factory = DictionaryFactory()
