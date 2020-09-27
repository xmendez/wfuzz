# Python 2 and 3: zip_longest
try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest

from ..helpers.obj_factory import ObjectFactory
from ..exception import FuzzExceptBadOptions
from ..facade import Facade
from ..dictionaries import (
    TupleIt,
    WrapperIt,
    SliceIt,
    EncodeIt,
    AllVarDictio,
)


class DictionaryFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(
            self,
            {
                "dictio_from_iterable": DictioFromIterableBuilder(),
                "dictio_from_payload": DictioFromPayloadBuilder(),
                "dictio_from_allvar": DictioFromAllVarBuilder(),
                "dictio_from_options": DictioFromOptions(),
            },
        )


class BaseDictioBuilder:
    @staticmethod
    def validate(options, selected_dic):
        if not selected_dic:
            raise FuzzExceptBadOptions("Empty dictionary! Check payload and filter")

        if len(selected_dic) == 1 and options["iterator"]:
            raise FuzzExceptBadOptions(
                "Several dictionaries must be used when specifying an iterator"
            )

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

        for payload in options["payloads"]:
            try:
                name, params, slicestr = [
                    x[0] for x in zip_longest(payload, (None, None, None))
                ]
            except ValueError:
                raise FuzzExceptBadOptions(
                    "You must supply a list of payloads in the form of [(name, {params}), ... ]"
                )

            if not params:
                raise FuzzExceptBadOptions(
                    "You must supply a list of payloads in the form of [(name, {params}), ... ]"
                )

            dictionary = Facade().payloads.get_plugin(name)(params)
            if "encoder" in params and params["encoder"] is not None:
                dictionary = EncodeIt(dictionary, params["encoder"])

            selected_dic.append(
                SliceIt(dictionary, slicestr) if slicestr else dictionary
            )

        self.validate(options, selected_dic)

        return self.get_dictio(options, selected_dic)


class DictioFromAllVarBuilder(BaseDictioBuilder):
    @staticmethod
    def from_all_fuzz_request_gen(options, dictio_list):
        for payload in dictio_list:
            if len(payload) > 1:
                raise FuzzExceptBadOptions(
                    "Only one payload is allowed when fuzzing all parameters!"
                )

            for var_name in options["compiled_seed"].history.wf_allvars_set.keys():
                yield (var_name, payload[0])

    def __call__(self, options):
        dictio_list = DictioFromOptions()(options)

        return AllVarDictio(
            self.from_all_fuzz_request_gen(options, dictio_list),
            dictio_list.count() * len(options["compiled_seed"].history.wf_allvars_set),
        )


class DictioFromOptions(BaseDictioBuilder):
    def __call__(self, options):
        if options["dictio"]:
            return DictioFromIterableBuilder()(options)
        else:
            return DictioFromPayloadBuilder()(options)


dictionary_factory = DictionaryFactory()
