from ..fuzzobjects import (
    FPayloadManager,
    FuzzWord,
    FuzzWordType
)

from ..helpers.obj_factory import (
    ObjectFactory,
    SeedBuilderHelper
)


class PayManFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(self, {
            'baseline_payloadman_from_request': BaselinePayloadManBuilder(),
            'seed_payloadman_from_request': SeedPayloadManBuilder(),
            'empty_payloadman': OnePayloadManBuilder(),
        })


class SeedPayloadManBuilder:
    def __call__(self, freq):
        fpm = FPayloadManager()

        for pdict in [pdict for pdict in SeedBuilderHelper.get_marker_dict(freq) if pdict["word"] is not None]:
            fpm.add(pdict)

        return fpm


class OnePayloadManBuilder:
    def __call__(self, dictio_item):
        fpm = FPayloadManager()
        fpm.add({
            "full_marker": None,
            "word": None,
            "index": None,
            "field": None
        }, dictio_item[0])

        fpm.update_from_dictio(dictio_item)

        return fpm


class BaselinePayloadManBuilder:
    def __call__(self, freq):
        fpm = FPayloadManager()

        for pdict in [pdict for pdict in SeedBuilderHelper.get_marker_dict(freq) if pdict["bl_value"] is not None]:
            fpm.add(pdict, FuzzWord(pdict["bl_value"], FuzzWordType.WORD), True)

        return fpm


payman_factory = PayManFactory()
