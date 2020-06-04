from ..fuzzobjects import FPayloadManager, FuzzWord, FuzzWordType

from ..helpers.obj_factory import ObjectFactory, SeedBuilderHelper


class PayManFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(
            self,
            {
                "payloadman_from_baseline": BaselinePayloadManBuilder(),
                "payloadman_from_request": FuzzReqPayloadManBuilder(),
                "empty_payloadman": OnePayloadManBuilder(),
            },
        )


class FuzzReqPayloadManBuilder:
    def __call__(self, freq):
        fpm = FPayloadManager()

        for pdict in [
            pdict
            for pdict in SeedBuilderHelper.get_marker_dict(freq)
            if pdict["word"] is not None
        ]:
            fpm.add(pdict)

        return fpm


class OnePayloadManBuilder:
    def __call__(self, content):
        fpm = FPayloadManager()
        fpm.add(
            {"full_marker": None, "word": None, "index": None, "field": None}, content
        )

        return fpm


class BaselinePayloadManBuilder:
    def __call__(self, freq):
        fpm = FPayloadManager()

        for pdict in [
            pdict
            for pdict in SeedBuilderHelper.get_marker_dict(freq)
            if pdict["bl_value"] is not None
        ]:
            fpm.add(pdict, FuzzWord(pdict["bl_value"], FuzzWordType.WORD), True)

        return fpm


payman_factory = PayManFactory()
