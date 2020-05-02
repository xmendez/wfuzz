import copy

from .fuzzfactory import reqfactory
from .payman import payman_factory

from ..fuzzobjects import (
    FuzzResult,
)
from ..helpers.obj_factory import (
    ObjectFactory,
    SeedBuilderHelper
)


class FuzzResultFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(self, {
            'fuzzres_replace_markers': FuzzResultReplaceBuilder(),
            'fuzzres_from_options_and_dict': FuzzResultDictioBuilder(),
            'fuzzres_from_allvar': FuzzResultAllVarBuilder(),
            'seed_from_options': SeedResultBuilder(),
            'seed_from_options_and_dict': FuzzResultDictSeedBuilder(),
            'baseline_from_options': BaselineResultBuilder()
        })


class FuzzResultReplaceBuilder:
    def __call__(self, fpm, freq):
        my_req = freq.from_copy()
        SeedBuilderHelper.replace_markers(my_req, fpm)

        fr = FuzzResult(my_req)
        fr.payload_man = fpm

        return fr


class FuzzResultDictioBuilder:
    def __call__(self, options, dictio_item):
        payload_man = copy.deepcopy(options["compiled_seed"].payload_man)
        payload_man.update_from_dictio(dictio_item)

        res = resfactory.create("fuzzres_replace_markers", payload_man, options["compiled_seed"].history)
        res.update_from_options(options)

        return res


class SeedResultBuilder:
    def __call__(self, options):
        seed = reqfactory.create("seed_from_options", options)
        res = FuzzResult(seed)
        res.payload_man = payman_factory.create("seed_payloadman_from_request", seed)

        return res


class BaselineResultBuilder:
    def __call__(self, options):
        raw_seed = reqfactory.create("request_from_options", options)
        baseline_payloadman = payman_factory.create(
            "baseline_payloadman_from_request",
            raw_seed
        )

        if baseline_payloadman.payloads:
            res = resfactory.create("fuzzres_replace_markers", baseline_payloadman, raw_seed)
            res.is_baseline = True
            res._fields = options['fields']
            res._show_field = options['show_field']

            return res
        else:
            return None


class FuzzResultAllVarBuilder:
    def __call__(self, options, var_name, payload):
        fuzzres = FuzzResult(options["compiled_seed"].history.from_copy())
        fuzzres.payload_man = payman_factory.create("empty_payloadman", [payload])
        fuzzres.history.wf_allvars_set = {var_name: payload.content}

        return fuzzres


class FuzzResultDictSeedBuilder:
    def __call__(self, options, dictio):
        fuzzres = dictio[0].content.from_soft_copy()
        fuzzres.history.update_from_options(options)
        fuzzres.update_from_options(options)
        fuzzres.payload_man = payman_factory.create("empty_payloadman", dictio)

        return fuzzres


resfactory = FuzzResultFactory()
