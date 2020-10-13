import copy

from .fuzzfactory import reqfactory
from .payman import payman_factory

from ..fuzzobjects import FuzzResult, FuzzType, FuzzWord, FuzzWordType
from ..helpers.obj_factory import ObjectFactory, SeedBuilderHelper


class FuzzResultFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(
            self,
            {
                "fuzzres_from_options_and_dict": FuzzResultDictioBuilder(),
                "fuzzres_from_allvar": FuzzResultAllVarBuilder(),
                "fuzzres_from_recursion": FuzzResRecursiveBuilder(),
                "seed_from_recursion": SeedRecursiveBuilder(),
                "seed_from_options": SeedResultBuilder(),
                "seed_from_options_and_dict": FuzzResultDictSeedBuilder(),
                "baseline_from_options": BaselineResultBuilder(),
            },
        )


class FuzzResultDictioBuilder:
    def __call__(self, options, dictio_item):
        res = copy.deepcopy(options["compiled_seed"])
        res.item_type = FuzzType.RESULT
        res.discarded = False
        res.payload_man.update_from_dictio(dictio_item)
        res.update_from_options(options)

        SeedBuilderHelper.replace_markers(res.history, res.payload_man)
        res.nres = next(FuzzResult.newid)

        return res


class SeedResultBuilder:
    def __call__(self, options):
        seed = reqfactory.create("seed_from_options", options)
        res = FuzzResult(seed)
        res.payload_man = payman_factory.create("payloadman_from_request", seed)

        return res


class BaselineResultBuilder:
    def __call__(self, options):
        raw_seed = reqfactory.create("request_from_options", options)
        baseline_payloadman = payman_factory.create(
            "payloadman_from_baseline", raw_seed
        )

        if baseline_payloadman.payloads:
            res = FuzzResult(raw_seed)
            res.payload_man = baseline_payloadman
            res.update_from_options(options)
            res.is_baseline = True

            SeedBuilderHelper.replace_markers(raw_seed, baseline_payloadman)

            return res
        else:
            return None


class FuzzResultAllVarBuilder:
    def __call__(self, options, var_name, payload):
        fuzzres = copy.deepcopy(options["compiled_seed"])
        fuzzres.item_type = FuzzType.RESULT
        fuzzres.discarded = False
        fuzzres.payload_man = payman_factory.create("empty_payloadman", payload)
        fuzzres.payload_man.update_from_dictio([payload])
        fuzzres.history.wf_allvars_set = {var_name: payload.content}
        fuzzres.nres = next(FuzzResult.newid)

        return fuzzres


class FuzzResultDictSeedBuilder:
    def __call__(self, options, dictio):
        fuzzres = copy.deepcopy(dictio[0].content)
        fuzzres.history.update_from_options(options)
        fuzzres.update_from_options(options)
        fuzzres.payload_man = payman_factory.create("empty_payloadman", dictio[0])
        fuzzres.payload_man.update_from_dictio(dictio)

        return fuzzres


class SeedRecursiveBuilder:
    def __call__(self, seed):
        new_seed = copy.deepcopy(seed)
        new_seed.history.url = seed.history.recursive_url + "FUZZ"
        new_seed.rlevel += 1
        if new_seed.rlevel_desc:
            new_seed.rlevel_desc += " - "
        new_seed.rlevel_desc += seed.payload_man.description()
        new_seed.item_type = FuzzType.SEED
        new_seed.discarded = False
        new_seed.payload_man = payman_factory.create(
            "payloadman_from_request", new_seed.history
        )

        return new_seed


class FuzzResRecursiveBuilder:
    def __call__(self, seed, url):
        fr = copy.deepcopy(seed)
        fr.history.url = str(url)
        fr.rlevel = seed.rlevel + 1
        if fr.rlevel_desc:
            fr.rlevel_desc += " - "
        fr.rlevel_desc += seed.payload_man.description()
        fr.item_type = FuzzType.BACKFEED
        fr.discarded = False
        fr.is_baseline = False

        fr.payload_man = payman_factory.create(
            "empty_payloadman", FuzzWord(url, FuzzWordType.WORD)
        )

        return fr


resfactory = FuzzResultFactory()
