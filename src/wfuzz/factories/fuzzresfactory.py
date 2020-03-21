import copy

from .fuzzfactory import reqfactory

from ..fuzzobjects import (
    FuzzResult,
)
from ..utils import (
    ObjectFactory
)


class FuzzResultFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(self, {
            'fuzzres_from_pm_and_request': FuzzResultBuilder(),
            'fuzzres_from_options_and_dict': FuzzResultDictioBuilder(),
            'fuzzres_from_allvar': FuzzResultAllVarBuilder(),
            'seed_from_options': SeedResultBuilder(),
            'baseline_from_options': BaselineResultBuilder()
        })


class FuzzResultBuilder:
    def __call__(self, fpm, freq):
        return self.create_fuzz_result(fpm, freq)

    def create_fuzz_result(self, fpm, freq):
        my_req = freq.from_copy()
        self.replace_markers(my_req, fpm)

        fr = FuzzResult(my_req)
        fr.payload_man = fpm

        return fr

    # Not working due to reqresp internals
    # def replace_markers(self, seed, fpm):
    #     for payload in fpm.get_payloads():
    #         for field in self.REQ_ATTR:
    #             old_value = rgetattr(seed, field)
    #             new_value = old_value.replace(payload.marker, payload.value)
    #             rsetattr(seed, field, new_value , None)

    def replace_markers(self, seed, fpm):
        rawReq = str(seed)
        rawUrl = seed.redirect_url
        scheme = seed.scheme
        auth_method, userpass = seed.auth

        for payload in [payload for payload in fpm.get_payloads() if payload.marker is not None]:
            userpass = userpass.replace(payload.marker, payload.value)
            rawUrl = rawUrl.replace(payload.marker, payload.value)
            rawReq = rawReq.replace(payload.marker, payload.value)
            scheme = scheme.replace(payload.marker, payload.value)

        seed.update_from_raw_http(rawReq, scheme)
        seed.url = rawUrl
        if auth_method != 'None':
            seed.auth = (auth_method, userpass)


class FuzzResultDictioBuilder(FuzzResultBuilder):
    def __call__(self, options, dictio_item):
        payload_man = copy.deepcopy(options["compiled_seed"].payload_man)
        payload_man.update_from_dictio(dictio_item)

        res = self.create_fuzz_result(payload_man, options["compiled_seed"].history)
        res.update_from_options(options)

        return res


class SeedResultBuilder(FuzzResultBuilder):
    def __call__(self, options):
        seed = reqfactory.create(
                "request_removing_baseline_markers",
                reqfactory.create("request_from_options", options)
        )

        res = FuzzResult(seed)
        res.payload_man = reqfactory.create("seed_payloadman_from_request", seed)

        return res


class BaselineResultBuilder(FuzzResultBuilder):
    def __call__(self, options):
        raw_seed = reqfactory.create("request_from_options", options)
        baseline_payloadman = reqfactory.create(
                "baseline_payloadman_from_request",
                raw_seed
        )

        if baseline_payloadman.payloads:
            res = FuzzResultBuilder()(baseline_payloadman, raw_seed)
            res.is_baseline = True
            res._description = options['description']
            res._show_field = options['show_field']

            return res
        else:
            return None


class FuzzResultAllVarBuilder(FuzzResultBuilder):
    def __call__(self, options, var_name, payload):
        fuzzres = FuzzResult(options["compiled_seed"].history.from_copy())
        fuzzres.payload_man = reqfactory.create("empty_payloadman", [payload])
        fuzzres.history.wf_allvars_set = {var_name: payload.content}

        return fuzzres


resfactory = FuzzResultFactory()
