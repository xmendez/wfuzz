import copy
import re

from ..fuzzrequest import FuzzRequest
from ..fuzzobjects import (
    FPayloadManager,
    FuzzResult,
    FuzzWord,
    FuzzWordType
)
from ..exception import FuzzExceptBadOptions
from ..utils import (
    rgetattr,
    rsetattr,
    ObjectFactory
)


class FuzzRequestFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(self, {
            'request_from_options': RequestBuilder(),
            'request_removing_baseline_markers': SeedBuilder(),
            'baseline_payloadman_from_request': BaselinePayloadBuilder(),
            'seed_payloadman_from_request': SeedPayloadBuilder(),
            'empty_payloadman': OnePayloadBuilder(),
            'fuzzres_from_pm_and_request': FuzzResultBuilder(),
            'fuzzres_from_options_and_dict': FuzzResultDictioBuilder(),
        })


class RequestBuilder:
    def __call__(self, options):
        fr = FuzzRequest()

        fr.url = options['url']
        fr.wf_fuzz_methods = options['method']
        fr.update_from_options(options)

        return fr


class SeedBaseBuilder:
    FUZZ_MARKERS_REGEX = re.compile(r"(?P<full_marker>(?P<word>FUZ(?P<index>\d)*Z)(?P<nonfuzz_marker>(?:\[(?P<field>.*?)\])?(?P<full_bl>\{(?P<bl_value>.*?)\})?))")
    REQ_ATTR = [
        "raw_request",
        "scheme",
        "method",
        # "auth.credentials"
    ]

    def _get_markers(self, text):
        return [m.groupdict() for m in self.FUZZ_MARKERS_REGEX.finditer(text)]

    def get_marker_dict(self, seed):
        marker_dict_list = []

        for text in [rgetattr(seed, field) for field in self.REQ_ATTR]:
            marker_dict_list += self._get_markers(text)

        # validate
        if len({bd['bl_value'] is None for bd in marker_dict_list}) > 1:
            raise FuzzExceptBadOptions("You must supply a baseline value per FUZZ word.")

        return marker_dict_list


class SeedBuilder(SeedBaseBuilder):
    def __call__(self, freq):
        my_req = freq.from_copy()

        marker_dict = self.get_marker_dict(my_req)
        self.remove_baseline_markers(my_req, marker_dict)

        return my_req

    def remove_markers(self, seed, markers, mark_name):
        scheme = seed.scheme
        for mark in [mark[mark_name] for mark in markers if mark[mark_name] is not None]:
            for field in self.REQ_ATTR:
                old_value = rgetattr(seed, field)
                new_value = old_value.replace(mark, '')

                if field == "raw_request":
                    seed.update_from_raw_http(new_value, scheme)
                else:
                    rsetattr(seed, field, new_value, None)

    def remove_baseline_markers(self, seed, markers):
        self.remove_markers(seed, markers, "full_bl")

    def remove_nonfuzz_markers(self, seed, markers):
        self.remove_markers(seed, markers, "nonfuzz_marker")


class SeedPayloadBuilder(SeedBaseBuilder):
    def __call__(self, freq):
        fpm = FPayloadManager()

        for pdict in [pdict for pdict in self.get_marker_dict(freq) if pdict["word"] is not None]:
            fpm.add(pdict)

        return fpm


class OnePayloadBuilder(SeedBaseBuilder):
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


class BaselinePayloadBuilder(SeedBaseBuilder):
    def __call__(self, freq):
        fpm = FPayloadManager()

        for pdict in [pdict for pdict in self.get_marker_dict(freq) if pdict["bl_value"] is not None]:
            fpm.add(pdict, FuzzWord(pdict["bl_value"], FuzzWordType.WORD), True)

        return fpm


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


reqfactory = FuzzRequestFactory()
