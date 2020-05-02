import re

from ..fuzzrequest import FuzzRequest
from ..fuzzobjects import (
    FPayloadManager,
    FuzzResult,
    FuzzWord,
    FuzzWordType
)
from ..exception import FuzzExceptBadOptions
from ..helpers.obj_dyn import (
    rgetattr,
    rsetattr,
)

from ..helpers.obj_factory import ObjectFactory


class FuzzRequestFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(self, {
            'request_from_options': RequestBuilder(),
            'request_removing_baseline_markers': SeedBuilder(),
            'baseline_payloadman_from_request': BaselinePayloadBuilder(),
            'seed_payloadman_from_request': SeedPayloadBuilder(),
            'empty_payloadman': OnePayloadBuilder(),
        })


class SeedBuilderHelper:
    FUZZ_MARKERS_REGEX = re.compile(r"(?P<full_marker>(?P<word>FUZ(?P<index>\d)*Z)(?P<nonfuzz_marker>(?:\[(?P<field>.*?)\])?(?P<full_bl>\{(?P<bl_value>.*?)\})?))")
    REQ_ATTR = [
        "raw_request",
        "scheme",
        "method",
        # "auth.credentials"
    ]

    @staticmethod
    def _get_markers(text):
        return [m.groupdict() for m in SeedBuilderHelper.FUZZ_MARKERS_REGEX.finditer(text)]

    @staticmethod
    def get_marker_dict(freq):
        marker_dict_list = []

        for text in [rgetattr(freq, field) for field in SeedBuilderHelper.REQ_ATTR]:
            marker_dict_list += SeedBuilderHelper._get_markers(text)

        # validate
        if len({bd['bl_value'] is None for bd in marker_dict_list}) > 1:
            raise FuzzExceptBadOptions("You must supply a baseline value per FUZZ word.")

        return marker_dict_list

    @staticmethod
    def _remove_markers(freq, markers, mark_name):
        scheme = freq.scheme
        for mark in [mark[mark_name] for mark in markers if mark[mark_name] is not None]:
            for field in SeedBuilderHelper.REQ_ATTR:
                old_value = rgetattr(freq, field)
                new_value = old_value.replace(mark, '')

                if field == "raw_request":
                    freq.update_from_raw_http(new_value, scheme)
                else:
                    rsetattr(freq, field, new_value, None)

    @staticmethod
    def remove_baseline_markers(freq, markers):
        SeedBuilderHelper._remove_markers(freq, markers, "full_bl")
        return freq

    @staticmethod
    def remove_nonfuzz_markers(freq, markers):
        SeedBuilderHelper._remove_markers(markers, "nonfuzz_marker")
        return freq

    # Not working due to reqresp internals
    # def replace_markers(self, seed, fpm):
    #     for payload in fpm.get_payloads():
    #         for field in self.REQ_ATTR:
    #             old_value = rgetattr(seed, field)
    #             new_value = old_value.replace(payload.marker, payload.value)
    #             rsetattr(seed, field, new_value , None)

    @staticmethod
    def replace_markers(freq, fpm):
        rawReq = str(freq)
        rawUrl = freq.redirect_url
        scheme = freq.scheme
        auth_method, userpass = freq.auth

        for payload in [payload for payload in fpm.get_payloads() if payload.marker is not None]:
            userpass = userpass.replace(payload.marker, payload.value)
            rawUrl = rawUrl.replace(payload.marker, payload.value)
            rawReq = rawReq.replace(payload.marker, payload.value)
            scheme = scheme.replace(payload.marker, payload.value)

        freq.update_from_raw_http(rawReq, scheme)
        freq.url = rawUrl
        if auth_method != 'None':
            freq.auth = (auth_method, userpass)

        return freq


class RequestBuilder:
    def __call__(self, options):
        fr = FuzzRequest()

        fr.url = options['url']
        fr.wf_fuzz_methods = options['method']
        fr.update_from_options(options)

        return fr


class SeedBuilder:
    def __call__(self, freq):
        my_req = freq.from_copy()

        marker_dict = SeedBuilderHelper.get_marker_dict(my_req)
        SeedBuilderHelper.remove_baseline_markers(my_req, marker_dict)

        return my_req


class SeedPayloadBuilder:
    def __call__(self, freq):
        fpm = FPayloadManager()

        for pdict in [pdict for pdict in SeedBuilderHelper.get_marker_dict(freq) if pdict["word"] is not None]:
            fpm.add(pdict)

        return fpm


class OnePayloadBuilder:
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


class BaselinePayloadBuilder:
    def __call__(self, freq):
        fpm = FPayloadManager()

        for pdict in [pdict for pdict in SeedBuilderHelper.get_marker_dict(freq) if pdict["bl_value"] is not None]:
            fpm.add(pdict, FuzzWord(pdict["bl_value"], FuzzWordType.WORD), True)

        return fpm


class FuzzResultBuilder:
    def __call__(self, fpm, freq):
        return self.create_fuzz_result(fpm, freq)

    def create_fuzz_result(self, fpm, freq):
        my_req = freq.from_copy()
        SeedBuilderHelper.replace_markers(my_req, fpm)

        fr = FuzzResult(my_req)
        fr.payload_man = fpm

        return fr


reqfactory = FuzzRequestFactory()
