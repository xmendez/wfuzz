import re
import abc

from ..helpers.obj_dyn import (
    rgetattr,
    rsetattr,
)
from ..exception import FuzzExceptBadOptions


class Singleton(type):
    """ Singleton metaclass. Use by defining the metaclass of a class Singleton,
        e.g.: class ThereCanBeOnlyOne:
                  __metaclass__ = Singleton
    """

    def __call__(class_, *args, **kwargs):
        if not class_.hasInstance():
            class_.instance = super(Singleton, class_).__call__(*args, **kwargs)
        return class_.instance

    def deleteInstance(class_):
        """ Delete the (only) instance. This method is mainly for unittests so
            they can start with a clean slate. """
        if class_.hasInstance():
            del class_.instance

    def hasInstance(class_):
        """ Has the (only) instance been created already? """
        return hasattr(class_, "instance")


class ObjectFactory:
    def __init__(self, builders):
        self._builders = builders

    def create(self, key, *args, **kwargs):
        builder = self._builders.get(key)
        if not builder:
            raise ValueError(key)
        return builder(*args, **kwargs)


class HttpRequestFactory(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def to_http_object(options, to_http, from_req):
        pass

    @staticmethod
    @abc.abstractmethod
    def from_http_object(options, from_http, raw_header, raw_body):
        pass


class SeedBuilderHelper:
    FUZZ_MARKERS_REGEX = re.compile(
        r"(?P<full_marker>(?P<word>FUZ(?P<index>\d)*Z)(?P<nonfuzz_marker>(?:\[(?P<field>.*?)\])?(?P<full_bl>\{(?P<bl_value>.*?)\})?))"
    )
    REQ_ATTR = ["raw_request", "scheme", "method", "auth.credentials"]

    @staticmethod
    def _get_markers(text):
        return [
            m.groupdict() for m in SeedBuilderHelper.FUZZ_MARKERS_REGEX.finditer(text)
        ]

    @staticmethod
    def get_marker_dict(freq):
        marker_dict_list = []

        for text in [rgetattr(freq, field) for field in SeedBuilderHelper.REQ_ATTR]:
            marker_dict_list += SeedBuilderHelper._get_markers(text)

        # validate
        if len({bd["bl_value"] is None for bd in marker_dict_list}) > 1:
            raise FuzzExceptBadOptions(
                "You must supply a baseline value per FUZZ word."
            )

        return marker_dict_list

    @staticmethod
    def _remove_markers(freq, markers, mark_name):
        scheme = freq.scheme
        for mark in [
            mark[mark_name] for mark in markers if mark[mark_name] is not None
        ]:
            for field in SeedBuilderHelper.REQ_ATTR:
                old_value = rgetattr(freq, field)
                new_value = old_value.replace(mark, "")

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
        old_auth = freq.auth

        for payload in [
            payload for payload in fpm.get_payloads() if payload.marker is not None
        ]:
            if old_auth.method:
                old_auth["credentials"] = old_auth["credentials"].replace(
                    payload.marker, str(payload.value)
                )
            rawUrl = rawUrl.replace(payload.marker, str(payload.value))
            rawReq = rawReq.replace(payload.marker, str(payload.value))
            scheme = scheme.replace(payload.marker, str(payload.value))

        freq.update_from_raw_http(rawReq, scheme)
        freq.url = rawUrl
        if old_auth.method:
            freq.auth = old_auth

        return freq
