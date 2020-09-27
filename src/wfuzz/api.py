from .options import FuzzSession
from .facade import Facade
from .ui.console.clparser import CLParser

"""
Wfuzz API
"""


def fuzz(**kwargs):
    return FuzzSession(**kwargs).fuzz()


def get_payloads(iterator):
    fs = FuzzSession()

    return fs.get_payloads(iterator)


def get_payload(iterator):
    fs = FuzzSession()
    return fs.get_payload(iterator)


def encode(name, value):
    return Facade().encoders.get_plugin(name)().encode(value)


def decode(name, value):
    return Facade().encoders.get_plugin(name)().decode(value)


def payload(**kwargs):
    return FuzzSession(**kwargs).payload()


def get_session(cline):
    cl = ["wfuzz"] + cline.split(" ")
    return FuzzSession(**CLParser(cl).parse_cl())
