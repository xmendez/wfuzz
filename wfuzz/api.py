from .core import Fuzzer
from .core import dictionary
from .options import FuzzSession
from .facade import Facade

'''
Wfuzz API
---------

Examples:

wfuzz.fuzz('http://www.google.com/FUZZ', [1,2,3])
wfuzz.fuzz('http://httpbin.org/post', postdata = {'key':'value'}
wfuzz.fuzz(url, hc=[404], headers=[('user-agent', 'my-app/0.0.1')])
wfuzz.fuzz(('http://example.org', proxies=[('10.10.1.10', '3128', 'http')])


wfuzz.payload(type="file", params="", extra="").fuzz("http://www.google.com/FUZZ")

with wfuzz.payload(..) as p:
    p.fuzz('http://httpbin.org/cookies/set/sessioncookie/123456789')

s = fuzz.session()
s.auth = ('user', 'pass')
s.headers.append(('x-test': 'true'))

s.fuzz('http://httpbin.org/headers', headers={'x-test2': 'true'})

with wfuzz.session() as s:
    s.fuzz('http://httpbin.org/cookies/set/sessioncookie/123456789')

'''

def fuzz(**kwargs):
    """Constructs and sends a :class:`Request <Request>`.

    :param url: URL for the new :class:`FuzzSession` object.
    :param payload: payload for the new :class:`FuzzSession` object.
    :param filter: (Optional) filter the shown results with the provided filter string.
    :param prefilter: (Optional) filter the given payload with the provided prefilter string.
    :param hs: (Optional) Hide :class:`FuzzResult` using the provided regex.
    :param hc: (Optional) Hide :class:`FuzzResult` using the provided http codes.
    :param hw: (Optional) Hide :class:`FuzzResult` using the provided word number.
    :param hl: (Optional) Hide :class:`FuzzResult` using the provided lines number.
    :param hh: (Optional) Hide :class:`FuzzResult` using the provided charachers number.
    :param ss: (Optional) Show :class:`FuzzResult` using the provided regex.
    :param sc: (Optional) Show :class:`FuzzResult` using the provided http codes.
    :param sw: (Optional) Show :class:`FuzzResult` using the provided word number.
    :param sl: (Optional) Show :class:`FuzzResult` using the provided lines number.
    :param sh: (Optional) Show :class:`FuzzResult` using the provided charachers number.
    :return: :class:`Fuzzer <Fuzzer>` object
    :rtype: wfuzz.core.Fuzzer

    Usage::
    

      >>> import wfuzz
      >>> results = wfuzz.fuzz('http://www.google.com/FUZZ', [("range", dict(range="0-10"), ["md5", "sha1"])])
    """

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

def get_dictio(name, params, sliceit = None):
    payloads_list = []
    payloads_list.append((name, params, sliceit))
    options = dict(dictio=None, payloads=payloads_list, iterator="")

    return dictionary.from_options(options)

