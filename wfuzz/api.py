from .core import Fuzzer, Payload
from .options import FuzzSession, FuzzOptions

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

def fuzz(url, payloads, **kwargs):
    """Constructs and sends a :class:`Request <Request>`.

    :param url: URL for the new :class:`FuzzOptions` object.
    :param payload: payload for the new :class:`FuzzOptions` object.
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
      >>> results = wfuzz.fuzz('http://www.google.com/FUZZ', [1,2,3])
    """

    return Fuzzer(FuzzSession.from_options(FuzzOptions(url=url, payloads=payloads, **kwargs)))

def payload(name, params, encoders = None, extraparams = None, slice = None):
    """Constructs and sends a :class:`Request <Request>`.

    :param name: name of the payload
    :param params: payload params
    :param encoders: (Optional) payload encoder
    :param extraparams: (Optional) payload extraparameters
    :param slice: (Optional) paylosd's filter
    :return: list containing payload's parameters

    Usage::
    

      >>> import wfuzz
      >>> results = wfuzz.fuzz('http://www.google.com/FUZZ', wfuzz.payload("range", "0-10"))
    """


    p = Payload()
    p.add(name, params, extraparams, encoders, slice)

    return p

