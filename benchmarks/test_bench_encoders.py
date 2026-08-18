"""Benchmarks for the payload encoders.

Encoders are applied to every single word of a wordlist while fuzzing, so they
sit on the hottest path of wfuzz.
"""

import pytest

from wfuzz.plugins.encoders.encoders import (
    base64,
    double_urlencode,
    first_nibble_hex,
    hexlify,
    html_escape,
    md5,
    mssql_char,
    mysql_char,
    oracle_char,
    sha1,
    sha256,
    uri_double_hex,
    uri_hex,
    uri_unicode,
    urlencode,
    utf8,
)

ENCODERS = {
    "urlencode": urlencode,
    "double_urlencode": double_urlencode,
    "uri_hex": uri_hex,
    "uri_double_hex": uri_double_hex,
    "uri_unicode": uri_unicode,
    "first_nibble_hex": first_nibble_hex,
    "base64": base64,
    "hexlify": hexlify,
    "md5": md5,
    "sha1": sha1,
    "sha256": sha256,
    "html_escape": html_escape,
    "utf8": utf8,
    "mysql_char": mysql_char,
    "mssql_char": mssql_char,
    "oracle_char": oracle_char,
}

DECODERS = ["urlencode", "double_urlencode", "base64", "hexlify", "mysql_char"]


@pytest.mark.parametrize("encoder_name", sorted(ENCODERS))
def test_encode_wordlist(benchmark, words, encoder_name):
    encoder = ENCODERS[encoder_name]()

    encoded = benchmark(lambda: [encoder.encode(word) for word in words])

    assert len(encoded) == len(words)


@pytest.mark.parametrize("encoder_name", sorted(DECODERS))
def test_decode_wordlist(benchmark, words, encoder_name):
    encoder = ENCODERS[encoder_name]()
    encoded = [encoder.encode(word) for word in words]

    decoded = benchmark(lambda: [encoder.decode(word) for word in encoded])

    assert decoded == words


def test_encode_chained_encoders(benchmark, words):
    """Equivalent of the `md5@urlencode@base64` chained encoder syntax."""
    chain = [base64(), urlencode(), md5()]

    def run():
        result = []
        for word in words:
            value = word
            for encoder in chain:
                value = encoder.encode(value)
            result.append(value)
        return result

    assert len(benchmark(run)) == len(words)


def test_encode_injection_payloads(benchmark, words):
    """Encoding of special characters, the worst case for the url encoders."""
    payloads = ["../../etc/passwd?a=1&b=<script>'\"%s" % word for word in words[:200]]
    encoder = urlencode()

    assert len(benchmark(lambda: [encoder.encode(p) for p in payloads])) == len(
        payloads
    )
