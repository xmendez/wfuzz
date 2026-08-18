"""Benchmarks for the payload plugins.

Payloads generate the words that are injected in the fuzzed requests. Iterating
a full payload is what determines how fast a wordlist can be consumed.
"""

import pytest

from wfuzz.plugins.payloads.buffer_overflow import buffer_overflow
from wfuzz.plugins.payloads.file import file as file_payload
from wfuzz.plugins.payloads.hexrange import hexrange
from wfuzz.plugins.payloads.list import list as list_payload
from wfuzz.plugins.payloads.names import names
from wfuzz.plugins.payloads.permutation import permutation
from wfuzz.plugins.payloads.range import range as range_payload


def drain(payload):
    return [word.content for word in payload]


def test_payload_range(benchmark):
    words = benchmark(lambda: drain(range_payload({"default": "0-5000"})))

    assert len(words) == 5001


def test_payload_hexrange(benchmark):
    words = benchmark(lambda: drain(hexrange({"default": "0-fff"})))

    assert len(words) == 4096


def test_payload_permutation(benchmark):
    words = benchmark(lambda: drain(permutation({"default": "abcdef0123-3"})))

    assert len(words) == 1000


def test_payload_buffer_overflow(benchmark):
    words = benchmark(lambda: drain(buffer_overflow({"default": "50000"})))

    assert len(words[0]) == 50000


def test_payload_list(benchmark, words):
    spec = "-".join(word.replace("-", "\\-") for word in words)

    generated = benchmark(lambda: drain(list_payload({"default": spec})))

    assert len(generated) == len(words)


def test_payload_names(benchmark):
    generated = benchmark(lambda: drain(names({"default": "john-fitzgerald-smith"})))

    assert len(generated) > 10


def test_payload_file(benchmark, common_wordlist_path):
    """Reads a wordlist from disk, including the encoding auto-detection."""

    def run():
        payload = file_payload(
            {"fn": common_wordlist_path, "count": "False", "encoding": "Auto"}
        )
        try:
            return drain(payload)
        finally:
            payload.close()

    assert len(benchmark(run)) > 900


def test_payload_file_fixed_encoding(benchmark, common_wordlist_path):
    """Same as above without the chardet based encoding detection."""

    def run():
        payload = file_payload(
            {"fn": common_wordlist_path, "count": "False", "encoding": "utf-8"}
        )
        try:
            return drain(payload)
        finally:
            payload.close()

    assert len(benchmark(run)) > 900


def test_payload_ipnet(benchmark):
    pytest.importorskip("netaddr")
    from wfuzz.plugins.payloads.ipnet import ipnet

    generated = benchmark(lambda: drain(ipnet({"default": "192.168.0.0/22"})))

    assert len(generated) == 1022


def test_payload_iprange(benchmark):
    pytest.importorskip("netaddr")
    from wfuzz.plugins.payloads.iprange import iprange

    generated = benchmark(
        lambda: drain(iprange({"default": "192.168.0.1-192.168.3.254"}))
    )

    assert len(generated) == 1022
