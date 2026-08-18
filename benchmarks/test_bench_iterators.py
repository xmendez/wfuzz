"""Benchmarks for the payload combination iterators.

When several payloads are given (-z ... -z ...), an iterator combines them. The
cost of that combination is paid for every request wfuzz sends.
"""

from wfuzz.dictionaries import TupleIt
from wfuzz.plugins.iterators.iterations import chain, product
from wfuzz.plugins.iterators.iterations import zip as zip_it
from wfuzz.plugins.payloads.range import range as range_payload


def make_payload(spec="0-999"):
    return range_payload({"default": spec})


def test_iterator_zip(benchmark):
    def run():
        return list(zip_it(make_payload(), make_payload(), make_payload()))

    assert len(benchmark(run)) == 1000


def test_iterator_chain(benchmark):
    def run():
        return list(chain(make_payload(), make_payload(), make_payload()))

    assert len(benchmark(run)) == 3000


def test_iterator_product(benchmark):
    def run():
        return list(product(make_payload("0-99"), make_payload("0-99")))

    assert len(benchmark(run)) == 10000


def test_iterator_product_three_payloads(benchmark):
    def run():
        return list(
            product(make_payload("0-19"), make_payload("0-19"), make_payload("0-19"))
        )

    assert len(benchmark(run)) == 8000


def test_iterator_single_payload(benchmark):
    def run():
        return list(TupleIt(make_payload("0-4999")))

    assert len(benchmark(run)) == 5000
