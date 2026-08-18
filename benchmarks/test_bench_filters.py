"""Benchmarks for the result filters.

The filter language is evaluated for every single result, and the pyparsing
grammar is built every time a filter is created.
"""

import re

import pytest

from wfuzz.filters.ppfilter import FuzzResFilter
from wfuzz.filters.simplefilter import FuzzResSimpleFilter

FILTERS = {
    "code": "c=200",
    "size": "l>2 and w>100 and h>1000",
    "header": "r.headers.response.Server~'nginx'",
    "content": "content~'benchmark' and not content~'missing'",
    "url_params": "r.params.get.lang='en' and r.url~'login'",
    "nested": "(c=200 and w>10) or (c=404 and w<10)",
}


@pytest.mark.parametrize("filter_name", sorted(FILTERS))
def test_filter_creation(benchmark, filter_name):
    filter_string = FILTERS[filter_name]

    ffilter = benchmark(lambda: FuzzResFilter(filter_string=filter_string))

    assert ffilter is not None


@pytest.mark.parametrize("filter_name", sorted(FILTERS))
def test_filter_is_visible(benchmark, fuzz_result, filter_name):
    ffilter = FuzzResFilter(filter_string=FILTERS[filter_name])

    assert benchmark(lambda: ffilter.is_visible(fuzz_result)) is not None


def test_filter_is_visible_many_results(benchmark, fuzz_result):
    """Filtering a batch of results, as done when consuming a wordlist."""
    ffilter = FuzzResFilter(filter_string=FILTERS["size"])
    results = [fuzz_result] * 100

    assert len(benchmark(lambda: [ffilter.is_visible(r) for r in results])) == 100


def test_simple_filter_codes(benchmark, fuzz_result):
    ffilter = FuzzResSimpleFilter()
    ffilter.hideparams["codes_show"] = False
    ffilter.hideparams["codes"] = [404, 403, 500]
    results = [fuzz_result] * 100

    assert all(benchmark(lambda: [ffilter.is_visible(r) for r in results]))


def test_simple_filter_regex(benchmark, fuzz_result):
    ffilter = FuzzResSimpleFilter()
    ffilter.hideparams["regex_show"] = True
    ffilter.hideparams["regex"] = re.compile("Item 149", re.MULTILINE | re.DOTALL)
    results = [fuzz_result] * 20

    assert all(benchmark(lambda: [ffilter.is_visible(r) for r in results]))
