import pytest


@pytest.mark.parametrize(
    "filter_string, expected_result",
    [
        ("h=28 or w=6 or l=2", True),
        ("r.params.get.param2='2'", True),
        ("r.headers.response.Location", 'https://wfuzz.readthedocs.io/en/latest/')
    ],
)
def test_lwh(filter_obj, example_full_fuzzres, filter_string, expected_result):
    assert filter_obj.is_visible(example_full_fuzzres, filter_string) == expected_result
