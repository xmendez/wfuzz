import pytest


@pytest.mark.parametrize(
    "filter_string, expected_result",
    [
        ("h=28 or w=6 or l=2", True)
    ],
)
def test_lwh(filter_obj, example_full_fuzzres, filter_string, expected_result):
    filter_obj.is_visible(example_full_fuzzres, filter_string)
    assert example_full_fuzzres.code == expected_result


@pytest.mark.parametrize(
    "filter_string, expected_result",
    [
        ("r.params.get.param2='2'", True)
    ],
)
def test_params(filter_obj, example_full_fuzzres, filter_string, expected_result):
    filter_obj.is_visible(example_full_fuzzres, filter_string)
    assert example_full_fuzzres.code == expected_result


@pytest.mark.parametrize(
    "filter_string, expected_result",
    [
        ("r.headers.response.Location", True)
    ],
)
def test_headers(filter_obj, example_full_fuzzres, filter_string, expected_result):
    filter_obj.is_visible(example_full_fuzzres, filter_string)
    assert example_full_fuzzres.code == expected_result
