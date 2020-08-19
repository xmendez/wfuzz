import pytest


@pytest.mark.parametrize(
    "filter_string, expected_result",
    [("r.code:=429", 429), ("r.c:=404", 404), ("r.c=+404", 706), ("r.c=-2", 300)],
)
def test_code_set(filter_obj, example_full_fuzzres, filter_string, expected_result):
    filter_obj.is_visible(example_full_fuzzres, filter_string)
    assert example_full_fuzzres.code == expected_result
