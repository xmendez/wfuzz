import pytest


@pytest.mark.parametrize(
    "filter_string, expected_result",
    [
        ("h=28 or w=6 or l=2", True),
        ("r.params.get.param2='2'", True),
        ("r.headers.response.Location", "https://wfuzz.readthedocs.io/en/latest/"),
        ("r.headers.response.notthere", {}),
        ("r.params.get.notthere", {}),
        ("r.cookies.response.notthere", {}),
        ("r.cookies.response.notthere='something'", False),
        ("r.cookies.response.notthere~'something'", False),
        ("r.headers.request.Host", "www.wfuzz.org"),
        ("r.headers.request.host", "www.wfuzz.org"),
        ("r.headers.response.SeRVEr", "nginx/1.14.0 (Ubuntu)"),
        ("r.headers.response.server", "nginx/1.14.0 (Ubuntu)"),
        ("r.cookies.request.cookie1", "1"),
        ("r.cookies.request.cOOkiE1", "1"),
        ("r.cookies.response.name", "Nicholas"),
        ("r.cookies.response.nAMe", "Nicholas"),
        ("r.params.get.param1", "1"),
        ("r.params.get.pAraM1", "1"),
    ],
)
def test_filter_ret_values(
    filter_obj, example_full_fuzzres, filter_string, expected_result
):
    assert filter_obj.is_visible(example_full_fuzzres, filter_string) == expected_result


@pytest.mark.parametrize(
    "filter_string, expected_result",
    [
        ("r.headers.response.notthere", {}),
        ("r.params.get.notthere", {}),
        ("r.cookies.response.notthere", {}),
        ("r.cookies.response.notthere='something'", False),
    ],
)
def test_filter_ret_values_no_response(
    filter_obj, example_full_fuzzres_no_response, filter_string, expected_result
):
    assert (
        filter_obj.is_visible(example_full_fuzzres_no_response, filter_string)
        == expected_result
    )
