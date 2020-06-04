import pytest


@pytest.mark.parametrize(
    "fuzzres_from_url, filter_string, expected_result",
    [
        (
            "http://www.wfuzz.org/path?param=1&param2=2",
            "r.url=+'test'",
            "http://www.wfuzz.org/path?param=1&param2=2test",
        ),
        ("http://www.wfuzz.org/path?param=1&param2=2", "r.url:='test'", "http://test/"),
        (
            "http://www.wfuzz.org/path?param=1&param2=2",
            "r.url=-'test'",
            "testhttp://www.wfuzz.org/path?param=1&param2=2",
        ),
    ],
    indirect=["fuzzres_from_url"],
)
def test_url_set(filter_obj, fuzzres_from_url, filter_string, expected_result):
    filter_obj.is_visible(fuzzres_from_url, filter_string)
    assert fuzzres_from_url.history.url == expected_result


@pytest.mark.parametrize(
    "fuzzres_from_url, filter_string, expected_result",
    [("http://www.wfuzz.org/path?param", "r.params.all=+'test'", {"param": None})],
    indirect=["fuzzres_from_url"],
)
def test_params_set_no_value(
    filter_obj, fuzzres_from_url, filter_string, expected_result
):
    filter_obj.is_visible(fuzzres_from_url, filter_string)
    assert fuzzres_from_url.history.params.get == expected_result


@pytest.mark.parametrize(
    "fuzzres_from_url, filter_string, expected_result",
    [
        (
            "http://www.wfuzz.org/path?param=1&param2=2",
            "r.params.get.param=+'test'",
            {"param": "1test", "param2": "2"},
        ),
        (
            "http://www.wfuzz.org/path?param=1&param2=2",
            "r.params.get.param=-'test'",
            {"param": "test1", "param2": "2"},
        ),
        (
            "http://www.wfuzz.org/path?param=1&param2=2",
            "r.params.all=+'2'",
            {"param": "12", "param2": "22"},
        ),
        (
            "http://www.wfuzz.org/path?param=1&param2=2",
            "r.params.all:='2'",
            {"param": "2", "param2": "2"},
        ),
        (
            "http://www.wfuzz.org/path?param=1&param2=2",
            "r.params.get.notthere=-'2'",
            {"param": "1", "param2": "2"},
        ),
        (
            "http://www.wfuzz.org/path?param=1&param2=2",
            "r.params.get.notthere=+'2'",
            {"param": "1", "param2": "2"},
        ),
        (
            "http://www.wfuzz.org/path?param=1&param2=2",
            "r.params.get.notthere:='2'",
            {"notthere": "2", "param": "1", "param2": "2"},
        ),
    ],
    indirect=["fuzzres_from_url"],
)
def test_params_set(filter_obj, fuzzres_from_url, filter_string, expected_result):
    filter_obj.is_visible(fuzzres_from_url, filter_string)
    assert fuzzres_from_url.history.params.all == expected_result
