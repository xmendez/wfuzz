import pytest


@pytest.mark.parametrize(
    "fuzzres_from_url, filter_string, expected_result",
    [
        (
            "http://www.wfuzz.org/path/test.php?param=1&param2=2",
            "r.urlp.scheme='http'",
            True,
        ),
        (
            "http://www.wfuzz.org/path/test.php?param=1&param2=2",
            "r.urlp.netloc='www.wfuzz.org'",
            True,
        ),
        (
            "http://www.wfuzz.org/path/test.php?param=1&param2=2",
            "r.urlp.path='/path/test.php'",
            True,
        ),
        (
            "http://www.wfuzz.org/path/test.php?param=1&param2=2",
            "r.urlp.ffname='test.php'",
            True,
        ),
        (
            "http://www.wfuzz.org/path/test.php?param=1&param2=2",
            "r.urlp.fname='test'",
            True,
        ),
        (
            "http://www.wfuzz.org/path/test.php?param=1&param2=2",
            "r.urlp.hasquery",
            True,
        ),
        (
            "http://www.wfuzz.org/path/test.php?param=1&param2=2",
            "not r.urlp.isbllist",
            True,
        ),
    ],
    indirect=["fuzzres_from_url"],
)
def test_urlp(filter_obj, fuzzres_from_url, filter_string, expected_result):
    assert filter_obj.is_visible(fuzzres_from_url, filter_string) == expected_result


@pytest.mark.parametrize(
    "fuzzres_from_url, filter_string, expected_result",
    [("http://www.wfuzz.org/path?param=1&param2=2", "r.is_path", False)],
    indirect=["fuzzres_from_url"],
)
def test_ispath(filter_obj, fuzzres_from_url, filter_string, expected_result):
    assert filter_obj.is_visible(fuzzres_from_url, filter_string) == expected_result


@pytest.mark.parametrize(
    "fuzzres_from_url, filter_string, expected_result",
    [
        (
            "http://www.wfuzz.org/path?param=1&param2=2",
            "r.pstrip",
            "http://www.wfuzz.org/path-gparam-gparam2",
        ),
    ],
    indirect=["fuzzres_from_url"],
)
def test_pstrip(filter_obj, fuzzres_from_url, filter_string, expected_result):
    assert filter_obj.is_visible(fuzzres_from_url, filter_string) == expected_result
