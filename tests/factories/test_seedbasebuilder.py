import pytest

from wfuzz.factories.fuzzfactory import SeedBuilderHelper


@pytest.mark.parametrize(
    "full_fuzzreq, expected_result",
    [
        (
            (
                "GET /FUZZ HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                None,
            ),
            [
                {
                    "bl_value": None,
                    "field": None,
                    "full_bl": None,
                    "full_marker": "FUZZ",
                    "index": None,
                    "nonfuzz_marker": "",
                    "word": "FUZZ",
                }
            ],
        ),
        (
            (
                "GET /FUZZ{a_bl_value} HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                None,
            ),
            [
                {
                    "bl_value": "a_bl_value",
                    "field": None,
                    "full_bl": "{a_bl_value}",
                    "full_marker": "FUZZ{a_bl_value}",
                    "index": None,
                    "nonfuzz_marker": "{a_bl_value}",
                    "word": "FUZZ",
                }
            ],
        ),
        (
            (
                "GET /FUZZ[url] HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                None,
            ),
            [
                {
                    "bl_value": None,
                    "field": "url",
                    "full_bl": None,
                    "full_marker": "FUZZ[url]",
                    "index": None,
                    "nonfuzz_marker": "[url]",
                    "word": "FUZZ",
                }
            ],
        ),
        (
            (
                "GET /FUZZ/FUZ2Z[url] HTTP/1.1\n"
                "Host: www.wfuzz.org\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "User-Agent: Wfuzz/2.1\n",
                None,
            ),
            [
                {
                    "bl_value": None,
                    "field": None,
                    "full_bl": None,
                    "full_marker": "FUZZ",
                    "index": None,
                    "nonfuzz_marker": "",
                    "word": "FUZZ",
                },
                {
                    "bl_value": None,
                    "field": "url",
                    "full_bl": None,
                    "full_marker": "FUZ2Z[url]",
                    "index": "2",
                    "nonfuzz_marker": "[url]",
                    "word": "FUZ2Z",
                },
            ],
        ),
    ],
    indirect=["full_fuzzreq"],
)
def test_get_marker_dict(full_fuzzreq, expected_result):
    assert SeedBuilderHelper().get_marker_dict(full_fuzzreq) == expected_result
