import pytest

from wfuzz.fuzzobjects import FuzzWord, FuzzWordType
from wfuzz.factories.fuzzfactory import SeedBuilderHelper
from wfuzz.ui.console.clparser import CLParser
from wfuzz.factories.fuzzresfactory import resfactory

from wfuzz.helpers.obj_dyn import rgetattr
import wfuzz.api


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


@pytest.mark.parametrize(
    "session_string, dictio, expected_field, expected_result",
    [
        (
            "wfuzz http://www.wfuzz.io/FUZZ",
            [FuzzWord("sub1", FuzzWordType.WORD)],
            "url",
            "http://www.wfuzz.io/sub1",
        ),
        (
            "wfuzz --basic FUZZ:FUZ2Z http://www.wfuzz.io/",
            (FuzzWord("sub1", FuzzWordType.WORD), FuzzWord("sub2", FuzzWordType.WORD)),
            "auth.credentials",
            "sub1:sub2",
        ),
        (
            "wfuzz --basic FUZZ:FUZ2Z http://www.wfuzz.io/",
            (FuzzWord("sub1", FuzzWordType.WORD), FuzzWord("sub2", FuzzWordType.WORD)),
            "auth.method",
            "basic",
        ),
    ],
)
def test_replace_markers(session_string, dictio, expected_field, expected_result):
    options = CLParser(session_string.split(" ")).parse_cl()
    options.compile_seeds()

    res = resfactory.create("fuzzres_from_options_and_dict", options, dictio)

    assert rgetattr(res.history, expected_field) == expected_result
