import pytest

from wfuzz.helpers.obj_dic import CaseInsensitiveDict


@pytest.fixture
def case_dict():
    return CaseInsensitiveDict({"OnE": 1})


@pytest.mark.parametrize("key, expected_result", [("one", 1), ("oNe", 1)])
def test_key_get_item(case_dict, key, expected_result):
    assert case_dict[key] == expected_result
    assert case_dict.get(key) == expected_result


@pytest.mark.parametrize(
    "key, expected_result",
    [("One", True), ("OnE", True), ("one", True), ("onetwo", False)],
)
def test_key_in_item(case_dict, key, expected_result):
    assert (key in case_dict) == expected_result


def test_update():
    dd = CaseInsensitiveDict({})
    dd.update({"OnE": 1})

    assert dd["one"] == 1
    assert dd["oNe"] == 1


def test_key_in(case_dict):
    assert list(case_dict.keys()) == ["OnE"]
