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


def test_missing_get_returns_default(case_dict):
    default = object()
    assert case_dict.get("missing") is None
    assert case_dict.get("MISSING", default) is default


@pytest.mark.parametrize("value", [None, 0, "replacement"])
def test_assignment_replaces_case_insensitive_key(case_dict, value):
    case_dict["ONE"] = value

    assert len(case_dict) == 1
    assert list(case_dict.items()) == [("ONE", value)]
    assert case_dict["one"] == value
    assert case_dict.get("oNe", "default") == value


def test_constructor_merges_case_insensitive_keys():
    case_dict = CaseInsensitiveDict({"Content-Type": "first", "content-type": "last"})

    assert len(case_dict) == 1
    assert dict(case_dict) == {"content-type": "last"}


def test_update_and_delete_case_insensitive_key(case_dict):
    case_dict.update({"oNe": 2})
    del case_dict["ONE"]

    assert not case_dict
    assert not list(case_dict)
    assert case_dict.get("one", "missing") == "missing"
    with pytest.raises(KeyError):
        case_dict["oNe"]
