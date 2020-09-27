import pytest

from wfuzz.helpers.obj_dic import DotDict
from wfuzz.helpers.obj_dyn import rgetattr


@pytest.fixture
def dotdict_ex1():
    return DotDict({"a": "1"})


@pytest.fixture
def dotdict_ex2():
    return DotDict({"a": "2"})


def test_operators(dotdict_ex1, dotdict_ex2):
    assert dotdict_ex1 == {"a": "1"}
    assert dotdict_ex1 + "test" == {"a": "1test"}
    assert "test" + dotdict_ex1 == {"a": "test1"}
    assert dotdict_ex1 + dotdict_ex2 == {"a": "2"}
    assert dotdict_ex2 + dotdict_ex1 == {"a": "1"}


def test_nonexisting_key_returns_none(dotdict_ex1):
    assert dotdict_ex1["anything"] == {}


def test_nonexisting_attr_returns_empty_dict(dotdict_ex1):
    assert rgetattr(dotdict_ex1, "anything") == {}
