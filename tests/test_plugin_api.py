import pytest

from wfuzz.plugin_api.base import str_to_bool

def test_str_to_bool_true_values():
    for value in ["y", "yes", "t", "true", "on", "1", "Y", "TRUE"]:
        assert str_to_bool(value) is True


def test_str_to_bool_false_values():
    for value in ["n", "no", "f", "false", "off", "0", "N", "FALSE"]:
        assert str_to_bool(value) is False


def test_str_to_bool_invalid_value():
    with pytest.raises(ValueError):
        str_to_bool("banana")
