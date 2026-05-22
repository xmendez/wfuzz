try:
    from unittest import mock
except ImportError:
    import mock

from wfuzz.helpers import file_func


def test_get_filter_help_file_uses_package_data():
    with mock.patch(
        "wfuzz.helpers.file_func.pkgutil.get_data",
        return_value=b"Package help",
    ):
        assert file_func.get_filter_help_file() == "Package help"


def test_get_filter_help_file_falls_back_to_development_file(tmpdir):
    help_file = tmpdir.join("advanced.rst")
    help_file.write("Development help")

    with mock.patch(
        "wfuzz.helpers.file_func.pkgutil.get_data",
        return_value=None,
    ):
        with mock.patch(
            "wfuzz.helpers.file_func.get_path",
            return_value=str(help_file),
        ):
            assert file_func.get_filter_help_file() == "Development help"
