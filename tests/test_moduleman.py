import sys


try:
    # Python >= 3.3
    from unittest import mock
except ImportError:
    # Python < 3.3
    import mock

import unittest

from wfuzz.externals.moduleman.loader import DirLoader
from wfuzz.externals.moduleman.loader import FileLoader
from wfuzz.externals.moduleman.registrant import BRegistrant
from wfuzz.externals.moduleman.plugin import moduleman_plugin
import wfuzz.externals.moduleman.modulefilter as modulefilter


@moduleman_plugin
class test_plugin1:
    name = "test_plugin1"
    author = (("test plugin 1"),)
    version = "0.1"
    description = ("test plugin 1",)
    summary = "test plugin 1."
    category = ["aggressive"]
    priority = 79

    parameters = (("test", "", True, "test plugin 1"),)


@moduleman_plugin
class test_plugin2:
    name = "test_plugin2"
    author = (("test plugin 2"),)
    version = "0.1"
    description = ("test plugin 2",)
    summary = "test plugin 2."
    category = ["default"]
    priority = 89

    parameters = (("test", "", True, "test plugin 2"),)


@moduleman_plugin
class test_plugin3:
    name = "test_plugin3"
    author = (("test plugin 3"),)
    version = "0.1"
    description = ("test plugin 3",)
    summary = "test plugin 3."
    category = ["safe", "default"]
    priority = 99

    parameters = (("test", "", True, "test plugin 3"),)


class ModuleFilterTests(unittest.TestCase):
    def test_load_dir2(self):
        with mock.patch("os.listdir") as mocked_listdir:
            with mock.patch("os.path.isdir") as mocked_isdir:
                with mock.patch("os.path.isfile") as mocked_isfile:
                    with mock.patch("imp.find_module") as mocked_find_module:
                        with mock.patch("imp.load_module") as mocked_load_module:
                            mocked_listdir.return_value = ["alpha", "project.py"]
                            mocked_isdir.side_effect = [True, False]
                            mocked_isfile.return_value = True
                            mocked_find_module.return_value = (
                                None,
                                "/any/alpha/project.py",
                                (".py", "U", 1),
                            )
                            mocked_load_module.return_value = sys.modules[__name__]

                            br = BRegistrant(
                                DirLoader(**{"base_dir": "beta", "base_path": "any"})
                            )

                            self.assertEqual(
                                sorted(br.get_plugins_names()),
                                sorted(
                                    ["test_plugin1", "test_plugin2", "test_plugin3"]
                                ),
                            )
                            self.assertEqual(
                                br.get_plugins_names("default"),
                                ["test_plugin2", "test_plugin3"],
                            )
                            self.assertEqual(
                                br.get_plugins_names("aggressive"), ["test_plugin1"]
                            )
                            self.assertEqual(
                                sorted(br.get_plugins_names("not aggressive")),
                                sorted(["test_plugin2", "test_plugin3"]),
                            )
                            self.assertEqual(
                                sorted(br.get_plugins_names("default or aggressive")),
                                sorted(
                                    ["test_plugin1", "test_plugin2", "test_plugin3"]
                                ),
                            )
                            self.assertEqual(
                                sorted(br.get_plugins_names("default and safe")),
                                sorted(["test_plugin3"]),
                            )
                            self.assertEqual(
                                sorted(br.get_plugins_names("test_pl*")),
                                sorted(
                                    ["test_plugin1", "test_plugin2", "test_plugin3"]
                                ),
                            )
                            self.assertEqual(
                                sorted(br.get_plugins_names("test_plugin1")),
                                sorted(["test_plugin1"]),
                            )

    def test_load_file(self):
        with mock.patch("imp.find_module") as mocked_find_module:
            with mock.patch("imp.load_module") as mocked_load_module:
                mocked_find_module.return_value = (
                    None,
                    "any/project.py",
                    (".py", "U", 1),
                )
                mocked_load_module.return_value = sys.modules[__name__]

                br = BRegistrant(
                    FileLoader(**{"filename": "project1.py", "base_path": "any"})
                )

                self.assertEqual(
                    sorted(br.get_plugins_names()),
                    sorted(["test_plugin1", "test_plugin2", "test_plugin3"]),
                )

                self.assertTrue(br.get_plugin("test_plugin1").name == "test_plugin1")
                self.assertTrue(br.get_plugin("test_plugin2").name == "test_plugin2")

                with self.assertRaises(Exception) as context:
                    br.get_plugin("test_")
                self.assertTrue("Multiple plugins found" in str(context.exception))

    def test_simple_filter(self):
        with mock.patch("imp.find_module") as mocked_find_module:
            with mock.patch("imp.load_module") as mocked_load_module:
                mocked_find_module.return_value = (
                    None,
                    "/any/project.py",
                    (".py", "U", 1),
                )
                mocked_load_module.return_value = sys.modules[__name__]

                br = BRegistrant(
                    FileLoader(**{"filename": "project1.py", "base_path": "any"})
                )

                with self.assertRaises(Exception) as context:
                    modulefilter.PYPARSING = False
                    br.get_plugins_names("not aggressive")
                self.assertTrue(
                    "Pyparsing missing, complex filters not allowed."
                    in str(context.exception)
                )

                modulefilter.PYPARSING = False
                self.assertEqual(
                    sorted(br.get_plugins_names("test*")),
                    sorted(["test_plugin1", "test_plugin2", "test_plugin3"]),
                )
                self.assertEqual(
                    sorted(br.get_plugins_names("test_plugin1,test_plugin2")),
                    sorted(["test_plugin1", "test_plugin2"]),
                )
                self.assertEqual(
                    sorted(br.get_plugins_names("test_plugin5")), sorted([])
                )

    def test_plugin_decorator(self):
        with self.assertRaises(Exception) as context:

            @moduleman_plugin("method1")
            class test_plugin4:
                pass

            test_plugin4()
            self.assertTrue(
                "Required method method4 not implemented" in str(context.exception)
            )
