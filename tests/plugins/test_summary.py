from wfuzz.factories.plugin_factory import plugin_factory
from wfuzz.fuzzobjects import FuzzPlugin

from queue import Queue


def test_sum_plugin_output(example_full_fuzzres):
    plugin = plugin_factory.create("plugin_from_summary", "a message")

    assert plugin.is_visible(True) is False
    assert plugin.is_visible(False) is True


def test_find_plugin_output_from_factory():
    plugin = plugin_factory.create(
        "plugin_from_finding",
        "a plugin",
        "a source",
        "an issue",
        "some data",
        FuzzPlugin.INFO,
    )

    assert plugin.is_visible(True) is True
    assert plugin.is_visible(False) is False


def test_find_plugin_output(get_plugin):
    plugin = get_plugin("links")[0]
    plugin.results_queue = Queue()
    plugin.add_result("a source", "an issue", "some data", FuzzPlugin.INFO)

    plugin_res = plugin.results_queue.get()

    assert plugin_res.is_visible(True) is True
    assert plugin_res.is_visible(False) is False
