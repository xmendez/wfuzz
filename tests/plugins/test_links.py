import pytest
import re

from queue import Queue


@pytest.mark.parametrize(
    "example_full_fuzzres_content, expected_links",
    [
        # getting data-href for now (b'<link rel="manifest" data-href="/android-chrome-manifest.json">\n', [],),
        (
            b'<href="1.json"href="2.json">\n',
            ["http://www.wfuzz.org/1.json", "http://www.wfuzz.org/2.json"],
        ),
        (
            b'<link rel="manifest" href="/android-chrome-manifest.json">\n',
            ["http://www.wfuzz.org/android-chrome-manifest.json"],
        ),
        (
            b'<link rel="alternate" href="https://www.wfuzz.org/" hreflang="en-AE" />',
            ["https://www.wfuzz.org/"],
        ),
        (b'<link rel="dns-prefetch" href="https://www.wfuzz.io">\n', [],),
        (b'<script src="//js.wfuzz.org/sttc/main.93d0d236.js"></script>', [],),
    ],
    indirect=["example_full_fuzzres_content"],
)
def test_parsed_links(example_full_fuzzres_content, get_plugin, expected_links):
    links_plugin = get_plugin("links")[0]
    links_plugin.results_queue = Queue()
    links_plugin.base_fuzz_res = example_full_fuzzres_content
    links_plugin.add_path = False

    assert links_plugin.name == "links"

    links_plugin.process(example_full_fuzzres_content)

    results = []
    while not links_plugin.results_queue.empty():
        results.append(links_plugin.results_queue.get())

    assert [
        fzres._seed.history.url for fzres in results if fzres._seed
    ] == expected_links


@pytest.mark.parametrize(
    "example_full_fuzzres_content, expected_links",
    [
        (
            b'<link rel="dns-prefetch" href="https://www.wfuzz.io">\n',
            ["https://www.wfuzz.io/"],
        ),
        (
            b'<script src="//js.wfuzz.org/sttc/main.93d0d236.js"></script>',
            ["http://js.wfuzz.org/sttc/main.93d0d236.js"],
        ),
    ],
    indirect=["example_full_fuzzres_content"],
)
def test_regex_option(example_full_fuzzres_content, get_plugin, expected_links):
    links_plugin = get_plugin("links")[0]
    links_plugin.results_queue = Queue()
    links_plugin.base_fuzz_res = example_full_fuzzres_content
    links_plugin.add_path = False
    links_plugin.domain_regex = re.compile("wfuzz", re.MULTILINE | re.DOTALL)

    assert links_plugin.name == "links"

    links_plugin.process(example_full_fuzzres_content)

    results = []
    while not links_plugin.results_queue.empty():
        results.append(links_plugin.results_queue.get())

    assert [
        fzres._seed.history.url for fzres in results if fzres._seed
    ] == expected_links
