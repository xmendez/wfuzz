"""Benchmarks for the command line parser.

Parsing the command line happens once per run, but it validates every option and
builds the session options, so it is a good proxy for the wfuzz startup cost.
"""

import pytest

from wfuzz.ui.console.clparser import CLParser

COMMAND_LINES = {
    "simple": ["wfuzz", "-z", "range,0-100", "http://localhost/FUZZ"],
    "filters": [
        "wfuzz",
        "-z",
        "file,wordlist/general/common.txt",
        "--hc",
        "404,403",
        "--hw",
        "10",
        "--filter",
        "c=200 and l>2",
        "http://localhost/FUZZ",
    ],
    "multiple_payloads": [
        "wfuzz",
        "-z",
        "range,0-10",
        "--zE",
        "md5",
        "-z",
        "list,a-b-c",
        "-m",
        "zip",
        "-b",
        "session=1",
        "-H",
        "User-Agent: bench",
        "-d",
        "user=FUZZ&password=FUZ2Z",
        "http://localhost/login",
    ],
}


@pytest.mark.parametrize("command_line", sorted(COMMAND_LINES))
def test_parse_command_line(benchmark, command_line):
    argv = COMMAND_LINES[command_line]

    options = benchmark(lambda: CLParser(list(argv)).parse_cl())

    assert options.data["payloads"]
