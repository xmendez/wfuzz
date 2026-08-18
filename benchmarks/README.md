# Benchmarks

Performance benchmarks for wfuzz, written with
[pytest-codspeed](https://codspeed.io/docs/benchmarks/python) and continuously
measured on [CodSpeed](https://app.codspeed.io/maksimtech/wfuzz).

They cover the code paths that are executed for every request wfuzz sends:

| File                       | Covers                                                              |
| -------------------------- | ------------------------------------------------------------------- |
| `test_bench_encoders.py`   | Payload encoders/decoders (url, hex, hash, html, db) over a wordlist |
| `test_bench_payloads.py`   | Payload plugins: range, hexrange, permutation, list, file, ipnet...  |
| `test_bench_iterators.py`  | Payload combination iterators: zip, chain, product                   |
| `test_bench_request.py`    | Raw HTTP request/response parsing and FuzzResult computation         |
| `test_bench_filters.py`    | Filter language creation and evaluation (`--filter`, `--hc`, `--ss`) |
| `test_bench_helpers.py`    | Case insensitive dicts, dynamic field lookup, string helpers         |
| `test_bench_clparser.py`   | Command line parsing (startup cost)                                  |

The benchmarks are self-contained: they do not perform any network request, so
they can be run anywhere.

## Running locally

```
pip install setuptools netaddr pytest pytest-codspeed
pip install -e .

# plain run, checks that the benchmarks are functional
pytest benchmarks/

# measured run
make bench
```

To get the same measurements as in CI, use the
[CodSpeed CLI](https://codspeed.io/docs/cli):

```
codspeed run --mode simulation -- pytest benchmarks/ --codspeed
```
