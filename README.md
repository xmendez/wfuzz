<img src="https://github.com/xmendez/wfuzz/blob/master/docs/_static/logo/wfuzz_letters.svg" width="500">

[![Build Status](https://travis-ci.org/xmendez/wfuzz.svg?branch=master)](https://travis-ci.org/xmendez/wfuzz)
<a href="https://pypi.python.org/pypi/wfuzz"><img src="https://img.shields.io/pypi/v/wfuzz.svg"></a>
<a href="https://pypi.python.org/pypi/wfuzz"><img src="https://img.shields.io/pypi/dm/wfuzz"></a>
<a href="https://pypi.python.org/pypi/wfuzz"><img src="https://img.shields.io/pypi/pyversions/wfuzz.svg"></a>
<a href="https://codecov.io/github/xmendez/wfuzz"><img src="https://codecov.io/github/xmendez/wfuzz/coverage.svg?branch=master"></a>


# Wfuzz - The Web Fuzzer

Wfuzz has been created to facilitate the task in web applications assessments and it is based on a simple concept: it replaces any reference to the FUZZ keyword by the value of a given payload.

A payload in Wfuzz is a source of data.

This simple concept allows any input to be injected in any field of an HTTP request, allowing to perform complex web security attacks in different web application components such as: parameters, authentication, forms, directories/files, headers, etc.

Wfuzz is more than a web content scanner:

* Wfuzz could help you to secure your web applications by finding and exploiting web application vulnerabilities. Wfuzz’s web application vulnerability scanner is supported by plugins.

* Wfuzz is a completely modular framework and makes it easy for even the newest of Python developers to contribute. Building plugins is simple and takes little more than a few minutes.

* Wfuzz exposes a simple language interface to the previous HTTP requests/responses performed using Wfuzz or other tools, such as Burp. This allows you to perform manual and semi-automatic tests with full context and understanding of your actions, without relying on a web application scanner underlying implementation.


It was created to facilitate the task in web applications assessments, it's a tool by pentesters for pentesters ;)

## Installation 

To install WFuzz, simply use pip:

```
pip install wfuzz
```

To run Wfuzz from a docker image, run:

```
$ docker run -v $(pwd)/wordlist:/wordlist/ -it ghcr.io/xmendez/wfuzz wfuzz
```

## Documentation

Documentation is available at http://wfuzz.readthedocs.io

## Download 

Check github releases. Latest is available at https://github.com/xmendez/wfuzz/releases/latest
