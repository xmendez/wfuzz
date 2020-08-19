Breaking changes
=============

Following https://semver.org/ versioning since Wfuzz 3.0.0.

* Wfuzz 3.0.0:
    * In wfuzz library prefilter is a list of filters not a string.
    * When using --recipe, stored options that are a list are appended. Previously, the last one took precedence.
