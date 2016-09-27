from wfuzz.plugin_api.base import wfuzz_iterator

import os
import urllib


@wfuzz_iterator
class dirwalk:
    name = "dirwalk"
    description = "Returns filename's recursively from a local directory. ie. ~/Downloads/umbraco/umbraco/"
    category = ["default"]
    priority = 99

    def __init__(self, directory, extra):
        self.g = self._my_gen(directory)

    def _my_gen(self, directory):
        for root, dirs, fnames in os.walk(directory):
            for f in fnames:
                relative_path = os.path.relpath(os.path.join(root, f), directory)
                yield urllib.quote(relative_path)

    def next(self):
	return self.g.next()

    def count(self):
	return -1

    def __iter__(self):
	return self
