from wfuzz.plugin_api.base import wfuzz_iterator
from wfuzz.plugin_api.base import BasePayload

import os
import urllib


@wfuzz_iterator
class dirwalk(BasePayload):
    name = "dirwalk"
    description = "Returns filename's recursively from a local directory. ie. ~/Downloads/umbraco/umbraco/"
    category = ["default"]
    priority = 99

    parameters = (
        ("dir", "", True, "Directory path to walk and generate payload from."),
    )

    default_parameter = "dir"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        self.g = self._my_gen(self.params["dir"])

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
