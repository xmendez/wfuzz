from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload

import os
import urllib

@moduleman_plugin
class dirwalk(BasePayload):
    name = "dirwalk"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = (
        "Returns all the file paths found in the specified directory.",
        "Handy if you want to check a directory structure against a webserver,",
        "for example, because you have previously downloaded a specific version",
        "of what is supposed to be on-line."
    )
    summary = "Returns filename's recursively from a local directory."
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
