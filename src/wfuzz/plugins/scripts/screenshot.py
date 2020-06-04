from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin

import subprocess
import tempfile
import pipes
import os


@moduleman_plugin
class screenshot(BasePlugin):
    name = "screenshot"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Performs a screen capture using linux cutycapt tool"
    description = (
        "Performs a screen capture using linux cutycapt tool",
        "The tool must be installed and in the executable path",
    )
    category = ["tools", "active"]
    priority = 99

    parameters = ()

    def __init__(self):
        BasePlugin.__init__(self)

    def validate(self, fuzzresult):
        return fuzzresult.code not in [404]

    def process(self, fuzzresult):
        temp_name = next(tempfile._get_candidate_names())
        defult_tmp_dir = tempfile._get_default_tempdir()

        filename = os.path.join(defult_tmp_dir, temp_name + ".png")

        subprocess.call(
            [
                "cutycapt",
                "--url=%s" % pipes.quote(fuzzresult.url),
                "--out=%s" % filename,
            ]
        )
        self.add_result("Screnshot taken, output at %s" % filename)
