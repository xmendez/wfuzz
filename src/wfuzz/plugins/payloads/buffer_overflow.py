from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload


@moduleman_plugin
class buffer_overflow(BasePayload):
    name = "buffer_overflow"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = ()
    summary = "Returns a string using the following pattern A * given number."
    category = ["default"]
    priority = 99

    parameters = (
        ("size", "", True, "Size of the overflow string."),
    )

    default_parameter = "size"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        self.bov_list = ['A' * int(self.params["size"])]
        self.current = 0

    def __iter__(self):
        return self

    def count(self):
        return 1

    def __next__(self):
        if self.current == 0:
            elem = self.bov_list[self.current]
            self.current += 1
            return elem
        else:
            raise StopIteration
