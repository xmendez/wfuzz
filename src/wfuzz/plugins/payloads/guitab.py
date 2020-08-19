from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload
from wfuzz.fuzzobjects import FuzzWordType

from wfuzz.facade import Facade


@moduleman_plugin
class guitab(BasePayload):
    name = "guitab"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    description = (
        "** This is a beta plugin for the GUI under construction.",
        "This payload reads requests from a tab in the GUI",
    )
    summary = "This payload reads requests from a tab in the GUI"
    category = ["default"]
    priority = 99

    parameters = (
        ("tab", "", True, "Name of a valid GUI tab."),
        (
            "attr",
            None,
            False,
            "Attribute of fuzzresult to return. If not specified the whole object is returned.",
        ),
    )

    default_parameter = "tab"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        self.attr = self.params["attr"]
        self._it = iter(Facade().data[self.params["tab"]])

    def count(self):
        return len(Facade().data[self.params["tab"]])

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        next_item = next(self._it)

        return next_item if not self.attr else next_item.get_field(self.attr)
