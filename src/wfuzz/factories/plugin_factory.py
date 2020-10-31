from ..helpers.obj_factory import ObjectFactory

from ..fuzzobjects import FuzzPlugin, FuzzError
from ..factories.fuzzresfactory import resfactory


class PluginFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(
            self,
            {
                "plugin_from_recursion": PluginRecursiveBuilder(),
                "plugin_from_error": PluginErrorBuilder(),
                "plugin_from_finding": PluginFindingBuilder(),
                "plugin_from_summary": PluginFindingSummaryBuilder(),
            },
        )


class PluginRecursiveBuilder:
    def __call__(self, name, seed, url):
        plugin = FuzzPlugin()
        plugin.source = name
        plugin._exception = None
        plugin._seed = resfactory.create("fuzzres_from_recursion", seed, url)

        return plugin


class PluginErrorBuilder:
    def __call__(self, name, exception):
        plugin = FuzzPlugin()
        plugin.source = name
        plugin.issue = "Exception within plugin %s: %s" % (name, str(exception))
        plugin._exception = FuzzError(exception)
        plugin._seed = None

        return plugin


class PluginFindingBuilder:
    def __call__(self, name, itype, message, data, severity):
        plugin = FuzzPlugin()
        plugin.source = name
        plugin.issue = message
        plugin.itype = itype
        plugin.data = data
        plugin._exception = None
        plugin._seed = None
        plugin.severity = severity

        return plugin


class PluginFindingSummaryBuilder:
    def __call__(self, message):
        plugin = FuzzPlugin()
        plugin.source = FuzzPlugin.OUTPUT_SOURCE
        plugin.itype = FuzzPlugin.SUMMARY_ITYPE
        plugin.severity = FuzzPlugin.NONE
        plugin._exception = None
        plugin.data = None
        plugin._seed = None
        plugin.issue = message

        return plugin


plugin_factory = PluginFactory()
