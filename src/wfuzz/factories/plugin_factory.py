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
    def __call__(self, name, message):
        plugin = FuzzPlugin()
        plugin.source = name
        plugin.issue = message
        plugin._exception = None
        plugin._seed = None

        return plugin


plugin_factory = PluginFactory()
