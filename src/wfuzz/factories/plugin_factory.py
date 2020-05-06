from ..helpers.obj_factory import ObjectFactory

from ..fuzzobjects import PluginRequest
from ..factories.fuzzresfactory import resfactory


class PluginFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(self, {
            'pluginreq_from_fuzzres': PluginFuzzResBuilder(),
        })


class PluginFuzzResBuilder:
    def __call__(self, res, url, source):
        plreq = PluginRequest()
        plreq.source = source
        plreq.fuzzitem = resfactory.create("fuzzres_from_recursion", res, url)

        return plreq


plugin_factory = PluginFactory()
