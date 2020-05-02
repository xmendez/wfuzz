from ..fuzzrequest import FuzzRequest

from ..helpers.obj_factory import (
    ObjectFactory,
    SeedBuilderHelper
)


class FuzzRequestFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(self, {
            'request_from_options': RequestBuilder(),
            'request_removing_baseline_markers': SeedBuilder(),
        })


class RequestBuilder:
    def __call__(self, options):
        fr = FuzzRequest()

        fr.url = options['url']
        fr.wf_fuzz_methods = options['method']
        fr.update_from_options(options)

        return fr


class SeedBuilder:
    def __call__(self, freq):
        my_req = freq.from_copy()

        marker_dict = SeedBuilderHelper.get_marker_dict(my_req)
        SeedBuilderHelper.remove_baseline_markers(my_req, marker_dict)

        return my_req


reqfactory = FuzzRequestFactory()
