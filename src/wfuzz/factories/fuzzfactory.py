from ..fuzzrequest import FuzzRequest

from ..helpers.obj_factory import ObjectFactory, SeedBuilderHelper


class FuzzRequestFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(
            self,
            {
                "request_from_options": RequestBuilder(),
                "seed_from_options": SeedBuilder(),
            },
        )


class RequestBuilder:
    def __call__(self, options):
        fr = FuzzRequest()

        fr.url = options["url"]
        fr.wf_fuzz_methods = options["method"]
        fr.update_from_options(options)

        return fr


class SeedBuilder:
    def __call__(self, options):
        seed = reqfactory.create("request_from_options", options)
        marker_dict = SeedBuilderHelper.get_marker_dict(seed)
        SeedBuilderHelper.remove_baseline_markers(seed, marker_dict)

        return seed


reqfactory = FuzzRequestFactory()
