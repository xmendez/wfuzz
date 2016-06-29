
# decorator for iterator plugins
def wfuzz_iterator(cls):
    method_args = ["count", "next", "__iter__"]

    for method in method_args:
	if (not (method in dir(cls))):
	    raise Exception("Required method %s not implemented" % method)

    cls.__PLUGIN_MODULEMAN_MARK = "Plugin mark"

    return cls
