def moduleman_plugin(*args):
    method_args = []

    def inner_decorator(cls):
	for method in method_args:
	    if (not (method in dir(cls))):
		raise Exception("Required method %s not implemented" % method)
	cls.__PLUGIN_MODULEMAN_MARK = "Plugin mark"

	return cls

    if not callable(args[0]):
	method_args += args
	return inner_decorator

    return inner_decorator(args[0])

if __name__ == '__main__':
    @moduleman_plugin
    class test:
	def __init__(self):
	    print "test init"

	def description(self):
	    print "ii"

	def name(self):
	    print "ii"

    a = test()
    a.description()
    print a.__PLUGIN_MODULEMAN_MARK
