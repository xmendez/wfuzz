import collections


def moduleman_plugin(*args):
    method_args = []

    def inner_decorator(cls):
        for method in method_args:
            if (not (method in dir(cls))):
                raise Exception("Required method %s not implemented" % method)
        cls.__PLUGIN_MODULEMAN_MARK = "Plugin mark"

        return cls

    if not isinstance(args[0], collections.Callable):
        method_args += args
        return inner_decorator

    return inner_decorator(args[0])
