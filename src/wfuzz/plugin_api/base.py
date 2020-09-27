from wfuzz.fuzzobjects import FuzzWord
from wfuzz.exception import (
    FuzzExceptBadFile,
    FuzzExceptBadOptions,
    FuzzExceptPluginError,
)
from wfuzz.facade import Facade
from wfuzz.factories.plugin_factory import plugin_factory
from wfuzz.helpers.file_func import find_file_in_paths

import sys
import os

# python 2 and 3: iterator
from builtins import object


# Util methods for accessing search results
class BasePlugin:
    def __init__(self):
        self.results_queue = None
        self.base_fuzz_res = None

        # check mandatory params, assign default values
        for name, default_value, required, description in self.parameters:
            param_name = "%s.%s" % (self.name, name)

            if required and param_name not in list(self.kbase.keys()):
                raise FuzzExceptBadOptions(
                    "Plugins, missing parameter %s!" % (param_name,)
                )

            if param_name not in list(self.kbase.keys()):
                self.kbase[param_name] = default_value

    def run(self, fuzzresult, control_queue, results_queue):
        try:
            self.results_queue = results_queue
            self.base_fuzz_res = fuzzresult
            self.process(fuzzresult)
        except Exception as e:
            results_queue.put(plugin_factory.create("plugin_from_error", self.name, e))
        finally:
            control_queue.get()
            control_queue.task_done()
            return

    def process(self, fuzzresult):
        """
        This is were the plugin processing is done. Any wfuzz plugin must implement this method, do its job with the fuzzresult received and:
        - queue_url: if it is a discovery plugin enqueing more HTTP request that at some point will generate more results
        - add_result: Add information about the obtained results after the processing with an accurate description

        A kbase (get_kbase, has_kbase, add_kbase) is shared between all plugins. this can be used to store and retrieve relevant "collaborative" information.
        """
        raise NotImplementedError

    def validate(self):
        raise FuzzExceptPluginError("Method count not implemented")

    def add_result(self, issue):
        self.results_queue.put(
            plugin_factory.create("plugin_from_finding", self.name, issue)
        )

    def queue_url(self, url):
        self.results_queue.put(
            plugin_factory.create(
                "plugin_from_recursion", self.name, self.base_fuzz_res, url
            )
        )


class BasePrinter:
    def __init__(self, output):
        self.f = None
        if output:
            try:
                self.f = open(output, "w")
            except IOError as e:
                raise FuzzExceptBadFile("Error opening file. %s" % str(e))
        else:
            self.f = sys.stdout

        self.verbose = Facade().printers.kbase["verbose"]

    def header(self):
        raise FuzzExceptPluginError("Method header not implemented")

    def footer(self):
        raise FuzzExceptPluginError("Method footer not implemented")

    def result(self):
        raise FuzzExceptPluginError("Method result not implemented")


class BasePayload(object):
    def __init__(self, params):
        self.params = params

        # default params
        if "default" in self.params:
            self.params[self.default_parameter] = self.params["default"]

            if not self.default_parameter:
                raise FuzzExceptBadOptions("Too many plugin parameters specified")

        # Check for allowed parameters
        if [
            k
            for k in list(self.params.keys())
            if k not in [x[0] for x in self.parameters]
            and k not in ["encoder", "default"]
        ]:
            raise FuzzExceptBadOptions(
                "Plugin %s, unknown parameter specified!" % (self.name)
            )

        # check mandatory params, assign default values
        for name, default_value, required, description in self.parameters:
            if required and name not in self.params:
                raise FuzzExceptBadOptions(
                    "Plugin %s, missing parameter %s!" % (self.name, name)
                )

            if name not in self.params:
                self.params[name] = default_value

    def get_type(self):
        raise FuzzExceptPluginError("Method get_type not implemented")

    def get_next(self):
        raise FuzzExceptPluginError("Method get_next not implemented")

    def __next__(self):
        return FuzzWord(self.get_next(), self.get_type())

    def count(self):
        raise FuzzExceptPluginError("Method count not implemented")

    def __iter__(self):
        return self

    def close(self):
        pass

    def find_file(self, name):
        if os.path.exists(name):
            return name

        for pa in Facade().sett.get("general", "lookup_dirs").split(","):
            fn = find_file_in_paths(name, pa)

            if fn is not None:
                return fn

        return name
