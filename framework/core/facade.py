from patterns.singleton import Singleton
from framework.core.myexception import FuzzException
from externals.moduleman.registrant import BRegistrant
from externals.moduleman.loader import FileLoader
from externals.moduleman.loader import DirLoader
from externals.settings.settings import SettingsBase

import os

version = "2.1.5"

class Settings(SettingsBase):
    def get_config_file(self):
	return "wfuzz.ini"

    def set_defaults(self):
	return dict(
	    plugins=[("file_bl", '.jpg,.gif,.png,.jpeg,.mov,.avi,.flv,.ico'), ("bing_apikey", '')],
	)

class FuzzSessionOptions:
    def __init__(self):
	self._values = {
	    "filter_params": None,
	    "printer_tool": "default",
	    "rlevel": 0,
	    "script_string": "",
	    "sleeper": None,
	    "proxy_list": None,
	    "scanmode": False,
	    "interactive": False,
	    "max_concurrent": 10,
	    "genreq": None,
	    }

    def set(self, name, value):
	self._values[name] = value

    def get(self, name):
	return self._values[name]

class Facade:
    __metaclass__ = Singleton 

    def __init__(self):
	try:
            self.__printers = BRegistrant(FileLoader(**{"filename": "printers.py", "base_path": os.path.join(self.get_path(), "plugins")}))
            self.__plugins = BRegistrant(DirLoader(**{"base_dir": "scripts", "base_path": os.path.join(self.get_path(), "plugins")}))
            self.__encoders = BRegistrant(FileLoader(**{"filename": "encoders.py", "base_path": os.path.join(self.get_path(), "plugins")}))
            self.__iterators = BRegistrant(FileLoader(**{"filename": "iterations.py", "base_path": os.path.join(self.get_path(), "plugins")}))
            self.__payloads = BRegistrant(FileLoader(**{"filename": "payloads.py", "base_path": os.path.join(self.get_path(), "plugins")}))
	except Exception, e:
	    raise FuzzException(FuzzException.FATAL, "Error loading plugins: %s" % str(e))

	self.sett = Settings()

    def get_path(self):
        abspath = os.path.abspath(__file__)
        abspath =  os.path.join(os.path.dirname(abspath))
        abspath =  os.path.join(os.path.dirname(abspath))
        return os.path.dirname(abspath)

    def proxy(self, which):
	if which == 'parsers':
	    return self.__plugins
	elif which == 'encoders':
	    return self.__encoders
	elif which == 'iterators':
	    return self.__iterators
	elif which == 'payloads':
	    return self.__payloads
	elif which == 'printers':
	    return self.__printers
	else:
	    raise FuzzException(FuzzException.FATAL, "Non-existent proxy %s" % which)

    def get_printer(self, name):
	try:
	    return self.__printers.get_plugin("printers/" + name)()
	except KeyError:
	    raise FuzzException(FuzzException.FATAL, name + " printer does not exists (-e printers for a list of available printers)")

    def get_payload(self, name):
	try:
	    return self.__payloads.get_plugin("payloads/" + name)
	except KeyError:
	    raise FuzzException(FuzzException.FATAL, name + " payload does not exists (-e payloads for a list of available payloads)")

    def get_iterator(self, name):
	try:
	    return self.__iterators.get_plugin("iterations/" + name)
	except KeyError:
	    raise FuzzException(FuzzException.FATAL, name + " iterator does not exists (-m iterators for a list of available iterators)")

    def get_encoder(self, name):
	try:
	    return self.__encoders.get_plugin("encoders/" + name)()
	except KeyError:
	    raise FuzzException(FuzzException.FATAL, name + " encoder does not exists (-e encodings for a list of available encoders)")

    def get_parsers(self, filterstr):
	try:
	    return self.__plugins.get_plugins(filterstr)
	except Exception, e:
	    raise FuzzException(FuzzException.FATAL, "Error selecting scripts: %s" % str(e))
