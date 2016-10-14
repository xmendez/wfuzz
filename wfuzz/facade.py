from . import utils
from .externals.moduleman.registrant import MulRegistrant
from .externals.moduleman.loader import FileLoader
from .externals.moduleman.loader import DirLoader
from .externals.settings.settings import SettingsBase
from .myhttp import HttpPool
from .exception import FuzzException

import os

version = "2.2"

class Settings(SettingsBase):
    def get_config_file(self):
        return os.path.join(utils.get_home(check=True), "wfuzz.ini")

    def set_defaults(self):
	return dict(
	    plugins=[("bing_apikey", '')],
	    kbase=[("discovery.blacklist", '.jpg-.gif-.png-.jpeg-.mov-.avi-.flv-.ico')],
	    connection=[("concurrent", '10'),
		("conn_delay", '90'),
		("req_delay", '90'),
		("retries", '3'),
		("User-Agent", "Wfuzz/%s" % version)
	    ],
	    general=[("default_printer", 'raw'),("cancel_on_plugin_except","1"),
                ("concurrent_plugins", '3'),
                ("encode_space", '1')
            ],
	)

class MyRegistrant(MulRegistrant):
    def get_plugin(self, identifier):
        try:
            return MulRegistrant.get_plugin(self, identifier)
        except Exception, e:
            raise FuzzException(FuzzException.FATAL, str(e))

class Facade:
    __metaclass__ = utils.Singleton 

    def __init__(self):

        self.__plugins = dict(
            printers = None,
            scripts = None,
            encoders = None,
            iterators = None,
            payloads = None,
        )

	self.sett = Settings()

        self.http_pool = HttpPool(int(self.sett.get("connection","retries")))

    def _load(self, cat):
	try:
	    if not self.__plugins.has_key(cat):
		raise FuzzException(FuzzException.FATAL, "Non-existent plugin category %s" % cat)

            if not self.__plugins[cat]:
                l = []
                l.append(DirLoader(**{"base_dir": cat, "base_path": utils.get_path("plugins")}))
                l.append(DirLoader(**{"base_dir": cat, "base_path": utils.get_home()}))
                self.__plugins[cat] = MyRegistrant(l)

            return self.__plugins[cat]
	except Exception, e:
	    raise FuzzException(FuzzException.FATAL, "Error loading plugins: %s" % str(e))

    def proxy(self, which):
	return self._load(which)

    def __getattr__(self, name):
        if name in ["printers", "payloads", "iterators", "encoders", "scripts"]:
            return self._load(name)
        else:
            raise AttributeError
