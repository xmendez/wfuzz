from .modulefilter import Filter
from collections import defaultdict

try:
    from collections.abc import MutableMapping
except ImportError:
    from collections import MutableMapping
from threading import Lock


class IRegistrant:
    def __init__(self, loader, plg_filter):
        self.plg_filter = plg_filter
        self.loader = loader

        self.start_loading()
        self.load()
        self.end_loading()

    def register(self, identifier, module):
        raise NotImplementedError

    def start_loading(self):
        raise NotImplementedError

    def load(self):
        raise NotImplementedError

    def end_loading(self):
        raise NotImplementedError

    def modify_instance(self, module):
        raise NotImplementedError


class KnowledgeBase(MutableMapping):
    def __init__(self, *args, **kwargs):
        self.__data = defaultdict(list)
        self.mutex = Lock()

    def __getitem__(self, key):
        with self.mutex:
            return self.__data[key]

    def __setitem__(self, key, value):
        with self.mutex:
            self.__data[key].append(value)

    def __delitem__(self, key):
        with self.mutex:
            del self.__data[key]

    def __len__(self):
        with self.mutex:
            return len(self.__data)

    def __str__(self):
        with self.mutex:
            return str(self.__data)

    def __iter__(self):
        return iter(self.__data)


class BRegistrant(IRegistrant):
    def __init__(self, loader, plg_filter=Filter()):
        self.__plugins = {}
        self.__active_plugins = {}
        self.kbase = KnowledgeBase()

        IRegistrant.__init__(self, loader, plg_filter)

    def register(self, identifier, module):
        self.__plugins[identifier] = self.modify_instance(module)
        self.__active_plugins[identifier] = True

    def load(self):
        self.loader.load(self)

    def start_loading(self):
        pass

    def end_loading(self):
        pass

    def modify_instance(self, module):
        module.kbase = self.kbase

        return module

    # ------------------------------------------------
    # plugin management functions
    # ------------------------------------------------
    def plugin_state(self, identifier, state):
        self.__active_plugins[identifier] = state

    def __get_plugins(self, category, sorting):
        def plugin_filter(x):
            plgid, plg = x

            if category == "$all$":
                return True
            elif not self.__active_plugins[plgid]:
                return False
            else:
                return self.plg_filter.is_visible(plg, category)

        def key_funtion(x):
            return x[1].priority

        plugin_list = list(filter(plugin_filter, list(self.__plugins.items())))

        if sorting:
            plugin_list.sort(key=key_funtion)

        return plugin_list

    def get_plugin(self, identifier):
        # strict and fuzzy search
        if identifier in self.__plugins:
            return self.__plugins[identifier]
        else:
            plugin_list = [
                plg
                for plg_id, plg in self.__get_plugins("$all$", True)
                if identifier in plg_id
            ]

            if not plugin_list:
                raise KeyError("No plugins found!")
            elif len(plugin_list) == 1:
                return plugin_list[0]
            else:
                raise KeyError(
                    "Multiple plugins found: %s"
                    % ",".join([plg.name for plg in plugin_list])
                )

        raise KeyError("No plugins found!")

    def get_plugins(self, category="$all$", sorting="true"):
        return [plg for plg_id, plg in self.__get_plugins(category, sorting)]

    def get_plugins_ext(self, category="$all$", sorting="true"):
        plugin_list = [["Id", "Priority", "Category", "Name", "Summary"]]

        for plg_id, plg in self.__get_plugins(category, sorting):
            plugin_list.append(
                [
                    plg_id,
                    str(plg.priority),
                    ", ".join(plg.category),
                    str(plg.name),
                    str(plg.summary),
                ]
            )

        return plugin_list

    def get_plugins_names(self, category="$all$", sorting="true"):
        return [plg.name for plg_id, plg in self.__get_plugins(category, sorting)]

    def get_plugins_ids(self, category="$all$", sorting="true"):
        return [plg_id for plg_id, plg in self.__get_plugins(category, sorting)]


class MulRegistrant(BRegistrant):
    def load(self):
        for loader in self.loader:
            loader.load(self)
