from collections.abc import MutableMapping


class CaseInsensitiveDict(MutableMapping):
    def __init__(self, *args, **kwargs):
        self.store = dict()
        self.proxy = dict()

        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __contains__(self, k):
        return k.lower() in self.proxy

    def __delitem__(self, k):
        key = self.proxy[k.lower()]

        del self.store[key]
        del self.proxy[k.lower()]

    def __getitem__(self, k):
        key = self.proxy[k.lower()]
        return self.store[key]

    def get(self, k, default=None):
        key = self.proxy[k.lower()]
        return self.store[key] if key in self.store else default

    def __setitem__(self, k, v):
        self.store[k] = v
        self.proxy[k.lower()] = k

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)


class DotDict(CaseInsensitiveDict):
    def __getattr__(obj, name):
        # Return {} if non-existent attr
        if name not in obj:
            return DotDict({})

        # python 3 val = dict.get(*args, None)
        val = obj.get(name)
        return DotDict(val) if type(val) is dict else val
        # return DotDict(val) if type(val) is dict else DotDict({args[1]: val})

    def __add__(self, other):
        if isinstance(other, str):
            return DotDict({k: v + other for k, v in self.items() if v})
        elif isinstance(other, DotDict):
            # python 3 return DotDict({**self, **other})
            new_dic = DotDict(self)
            new_dic.update(other)
            return new_dic

    def __radd__(self, other):
        if isinstance(other, str):
            return DotDict({k: other + v for k, v in self.items() if v})

    def __getitem__(self, key):
        try:
            return super(DotDict, self).__getitem__(key)
        except KeyError:
            return DotDict({})
