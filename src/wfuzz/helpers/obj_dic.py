

class DotDict(dict):
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __getattr__(*args):
        # Return {} if non-existent attr
        if args[1] not in args[0]:
            return DotDict()

        # python 3 val = dict.get(*args, None)
        val = dict.get(*args)
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
            return DotDict()


class CaseInsensitiveDict(dict):
    proxy = {}

    def __init__(self, data):
        self.proxy = dict((k.lower(), k) for k in data)
        for k in data:
            self[k] = data[k]

    def __contains__(self, k):
        return k.lower() in self.proxy

    def __delitem__(self, k):
        key = self.proxy[k.lower()]
        super(CaseInsensitiveDict, self).__delitem__(key)
        del self.proxy[k.lower()]

    def __getitem__(self, k):
        key = self.proxy[k.lower()]
        return super(CaseInsensitiveDict, self).__getitem__(key)

    def get(self, k, default=None):
        key = self.proxy[k.lower()]
        return self[key] if key in self else default

    def __setitem__(self, k, v):
        super(CaseInsensitiveDict, self).__setitem__(k, v)
        self.proxy[k.lower()] = k

    def update(self, other):
        for k, v in other.items():
            self[k] = v
