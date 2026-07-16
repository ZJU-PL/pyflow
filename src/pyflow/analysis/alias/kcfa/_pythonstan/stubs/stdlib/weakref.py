class ref:
    def __init__(self, ob, callback=None):
        self._referent = ob
        self._callback = callback

    def __call__(self):
        return self._referent

    def __hash__(self):
        return hash(self._referent)

    def __eq__(self, other):
        if isinstance(other, ref):
            return self._referent == other._referent
        return False


class proxy:
    def __init__(self, ob, callback=None):
        object.__setattr__(self, '_referent', ob)
        object.__setattr__(self, '_callback', callback)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, '_referent'), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, '_referent'), name, value)

    def __delattr__(self, name):
        delattr(object.__getattribute__(self, '_referent'), name)


class WeakValueDictionary(dict):
    def __init__(self, other=(), **kwargs):
        dict.__init__(self)
        self._refs = {}
        self.update(other, **kwargs)

    def __getitem__(self, key):
        r = self._refs[key]
        o = r()
        return o

    def __setitem__(self, key, value):
        self._refs[key] = ref(value)

    def __delitem__(self, key):
        del self._refs[key]

    def __contains__(self, key):
        return key in self._refs and self._refs[key]() is not None

    def __iter__(self):
        return iter(self._refs)

    def __len__(self):
        return len(self._refs)

    def get(self, key, default=None):
        r = self._refs.get(key)
        if r is not None:
            o = r()
            if o is not None:
                return o
        return default

    def keys(self):
        return self._refs.keys()

    def values(self):
        return [r() for r in self._refs.values()]

    def items(self):
        return [(k, r()) for k, r in self._refs.items()]

    def setdefault(self, key, default=None):
        if key not in self or self._refs[key]() is None:
            self[key] = default
        return self[key]

    def pop(self, key, *args):
        r = self._refs.pop(key, *args)
        if isinstance(r, ref):
            return r()
        return r

    def update(self, other=(), **kwargs):
        if hasattr(other, 'items'):
            for k, v in other.items():
                self[k] = v
        else:
            for k, v in other:
                self[k] = v
        for k, v in kwargs.items():
            self[k] = v

    def valuerefs(self):
        return list(self._refs.values())


class WeakKeyDictionary(dict):
    def __init__(self, other=(), **kwargs):
        dict.__init__(self)
        self._data = {}
        self.update(other, **kwargs)

    def __getitem__(self, key):
        return self._data[id(key)][1]

    def __setitem__(self, key, value):
        self._data[id(key)] = (ref(key), value)

    def __delitem__(self, key):
        del self._data[id(key)]

    def __contains__(self, key):
        return id(key) in self._data

    def __iter__(self):
        for r, v in self._data.values():
            k = r()
            if k is not None:
                yield k

    def __len__(self):
        return len(self._data)

    def get(self, key, default=None):
        pair = self._data.get(id(key))
        if pair is not None:
            return pair[1]
        return default

    def keys(self):
        return [r() for r, v in self._data.values() if r() is not None]

    def values(self):
        return [v for r, v in self._data.values()]

    def items(self):
        return [(r(), v) for r, v in self._data.values() if r() is not None]

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

    def pop(self, key, *args):
        pair = self._data.pop(id(key), *args)
        if isinstance(pair, tuple):
            return pair[1]
        return pair

    def update(self, other=(), **kwargs):
        if hasattr(other, 'items'):
            for k, v in other.items():
                self[k] = v
        else:
            for k, v in other:
                self[k] = v
        for k, v in kwargs.items():
            self[k] = v

    def keyrefs(self):
        return [r for r, v in self._data.values()]


class WeakSet:
    def __init__(self, data=None):
        self._data = {}
        if data is not None:
            self.update(data)

    def __contains__(self, item):
        r = self._data.get(id(item))
        return r is not None and r() is not None

    def __iter__(self):
        for r in list(self._data.values()):
            item = r()
            if item is not None:
                yield item

    def __len__(self):
        return len(self._data)

    def add(self, item):
        self._data[id(item)] = ref(item)

    def discard(self, item):
        self._data.pop(id(item), None)

    def remove(self, item):
        del self._data[id(item)]

    def pop(self):
        for r in self._data.values():
            item = r()
            if item is not None:
                self.discard(item)
                return item
        raise KeyError("pop from empty WeakSet")

    def clear(self):
        self._data.clear()

    def update(self, other):
        for item in other:
            self.add(item)

    def copy(self):
        return WeakSet(self)


class WeakMethod(ref):
    def __init__(self, meth, callback=None):
        try:
            func = meth.__func__
            obj = meth.__self__
        except AttributeError:
            raise TypeError("argument should be a bound method")
        ref.__init__(self, obj, callback)
        self._func = func

    def __call__(self):
        obj = ref.__call__(self)
        if obj is None:
            return None
        return self._func.__get__(obj, type(obj))


class finalize:
    def __init__(self, obj, func, *args, **kwargs):
        self._ref = ref(obj, self._invoke)
        self._func = func
        self._args = args
        self._kwargs = kwargs
        self._alive = True

    def _invoke(self, ref):
        if self._alive:
            self._alive = False
            self._func(*self._args, **self._kwargs)

    def __call__(self):
        self._invoke(None)

    def detach(self):
        self._alive = False
        return (self._ref(), self._func, self._args, self._kwargs)

    def peek(self):
        return (self._ref(), self._func, self._args, self._kwargs) if self._alive else None

    @property
    def alive(self):
        return self._alive


def getweakrefcount(obj):
    return 0


def getweakrefs(obj):
    return []


ProxyType = type(proxy(object()))
CallableProxyType = type(proxy(lambda: None))
ReferenceType = ref

ProxyTypes = (ProxyType, CallableProxyType)
