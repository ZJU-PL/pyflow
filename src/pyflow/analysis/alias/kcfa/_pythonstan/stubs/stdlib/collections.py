from collections import namedtuple as _namedtuple


class Counter(dict):
    def __init__(self, iterable=None):
        dict.__init__(self)
        if iterable is not None:
            for elem in iterable:
                self[elem] = self.get(elem, 0) + 1

    def most_common(self, n=None):
        items = list(self.items())
        return items[:n] if n is not None else items

    def elements(self):
        for elem, count in self.items():
            for _ in range(count):
                yield elem

    def update(self, iterable=None, **kwds):
        if iterable is not None:
            for elem in iterable:
                self[elem] = self.get(elem, 0) + 1
        for elem, count in kwds.items():
            self[elem] = self.get(elem, 0) + count

    def subtract(self, iterable=None, **kwds):
        if iterable is not None:
            for elem in iterable:
                self[elem] = self.get(elem, 0) - 1
        for elem, count in kwds.items():
            self[elem] = self.get(elem, 0) - count


class defaultdict(dict):
    def __init__(self, default_factory=None, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.default_factory = default_factory

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        self[key] = self.default_factory()
        return self[key]


class OrderedDict(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)

    def move_to_end(self, key, last=True):
        pass


class deque:
    def __init__(self, iterable=None, maxlen=None):
        self._items = list(iterable) if iterable is not None else []
        self.maxlen = maxlen

    def append(self, x):
        self._items.append(x)

    def appendleft(self, x):
        self._items.insert(0, x)

    def clear(self):
        self._items.clear()

    def copy(self):
        return deque(self._items, self.maxlen)

    def count(self, x):
        return self._items.count(x)

    def extend(self, iterable):
        self._items.extend(iterable)

    def extendleft(self, iterable):
        for item in iterable:
            self.appendleft(item)

    def index(self, x, start=0, stop=None):
        return self._items.index(x, start, stop)

    def insert(self, i, x):
        self._items.insert(i, x)

    def pop(self):
        return self._items.pop()

    def popleft(self):
        return self._items.pop(0)

    def remove(self, value):
        self._items.remove(value)

    def reverse(self):
        self._items.reverse()

    def rotate(self, n=1):
        for _ in range(n):
            self._items.insert(0, self._items.pop())

    def __len__(self):
        return len(self._items)

    def __iter__(self):
        return iter(self._items)


class ChainMap(dict):
    def __init__(self, *maps):
        dict.__init__(self)
        self.maps = list(maps) if maps else [{}]

    def new_child(self, m=None):
        if m is None:
            m = {}
        return ChainMap(m, *self.maps)

    @property
    def parents(self):
        return ChainMap(*self.maps[1:])


class UserDict:
    def __init__(self, dict=None):
        self.data = {}
        if dict is not None:
            self.data.update(dict)

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, item):
        self.data[key] = item

    def __delitem__(self, key):
        del self.data[key]

    def __iter__(self):
        return iter(self.data)

    def __len__(self):
        return len(self.data)


class UserList:
    def __init__(self, initlist=None):
        self.data = []
        if initlist is not None:
            self.data.extend(initlist)

    def __getitem__(self, i):
        return self.data[i]

    def __setitem__(self, i, item):
        self.data[i] = item

    def __delitem__(self, i):
        del self.data[i]

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        return iter(self.data)

    def append(self, item):
        self.data.append(item)


class UserString:
    def __init__(self, seq):
        self.data = str(seq)

    def __str__(self):
        return self.data

    def __repr__(self):
        return repr(self.data)

    def __getitem__(self, index):
        return self.data[index]


namedtuple = _namedtuple
