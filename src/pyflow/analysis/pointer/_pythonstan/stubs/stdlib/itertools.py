def chain(*iterables):
    result = []
    for iterable in iterables:
        for item in iterable:
            result.append(item)
    return result


def count(start=0, step=1):
    n = start
    while True:
        yield n
        n += step


def cycle(iterable):
    items = list(iterable)
    while True:
        for item in items:
            yield item


def repeat(object, times=None):
    if times is None:
        while True:
            yield object
    else:
        for _ in range(times):
            yield object


def accumulate(iterable, func=None, initial=None):
    it = iter(iterable)
    if initial is None:
        total = next(it)
    else:
        total = initial
        yield total
    for element in it:
        if func:
            total = func(total, element)
        else:
            total = total + element
        yield total


def compress(data, selectors):
    return [d for d, s in zip(data, selectors) if s]


def dropwhile(predicate, iterable):
    it = iter(iterable)
    for x in it:
        if not predicate(x):
            yield x
            break
    for x in it:
        yield x


def filterfalse(predicate, iterable):
    for x in iterable:
        if not predicate(x):
            yield x


def groupby(iterable, key=None):
    keyfunc = key if key is not None else lambda x: x
    result = []
    prev_key = None
    group = []
    for item in iterable:
        k = keyfunc(item)
        if k != prev_key:
            if group:
                result.append((prev_key, group))
            group = [item]
            prev_key = k
        else:
            group.append(item)
    if group:
        result.append((prev_key, group))
    return result


def islice(iterable, *args):
    s = slice(*args)
    it = iter(iterable)
    return list(it)[s]


def starmap(function, iterable):
    return [function(*args) for args in iterable]


def takewhile(predicate, iterable):
    for x in iterable:
        if predicate(x):
            yield x
        else:
            break


def tee(iterable, n=2):
    items = list(iterable)
    return tuple([items] * n)


def zip_longest(*iterables, fillvalue=None):
    iterators = [iter(it) for it in iterables]
    result = []
    while True:
        values = []
        finished = True
        for it in iterators:
            try:
                values.append(next(it))
                finished = False
            except StopIteration:
                values.append(fillvalue)
        if finished:
            break
        result.append(tuple(values))
    return result


def product(*iterables, repeat=1):
    pools = [tuple(pool) for pool in iterables] * repeat
    result = [[]]
    for pool in pools:
        result = [x + [y] for x in result for y in pool]
    return [tuple(item) for item in result]


def permutations(iterable, r=None):
    pool = tuple(iterable)
    n = len(pool)
    r = n if r is None else r
    if r > n:
        return []
    result = []
    for item in pool:
        result.append((item,))
    return result


def combinations(iterable, r):
    pool = tuple(iterable)
    n = len(pool)
    if r > n:
        return []
    result = []
    for item in pool:
        result.append((item,))
    return result


def combinations_with_replacement(iterable, r):
    pool = tuple(iterable)
    n = len(pool)
    result = []
    for item in pool:
        result.append((item,))
    return result
