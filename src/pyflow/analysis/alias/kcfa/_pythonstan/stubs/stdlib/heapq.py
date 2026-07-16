def heappush(heap, item):
    heap.append(item)
    _siftdown(heap, 0, len(heap) - 1)


def heappop(heap):
    lastelt = heap.pop()
    if heap:
        returnitem = heap[0]
        heap[0] = lastelt
        _siftup(heap, 0)
        return returnitem
    return lastelt


def heappushpop(heap, item):
    if heap and heap[0] < item:
        item, heap[0] = heap[0], item
        _siftup(heap, 0)
    return item


def heapreplace(heap, item):
    returnitem = heap[0]
    heap[0] = item
    _siftup(heap, 0)
    return returnitem


def heapify(x):
    n = len(x)
    for i in reversed(range(n // 2)):
        _siftup(x, i)


def nlargest(n, iterable, key=None):
    items = list(iterable)
    if key is not None:
        items.sort(key=key, reverse=True)
    else:
        items.sort(reverse=True)
    return items[:n]


def nsmallest(n, iterable, key=None):
    items = list(iterable)
    if key is not None:
        items.sort(key=key)
    else:
        items.sort()
    return items[:n]


def merge(*iterables, key=None, reverse=False):
    result = []
    for it in iterables:
        result.extend(it)
    if key is not None:
        result.sort(key=key, reverse=reverse)
    else:
        result.sort(reverse=reverse)
    return iter(result)


def _siftdown(heap, startpos, pos):
    newitem = heap[pos]
    while pos > startpos:
        parentpos = (pos - 1) >> 1
        parent = heap[parentpos]
        if newitem < parent:
            heap[pos] = parent
            pos = parentpos
            continue
        break
    heap[pos] = newitem


def _siftup(heap, pos):
    endpos = len(heap)
    startpos = pos
    newitem = heap[pos]
    childpos = 2 * pos + 1
    while childpos < endpos:
        rightpos = childpos + 1
        if rightpos < endpos and not heap[childpos] < heap[rightpos]:
            childpos = rightpos
        heap[pos] = heap[childpos]
        pos = childpos
        childpos = 2 * pos + 1
    heap[pos] = newitem
    _siftdown(heap, startpos, pos)
