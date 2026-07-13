def bisect_left(a, x, lo=0, hi=None, key=None):
    if hi is None:
        hi = len(a)
    if key is None:
        while lo < hi:
            mid = (lo + hi) // 2
            if a[mid] < x:
                lo = mid + 1
            else:
                hi = mid
    else:
        while lo < hi:
            mid = (lo + hi) // 2
            if key(a[mid]) < key(x):
                lo = mid + 1
            else:
                hi = mid
    return lo


def bisect_right(a, x, lo=0, hi=None, key=None):
    if hi is None:
        hi = len(a)
    if key is None:
        while lo < hi:
            mid = (lo + hi) // 2
            if x < a[mid]:
                hi = mid
            else:
                lo = mid + 1
    else:
        while lo < hi:
            mid = (lo + hi) // 2
            if key(x) < key(a[mid]):
                hi = mid
            else:
                lo = mid + 1
    return lo


def insort_left(a, x, lo=0, hi=None, key=None):
    lo = bisect_left(a, x, lo, hi, key)
    a.insert(lo, x)


def insort_right(a, x, lo=0, hi=None, key=None):
    lo = bisect_right(a, x, lo, hi, key)
    a.insert(lo, x)


bisect = bisect_right
insort = insort_right
