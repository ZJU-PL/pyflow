from __future__ import absolute_import

from ..stubcollector import stubgenerator

import functools


@stubgenerator
def makeFunctoolsStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    @export
    @attachPtr(functools, "partial")
    @llfunc
    def functools_partial(func, *args, **keywords):
        # Create partial function application
        return allocate(type(functools.partial(len)))

    @export
    @attachPtr(functools, "reduce")
    @llfunc
    def functools_reduce(function, iterable, initializer=None):
        # Apply function cumulatively to items of iterable
        return allocate(object)  # Return type depends on function and initializer

    @export
    @attachPtr(functools, "lru_cache")
    @llfunc
    def functools_lru_cache(maxsize=128, typed=False):
        # Decorator to wrap function with memoization
        def decorator(func):
            # Return the original function (simplified - real lru_cache returns wrapper)
            return func

        return decorator

    @export
    @attachPtr(functools, "wraps")
    @llfunc
    def functools_wraps(wrapped, assigned=None, updated=None):
        # Decorator to copy function metadata
        def decorator(wrapper):
            return wrapper

        return decorator

    @export
    @attachPtr(functools, "total_ordering")
    @llfunc
    def functools_total_ordering(cls):
        # Decorator to fill in missing ordering methods
        return cls

    @export
    @attachPtr(functools, "cmp_to_key")
    @llfunc
    def functools_cmp_to_key(mycmp):
        # Convert comparison function to key function
        return allocate(type(functools.cmp_to_key(lambda x, y: x - y)))
