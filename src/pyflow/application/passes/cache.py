"""Program-specific pass result cache."""

import weakref
from typing import Any, Dict, Optional, Set

from .base import PassResult


class PassCache:
    """Simple cache for pass results based on program state."""

    def __init__(self):
        self._cache: "weakref.WeakKeyDictionary[Any, Dict[str, tuple[Any, PassResult]]]" = (
            weakref.WeakKeyDictionary()
        )
        # Fallback for objects that do not support weak references.
        # Use object keys directly (when hashable) to avoid id-reuse collisions.
        self._fallback_cache: Dict[Any, Dict[str, tuple[Any, PassResult]]] = {}

    def _supports_weakrefs(self, program) -> bool:
        try:
            weakref.ref(program)
        except TypeError:
            return False
        return True

    def _is_hashable(self, program) -> bool:
        try:
            hash(program)
        except TypeError:
            return False
        return True

    def version_token(self, program):
        catalog = getattr(program, "ir", None)
        session = getattr(program, "session", None)
        return (
            catalog,
            getattr(catalog, "revision", None),
            getattr(getattr(catalog, "facts", None), "revision", None),
            getattr(session, "options", None),
            getattr(getattr(session, "results", None), "generation", None),
        )

    def _bucket(self, program, *, create=False):
        if not self._is_hashable(program):
            return None
        cache = self._cache if self._supports_weakrefs(program) else self._fallback_cache
        if create:
            return cache.setdefault(program, {})
        return cache.get(program)

    def get(self, program, pass_name: str) -> Optional[PassResult]:
        bucket = self._bucket(program)
        entry = bucket.get(pass_name) if bucket is not None else None
        if entry is None:
            return None
        token, result = entry
        if token != self.version_token(program):
            bucket.pop(pass_name, None)
            return None
        return result

    def put(self, program, pass_name: str, result: PassResult) -> None:
        bucket = self._bucket(program, create=True)
        if bucket is not None:
            bucket[pass_name] = (self.version_token(program), result)

    def rebase(self, program, pass_name: str, before_token) -> None:
        """Retag a result only when the transforming pass promises preservation."""
        bucket = self._bucket(program)
        if bucket is not None and pass_name in bucket:
            token, result = bucket[pass_name]
            if token == before_token:
                bucket[pass_name] = (self.version_token(program), result)
            else:
                bucket.pop(pass_name)

    def invalidate(self, program, pass_name: Optional[str] = None) -> None:
        """Invalidate cached results for a program or specific pass."""
        if self._supports_weakrefs(program):
            if program in self._cache:
                if pass_name is None:
                    del self._cache[program]
                else:
                    self._cache[program].pop(pass_name, None)
            return
        if not self._is_hashable(program):
            return
        if program in self._fallback_cache:
            if pass_name is None:
                del self._fallback_cache[program]
            else:
                self._fallback_cache[program].pop(pass_name, None)

    def pass_names(self, program) -> Set[str]:
        """Return cached pass names for a program."""
        if self._supports_weakrefs(program):
            return set(self._cache.get(program, ()))
        if not self._is_hashable(program):
            return set()
        return set(self._fallback_cache.get(program, ()))

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache.clear()
        self._fallback_cache.clear()
