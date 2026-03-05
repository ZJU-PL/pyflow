"""Shared sentinels for representing parameter-default holes."""


class _MissingDefault:
    __slots__ = ()


MISSING_DEFAULT = _MissingDefault()
