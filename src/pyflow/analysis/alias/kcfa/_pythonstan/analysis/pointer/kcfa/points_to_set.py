"""Bitset-backed points-to set representation for efficient pointer analysis.

Uses Python's arbitrary-precision int as a bitset for O(1) union/diff/intersection
and O(popcount) iteration. Objects are assigned dense IDs via ObjectIdTable.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, FrozenSet, Iterable, Iterator, TYPE_CHECKING

if TYPE_CHECKING:
    from .object import AbstractObject, ClassObject, MethodObject, InstanceObject

__all__ = ["PointsToSet", "reset_object_table"]


class _ObjectIdTable:
    """Maps abstract objects to dense integer IDs for bitset representation.

    Thread safety: Not thread-safe. Each analysis run should use a single
    table instance or ensure external synchronization.
    """

    _obj_to_id: Dict['AbstractObject', int]
    _id_to_obj: List['AbstractObject']

    def __init__(self):
        self._obj_to_id = {}
        self._id_to_obj = []

    def get_id(self, obj: 'AbstractObject') -> int:
        """Get or assign ID for an object.

        If the object already has an ID, returns it. Otherwise assigns a new
        incremental ID and returns it.
        """
        existing = self._obj_to_id.get(obj)
        if existing is not None:
            return existing

        new_id = len(self._id_to_obj)
        self._obj_to_id[obj] = new_id
        self._id_to_obj.append(obj)
        return new_id

    def get_obj(self, id_: int) -> 'AbstractObject':
        """Get object by ID. Raises IndexError if ID is invalid."""
        return self._id_to_obj[id_]

    def lookup_id(self, obj: 'AbstractObject') -> Optional[int]:
        """Get ID for object if it exists, None otherwise."""
        return self._obj_to_id.get(obj)

    def clear(self) -> None:
        """Clear all mappings. Used between analysis runs."""
        self._obj_to_id.clear()
        self._id_to_obj.clear()


# Module-level singleton for the current analysis run
_global_table: Optional[_ObjectIdTable] = None


def _get_object_table() -> _ObjectIdTable:
    """Get the global object ID table, creating it if necessary."""
    global _global_table
    if _global_table is None:
        _global_table = _ObjectIdTable()
    return _global_table


def reset_object_table() -> None:
    """Reset the global object ID table. Call between analysis runs."""
    global _global_table
    if _global_table is not None:
        _global_table.clear()
    _global_table = None


def _popcount(n: int) -> int:
    """Count set bits in an integer. Python 3.9 compatible."""
    return bin(n).count('1')


def _iter_bits(mask: int) -> Iterator[int]:
    """Iterate over set bit positions in O(popcount) time."""
    while mask:
        # Find lowest set bit position
        lsb = mask & -mask
        yield lsb.bit_length() - 1
        mask ^= lsb


@dataclass(frozen=True, repr=False)
class PointsToSet:
    """Immutable bitset-backed set of abstract objects.

    Internally stores three bitmasks for different object categories:
    - objs_mask: general objects (non-method)
    - classmethods_mask: class method objects
    - instancemethods_mask: instance method objects

    This separation allows efficient method binding/inheritance transforms.
    """

    objs_mask: int
    classmethods_mask: int
    instancemethods_mask: int

    @staticmethod
    def empty() -> 'PointsToSet':
        """Create empty points-to set."""
        return _EMPTY_PTS

    @staticmethod
    def singleton(obj: 'AbstractObject') -> 'PointsToSet':
        """Create singleton points-to set containing one object."""
        from .object import MethodObject

        table = _get_object_table()
        obj_id = table.get_id(obj)
        bit = 1 << obj_id

        if isinstance(obj, MethodObject):
            if obj.alloc_site.stmt.is_class_method:
                return PointsToSet(0, bit, 0)
            else:
                return PointsToSet(0, 0, bit)
        return PointsToSet(bit, 0, 0)

    @staticmethod
    def from_objects(objs: Iterable['AbstractObject']) -> 'PointsToSet':
        """Create points-to set from an iterable of objects."""
        from .object import MethodObject

        table = _get_object_table()
        objs_mask = 0
        cms_mask = 0
        ims_mask = 0

        for obj in objs:
            obj_id = table.get_id(obj)
            bit = 1 << obj_id
            if isinstance(obj, MethodObject):
                if obj.alloc_site.stmt.is_class_method:
                    cms_mask |= bit
                else:
                    ims_mask |= bit
            else:
                objs_mask |= bit

        if objs_mask == 0 and cms_mask == 0 and ims_mask == 0:
            return _EMPTY_PTS
        return PointsToSet(objs_mask, cms_mask, ims_mask)

    def inherit_to(self, new_cls: 'ClassObject') -> 'PointsToSet':
        """Transform methods for class inheritance.

        Creates new MethodObject instances with inherit_into() and interns them.
        """
        if self.classmethods_mask == 0 and self.instancemethods_mask == 0:
            return self

        table = _get_object_table()
        new_cms_mask = 0
        new_ims_mask = 0

        # Transform class methods
        for obj_id in _iter_bits(self.classmethods_mask):
            cm = table.get_obj(obj_id)
            new_cm = cm.inherit_into(new_cls)
            new_id = table.get_id(new_cm)
            new_cms_mask |= (1 << new_id)

        # Transform instance methods
        for obj_id in _iter_bits(self.instancemethods_mask):
            im = table.get_obj(obj_id)
            new_im = im.inherit_into(new_cls)
            new_id = table.get_id(new_im)
            new_ims_mask |= (1 << new_id)

        return PointsToSet(self.objs_mask, new_cms_mask, new_ims_mask)

    def deliver_into(self, new_inst: 'InstanceObject') -> 'PointsToSet':
        """Bind instance methods to a specific instance.

        Creates new MethodObject instances with deliver_into() and interns them.
        """
        if self.instancemethods_mask == 0:
            return self

        table = _get_object_table()
        new_ims_mask = 0

        for obj_id in _iter_bits(self.instancemethods_mask):
            im = table.get_obj(obj_id)
            new_im = im.deliver_into(new_inst)
            new_id = table.get_id(new_im)
            new_ims_mask |= (1 << new_id)

        return PointsToSet(self.objs_mask, self.classmethods_mask, new_ims_mask)

    def union(self, other: 'PointsToSet') -> 'PointsToSet':
        """Union with another points-to set."""
        new_objs = self.objs_mask | other.objs_mask
        new_cms = self.classmethods_mask | other.classmethods_mask
        new_ims = self.instancemethods_mask | other.instancemethods_mask

        if (new_objs == self.objs_mask and new_cms == self.classmethods_mask
                and new_ims == self.instancemethods_mask):
            return self
        if (new_objs == other.objs_mask and new_cms == other.classmethods_mask
                and new_ims == other.instancemethods_mask):
            return other
        return PointsToSet(new_objs, new_cms, new_ims)

    def intersection(self, other: 'PointsToSet') -> 'PointsToSet':
        """Intersection with another points-to set."""
        new_objs = self.objs_mask & other.objs_mask
        new_cms = self.classmethods_mask & other.classmethods_mask
        new_ims = self.instancemethods_mask & other.instancemethods_mask

        if new_objs == 0 and new_cms == 0 and new_ims == 0:
            return _EMPTY_PTS
        return PointsToSet(new_objs, new_cms, new_ims)

    def is_empty(self) -> bool:
        """Check if set is empty."""
        return (self.objs_mask == 0 and self.classmethods_mask == 0
                and self.instancemethods_mask == 0)

    def __len__(self) -> int:
        """Get number of objects in set."""
        return (_popcount(self.objs_mask)
                + _popcount(self.classmethods_mask)
                + _popcount(self.instancemethods_mask))

    def __iter__(self) -> Iterator['AbstractObject']:
        """Iterate over objects in set."""
        table = _get_object_table()
        for obj_id in _iter_bits(self.classmethods_mask):
            yield table.get_obj(obj_id)
        for obj_id in _iter_bits(self.instancemethods_mask):
            yield table.get_obj(obj_id)
        for obj_id in _iter_bits(self.objs_mask):
            yield table.get_obj(obj_id)

    def __contains__(self, obj: 'AbstractObject') -> bool:
        """Check if object is in set."""
        table = _get_object_table()
        obj_id = table.lookup_id(obj)
        if obj_id is None:
            return False
        bit = 1 << obj_id
        combined_mask = self.objs_mask | self.classmethods_mask | self.instancemethods_mask
        return bool(combined_mask & bit)

    def __sub__(self, other: 'PointsToSet') -> 'PointsToSet':
        """Subtract another points-to set (set difference)."""
        new_objs = self.objs_mask & ~other.objs_mask
        new_cms = self.classmethods_mask & ~other.classmethods_mask
        new_ims = self.instancemethods_mask & ~other.instancemethods_mask

        if new_objs == 0 and new_cms == 0 and new_ims == 0:
            return _EMPTY_PTS
        if (new_objs == self.objs_mask and new_cms == self.classmethods_mask
                and new_ims == self.instancemethods_mask):
            return self
        return PointsToSet(new_objs, new_cms, new_ims)

    def __str__(self) -> str:
        """String representation for debugging."""
        if self.is_empty():
            return "{}"
        objs = sorted((str(o) for o in self), key=str)
        return "{" + ", ".join(objs) + "}"

    def __repr__(self) -> str:
        return f"PointsToSet({self})"

    # Compatibility properties for code that directly accesses the frozenset fields
    @property
    def objects(self) -> FrozenSet['AbstractObject']:
        """Lazy materialization of objects frozenset for compatibility."""
        table = _get_object_table()
        return frozenset(table.get_obj(obj_id) for obj_id in _iter_bits(self.objs_mask))

    @property
    def classmethods(self) -> FrozenSet['MethodObject']:
        """Lazy materialization of classmethods frozenset for compatibility."""
        table = _get_object_table()
        return frozenset(table.get_obj(obj_id) for obj_id in _iter_bits(self.classmethods_mask))

    @property
    def instancemethods(self) -> FrozenSet['MethodObject']:
        """Lazy materialization of instancemethods frozenset for compatibility."""
        table = _get_object_table()
        return frozenset(table.get_obj(obj_id) for obj_id in _iter_bits(self.instancemethods_mask))


# Singleton empty set to avoid repeated allocations
_EMPTY_PTS = PointsToSet(0, 0, 0)
