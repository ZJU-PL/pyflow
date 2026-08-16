"""Bitset-backed points-to sets with analysis-local object interning.

Python integers provide a compact and fast bitset representation, but the bits
only have meaning relative to the object table that assigned them.  Earlier
versions kept that table in a module global and reset it before every run.  Two
overlapping analyses could therefore reinterpret each other's points-to sets.

``AnalysisArena`` makes the ownership explicit.  A normal analysis owns one
arena through :class:`PointerAnalysisState`; standalone sets created by tests or
clients can still be combined because operations transparently rebase the
right-hand operand into the left-hand arena.
"""

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, Iterator, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .object import AbstractObject, ClassObject, InstanceObject, MethodObject

__all__ = ["AnalysisArena", "PointsToSet"]


class AnalysisArena:
    """Analysis-local interner assigning dense bit positions to objects.

    The mapping is intentionally owned by a single analysis state.  Dense IDs
    are an implementation detail; semantic identity remains the immutable
    ``AbstractObject`` value, so rebasing between arenas is lossless.
    """

    def __init__(self) -> None:
        self._obj_to_id: Dict['AbstractObject', int] = {}
        self._id_to_obj: List['AbstractObject'] = []

    def intern(self, obj: 'AbstractObject') -> int:
        existing = self._obj_to_id.get(obj)
        if existing is not None:
            return existing
        object_id = len(self._id_to_obj)
        self._obj_to_id[obj] = object_id
        self._id_to_obj.append(obj)
        return object_id

    def object_at(self, object_id: int) -> 'AbstractObject':
        return self._id_to_obj[object_id]

    def lookup(self, obj: 'AbstractObject') -> Optional[int]:
        return self._obj_to_id.get(obj)

    def __len__(self) -> int:
        return len(self._id_to_obj)


def _popcount(value: int) -> int:
    return value.bit_count()


def _iter_bits(mask: int) -> Iterator[int]:
    while mask:
        least_bit = mask & -mask
        yield least_bit.bit_length() - 1
        mask ^= least_bit


@dataclass(frozen=True, repr=False, eq=False)
class PointsToSet:
    """Immutable bitset-backed set of abstract objects.

    Empty sets may be arena-neutral.  Every non-empty set has an arena, and all
    operations preserve or explicitly convert arena ownership.
    """

    objs_mask: int
    classmethods_mask: int
    instancemethods_mask: int
    arena: Optional[AnalysisArena] = None

    def __post_init__(self) -> None:
        if not self.is_empty() and self.arena is None:
            raise ValueError("a non-empty points-to set requires an AnalysisArena")

    @staticmethod
    def empty(arena: Optional[AnalysisArena] = None) -> 'PointsToSet':
        if arena is None:
            return _EMPTY_PTS
        return PointsToSet(0, 0, 0, arena)

    @staticmethod
    def singleton(
        obj: 'AbstractObject',
        arena: Optional[AnalysisArena] = None,
    ) -> 'PointsToSet':
        return PointsToSet.from_objects((obj,), arena=arena)

    @staticmethod
    def from_objects(
        objs: Iterable['AbstractObject'],
        arena: Optional[AnalysisArena] = None,
    ) -> 'PointsToSet':
        from .object import MethodObject

        materialized = tuple(objs)
        if not materialized:
            return PointsToSet.empty(arena)
        # ``AnalysisArena`` implements ``__len__`` and a fresh arena is falsey;
        # use an identity check so an explicitly supplied empty arena is kept.
        owner = arena if arena is not None else AnalysisArena()
        objs_mask = 0
        classmethods_mask = 0
        instancemethods_mask = 0
        for obj in materialized:
            bit = 1 << owner.intern(obj)
            if isinstance(obj, MethodObject):
                if obj.alloc_site.stmt.is_class_method:
                    classmethods_mask |= bit
                else:
                    instancemethods_mask |= bit
            else:
                objs_mask |= bit
        return PointsToSet(
            objs_mask,
            classmethods_mask,
            instancemethods_mask,
            owner,
        )

    def rebase(self, arena: AnalysisArena) -> 'PointsToSet':
        """Return an equivalent set whose bits belong to ``arena``."""
        if self.arena is arena:
            return self
        if self.is_empty():
            return PointsToSet.empty(arena)
        return PointsToSet.from_objects(self, arena=arena)

    def _common_arena(self, other: 'PointsToSet') -> Optional[AnalysisArena]:
        if self.arena is not None:
            return self.arena
        return other.arena

    def inherit_to(self, new_cls: 'ClassObject') -> 'PointsToSet':
        if self.classmethods_mask == 0 and self.instancemethods_mask == 0:
            return self
        assert self.arena is not None
        new_classmethods = 0
        new_instancemethods = 0
        for object_id in _iter_bits(self.classmethods_mask):
            method = self.arena.object_at(object_id)
            new_classmethods |= 1 << self.arena.intern(method.inherit_into(new_cls))
        for object_id in _iter_bits(self.instancemethods_mask):
            method = self.arena.object_at(object_id)
            new_instancemethods |= 1 << self.arena.intern(method.inherit_into(new_cls))
        return PointsToSet(
            self.objs_mask,
            new_classmethods,
            new_instancemethods,
            self.arena,
        )

    def deliver_into(self, new_inst: 'InstanceObject') -> 'PointsToSet':
        if self.instancemethods_mask == 0:
            return self
        assert self.arena is not None
        new_instancemethods = 0
        for object_id in _iter_bits(self.instancemethods_mask):
            method = self.arena.object_at(object_id)
            new_instancemethods |= 1 << self.arena.intern(method.deliver_into(new_inst))
        return PointsToSet(
            self.objs_mask,
            self.classmethods_mask,
            new_instancemethods,
            self.arena,
        )

    def union(self, other: 'PointsToSet') -> 'PointsToSet':
        arena = self._common_arena(other)
        if arena is None:
            return _EMPTY_PTS
        left = self.rebase(arena)
        right = other.rebase(arena)
        new_masks = (
            left.objs_mask | right.objs_mask,
            left.classmethods_mask | right.classmethods_mask,
            left.instancemethods_mask | right.instancemethods_mask,
        )
        if new_masks == (
            left.objs_mask,
            left.classmethods_mask,
            left.instancemethods_mask,
        ):
            return left
        if new_masks == (
            right.objs_mask,
            right.classmethods_mask,
            right.instancemethods_mask,
        ):
            return right
        return PointsToSet(*new_masks, arena)

    def intersection(self, other: 'PointsToSet') -> 'PointsToSet':
        arena = self._common_arena(other)
        if arena is None:
            return _EMPTY_PTS
        left = self.rebase(arena)
        right = other.rebase(arena)
        masks = (
            left.objs_mask & right.objs_mask,
            left.classmethods_mask & right.classmethods_mask,
            left.instancemethods_mask & right.instancemethods_mask,
        )
        return PointsToSet(*masks, arena)

    def is_empty(self) -> bool:
        return not (self.objs_mask or self.classmethods_mask or self.instancemethods_mask)

    def __len__(self) -> int:
        return (
            _popcount(self.objs_mask)
            + _popcount(self.classmethods_mask)
            + _popcount(self.instancemethods_mask)
        )

    def __iter__(self) -> Iterator['AbstractObject']:
        if self.is_empty():
            return
        assert self.arena is not None
        for object_id in _iter_bits(self.classmethods_mask):
            yield self.arena.object_at(object_id)
        for object_id in _iter_bits(self.instancemethods_mask):
            yield self.arena.object_at(object_id)
        for object_id in _iter_bits(self.objs_mask):
            yield self.arena.object_at(object_id)

    def __contains__(self, obj: 'AbstractObject') -> bool:
        if self.arena is None:
            return False
        object_id = self.arena.lookup(obj)
        if object_id is None:
            return False
        mask = self.objs_mask | self.classmethods_mask | self.instancemethods_mask
        return bool(mask & (1 << object_id))

    def __sub__(self, other: 'PointsToSet') -> 'PointsToSet':
        arena = self._common_arena(other)
        if arena is None:
            return _EMPTY_PTS
        left = self.rebase(arena)
        right = other.rebase(arena)
        masks = (
            left.objs_mask & ~right.objs_mask,
            left.classmethods_mask & ~right.classmethods_mask,
            left.instancemethods_mask & ~right.instancemethods_mask,
        )
        if masks == (
            left.objs_mask,
            left.classmethods_mask,
            left.instancemethods_mask,
        ):
            return left
        return PointsToSet(*masks, arena)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PointsToSet):
            return NotImplemented
        if self.is_empty() and other.is_empty():
            return True
        if self.arena is other.arena:
            return (
                self.objs_mask == other.objs_mask
                and self.classmethods_mask == other.classmethods_mask
                and self.instancemethods_mask == other.instancemethods_mask
            )
        return frozenset(self) == frozenset(other)

    def __hash__(self) -> int:
        return hash(frozenset(self))

    def __str__(self) -> str:
        if self.is_empty():
            return "{}"
        return "{" + ", ".join(sorted(str(obj) for obj in self)) + "}"

    def __repr__(self) -> str:
        return f"PointsToSet({self})"

    @property
    def objects(self) -> FrozenSet['AbstractObject']:
        if self.arena is None:
            return frozenset()
        return frozenset(
            self.arena.object_at(object_id)
            for object_id in _iter_bits(self.objs_mask)
        )

    @property
    def classmethods(self) -> FrozenSet['MethodObject']:
        if self.arena is None:
            return frozenset()
        return frozenset(
            self.arena.object_at(object_id)
            for object_id in _iter_bits(self.classmethods_mask)
        )

    @property
    def instancemethods(self) -> FrozenSet['MethodObject']:
        if self.arena is None:
            return frozenset()
        return frozenset(
            self.arena.object_at(object_id)
            for object_id in _iter_bits(self.instancemethods_mask)
        )


_EMPTY_PTS = PointsToSet(0, 0, 0)
