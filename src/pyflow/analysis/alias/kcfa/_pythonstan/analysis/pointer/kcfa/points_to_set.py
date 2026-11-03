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
        self._obj_to_id: Dict["AbstractObject", int] = {}
        self._id_to_obj: List["AbstractObject"] = []
        # Bitset of interned function/method objects.  Method rebinding checks
        # this before scanning a points-to set, which keeps class lookups cheap
        # on large programs where most objects are not callables.
        self.callable_mask = 0

    def intern(self, obj: "AbstractObject") -> int:
        existing = self._obj_to_id.get(obj)
        if existing is not None:
            return existing
        object_id = len(self._id_to_obj)
        self._obj_to_id[obj] = object_id
        self._id_to_obj.append(obj)
        from .object import FunctionObject

        if isinstance(obj, FunctionObject):
            self.callable_mask |= 1 << object_id
        return object_id

    def object_at(self, object_id: int) -> "AbstractObject":
        return self._id_to_obj[object_id]

    def lookup(self, obj: "AbstractObject") -> Optional[int]:
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
    def empty(arena: Optional[AnalysisArena] = None) -> "PointsToSet":
        if arena is None:
            return _EMPTY_PTS
        return PointsToSet(0, 0, 0, arena)

    @staticmethod
    def singleton(
        obj: "AbstractObject",
        arena: Optional[AnalysisArena] = None,
    ) -> "PointsToSet":
        return PointsToSet.from_objects((obj,), arena=arena)

    @staticmethod
    def from_objects(
        objs: Iterable["AbstractObject"],
        arena: Optional[AnalysisArena] = None,
    ) -> "PointsToSet":
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

    def rebase(self, arena: AnalysisArena) -> "PointsToSet":
        """Return an equivalent set whose bits belong to ``arena``."""
        if self.arena is arena:
            return self
        if self.is_empty():
            return PointsToSet.empty(arena)
        return PointsToSet.from_objects(self, arena=arena)

    def _common_arena(self, other: "PointsToSet") -> Optional[AnalysisArena]:
        if self.arena is not None:
            return self.arena
        return other.arena

    def _bind_plain_functions(
        self,
        class_obj: "ClassObject",
        instance_obj: Optional["InstanceObject"],
    ) -> int:
        """Bind plain functions stored through attribute assignment.

        ``A.m = f`` / ``a.m = f`` store a bare ``FunctionObject`` in the class
        (or instance) namespace rather than the ``MethodObject`` produced by a
        ``def`` in a class body.  Python still binds such functions on
        attribute access, so they must be rebound here; otherwise the call is
        dropped (arity check) or resolves to a stale method.
        """
        from .object import FunctionObject, MethodObject

        if self.objs_mask == 0 or self.arena is None:
            return self.objs_mask
        if not (self.objs_mask & self.arena.callable_mask):
            return self.objs_mask
        rebound = 0
        changed = False
        for object_id in _iter_bits(self.objs_mask):
            obj = self.arena.object_at(object_id)
            bound = obj
            if isinstance(obj, MethodObject):
                # Method objects can reach the plain-object mask through raw
                # pointer-flow joins.  Bind an unbound instance method to the
                # current receiver; never re-bind an already-bound method.
                if (
                    obj.instance_obj is None
                    and not getattr(obj.ir, "is_static_method", False)
                    and not getattr(obj.ir, "is_class_method", False)
                ):
                    if instance_obj is not None:
                        bound = obj.deliver_into(instance_obj)
                    elif obj.class_obj is not class_obj:
                        bound = obj.inherit_into(class_obj)
            elif isinstance(obj, FunctionObject):
                ir = getattr(obj, "ir", None)
                if not getattr(ir, "is_static_method", False):
                    holder = None if getattr(ir, "is_class_method", False) else instance_obj
                    bound = MethodObject(
                        obj.context,
                        obj.alloc_site,
                        obj.container_scope,
                        obj.ir,
                        class_obj,
                        holder,
                    )
            if bound is obj:
                rebound |= 1 << object_id
            else:
                rebound |= 1 << self.arena.intern(bound)
                changed = True
        return rebound if changed else self.objs_mask

    def inherit_to(self, new_cls: "ClassObject") -> "PointsToSet":
        new_objs = self._bind_plain_functions(new_cls, None)
        if (
            self.classmethods_mask == 0
            and self.instancemethods_mask == 0
            and new_objs == self.objs_mask
        ):
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
            new_objs,
            new_classmethods,
            new_instancemethods,
            self.arena,
        )

    def deliver_into(self, new_inst: "InstanceObject") -> "PointsToSet":
        from .object import InstanceObject

        if isinstance(new_inst, InstanceObject):
            bind_class = new_inst.class_obj
            holder = new_inst
        else:
            # Some callers pass a class object where an instance is expected
            # (for example a pending ``super()`` variant).  Binding to the
            # class that owns the attribute is the sound approximation.
            bind_class = new_inst
            holder = None
        new_objs = self._bind_plain_functions(bind_class, holder)
        if self.instancemethods_mask == 0 and new_objs == self.objs_mask:
            return self
        assert self.arena is not None
        new_instancemethods = 0
        for object_id in _iter_bits(self.instancemethods_mask):
            method = self.arena.object_at(object_id)
            if holder is None:
                rebound = method.inherit_into(bind_class)
            else:
                rebound = method.deliver_into(holder)
            new_instancemethods |= 1 << self.arena.intern(rebound)
        return PointsToSet(
            new_objs,
            self.classmethods_mask,
            new_instancemethods,
            self.arena,
        )

    def union(self, other: "PointsToSet") -> "PointsToSet":
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

    def intersection(self, other: "PointsToSet") -> "PointsToSet":
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

    def __iter__(self) -> Iterator["AbstractObject"]:
        if self.is_empty():
            return
        assert self.arena is not None
        for object_id in _iter_bits(self.classmethods_mask):
            yield self.arena.object_at(object_id)
        for object_id in _iter_bits(self.instancemethods_mask):
            yield self.arena.object_at(object_id)
        for object_id in _iter_bits(self.objs_mask):
            yield self.arena.object_at(object_id)

    def __contains__(self, obj: "AbstractObject") -> bool:
        if self.arena is None:
            return False
        object_id = self.arena.lookup(obj)
        if object_id is None:
            return False
        mask = self.objs_mask | self.classmethods_mask | self.instancemethods_mask
        return bool(mask & (1 << object_id))

    def __sub__(self, other: "PointsToSet") -> "PointsToSet":
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
    def objects(self) -> FrozenSet["AbstractObject"]:
        if self.arena is None:
            return frozenset()
        return frozenset(
            self.arena.object_at(object_id) for object_id in _iter_bits(self.objs_mask)
        )

    @property
    def classmethods(self) -> FrozenSet["MethodObject"]:
        if self.arena is None:
            return frozenset()
        return frozenset(
            self.arena.object_at(object_id) for object_id in _iter_bits(self.classmethods_mask)
        )

    @property
    def instancemethods(self) -> FrozenSet["MethodObject"]:
        if self.arena is None:
            return frozenset()
        return frozenset(
            self.arena.object_at(object_id) for object_id in _iter_bits(self.instancemethods_mask)
        )


_EMPTY_PTS = PointsToSet(0, 0, 0)
