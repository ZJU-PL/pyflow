"""Operations over user, builtin, native, and opaque abstract types."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Tuple

from .object import (
    AbstractObject,
    BuiltinClassObject,
    BuiltinFunctionObject,
    BuiltinInstanceObject,
    ClassObject,
    InstanceObject,
    NativeObject,
)
from .type_ref import TypeRef, TypeRefKind

if TYPE_CHECKING:
    from .heap_model import Field
    from .points_to_set import PointsToSet
    from .state import PointerAnalysisState


class TypeUniverse:
    """Single abstraction boundary for type-like semantic operations."""

    _BUILTIN_TYPE_NAMES = {
        "bool", "bytes", "dict", "float", "frozenset", "int", "list",
        "object", "range", "set", "str", "tuple", "type",
    }

    def __init__(self, state: 'PointerAnalysisState') -> None:
        self._state = state

    def ref(self, obj: AbstractObject) -> TypeRef:
        if isinstance(obj, ClassObject):
            return TypeRef.user(obj)
        if isinstance(obj, BuiltinClassObject):
            return TypeRef.builtin(obj.builtin_name, obj)
        if isinstance(obj, BuiltinFunctionObject):
            if obj.function_name in self._BUILTIN_TYPE_NAMES:
                return TypeRef.builtin(obj.function_name, obj)
            return TypeRef.opaque(obj.function_name, obj)
        if isinstance(obj, NativeObject):
            return TypeRef.native(obj, obj.access_path)
        return TypeRef.opaque(str(obj), obj)

    def instance_type(self, obj: AbstractObject) -> TypeRef:
        """Return the MRO-bearing type used to look up attributes on ``obj``."""
        if isinstance(obj, InstanceObject):
            return TypeRef.user(obj.class_obj)
        if isinstance(obj, ClassObject):
            # A class supplied as super's second argument contributes its own
            # class hierarchy, not the hierarchy of its metaclass.
            return TypeRef.user(obj)
        if isinstance(obj, BuiltinInstanceObject):
            return TypeRef.builtin(obj.builtin_type)
        return TypeRef.opaque(f"type({obj})", obj)

    def mro(self, type_ref: TypeRef) -> Tuple[TypeRef, ...]:
        if (
            type_ref.kind is TypeRefKind.USER
            and isinstance(type_ref.target, ClassObject)
        ):
            variants = self._state.classes.variants(type_ref.target)
            if variants:
                # Callers needing alternative-sensitive behavior iterate the
                # variants directly.  This merged view remains conservative.
                refs = []
                for variant in variants:
                    refs.extend(variant.mro)
                return tuple(dict.fromkeys(refs))
            hierarchy = self._state.class_hierarchy
            if hierarchy is not None:
                try:
                    return tuple(
                        TypeRef.user(obj)
                        for obj in hierarchy.get_mro(type_ref.target)
                    )
                except Exception:
                    pass
            return (type_ref,)
        if type_ref.kind is TypeRefKind.BUILTIN:
            if type_ref.name == "object":
                return (type_ref,)
            return (type_ref, TypeRef.builtin("object"))
        return (type_ref,)

    def c3_mro_for_bases(
        self, bases: Tuple[TypeRef, ...]
    ) -> Tuple[TypeRef, ...]:
        """Compute the C3 tail for a concrete sequence of type references."""
        from .class_hierarchy import MROError

        sequences = [list(self.mro(base)) for base in bases]
        sequences.append(list(bases))
        result = []
        while True:
            sequences = [sequence for sequence in sequences if sequence]
            if not sequences:
                return tuple(result)
            candidate = None
            for sequence in sequences:
                head = sequence[0]
                if all(head not in other[1:] for other in sequences):
                    candidate = head
                    break
            if candidate is None:
                raise MROError("inconsistent abstract C3 linearization")
            result.append(candidate)
            for sequence in sequences:
                if sequence and sequence[0] == candidate:
                    sequence.pop(0)

    def metaclass(self, type_ref: TypeRef) -> Tuple[TypeRef, ...]:
        if (
            type_ref.kind is TypeRefKind.USER
            and isinstance(type_ref.target, ClassObject)
        ):
            variants = self._state.classes.variants(type_ref.target)
            if variants:
                return tuple(dict.fromkeys(v.metaclass for v in variants))
            return self._state.classes.metaclass_refs_for_class(
                type_ref.target
            )
        if type_ref.kind is TypeRefKind.BUILTIN:
            return (TypeRef.builtin("type"),)
        return (TypeRef.opaque("unknown-metaclass"),)

    def raw_member(self, type_ref: TypeRef, field: 'Field') -> 'PointsToSet':
        if type_ref.target is None:
            from .points_to_set import PointsToSet

            return PointsToSet.empty(self._state.arena)
        return self._state.raw_field_points_to(type_ref.target, field)

    def is_subtype(self, candidate: TypeRef, expected: TypeRef) -> bool:
        return expected in self.mro(candidate)

    @staticmethod
    def is_subclassable(type_ref: TypeRef) -> Optional[bool]:
        if type_ref.kind in (TypeRefKind.USER, TypeRefKind.BUILTIN):
            return True
        if type_ref.kind is TypeRefKind.OPAQUE:
            return None
        return False
