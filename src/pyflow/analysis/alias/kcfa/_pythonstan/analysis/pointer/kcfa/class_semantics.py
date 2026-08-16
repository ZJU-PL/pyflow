"""Class construction state exposed independently from raw pointer storage."""

from __future__ import annotations

from itertools import product
from typing import TYPE_CHECKING, FrozenSet, Iterable, Optional, Set, Tuple

from .type_ref import (
    ClassConstructionKind,
    ClassConstructionState,
    ClassVariant,
    InvalidClassVariant,
    TypeRef,
    TypeRefKind,
)
from .object import ClassObject

if TYPE_CHECKING:
    from .object import ClassObject
    from .state import PointerAnalysisState


class ClassSemantics:
    """Authoritative read interface for abstract class construction."""

    def __init__(self, state: 'PointerAnalysisState') -> None:
        self._state = state

    def variants(self, owner: 'ClassObject') -> FrozenSet[ClassVariant]:
        return frozenset(self._state._class_variants.get(owner, ()))

    def invalid_variants(
        self, owner: 'ClassObject'
    ) -> FrozenSet[InvalidClassVariant]:
        return frozenset(
            self._state._invalid_class_variants.get(owner, ())
        )

    def metaclass_refs_for_class(
        self,
        class_obj: ClassObject,
        seen: Optional[Set[ClassObject]] = None,
    ) -> Tuple[TypeRef, ...]:
        state = self._state
        if seen is None:
            seen = set()
        if class_obj in seen:
            return (TypeRef.opaque("recursive-metaclass"),)
        seen.add(class_obj)
        if class_obj.metaclass_variables:
            refs = []
            for meta_var in class_obj.metaclass_variables:
                meta_ctx = state.get_variable(
                    class_obj.container_scope,
                    class_obj.container_scope.context,
                    meta_var,
                )
                pts = state.get_points_to(meta_ctx)
                if pts.is_empty():
                    return ()
                refs.extend(state.types.ref(obj) for obj in pts)
            return tuple(dict.fromkeys(refs))
        variants = self.variants(class_obj)
        if variants:
            return tuple(dict.fromkeys(
                variant.metaclass for variant in variants
            ))
        if not class_obj.base_variables:
            return (TypeRef.builtin("type"),)
        refs = []
        for position in range(len(class_obj.base_variables)):
            for sequence in state._effective_base_sequences.get(
                (class_obj, position), ()
            ):
                for base_ref in sequence:
                    refs.extend(state.types.metaclass(base_ref))
        return tuple(dict.fromkeys(refs))

    def select_metaclass(
        self, candidates: Iterable[TypeRef]
    ) -> Tuple[Optional[TypeRef], Optional[str]]:
        state = self._state
        refs = tuple(dict.fromkeys(candidates))
        if not refs:
            return TypeRef.builtin("type"), None
        if any(ref.is_opaque for ref in refs):
            return TypeRef.opaque("compatible-metaclass"), None
        user_refs = [
            ref for ref in refs
            if ref.kind is TypeRefKind.USER
            and isinstance(ref.target, ClassObject)
        ]
        if not user_refs:
            return refs[0], None
        if state.class_hierarchy is None:
            return TypeRef.opaque("unresolved-metaclass-hierarchy"), None
        compatible = []
        for candidate in user_refs:
            try:
                candidate_mro = set(
                    state.class_hierarchy.get_mro(candidate.target)
                )
            except Exception:
                continue
            if all(other.target in candidate_mro for other in user_refs):
                compatible.append(candidate)
        if not compatible:
            return None, "metaclass conflict"
        return compatible[0], None

    def refresh_variants(self, owner: ClassObject) -> None:
        state = self._state
        if not owner.base_variables:
            metaclass_refs = self.metaclass_refs_for_class(owner)
            if owner.metaclass_variables and not metaclass_refs:
                return
            if owner.metaclass_variables:
                metaclass_refs = tuple(
                    ref for ref in metaclass_refs
                    if ref.kind is not TypeRefKind.OPAQUE
                )
                if not metaclass_refs:
                    return
            metaclass, error = self.select_metaclass(metaclass_refs)
            if error is not None:
                state._invalid_class_variants[owner].add(
                    InvalidClassVariant(owner, (), error)
                )
                return
            if metaclass is not None:
                state._class_variants[owner].add(ClassVariant(
                    owner=owner,
                    effective_bases=(),
                    metaclass=metaclass,
                    mro=(TypeRef.user(owner),),
                ))
            return

        sequence_options = []
        for position in range(len(owner.base_variables)):
            options = tuple(state._effective_base_sequences.get(
                (owner, position), ()
            ))
            if not options:
                return
            sequence_options.append(options)
        combination_count = 1
        for options in sequence_options:
            combination_count *= len(options)
        if combination_count > state.MAX_BASE_COMBINATIONS:
            refs = []
            for options in sequence_options:
                for sequence in options:
                    refs.extend(sequence)
            unique_refs = tuple(dict.fromkeys(refs))
            state._class_variants[owner].add(ClassVariant(
                owner=owner,
                effective_bases=unique_refs,
                metaclass=TypeRef.opaque("widened-metaclass"),
                mro=(TypeRef.user(owner), *unique_refs),
                widened=True,
            ))
            return

        from .class_hierarchy import MROError

        for selected in product(*sequence_options):
            base_refs = tuple(
                base_ref for sequence in selected for base_ref in sequence
            )
            try:
                mro_tail = state.types.c3_mro_for_bases(base_refs)
            except MROError as error:
                state._invalid_class_variants[owner].add(
                    InvalidClassVariant(owner, base_refs, str(error))
                )
                continue
            metaclass_candidates = []
            if owner.metaclass_variables:
                metaclass_candidates.extend(
                    ref for ref in self.metaclass_refs_for_class(owner)
                    if ref.kind is not TypeRefKind.OPAQUE
                )
                if not metaclass_candidates:
                    continue
            for base_ref in base_refs:
                metaclass_candidates.extend(state.types.metaclass(base_ref))
            metaclass, error = self.select_metaclass(
                metaclass_candidates
            )
            if error is not None or metaclass is None:
                state._invalid_class_variants[owner].add(
                    InvalidClassVariant(
                        owner, base_refs, error or "invalid metaclass"
                    )
                )
                continue
            state._class_variants[owner].add(ClassVariant(
                owner=owner,
                effective_bases=base_refs,
                metaclass=metaclass,
                mro=(TypeRef.user(owner), *mro_tail),
            ))

    def variant_has_custom_metaclass_new(
        self, variant: ClassVariant
    ) -> bool:
        state = self._state
        metaclass = variant.metaclass
        if (
            metaclass.kind is not TypeRefKind.USER
            or not isinstance(metaclass.target, ClassObject)
        ):
            return False
        candidates = [metaclass.target]
        meta_variants = self.variants(metaclass.target)
        if meta_variants:
            candidates.extend(
                ref.target
                for meta_variant in meta_variants
                for ref in meta_variant.mro[1:]
                if (
                    ref.kind is TypeRefKind.USER
                    and isinstance(ref.target, ClassObject)
                )
            )
        elif state.class_hierarchy is not None:
            try:
                candidates = list(
                    state.class_hierarchy.get_mro(metaclass.target)
                )
            except Exception:
                pass
        return any(
            "__new__" in candidate.ir.get_definitely_declared_names()
            for candidate in candidates
        )

    def construction_state(
        self, owner: 'ClassObject'
    ) -> ClassConstructionState:
        self.refresh_variants(owner)
        variants = tuple(self.variants(owner))
        if variants:
            if any(
                variant.widened or variant.metaclass.is_opaque
                for variant in variants
            ):
                return ClassConstructionState(
                    ClassConstructionKind.UNKNOWN,
                    variants=variants,
                    reasons=("class alternatives were widened",),
                )
            return ClassConstructionState(
                ClassConstructionKind.FEASIBLE,
                variants=variants,
            )
        invalid = tuple(self.invalid_variants(owner))
        positions_resolved = all(
            self._state._effective_base_sequences.get((owner, position))
            for position in range(len(owner.base_variables))
        )
        if (
            self._state._construction_inputs_sealed
            and invalid
            and (not owner.base_variables or positions_resolved)
        ):
            return ClassConstructionState(
                ClassConstructionKind.INVALID,
                reasons=tuple(dict.fromkeys(v.reason for v in invalid)),
            )
        return ClassConstructionState(ClassConstructionKind.PENDING)
