"""Resolve PEP 560 class bases before hierarchy and metaclass analysis."""

import ast
from itertools import product
from typing import TYPE_CHECKING, Any, Optional

from .processor import Processor
from ..constraints import (
    BaseResolutionConstraint,
    CallConstraint,
    LoadConstraint,
)
from ..heap_model import attr, elem, key
from ..object import (
    BuiltinClassObject,
    BuiltinFunctionObject,
    ClassObject,
    TupleObject,
)
from ..points_to_set import PointsToSet
from ..stable_key import stable_token
from ..unknown_tracker import UnknownKind
from ..variable import Variable, VariableKind
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRAssign

if TYPE_CHECKING:
    from ..constraints import Constraint
    from ..context import Ctx, Scope
    from ..object import AbstractObject
    from ..solver import PointerSolver

__all__ = ["BaseResolutionProcessor"]


class BaseResolutionProcessor(Processor):
    """Expand non-type bases through ``__mro_entries__`` incrementally."""

    _BUILTIN_TYPE_NAMES = {
        "bool", "bytes", "dict", "float", "frozenset", "int", "list",
        "object", "range", "set", "str", "tuple", "type",
    }

    def __init__(self) -> None:
        self._scheduled_calls = set()
        self._installed_results = set()

    def handle_new_constraint(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        constraint: 'Constraint',
    ) -> bool:
        state = solver.state
        if isinstance(constraint, BaseResolutionConstraint):
            base_ctx = state.get_variable(scope, scope.context, constraint.base)
            state.dependencies.subscribe(
                (
                    "base-resolution",
                    constraint.owner,
                    constraint.position,
                    base_ctx,
                ),
                (base_ctx,),
                lambda: self._apply_base_candidates(
                    solver,
                    scope,
                    constraint,
                    state.get_points_to(base_ctx),
                ),
            )
            pts = state.get_points_to(base_ctx)
            if not pts.is_empty():
                self._apply_base_candidates(solver, scope, constraint, pts)
            return True
        return False

    def handle_constraint(
        self,
        solver: 'PointerSolver',
        target: 'Ctx[Any]',
        scope: 'Scope',
        constraint: 'Constraint',
        pts: 'PointsToSet',
    ) -> bool:
        return False

    def _apply_base_candidates(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        constraint: BaseResolutionConstraint,
        pts: 'PointsToSet',
    ) -> None:
        owner = constraint.owner
        if not isinstance(owner, ClassObject):
            return
        for base_obj in pts:
            if isinstance(base_obj, ClassObject):
                solver.state.record_effective_base_sequence(
                    owner, constraint.position, (base_obj,)
                )
                continue
            if self._is_builtin_type(base_obj):
                solver.state.record_opaque_effective_base(
                    owner, constraint.position, base_obj
                )
                continue

            call_key = (owner, constraint.position, base_obj)
            if call_key in self._scheduled_calls:
                continue
            self._scheduled_calls.add(call_key)
            token = (
                f"{stable_token(owner)}@{constraint.position}@"
                f"{stable_token(base_obj)}"
            )
            receiver = Variable(
                name=f"$mro_entries_receiver@{token}",
                kind=VariableKind.TEMPORARY,
            )
            receiver_ctx = solver.state.get_variable(
                scope, scope.context, receiver
            )
            solver.handle_new_points_to(
                receiver_ctx, scope, PointsToSet.singleton(base_obj)
            )
            method = Variable(
                name=f"$mro_entries_method@{token}",
                kind=VariableKind.TEMPORARY,
            )
            result = Variable(
                name=f"$mro_entries_result@{token}",
                kind=VariableKind.TEMPORARY,
            )
            solver.add_constraint(
                scope,
                scope.context,
                LoadConstraint(
                    base=receiver,
                    field=attr("__mro_entries__"),
                    target=method,
                ),
            )
            solver.add_constraint(
                scope,
                scope.context,
                CallConstraint(
                    callee=method,
                    args=(constraint.original_bases,),
                    kwargs=(),
                    target=result,
                    call_site=self._call_site(owner, constraint.position),
                ),
            )
            result_ctx = solver.state.get_variable(
                scope, scope.context, result
            )
            solver.state.dependencies.subscribe(
                ("mro-entries-result", owner, constraint.position, result_ctx),
                (result_ctx,),
                lambda result_ctx=result_ctx: self._apply_result_candidates(
                    solver,
                    scope,
                    owner,
                    constraint.position,
                    solver.state.get_points_to(result_ctx),
                ),
            )
            result_pts = solver.state.get_points_to(result_ctx)
            if not result_pts.is_empty():
                self._apply_result_candidates(
                    solver,
                    scope,
                    owner,
                    constraint.position,
                    result_pts,
                )

    def _apply_result_candidates(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        owner: ClassObject,
        position: int,
        pts: 'PointsToSet',
    ) -> None:
        if not isinstance(owner, ClassObject):
            return
        for result_obj in pts:
            if not isinstance(result_obj, TupleObject):
                self._mark_incomplete(
                    solver,
                    owner,
                    "__mro_entries__ did not return a tuple",
                )
                continue
            result_key = (owner, position, result_obj)
            if result_key in self._installed_results:
                continue
            self._installed_results.add(result_key)
            tuple_length = self._literal_tuple_length(result_obj)
            if tuple_length is None:
                self._mark_incomplete(
                    solver,
                    owner,
                    "cannot determine __mro_entries__ tuple length",
                )
                continue
            if tuple_length == 0:
                solver.state.record_effective_base_sequence(
                    owner, position, ()
                )
                continue

            elements = tuple(
                Variable(
                    name=(
                        f"$mro_entries_element@{stable_token(owner)}@"
                        f"{position}@{stable_token(result_obj)}@{index}"
                    ),
                    kind=VariableKind.TEMPORARY,
                )
                for index in range(tuple_length)
            )
            for index, element_var in enumerate(elements):
                field = key(index) if solver.config.index_sensitive else elem()
                field_ctx = solver.state.get_field(
                    scope, scope.context, result_obj, field
                )
                element_ctx = solver.state.get_variable(
                    scope, scope.context, element_var
                )
                solver.state._add_var_points_flow(field_ctx, element_ctx)
            element_contexts = tuple(
                solver.state.get_variable(scope, scope.context, element)
                for element in elements
            )
            solver.state.dependencies.subscribe(
                ("mro-entries-elements", owner, position, result_obj),
                element_contexts,
                lambda elements=elements: self._refresh_element_sequences(
                    solver, scope, owner, position, elements
                ),
            )
            self._refresh_element_sequences(
                solver, scope, owner, position, elements
            )

    def _refresh_element_sequences(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        owner: ClassObject,
        position: int,
        elements: tuple[Variable, ...],
    ) -> None:
        if not isinstance(owner, ClassObject):
            return
        position_options = []
        for element_var in elements:
            element_ctx = solver.state.get_variable(
                scope, scope.context, element_var
            )
            pts = solver.state.get_points_to(element_ctx)
            if pts.is_empty():
                return
            options = tuple(obj for obj in pts if isinstance(obj, ClassObject))
            if len(options) != len(pts):
                self._mark_incomplete(
                    solver,
                    owner,
                    "__mro_entries__ tuple contains a non-class value",
                )
            if not options:
                return
            position_options.append(options)

        count = 1
        for options in position_options:
            count *= len(options)
        if count > solver.state.MAX_BASE_COMBINATIONS:
            self._mark_incomplete(
                solver,
                owner,
                "too many __mro_entries__ alternatives",
            )
            for options in position_options:
                for base_obj in options:
                    solver.state.record_effective_base_sequence(
                        owner, position, (base_obj,)
                    )
            return

        for sequence in product(*position_options):
            solver.state.record_effective_base_sequence(
                owner, position, tuple(sequence)
            )

    @staticmethod
    def _is_builtin_type(base_obj: 'AbstractObject') -> bool:
        if isinstance(base_obj, BuiltinClassObject):
            return True
        return (
            isinstance(base_obj, BuiltinFunctionObject)
            and base_obj.function_name
            in BaseResolutionProcessor._BUILTIN_TYPE_NAMES
        )

    @staticmethod
    def _literal_tuple_length(result_obj: TupleObject) -> Optional[int]:
        statement = result_obj.alloc_site.stmt
        if not isinstance(statement, IRAssign):
            return None
        value = statement.get_rval()
        if not isinstance(value, ast.Tuple):
            return None
        return len(value.elts)

    @staticmethod
    def _call_site(owner: ClassObject, position: int):
        from ..context import CallSite

        return CallSite(
            statement=owner.ir,
            scope_name=owner.ir.get_qualname(),
            index=position,
        )

    @staticmethod
    def _mark_incomplete(
        solver: 'PointerSolver',
        owner: ClassObject,
        message: str,
    ) -> None:
        solver.mark_semantic_incomplete()
        solver._unknown_tracker.record(
            UnknownKind.BASE_RESOLUTION,
            owner.ir.get_qualname(),
            message,
            context=str(owner.container_scope.context),
        )
