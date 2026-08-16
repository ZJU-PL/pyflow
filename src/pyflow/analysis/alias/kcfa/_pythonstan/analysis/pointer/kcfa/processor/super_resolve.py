"""Resolve explicit and zero-argument ``super()`` variants monotonically."""

from typing import TYPE_CHECKING, Any, Iterable

from .processor import Processor
from ..constraints import AllocConstraint, SuperResolveConstraint
from ..object import AllocKind, MethodObject, SuperObject
from ..points_to_set import PointsToSet
from ..type_ref import TypeRef
from ..variable import Variable, VariableKind
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRCall, IRFunc

if TYPE_CHECKING:
    from ..constraints import Constraint
    from ..context import AbstractContext, Ctx, Scope
    from ..object import AbstractObject
    from ..solver import PointerSolver


class SuperResolveProcessor(Processor):
    """Materialize every feasible ``(start type, receiver)`` alternative."""

    MAX_SUPER_VARIANTS = 64

    def handle_allocation(
        self,
        solver: 'PointerSolver',
        target: 'Ctx[Any]',
        scope: 'Scope',
        context: 'AbstractContext',
        constraint: AllocConstraint,
    ) -> bool:
        if (
            constraint.alloc_site.kind != AllocKind.OBJECT
            or not self._is_super_alloc(solver, target, constraint)
        ):
            return False
        pending = SuperObject(
            context=context,
            alloc_site=constraint.alloc_site,
            start_type=None,
            receiver=None,
            receiver_type=None,
        )
        solver.state._heap.set_obj(
            scope, context, constraint.alloc_site, pending
        )
        solver.state.obj_scope[pending] = scope
        solver.handle_new_points_to(
            target, scope, PointsToSet.singleton(pending)
        )
        return True

    def handle_constraint(
        self,
        solver: 'PointerSolver',
        target: 'Ctx[Any]',
        scope: 'Scope',
        constraint: 'Constraint',
        pts: 'PointsToSet',
    ) -> bool:
        if not isinstance(constraint, SuperResolveConstraint):
            return False
        self._refresh(solver, scope, constraint)
        return True

    def handle_new_constraint(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        constraint: 'Constraint',
    ) -> bool:
        if not isinstance(constraint, SuperResolveConstraint):
            return False
        state = solver.state
        context = scope.context
        target = state.get_variable(scope, context, constraint.target)
        state.constraints.add(scope, target, constraint)
        sources = [target]
        if constraint.class_var is not None:
            sources.append(state.get_variable(
                scope, context, constraint.class_var
            ))
        if constraint.instance_var is not None:
            sources.append(state.get_variable(
                scope, context, constraint.instance_var
            ))
        if constraint.implicit:
            sources.extend(self._implicit_source_cells(solver, scope))
        state.dependencies.subscribe(
            ("super-resolution", scope, constraint),
            sources,
            lambda: self._refresh(solver, scope, constraint),
            run_initial=True,
        )
        return True

    def _refresh(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        constraint: SuperResolveConstraint,
    ) -> None:
        state = solver.state
        context = scope.context
        target = state.get_variable(scope, context, constraint.target)
        pending = tuple(
            obj for obj in state.get_points_to(target)
            if isinstance(obj, SuperObject) and obj.start_type is None
        )
        if not pending:
            return

        if constraint.implicit:
            start_objects, receivers = self._implicit_candidates(
                solver, scope
            )
        else:
            class_ctx = state.get_variable(
                scope, context, constraint.class_var
            )
            receiver_ctx = state.get_variable(
                scope, context, constraint.instance_var
            )
            start_objects = tuple(state.get_points_to(class_ctx))
            receivers = tuple(state.get_points_to(receiver_ctx))
        if not start_objects or not receivers:
            return

        alternatives = [
            (state.types.ref(start), receiver)
            for start in start_objects
            for receiver in receivers
            if state.types.is_subclassable(state.types.ref(start)) is True
        ]
        if not alternatives:
            solver.mark_semantic_incomplete(
                variables=(target,),
                message="super() start argument is not a known type",
            )
            return
        if len(alternatives) > self.MAX_SUPER_VARIANTS:
            solver.mark_semantic_incomplete(
                variables=(target,),
                message="super() alternatives widened",
            )

        resolved = []
        for allocation in pending:
            for start_type, receiver in alternatives:
                resolved.append(SuperObject(
                    context=allocation.context,
                    alloc_site=allocation.alloc_site,
                    start_type=start_type,
                    receiver=receiver,
                    receiver_type=state.types.instance_type(receiver),
                ))
        solver.handle_new_points_to(
            target,
            scope,
            PointsToSet.from_objects(resolved, state.arena),
        )

    def _implicit_source_cells(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
    ) -> Iterable['Ctx[Any]']:
        state = solver.state
        context = scope.context
        cells = [state.get_variable(
            scope,
            context,
            Variable(name="__class__", kind=VariableKind.CELL),
        )]
        if isinstance(scope.stmt, IRFunc) and scope.stmt.args.args:
            cells.append(state.get_variable(
                scope,
                context,
                Variable(
                    name=scope.stmt.args.args[0].arg,
                    kind=VariableKind.LOCAL,
                ),
            ))
        return cells

    def _implicit_candidates(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
    ) -> tuple[tuple['AbstractObject', ...], tuple['AbstractObject', ...]]:
        state = solver.state
        starts = []
        receivers = []
        if isinstance(scope.obj, MethodObject):
            starts.append(scope.obj.class_obj)
            if scope.obj.instance_obj is not None:
                receivers.append(scope.obj.instance_obj)
        cells = tuple(self._implicit_source_cells(solver, scope))
        starts.extend(state.get_points_to(cells[0]))
        if len(cells) > 1:
            receivers.extend(state.get_points_to(cells[1]))
        return tuple(dict.fromkeys(starts)), tuple(dict.fromkeys(receivers))

    @staticmethod
    def _is_super_alloc(
        solver: 'PointerSolver',
        target: 'Ctx[Any]',
        constraint: AllocConstraint,
    ) -> bool:
        statement = constraint.alloc_site.stmt
        if isinstance(statement, IRCall) and statement.func_name == "super":
            return True
        return any(
            isinstance(other, SuperResolveConstraint)
            for _, other in solver.state.constraints.iter_scoped_by_variable(
                target
            )
        )
