"""Translate Python attribute operations into pointer-flow constraints.

The processor models instance and class lookup, inheritance, descriptors, and
the interception hooks used by ``__getattribute__``, ``__getattr__``, and
``__setattr__``.
"""

import ast
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from .processor import Processor
from ..constraints import (
    AttrReadConstraint,
    AttrWriteConstraint,
    LoadConstraint,
    StoreConstraint,
    CallConstraint,
    AllocConstraint,
)
from ..context import Ctx
from ..heap_model import Field, FieldKind, attr, unknown
from ..object import AllocKind, AllocSite, InstanceObject
from ..points_to_set import PointsToSet
from ..pointer_flow_graph import GuardNode, NormalNode, PointerFlowEdge, PointerFlowKind, SelectorNode
from ..variable import Variable, VariableKind
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRAssign

if TYPE_CHECKING:
    from ..context import Scope, AbstractContext
    from ..solver import PointerSolver
    from ..constraints import Constraint
    from ..object import AbstractObject, ClassObject

__all__ = ["AttributeSemanticsProcessor"]


class AttributeSemanticsProcessor(Processor):
    """Apply Python attribute read and write semantics during solving.

    Constant attribute names are resolved precisely.  Dynamic names fall back
    to conservative unknown fields so that dataflow is retained when the
    concrete attribute cannot be determined statically.
    """

    _READ_INTERCEPT_SKIP = {"__getattribute__", "__getattr__"}
    _WRITE_INTERCEPT_SKIP = {"__setattr__"}
    
    def __init__(self) -> None:
        self._const_alloc_sites: Dict[str, AllocSite] = {}
    
    def handle_new_constraint(self, solver: 'PointerSolver', scope: 'Scope', constraint: 'Constraint') -> bool:
        state = solver.state
        if isinstance(constraint, AttrReadConstraint):
            base_ctx = state.get_variable(scope, scope.context, constraint.base)
            state.constraints.add(scope, base_ctx, constraint)
            base_pts = state.get_points_to(base_ctx)
            if not base_pts.is_empty():
                self._apply_attr_read(solver, scope, base_ctx, constraint, base_pts)
            return True
        if isinstance(constraint, AttrWriteConstraint):
            base_ctx = state.get_variable(scope, scope.context, constraint.base)
            state.constraints.add(scope, base_ctx, constraint)
            base_pts = state.get_points_to(base_ctx)
            if not base_pts.is_empty():
                self._apply_attr_write(solver, scope, base_ctx, constraint, base_pts)
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
        if isinstance(constraint, AttrReadConstraint):
            self._apply_attr_read(solver, scope, target, constraint, pts)
            return True
        if isinstance(constraint, AttrWriteConstraint):
            self._apply_attr_write(solver, scope, target, constraint, pts)
            return True
        return False
    
    def _apply_attr_read(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        base_ctx: 'Ctx[Any]',
        constraint: AttrReadConstraint,
        pts: 'PointsToSet',
    ) -> None:
        attr_field, attr_name = self._resolve_attr(constraint.attr)
        for base_obj in pts:
            if isinstance(base_obj, InstanceObject):
                self._apply_instance_attr_read(
                    solver=solver,
                    scope=scope,
                    base_obj=base_obj,
                    attr_field=attr_field,
                    attr_name=attr_name,
                    target_var=constraint.target,
                    call_site=constraint.call_site,
                )
            else:
                solver._apply_load(
                    scope,
                    base_ctx,
                    LoadConstraint(
                        base=constraint.base,
                        field=attr_field,
                        target=constraint.target,
                    ),
                    PointsToSet.singleton(base_obj),
                )
    
    def _apply_attr_write(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        base_ctx: 'Ctx[Any]',
        constraint: AttrWriteConstraint,
        pts: 'PointsToSet',
    ) -> None:
        attr_field, attr_name = self._resolve_attr(constraint.attr)
        for base_obj in pts:
            if isinstance(base_obj, InstanceObject):
                self._apply_instance_attr_write(
                    solver=solver,
                    scope=scope,
                    base_obj=base_obj,
                    attr_field=attr_field,
                    attr_name=attr_name,
                    source_var=constraint.source,
                    call_site=constraint.call_site,
                )
            else:
                solver._apply_store(
                    scope,
                    base_ctx,
                    StoreConstraint(
                        base=constraint.base,
                        field=attr_field,
                        source=constraint.source,
                    ),
                    PointsToSet.singleton(base_obj),
                )
    
    def _apply_instance_attr_read(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        base_obj: InstanceObject,
        attr_field: Field,
        attr_name: str,
        target_var: Variable,
        call_site,
    ) -> None:
        state = solver.state
        context = scope.context
        target_ctx = state.get_variable(scope, context, target_var)
        attr_token = self._attr_token(attr_name)
        
        inst_var = self._make_object_var(
            solver,
            scope,
            base_obj,
            "attr_self",
            call_site,
            f"{attr_token}@{id(base_obj)}",
        )
        class_obj = base_obj.class_obj
        class_var = self._make_object_var(
            solver,
            scope,
            class_obj,
            "attr_cls",
            call_site,
            f"{attr_token}@{id(class_obj)}",
        )
        name_var = self._make_const_name_var(solver, scope, attr_name, call_site)
        
        if attr_name not in self._READ_INTERCEPT_SKIP:
            getattribute_var = self._make_temp_var("getattribute", call_site, f"{attr_token}@{id(base_obj)}")
            solver.add_constraint(
                scope,
                context,
                LoadConstraint(
                    base=inst_var,
                    field=attr("__getattribute__"),
                    target=getattribute_var,
                ),
            )
            solver.add_constraint(
                scope,
                context,
                CallConstraint(
                    callee=getattribute_var,
                    args=(name_var,),
                    kwargs=(),
                    target=target_var,
                    call_site=call_site,
                ),
            )
        
        selector = SelectorNode()
        state._add_points_flow_edge(
            PointerFlowEdge(selector, NormalNode(target_ctx), PointerFlowKind.NORMAL)
        )
        
        class_field = self._get_class_field(solver, scope, class_obj, attr_field)
        instance_field = state.get_field(scope, context, base_obj, attr_field)
        guard = GuardNode(
            lambda edge, pts, state=state, class_field=class_field: pts - state.get_points_to(class_field)
        )
        state._add_points_flow_edge(
            PointerFlowEdge(NormalNode(instance_field), guard, PointerFlowKind.NORMAL)
        )
        instance_edge = PointerFlowEdge(guard, selector, PointerFlowKind.NORMAL)
        selector.add_edge(instance_edge, 1)
        state._add_points_flow_edge(instance_edge)
        
        data_desc_var = self._make_temp_var("descriptor_data", call_site, f"{attr_token}@{id(base_obj)}")
        data_desc_ctx = state.get_variable(scope, context, data_desc_var)
        data_guard = GuardNode(
            lambda edge, pts, solver=solver, scope=scope, self=self: PointsToSet.from_objects(
                [obj for obj in pts if self._is_data_descriptor(solver, scope, obj)]
            )
        )
        state._add_points_flow_edge(
            PointerFlowEdge(NormalNode(class_field), data_guard, PointerFlowKind.NORMAL)
        )
        state._add_points_flow_edge(
            PointerFlowEdge(data_guard, NormalNode(data_desc_ctx), PointerFlowKind.NORMAL)
        )
        
        data_get_var = self._make_temp_var("descriptor_data_get", call_site, f"{attr_token}@{id(base_obj)}")
        solver.add_constraint(
            scope,
            context,
            LoadConstraint(
                base=data_desc_var,
                field=attr("__get__"),
                target=data_get_var,
            ),
        )
        data_result_var = self._make_temp_var("descriptor_data_result", call_site, f"{attr_token}@{id(base_obj)}")
        solver.add_constraint(
            scope,
            context,
            CallConstraint(
                callee=data_get_var,
                args=(inst_var, class_var),
                kwargs=(),
                target=data_result_var,
                call_site=call_site,
            ),
        )
        data_result_ctx = state.get_variable(scope, context, data_result_var)
        data_edge = PointerFlowEdge(NormalNode(data_result_ctx), selector, PointerFlowKind.NORMAL)
        selector.add_edge(data_edge, 0)
        state._add_points_flow_edge(data_edge)
        
        nondata_desc_var = self._make_temp_var("descriptor_nond_data", call_site, f"{attr_token}@{id(base_obj)}")
        nondata_desc_ctx = state.get_variable(scope, context, nondata_desc_var)
        nondata_guard = GuardNode(
            lambda edge, pts, solver=solver, scope=scope, self=self: PointsToSet.from_objects(
                [obj for obj in pts if not self._is_data_descriptor(solver, scope, obj)]
            )
        )
        state._add_points_flow_edge(
            PointerFlowEdge(NormalNode(class_field), nondata_guard, PointerFlowKind.NORMAL)
        )
        state._add_points_flow_edge(
            PointerFlowEdge(nondata_guard, NormalNode(nondata_desc_ctx), PointerFlowKind.NORMAL)
        )
        
        nondata_get_var = self._make_temp_var("descriptor_nond_data_get", call_site, f"{attr_token}@{id(base_obj)}")
        solver.add_constraint(
            scope,
            context,
            LoadConstraint(
                base=nondata_desc_var,
                field=attr("__get__"),
                target=nondata_get_var,
            ),
        )
        nondata_result_var = self._make_temp_var("descriptor_nond_data_result", call_site, f"{attr_token}@{id(base_obj)}")
        solver.add_constraint(
            scope,
            context,
            CallConstraint(
                callee=nondata_get_var,
                args=(inst_var, class_var),
                kwargs=(),
                target=nondata_result_var,
                call_site=call_site,
            ),
        )
        nondata_result_ctx = state.get_variable(scope, context, nondata_result_var)
        nondata_edge = PointerFlowEdge(NormalNode(nondata_result_ctx), selector, PointerFlowKind.NORMAL)
        selector.add_edge(nondata_edge, 2)
        state._add_points_flow_edge(nondata_edge)
        
        class_edge = PointerFlowEdge(NormalNode(class_field), selector, PointerFlowKind.NORMAL)
        selector.add_edge(class_edge, 3)
        state._add_points_flow_edge(class_edge)
        
        if attr_name not in self._READ_INTERCEPT_SKIP:
            getattr_var = self._make_temp_var("getattr", call_site, f"{attr_token}@{id(base_obj)}")
            solver.add_constraint(
                scope,
                context,
                LoadConstraint(
                    base=inst_var,
                    field=attr("__getattr__"),
                    target=getattr_var,
                ),
            )
            getattr_result = self._make_temp_var("getattr_result", call_site, f"{attr_token}@{id(base_obj)}")
            solver.add_constraint(
                scope,
                context,
                CallConstraint(
                    callee=getattr_var,
                    args=(name_var,),
                    kwargs=(),
                    target=getattr_result,
                    call_site=call_site,
                ),
            )
            getattr_ctx = state.get_variable(scope, context, getattr_result)
            getattr_edge = PointerFlowEdge(NormalNode(getattr_ctx), selector, PointerFlowKind.NORMAL)
            selector.add_edge(getattr_edge, 4)
            state._add_points_flow_edge(getattr_edge)
    
    def _apply_instance_attr_write(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        base_obj: InstanceObject,
        attr_field: Field,
        attr_name: str,
        source_var: Variable,
        call_site,
    ) -> None:
        state = solver.state
        context = scope.context
        attr_token = self._attr_token(attr_name)
        
        inst_var = self._make_object_var(
            solver,
            scope,
            base_obj,
            "attr_self",
            call_site,
            f"{attr_token}@{id(base_obj)}",
        )
        name_var = self._make_const_name_var(solver, scope, attr_name, call_site)
        source_ctx = state.get_variable(scope, context, source_var)
        
        class_obj = base_obj.class_obj
        class_field = self._get_class_field(solver, scope, class_obj, attr_field)
        class_pts = state.get_points_to(class_field)
        
        has_non_descriptor = False
        for desc_obj in class_pts:
            if not self._descriptor_has_method(solver, scope, desc_obj, "__set__"):
                has_non_descriptor = True
                continue
            desc_var = self._make_object_var(
                solver,
                scope,
                desc_obj,
                "descriptor",
                call_site,
                f"{attr_token}@{id(desc_obj)}",
            )
            set_var = self._make_temp_var("descriptor_set", call_site, f"{attr_token}@{id(desc_obj)}")
            solver.add_constraint(
                scope,
                context,
                LoadConstraint(
                    base=desc_var,
                    field=attr("__set__"),
                    target=set_var,
                ),
            )
            solver.add_constraint(
                scope,
                context,
                CallConstraint(
                    callee=set_var,
                    args=(inst_var, source_var),
                    kwargs=(),
                    target=None,
                    call_site=call_site,
                ),
            )
        
        if class_pts.is_empty() or has_non_descriptor:
            instance_field = state.get_field(scope, context, base_obj, attr_field)
            state._add_var_points_flow(source_ctx, instance_field)
        
        if attr_name not in self._WRITE_INTERCEPT_SKIP:
            setattr_var = self._make_temp_var("setattr", call_site, f"{attr_token}@{id(base_obj)}")
            solver.add_constraint(
                scope,
                context,
                LoadConstraint(
                    base=inst_var,
                    field=attr("__setattr__"),
                    target=setattr_var,
                ),
            )
            solver.add_constraint(
                scope,
                context,
                CallConstraint(
                    callee=setattr_var,
                    args=(name_var, source_var),
                    kwargs=(),
                    target=None,
                    call_site=call_site,
                ),
            )
    
    @staticmethod
    def _resolve_attr(attr_value: Any) -> Tuple[Field, str]:
        if isinstance(attr_value, Field):
            field = attr_value
        elif isinstance(attr_value, str):
            field = attr(attr_value if attr_value else "<unknown>")
        else:
            field = unknown()
        if field.kind == FieldKind.ATTRIBUTE and field.name:
            return field, field.name
        return field, "<unknown>"
    
    def _make_const_name_var(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        name: str,
        call_site,
    ) -> Variable:
        token = self._attr_token(name)
        var_name = f"$const_attr_{call_site.short_id()}_{token}"
        var = Variable(name=var_name, kind=VariableKind.TEMPORARY)
        alloc_site = self._const_alloc_sites.get(var_name)
        if alloc_site is None:
            assign = ast.Assign(
                targets=[ast.Name(id=var_name, ctx=ast.Store())],
                value=ast.Constant(value=name),
            )
            const_assign = IRAssign(assign)
            alloc_site = AllocSite.from_ir_node(const_assign, AllocKind.CONSTANT)
            self._const_alloc_sites[var_name] = alloc_site
        solver.add_constraint(
            scope,
            scope.context,
            AllocConstraint(target=var, alloc_site=alloc_site),
        )
        return var
    
    @staticmethod
    def _attr_token(name: str) -> str:
        return "".join(ch if (ch.isalnum() or ch in "._") else "_" for ch in name)
    
    @staticmethod
    def _make_temp_var(prefix: str, call_site, token: Optional[str] = None) -> Variable:
        suffix = f"@{token}" if token else ""
        return Variable(
            name=f"${prefix}@{call_site.short_id()}{suffix}",
            kind=VariableKind.TEMPORARY,
        )
    
    @staticmethod
    def _make_object_var(
        solver: 'PointerSolver',
        scope: 'Scope',
        obj: 'AbstractObject',
        prefix: str,
        call_site,
        token: str,
    ) -> Variable:
        var = Variable(
            name=f"${prefix}@{call_site.short_id()}@{token}",
            kind=VariableKind.TEMPORARY,
        )
        ctx_var = solver.state.get_variable(scope, scope.context, var)
        solver.handle_new_points_to(ctx_var, scope, PointsToSet.singleton(obj))
        return var
    
    @staticmethod
    def _descriptor_has_method(
        solver: 'PointerSolver',
        scope: 'Scope',
        obj: 'AbstractObject',
        method_name: str,
    ) -> bool:
        field_access = solver.state.get_field(scope, scope.context, obj, attr(method_name))
        return not solver.state.get_points_to(field_access).is_empty()

    def _is_data_descriptor(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        obj: 'AbstractObject',
    ) -> bool:
        return (
            self._descriptor_has_method(solver, scope, obj, "__set__")
            or self._descriptor_has_method(solver, scope, obj, "__delete__")
        )
    
    @staticmethod
    def _get_class_field(
        solver: 'PointerSolver',
        scope: 'Scope',
        class_obj: 'ClassObject',
        field: Field,
    ) -> 'Ctx[Any]':
        class_scope = solver.state.get_internal_scope(class_obj)
        if class_scope is None:
            return solver.state.get_field(scope, scope.context, class_obj, field)
        return solver.state.get_field(class_scope, class_scope.context, class_obj, field)
