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
    AttrDeleteConstraint,
    LoadConstraint,
    StoreConstraint,
    CallConstraint,
    AllocConstraint,
)
from ..context import Ctx
from ..heap_model import Field, FieldKind, attr, unknown
from ..object import (
    AllocKind,
    AllocSite,
    ClassObject,
    InstanceObject,
    SlotDescriptorObject,
    SuperObject,
)
from ..points_to_set import PointsToSet
from ..stable_key import stable_token
from ..pointer_flow_graph import (
    ClassBindingNode,
    GuardNode,
    InstanceBindingNode,
    NormalNode,
    PointerFlowEdge,
    PointerFlowKind,
    SelectorNode,
)
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
        self._installed_field_lookups = set()

    def handle_field_read(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        context: 'AbstractContext',
        base_obj: 'AbstractObject',
        field: Field,
        target,
    ) -> bool:
        """Resolve semantic attribute reads over exact raw heap fields."""
        if field.kind is not FieldKind.ATTRIBUTE:
            return False
        state = solver.state
        target_ctx = (
            target
            if isinstance(target, Ctx)
            else state.get_variable(scope, context, target)
        )
        if isinstance(base_obj, InstanceObject):
            raw_instance = state.raw_field(scope, context, base_obj, field)
            state._add_var_points_flow(raw_instance, target_ctx)
            self._install_class_lookup(
                solver,
                scope,
                base_obj.class_obj,
                field,
                target_ctx,
                instance_obj=base_obj,
            )
            return True
        if isinstance(base_obj, ClassObject):
            self._install_class_lookup(
                solver, scope, base_obj, field, target_ctx
            )
            return True
        if isinstance(base_obj, SuperObject):
            self._install_super_lookup(
                solver, scope, base_obj, field, target_ctx
            )
            return True
        return False

    def _install_class_lookup(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        class_obj: ClassObject,
        field: Field,
        target_ctx: 'Ctx[Any]',
        *,
        instance_obj: Optional[InstanceObject] = None,
    ) -> None:
        state = solver.state
        lookup_key = (
            "class-lookup",
            class_obj,
            field,
            target_ctx,
            instance_obj,
        )
        if lookup_key in self._installed_field_lookups:
            return
        self._installed_field_lookups.add(lookup_key)

        selector = SelectorNode()
        own_field = state.raw_field(
            class_obj.container_scope,
            class_obj.container_scope.context,
            class_obj,
            field,
        )
        own_edge = PointerFlowEdge(
            NormalNode(own_field), selector, PointerFlowKind.NORMAL
        )
        selector.add_edge(own_edge, 0)
        state._add_points_flow_edge(own_edge)

        class_binding = ClassBindingNode(class_obj, lookup_key)
        state._add_points_flow_edge(
            PointerFlowEdge(selector, class_binding, PointerFlowKind.NORMAL)
        )
        source_node = class_binding
        if instance_obj is not None:
            instance_binding = InstanceBindingNode(instance_obj, lookup_key)
            state._add_points_flow_edge(
                PointerFlowEdge(
                    class_binding,
                    instance_binding,
                    PointerFlowKind.NORMAL,
                )
            )
            source_node = instance_binding
        state._add_points_flow_edge(
            PointerFlowEdge(
                source_node,
                NormalNode(target_ctx),
                PointerFlowKind.NORMAL,
            )
        )

        if state.get_attribute_presence(class_obj, field).must_exist:
            return
        state.register_class_inheritance_lookup(class_obj, field, selector)
        state.refresh_class_inheritance(class_obj, field, selector)
        base_sources = tuple(
            state.get_variable(
                class_obj.container_scope,
                class_obj.container_scope.context,
                base_var,
            )
            for base_var in class_obj.base_variables
        )
        if base_sources:
            state.dependencies.subscribe(
                ("class-lookup-bases", *lookup_key),
                base_sources,
                lambda: state.refresh_class_inheritance(
                    class_obj, field, selector
                ),
            )

    def _install_super_lookup(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        super_obj: SuperObject,
        field: Field,
        target_ctx: 'Ctx[Any]',
    ) -> None:
        current_class = super_obj.current_class
        if current_class is None:
            solver.mark_semantic_incomplete()
            return
        key = ("super-lookup", super_obj, field, target_ctx)
        if key in self._installed_field_lookups:
            return
        self._installed_field_lookups.add(key)
        selector = SelectorNode()
        source_node = selector
        if super_obj.instance_obj is not None:
            binding = InstanceBindingNode(super_obj.instance_obj, key)
            solver.state._add_points_flow_edge(
                PointerFlowEdge(selector, binding, PointerFlowKind.NORMAL)
            )
            source_node = binding
        solver.state._add_points_flow_edge(
            PointerFlowEdge(
                source_node,
                NormalNode(target_ctx),
                PointerFlowKind.NORMAL,
            )
        )
        solver.state.register_class_inheritance_lookup(
            current_class, field, selector
        )
        solver.state.refresh_class_inheritance(
            current_class, field, selector
        )
    
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
        if isinstance(constraint, AttrDeleteConstraint):
            base_ctx = state.get_variable(scope, scope.context, constraint.base)
            state.constraints.add(scope, base_ctx, constraint)
            base_pts = state.get_points_to(base_ctx)
            if not base_pts.is_empty():
                self._apply_attr_delete(
                    solver, scope, base_ctx, constraint, base_pts
                )
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
        if isinstance(constraint, AttrDeleteConstraint):
            self._apply_attr_delete(solver, scope, target, constraint, pts)
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

    def _apply_attr_delete(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        base_ctx: 'Ctx[Any]',
        constraint: AttrDeleteConstraint,
        pts: 'PointsToSet',
    ) -> None:
        attr_field, attr_name = self._resolve_attr(constraint.attr)
        for base_obj in pts:
            if isinstance(base_obj, InstanceObject):
                self._apply_instance_attr_delete(
                    solver,
                    scope,
                    base_obj,
                    attr_field,
                    attr_name,
                    constraint.call_site,
                )
            # A union-only heap cannot retract a raw cell for class/module
            # deletion.  Retaining the old value is the sound may-analysis
            # result; instance protocol effects are modeled below.
    
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
            f"{attr_token}@{stable_token(base_obj)}",
        )
        class_obj = base_obj.class_obj
        class_var = self._make_object_var(
            solver,
            scope,
            class_obj,
            "attr_cls",
            call_site,
            f"{attr_token}@{stable_token(class_obj)}",
        )
        name_var = self._make_const_name_var(solver, scope, attr_name, call_site)
        
        if attr_name not in self._READ_INTERCEPT_SKIP:
            getattribute_var = self._make_temp_var(
                "getattribute", call_site,
                f"{attr_token}@{stable_token(base_obj)}",
            )
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
        
        class_field = self._get_class_field(
            solver,
            scope,
            class_obj,
            attr_field,
            instance_obj=base_obj,
        )
        if state.instance_field_allowed(class_obj, attr_field):
            instance_field = state.raw_field(
                scope, context, base_obj, attr_field
            )
            # Suppressing an instance value requires proving that the class
            # field is a data descriptor on every abstract execution.  Until
            # descriptor-kind facts carry their own may/must lattice, retain
            # the instance value whenever an instance-dict cell is possible.
            instance_edge = PointerFlowEdge(
                NormalNode(instance_field), selector, PointerFlowKind.NORMAL
            )
            selector.add_edge(instance_edge, 1)
            state._add_points_flow_edge(instance_edge)
        
        descriptor_var = self._make_temp_var(
            "descriptor", call_site, f"{attr_token}@{stable_token(base_obj)}"
        )
        descriptor_ctx = state.get_variable(scope, context, descriptor_var)
        state._add_points_flow_edge(
            PointerFlowEdge(
                NormalNode(class_field),
                NormalNode(descriptor_ctx),
                PointerFlowKind.NORMAL,
            )
        )
        
        descriptor_get_var = self._make_temp_var(
            "descriptor_get", call_site, f"{attr_token}@{stable_token(base_obj)}"
        )
        solver.add_constraint(
            scope,
            context,
            LoadConstraint(
                base=descriptor_var,
                field=attr("__get__"),
                target=descriptor_get_var,
            ),
        )
        descriptor_result_var = self._make_temp_var(
            "descriptor_result", call_site, f"{attr_token}@{stable_token(base_obj)}"
        )
        solver.add_constraint(
            scope,
            context,
            CallConstraint(
                callee=descriptor_get_var,
                args=(inst_var, class_var),
                kwargs=(),
                target=descriptor_result_var,
                call_site=call_site,
            ),
        )
        descriptor_result_ctx = state.get_variable(
            scope, context, descriptor_result_var
        )
        descriptor_edge = PointerFlowEdge(
            NormalNode(descriptor_result_ctx), selector, PointerFlowKind.NORMAL
        )
        selector.add_edge(descriptor_edge, 0)
        state._add_points_flow_edge(descriptor_edge)
        
        # A later-discovered __get__ must not invalidate an earlier classification
        # as a plain value.  Passing the class value as well is a sound, monotone
        # over-approximation of the descriptor/plain split.
        plain_class_values = GuardNode(
            lambda _edge, pts: PointsToSet.from_objects(
                (
                    obj for obj in pts
                    if not isinstance(obj, SlotDescriptorObject)
                ),
                arena=state.arena,
            )
        )
        class_guard_edge = PointerFlowEdge(
            NormalNode(class_field),
            plain_class_values,
            PointerFlowKind.NORMAL,
        )
        state._add_points_flow_edge(class_guard_edge)
        class_edge = PointerFlowEdge(
            plain_class_values, selector, PointerFlowKind.NORMAL
        )
        selector.add_edge(class_edge, 3)
        state._add_points_flow_edge(class_edge)
        
        if attr_name not in self._READ_INTERCEPT_SKIP:
            getattr_var = self._make_temp_var(
                "getattr", call_site,
                f"{attr_token}@{stable_token(base_obj)}",
            )
            solver.add_constraint(
                scope,
                context,
                LoadConstraint(
                    base=inst_var,
                    field=attr("__getattr__"),
                    target=getattr_var,
                ),
            )
            getattr_result = self._make_temp_var(
                "getattr_result", call_site,
                f"{attr_token}@{stable_token(base_obj)}",
            )
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
            f"{attr_token}@{stable_token(base_obj)}",
        )
        name_var = self._make_const_name_var(solver, scope, attr_name, call_site)
        source_ctx = state.get_variable(scope, context, source_var)
        
        class_obj = base_obj.class_obj
        class_field = self._get_class_field(solver, scope, class_obj, attr_field)
        # Keep the ordinary instance write unless a data descriptor is known on
        # every abstract execution.  The PFG cannot retract a write that escaped
        # before descriptor discovery.
        if state.instance_field_allowed(class_obj, attr_field):
            instance_field = state.raw_field(
                scope, context, base_obj, attr_field
            )
            state._add_var_points_flow(source_ctx, instance_field)

        # Route every current and future class-field candidate through __set__.
        # Non-descriptors simply produce no callable target, while descriptors
        # discovered later are handled incrementally by the load constraint.
        descriptor_var = self._make_temp_var(
            "descriptor", call_site, f"{attr_token}@{stable_token(base_obj)}"
        )
        descriptor_ctx = state.get_variable(scope, context, descriptor_var)
        state._add_var_points_flow(class_field, descriptor_ctx)
        set_var = self._make_temp_var(
            "descriptor_set", call_site, f"{attr_token}@{stable_token(base_obj)}"
        )
        solver.add_constraint(
            scope,
            context,
            LoadConstraint(
                base=descriptor_var,
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
        
        if attr_name not in self._WRITE_INTERCEPT_SKIP:
            setattr_var = self._make_temp_var(
                "setattr", call_site,
                f"{attr_token}@{stable_token(base_obj)}",
            )
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

    def _apply_instance_attr_delete(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        base_obj: InstanceObject,
        attr_field: Field,
        attr_name: str,
        call_site,
    ) -> None:
        context = scope.context
        token = f"{self._attr_token(attr_name)}@{stable_token(base_obj)}"
        inst_var = self._make_object_var(
            solver, scope, base_obj, "attr_delete_self", call_site, token
        )
        name_var = self._make_const_name_var(
            solver, scope, attr_name, call_site
        )
        class_field = self._get_class_field(
            solver, scope, base_obj.class_obj, attr_field
        )
        descriptor_var = self._make_temp_var(
            "delete_descriptor", call_site, token
        )
        descriptor_ctx = solver.state.get_variable(
            scope, context, descriptor_var
        )
        solver.state._add_var_points_flow(class_field, descriptor_ctx)
        delete_var = self._make_temp_var(
            "descriptor_delete", call_site, token
        )
        solver.add_constraint(
            scope,
            context,
            LoadConstraint(
                base=descriptor_var,
                field=attr("__delete__"),
                target=delete_var,
            ),
        )
        solver.add_constraint(
            scope,
            context,
            CallConstraint(
                callee=delete_var,
                args=(inst_var,),
                kwargs=(),
                target=None,
                call_site=call_site,
            ),
        )
        delattr_var = self._make_temp_var(
            "delattr", call_site, token
        )
        solver.add_constraint(
            scope,
            context,
            LoadConstraint(
                base=inst_var,
                field=attr("__delattr__"),
                target=delattr_var,
            ),
        )
        solver.add_constraint(
            scope,
            context,
            CallConstraint(
                callee=delattr_var,
                args=(name_var,),
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
    
    def _get_class_field(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        class_obj: 'ClassObject',
        field: Field,
        *,
        instance_obj: Optional[InstanceObject] = None,
    ) -> 'Ctx[Any]':
        lookup_var = Variable(
            name=(
                f"$class_lookup@{stable_token(class_obj)}@"
                f"{stable_token(field)}@"
                f"{stable_token(instance_obj) if instance_obj else 'class'}"
            ),
            kind=VariableKind.TEMPORARY,
        )
        lookup_ctx = solver.state.get_variable(
            scope, scope.context, lookup_var
        )
        self._install_class_lookup(
            solver,
            scope,
            class_obj,
            field,
            lookup_ctx,
            instance_obj=instance_obj,
        )
        return lookup_ctx
