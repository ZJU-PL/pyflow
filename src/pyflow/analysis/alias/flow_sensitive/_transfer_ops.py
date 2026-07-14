"""Operation-level heap transfer methods (mixin for HeapTransferEngine).

This module contains the operation-level methods extracted from
:class:`HeapTransferEngine`. It is used as a mixin and should not be
instantiated directly.
"""

from __future__ import annotations

from pyflow.analysis.ir_utils import (
    actual_argument_expressions,
    assigned_locals,
    resolve_call_name,
)
from pyflow.language.python import ast as py_ast

from .heap_effects import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    DYNAMIC_SUBSCRIPT_WILDCARD,
)
from .intrinsics import CALL_RETURN_NONE
from .model import HeapLocation, HeapObjectKind, UpdatePolicy


class _TransferOpsMixin:
    """Mixin providing operation-level transfer methods.

    This class contains only methods; it does not define ``__init__``.
    At runtime ``self`` is the :class:`HeapTransferEngine` instance.
    """

    def _prepared_target_writes(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[object, ...] | None:
        bases: tuple[HeapLocation, ...]
        locations: tuple[HeapLocation, ...]
        if isinstance(operation, (py_ast.SetAttr, py_ast.Store)):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.name)
            if isinstance(operation, py_ast.Store) and getattr(
                operation,
                "fieldtype",
                None,
            ) in {"Dictionary", "Array"}:
                locations = self.heap.dynamic_subscript_locations(
                    bases,
                    (f"[{self.effect_builder._path_component(operation.name)}]",),
                )
                self.locations_for_expression(procedure, operation.value)
            else:
                attribute = (
                    self.effect_builder._path_component(operation.name)
                    if isinstance(operation, py_ast.Store)
                    else self.effect_builder._constant_string(operation.name) or "*"
                )
                locations = self.heap.dynamic_attribute_locations(
                    bases,
                    (attribute,),
                )
                if isinstance(operation, py_ast.Store):
                    self.locations_for_expression(procedure, operation.value)
            return self._prepared_writes_for_bases(locations, bases)
        if isinstance(operation, py_ast.SetSubscript):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.subscript)
            subscript = self.effect_builder._constant_subscript(operation.subscript)
            locations = self.heap.dynamic_subscript_locations(
                bases,
                (subscript or DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
            return self._prepared_writes_for_bases(locations, bases)
        if isinstance(operation, py_ast.SetSlice):
            bases = self.locations_for_expression(procedure, operation.expr)
            for component in (operation.start, operation.stop, operation.step):
                self.locations_for_expression(procedure, component)
            locations = self.heap.dynamic_subscript_locations(
                bases,
                (DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
            return self._prepared_writes_for_bases(locations, bases)
        return None

    def _prepared_writes_for_bases(
        self,
        locations: tuple[HeapLocation, ...],
        bases: tuple[HeapLocation, ...],
    ) -> tuple[object, ...]:
        ambiguous = len({base.root for base in bases}) > 1
        return tuple(
            self.heap.write_for_location(
                location,
                policy=UpdatePolicy.WEAK if ambiguous else None,
            )
            for location in locations
        )

    def _prepared_delete_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...] | None:
        if isinstance(operation, py_ast.DeleteAttr):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.name)
            attribute = self.effect_builder._constant_string(operation.name) or "*"
            return self.heap.dynamic_attribute_locations(bases, (attribute,))
        if isinstance(operation, py_ast.DeleteSubscript):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.subscript)
            subscript = self.effect_builder._constant_subscript(operation.subscript)
            return self.heap.dynamic_subscript_locations(
                bases,
                (subscript or DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
        if isinstance(operation, py_ast.DeleteSlice):
            bases = self.locations_for_expression(procedure, operation.expr)
            for component in (operation.start, operation.stop, operation.step):
                self.locations_for_expression(procedure, component)
            return self.heap.dynamic_subscript_locations(
                bases,
                (DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
        return None

    @staticmethod
    def _immediate_escape_locations(
        operation: object,
        effect: object,
    ) -> tuple[HeapLocation, ...]:
        """Return effect escapes that are externally reachable immediately.

        Stores into fields, subscripts, cells, or collection mutators create
        heap reachability edges. The stored values escape only if the
        destination root is, or later becomes, escaped; the fixed-point escape
        propagation handles that through ``HeapState``.
        """
        escapes = getattr(effect, "escapes", ())
        writes = getattr(effect, "writes", ())
        if not writes or not escapes:
            return escapes
        if isinstance(operation, py_ast.SetGlobal):
            return escapes
        if isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ):
            return ()
        call = _TransferOpsMixin._call_expression(operation)
        if call is not None:
            return ()
        return escapes

    def locations_for_expression(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        cache = (
            self._operation_expression_caches[-1]
            if self._operation_expression_caches
            else None
        )
        cacheable = not isinstance(
            expression,
            (
                HeapLocation,
                py_ast.Local,
                py_ast.GetGlobal,
                py_ast.GetCell,
                py_ast.GetCellDeref,
                py_ast.Cell,
                py_ast.Input,
            ),
        )
        if cache is not None and cacheable:
            cached = cache.get(id(expression))
            if cached is not None:
                return cached
        self._record_exception_prefix()
        result = self._locations_for_expression_impl(procedure, expression)
        self._record_exception_prefix()
        if cache is not None and cacheable:
            cache[id(expression)] = result
        return result

    def _locations_for_expression_impl(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        """Best-effort locations read by an expression."""
        if expression is None:
            return ()
        if isinstance(expression, HeapLocation):
            return (expression,)
        if isinstance(expression, py_ast.Input):
            return self.locations_for_expression(procedure, expression.lcl)
        if isinstance(expression, py_ast.Cell):
            return (self.effect_builder.cell_location(expression, procedure),)
        if isinstance(expression, py_ast.TypeParam):
            bound = self.locations_for_expression(procedure, expression.bound)
            parameter = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label=f"type parameter {expression.name}",
                    context=self._current_context,
                )
            )
            if bound:
                self.state.write(
                    self.heap.dynamic_attribute_location(parameter, "__bound__"),
                    bound,
                    UpdatePolicy.STRONG,
                )
            return tuple(dict.fromkeys((parameter, *bound)))
        if isinstance(expression, py_ast.TypeParams):
            parameters = self._merge_expression_locations(
                procedure,
                *getattr(expression, "params", ()),
            )
            collection = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label="type parameters",
                    context=self._current_context,
                )
            )
            if parameters:
                self.state.write(
                    self.heap.dynamic_subscript_location(
                        collection,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    ),
                    parameters,
                    UpdatePolicy.WEAK,
                )
            return tuple(dict.fromkeys((collection, *parameters)))
        if isinstance(expression, py_ast.Local):
            declared = self._declared_location(procedure, expression)
            if declared is not None:
                return self.state.read(declared)
            locations = self.heap.locations_for_local(procedure, expression)
            if locations:
                return locations
            if isinstance(procedure, py_ast.ClassDef):
                outer_locations = self._outer_local_locations(expression)
                if outer_locations:
                    return outer_locations
            obj = self.heap.local_object(procedure, expression)
            self.heap.bind_local_to_object(procedure, expression, obj)
            return self.heap.locations_for_local(procedure, expression)
        if isinstance(expression, py_ast.GetGlobal):
            location = self.effect_builder.global_location(procedure, expression.name)
            return self.state.read(location)
        if isinstance(expression, (py_ast.GetCell, py_ast.GetCellDeref)):
            location = self.effect_builder.cell_location(expression.cell, procedure)
            return self.state.read(location)
        if isinstance(expression, (py_ast.GetAttr, py_ast.Load)):
            bases = self.locations_for_expression(procedure, expression.expr)
            self.locations_for_expression(procedure, expression.name)
            attribute = (
                self.effect_builder._path_component(expression.name)
                if isinstance(expression, py_ast.Load)
                else self.effect_builder._constant_string(expression.name) or "*"
            )
            if isinstance(expression, py_ast.Load) and getattr(
                expression, "fieldtype", None
            ) in {"Dictionary", "Array"}:
                locations = self.heap.dynamic_subscript_locations(
                    bases,
                    (f"[{attribute}]",),
                )
            else:
                locations = self.heap.dynamic_attribute_locations(
                    bases,
                    (attribute,),
                )
            values = list(self._read_heap_locations(locations))
            if attribute != "*":
                classes = tuple(
                    dict.fromkeys(
                        class_location
                        for base in bases
                        for class_location in self.state.read(
                            self.heap.dynamic_attribute_location(base, "__class__"),
                            fallback=(),
                        )
                    )
                )
                values.extend(self._class_attribute_values(classes, attribute))
            return tuple(dict.fromkeys(values))
        if isinstance(expression, py_ast.GetSubscript):
            bases = self.locations_for_expression(procedure, expression.expr)
            self.locations_for_expression(procedure, expression.subscript)
            subscript = self.effect_builder._constant_subscript(expression.subscript)
            if subscript is None:
                values: list[HeapLocation] = []
                for base in bases:
                    wildcard = self.heap.dynamic_subscript_location(
                        base,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    )
                    values.extend(self.state.read_contained(wildcard))
                if values:
                    return tuple(dict.fromkeys(values))
                return self.heap.dynamic_subscript_locations(
                    bases,
                    (DYNAMIC_SUBSCRIPT_WILDCARD,),
                )
            locations = self.heap.dynamic_subscript_locations(
                bases,
                (subscript, DYNAMIC_SUBSCRIPT_WILDCARD),
            )
            return self._read_heap_locations(locations)
        if isinstance(expression, py_ast.DirectCall) and isinstance(
            expression.code,
            py_ast.Code,
        ):
            return self._evaluate_direct_call_expression(procedure, expression)
        if isinstance(expression, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            operand_locations = self._evaluate_call_operands(
                procedure,
                expression,
            )
            kind = self.effect_builder.call_return_kind(expression)
            if kind == CALL_RETURN_NONE:
                return ()
            modeled = self._modeled_call_return_locations(
                procedure,
                expression,
                kind,
                operand_locations,
            )
            if modeled:
                self._attach_known_class(procedure, expression, modeled)
                return modeled
            result = (
                HeapLocation(
                    self.effect_builder.call_return_object(procedure, expression)
                ),
            )
            call_name = resolve_call_name(expression)
            if (
                kind == CALL_RETURN_FRESH
                and call_name is not None
                and (
                    self._module_owner(procedure),
                    call_name.rsplit(".", 1)[-1],
                )
                in self._class_definitions
            ):
                result = tuple(
                    dict.fromkeys(
                        (*result, self._external_value_location(procedure))
                    )
                )
            if kind == CALL_RETURN_COPY:
                self._copy_call_result_contents(
                    procedure,
                    None,
                    expression,
                    result,
                )
            self._attach_known_class(procedure, expression, result)
            return result
        if isinstance(
            expression,
            (
                py_ast.BuildTuple,
                py_ast.BuildList,
                py_ast.BuildSet,
                py_ast.BuildMap,
                py_ast.BuildSlice,
                py_ast.Allocate,
            ),
        ):
            if isinstance(expression, py_ast.BuildSlice):
                for component in (
                    expression.start,
                    expression.stop,
                    expression.step,
                ):
                    self.locations_for_expression(procedure, component)
            elif isinstance(expression, py_ast.Allocate):
                self.locations_for_expression(procedure, expression.expr)
            allocation = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label=self.effect_builder._allocation_label(expression),
                    context=self._current_context,
                )
            )
            if isinstance(
                expression,
                (py_ast.BuildTuple, py_ast.BuildList, py_ast.BuildSet, py_ast.BuildMap),
            ):
                self.state.complete_roots.add(allocation.root)
                for argument in getattr(expression, "args", ()):
                    self.locations_for_expression(procedure, argument)
                self._write_collection_literal_elements(
                    procedure,
                    allocation,
                    expression,
                    self._collection_literal_values(expression),
                )
            elif isinstance(expression, py_ast.BuildSlice):
                for slice_field, component in (
                    ("start", expression.start),
                    ("stop", expression.stop),
                    ("step", expression.step),
                ):
                    component_locations = self.locations_for_expression(
                        procedure,
                        component,
                    )
                    if component_locations:
                        self.state.write(
                            self.heap.dynamic_attribute_location(
                                allocation,
                                slice_field,
                            ),
                            component_locations,
                            UpdatePolicy.STRONG,
                        )
            return (allocation,)
        if isinstance(expression, py_ast.MakeFunction):
            function = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label="function",
                    context=self._current_context,
                )
            )
            default_locations = self._merge_expression_locations(
                procedure,
                *getattr(expression, "defaults", ()),
            )
            if default_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(function, "__defaults__"),
                    default_locations,
                    UpdatePolicy.STRONG,
                )
            closure_locations = self._merge_expression_locations(
                procedure,
                *getattr(expression, "cells", ()),
            )
            if closure_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(function, "__closure__"),
                    closure_locations,
                    UpdatePolicy.STRONG,
                )
            return (function,)
        if isinstance(expression, (py_ast.GetIter, py_ast.AsyncGetIter)):
            sources = self.locations_for_expression(procedure, expression.expr)
            iterator = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label="async iterator" if isinstance(expression, py_ast.AsyncGetIter) else "iterator",
                    context=self._current_context,
                )
            )
            self._copy_locations(sources, (iterator,))
            self.state.write(
                self.heap.dynamic_attribute_location(iterator, "__iterable__"),
                sources,
                UpdatePolicy.STRONG,
            )
            return tuple(
                dict.fromkeys(
                    (iterator, *sources, self._external_value_location(procedure))
                )
            )
        if isinstance(expression, py_ast.GetSlice):
            bases = self.locations_for_expression(procedure, expression.expr)
            for component in (
                expression.start,
                expression.stop,
                expression.step,
            ):
                self.locations_for_expression(procedure, component)
            sliced = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label="slice result",
                    context=self._current_context,
                )
            )
            self._copy_locations(bases, (sliced,))
            return tuple(
                dict.fromkeys(
                    (*bases, sliced, self._external_value_location(procedure))
                )
            )
        if isinstance(expression, (py_ast.UnaryPrefixOp,)):
            return self._merge_expression_locations(
                procedure,
                expression.expr,
                self._external_value_location(procedure),
            )
        if isinstance(expression, py_ast.BinaryOp):
            return self._merge_expression_locations(
                procedure,
                expression.left,
                expression.right,
                self._external_value_location(procedure),
            )
        if isinstance(expression, (py_ast.ConvertToBool, py_ast.Not)):
            self.locations_for_expression(procedure, expression.expr)
            return ()
        if isinstance(expression, (py_ast.Is, py_ast.Check)):
            self.locations_for_expression(procedure, expression.left if isinstance(expression, py_ast.Is) else expression.expr)
            if isinstance(expression, py_ast.Is):
                self.locations_for_expression(procedure, expression.right)
            else:
                self.locations_for_expression(procedure, expression.name)
            return ()
        if isinstance(expression, py_ast.Await):
            awaitable = self.locations_for_expression(procedure, expression.expr)
            resumed = self._resume_deferred_activations(
                procedure,
                awaitable,
                use_yields=False,
            )
            self.heap.mark_all_escaped(awaitable)
            self.state.mark_escaped(awaitable)
            return tuple(
                dict.fromkeys(
                    (
                        *resumed,
                        *awaitable,
                        self._external_value_location(procedure),
                    )
                )
            )
        if isinstance(expression, (py_ast.Yield, py_ast.AsyncYield)):
            yielded = self.locations_for_expression(procedure, expression.expr)
            self.state.set_yields(procedure, yielded)
            self.heap.mark_all_escaped(yielded)
            self.state.mark_escaped(yielded)
            if self._yield_state_stack:
                self._yield_state_stack[-1].append(
                    (self._capture_flow_state(), yielded)
                )
            if self._resume_input_stack and self._resume_input_stack[-1]:
                return self._resume_input_stack[-1]
            return (self._external_value_location(procedure),)
        if isinstance(expression, py_ast.YieldFrom):
            yielded = self.locations_for_expression(procedure, expression.expr)
            resumed = self._resume_deferred_activations(
                procedure,
                yielded,
                use_yields=True,
            )
            expanded = tuple(
                dict.fromkeys((*resumed, *self._contained_values(yielded)))
            )
            self.state.set_yields(
                procedure,
                expanded or yielded,
            )
            self.heap.mark_all_escaped(yielded)
            self.state.mark_escaped(yielded)
            if self._yield_state_stack:
                self._yield_state_stack[-1].append(
                    (
                        self._capture_flow_state(),
                        expanded or yielded,
                    )
                )
            return tuple(
                dict.fromkeys(
                    (*yielded, self._external_value_location(procedure))
                )
            )
        if isinstance(expression, (py_ast.ShortCircutAnd, py_ast.ShortCircutOr)):
            terms = tuple(getattr(expression, "terms", ()))
            if not terms:
                return ()
            possible_locations: list[HeapLocation] = []
            prefix_states: list[_FlowState] = []
            for term in terms:
                possible_locations.extend(
                    self.locations_for_expression(procedure, term)
                )
                # Evaluation may stop after every term.  Joining all prefixes
                # preserves both skipped and executed side effects from later
                # terms without pretending they execute unconditionally.
                prefix_states.append(self._capture_flow_state())
            self._restore_flow_state(
                self._join_flow_states(tuple(prefix_states))
            )
            return tuple(dict.fromkeys(possible_locations))
        if isinstance(expression, py_ast.ConditionalExpr):
            self.locations_for_expression(procedure, expression.test)
            branch_entry = self._capture_flow_state()
            self._restore_flow_state(branch_entry)
            body_locations = self.locations_for_expression(
                procedure,
                expression.body,
            )
            body_state = self._capture_flow_state()
            self._restore_flow_state(branch_entry)
            else_locations = self.locations_for_expression(
                procedure,
                expression.orelse,
            )
            else_state = self._capture_flow_state()
            self._restore_flow_state(
                self._join_flow_states((body_state, else_state))
            )
            return tuple(dict.fromkeys((*body_locations, *else_locations)))
        if isinstance(expression, py_ast.NamedExpr):
            locations = self.locations_for_expression(procedure, expression.value)
            if locations:
                self._bind_runtime_local(
                    procedure,
                    expression.target,
                    locations,
                )
            else:
                self._clear_runtime_local(procedure, expression.target)
            return locations
        if isinstance(expression, py_ast.Existing):
            value = getattr(expression.object, "pyobj", None)
            if isinstance(
                value,
                (str, bytes, int, float, complex, bool, type(None)),
            ):
                return ()
            return (
                HeapLocation(
                    self.heap.external_object(
                        ("existing", id(expression.object)),
                        label=repr(value),
                    )
                ),
            )
        return ()

    def _class_attribute_values(
        self,
        classes: tuple[HeapLocation, ...],
        attribute: str,
    ) -> tuple[HeapLocation, ...]:
        values: list[HeapLocation] = []
        pending = list(classes)
        seen: set[HeapLocation] = set()
        while pending:
            class_location = pending.pop()
            if class_location in seen:
                continue
            seen.add(class_location)
            values.extend(
                self.state.read(
                    self.heap.dynamic_attribute_location(
                        class_location,
                        attribute,
                    ),
                    fallback=(),
                )
            )
            pending.extend(
                self.state.read(
                    self.heap.dynamic_attribute_location(
                        class_location,
                        "__bases__",
                    ),
                    fallback=(),
                )
            )
        return tuple(dict.fromkeys(values))

    def _external_value_location(self, procedure: object) -> HeapLocation:
        return HeapLocation(
            self.heap.summary_object(
                ("external-value", id(procedure)),
                label="external value",
            )
        )

    def _read_heap_locations(
        self,
        locations: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        values: list[HeapLocation] = []
        for location in locations:
            stored = self.state.read(location, fallback=())
            if stored:
                values.extend(stored)
            elif (
                not self.state.definitely_absent(location)
                and location.root not in self.state.complete_roots
            ):
                values.append(location)
        return tuple(dict.fromkeys(values))

    def _outer_local_locations(
        self,
        local: py_ast.Local,
    ) -> tuple[HeapLocation, ...]:
        local_id = id(local)
        local_name = getattr(local, "name", None)
        locations: list[HeapLocation] = []
        keys = set(self.heap.storage_overrides) | set(self.heap.allocation_sites)
        for key in keys:
            if (
                key[1] != local_id
                and (
                    not isinstance(local_name, str)
                    or self.heap._local_names.get(key) != local_name
                )
            ):
                continue
            storage = self.heap.storage_overrides.get(key)
            if storage is None:
                site = self.heap.allocation_sites.get(key)
                storage = (
                    self.heap.site_storage.get(site, ())
                    if site is not None
                    else ()
                )
            locations.extend(
                self.heap.location_for_raw(raw) for raw in storage
            )
        return tuple(dict.fromkeys(locations))

    def _declared_location(
        self,
        procedure: object,
        local: py_ast.Local,
    ) -> HeapLocation | None:
        name = getattr(local, "name", None)
        if not name:
            return None
        if name in self._global_declarations.get(id(procedure), set()):
            return self.effect_builder.global_location(procedure, name)
        if name in self._nonlocal_declarations.get(id(procedure), set()):
            return HeapLocation(
                self.heap.summary_object(
                    ("nonlocal-cell", name),
                    label=f"nonlocal {name}",
                )
            )
        return None

    def _bind_runtime_local(
        self,
        procedure: object,
        local: py_ast.Local,
        locations: tuple[HeapLocation, ...],
        *,
        include_raw_fallback: bool = False,
    ) -> None:
        declared = self._declared_location(procedure, local)
        if declared is not None:
            self.state.write(declared, locations, UpdatePolicy.STRONG)
            return
        self.heap.bind_local_to_locations(
            procedure,
            local,
            locations,
            include_raw_fallback=include_raw_fallback,
        )

    def _clear_runtime_local(
        self,
        procedure: object,
        local: py_ast.Local,
    ) -> None:
        declared = self._declared_location(procedure, local)
        if declared is not None:
            self.state.delete(declared)
            return
        self.heap.clear_local_binding(procedure, local)

    def _merge_expression_locations(self, procedure, *expressions):
        """Return the deduplicated union of heap locations from multiple expressions."""
        locations: list[HeapLocation] = []
        for expr in expressions:
            if expr is not None:
                locations.extend(self.locations_for_expression(procedure, expr))
        return tuple(dict.fromkeys(locations))

    @classmethod
    def iter_code_objects(cls, root: object):
        """Yield code objects reachable from *root* without recursing into bodies."""
        seen: set[int] = set()

        def visit(value: object):
            if value is None or isinstance(value, py_ast.leafTypes):
                return
            if isinstance(value, py_ast.Code):
                key = id(value)
                if key not in seen:
                    seen.add(key)
                    yield value
                return
            if isinstance(value, (list, tuple, set, frozenset)):
                for item in value:
                    yield from visit(item)
                return
            for attr in ("liveCode", "entryPoints", "codes", "procedures", "functions"):
                child = getattr(value, attr, None)
                if child is not None:
                    yield from visit(child)
            code = getattr(value, "code", None)
            if code is not value:
                yield from visit(code)

        yield from visit(root)

    @classmethod
    def iter_operations(cls, node: object):
        """Yield operation nodes inside a code body."""
        if node is None or isinstance(node, py_ast.leafTypes):
            return
        if isinstance(node, py_ast.Code):
            return
        if isinstance(node, py_ast.Suite):
            for block in node.blocks:
                yield from cls.iter_operations(block)
            return
        if isinstance(node, py_ast.PythonASTNode):
            yield node
            if hasattr(node, "visitChildren"):
                children: list[object] = []
                node.visitChildren(children.append)
                for child in children:
                    yield from cls.iter_operations(child)

    def _materialize_assignment_result(
        self, procedure: object, operation: object
    ) -> None:
        targets = self._direct_assigned_locals(operation)
        if not targets:
            return
        if isinstance(operation, py_ast.InputBlock):
            external = self._external_value_location(procedure)
            for target in targets:
                self._bind_runtime_local(procedure, target, (external,))
            return
        if isinstance(operation, py_ast.Phi):
            phi_locations = tuple(
                dict.fromkeys(
                    location
                    for argument in getattr(operation, "arguments", ())
                    if argument is not None
                    for location in self.locations_for_expression(procedure, argument)
                )
            )
            if phi_locations:
                self._bind_runtime_local(
                    procedure,
                    operation.target,
                    phi_locations,
                )
            else:
                self._bind_runtime_local(
                    procedure,
                    operation.target,
                    (self._external_value_location(procedure),),
                )
            return
        if isinstance(operation, py_ast.UnpackSequence):
            self._materialize_unpack_targets(procedure, operation)
            return
        expr = self._assigned_expression(operation)
        if isinstance(
            expr,
            (
                py_ast.BuildTuple,
                py_ast.BuildList,
                py_ast.BuildSet,
                py_ast.BuildMap,
                py_ast.BuildSlice,
                py_ast.MakeFunction,
                py_ast.Allocate,
            ),
        ):
            allocations = self.locations_for_expression(procedure, expr)
            for target in targets:
                self._bind_runtime_local(procedure, target, allocations)
            return
        if isinstance(expr, py_ast.Import):
            module = self.effect_builder.import_object(expr, procedure)
            imported = [HeapLocation(module)]
            if not getattr(expr, "fromlist", None) and "." in expr.name:
                imported.append(
                    HeapLocation(
                        self.heap.module_object(
                            expr.name.split(".", 1)[0],
                            label=expr.name.split(".", 1)[0],
                        )
                    )
                )
            if getattr(expr, "fromlist", None):
                imported.append(self._external_value_location(procedure))
            for target in targets:
                self._bind_runtime_local(
                    procedure,
                    target,
                    tuple(imported),
                )
            return
        if isinstance(expr, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            if isinstance(expr, py_ast.DirectCall) and isinstance(
                expr.code,
                py_ast.Code,
            ):
                # Resolved calls evaluate/bind their actuals and results in
                # _apply_call_transfer.  Binding a placeholder here would
                # overwrite a target that may also be used as an argument.
                return
            slots = self._bind_call_result_targets(
                procedure,
                targets,
                expr,
                bind=False,
            )
            self._pending_call_results[id(operation)] = (targets, slots)
            return
        if expr is not None and not isinstance(expr, py_ast.Local):
            expr_locations = self.locations_for_expression(procedure, expr)
            if expr_locations:
                for target in targets:
                    self._bind_runtime_local(
                        procedure,
                        target,
                        expr_locations,
                    )
            else:
                for target in targets:
                    self._clear_runtime_local(procedure, target)
            return
        if isinstance(expr, py_ast.Local):
            source_locations = self.locations_for_expression(procedure, expr)
            for target in targets:
                self._bind_runtime_local(procedure, target, source_locations)
            return
        self.heap.update_assignment_aliases(procedure, targets, expr)

    @staticmethod
    def _direct_assigned_locals(operation: object) -> tuple[py_ast.Local, ...]:
        if isinstance(operation, py_ast.Assign):
            return tuple(
                local for local in operation.lcls if isinstance(local, py_ast.Local)
            )
        if isinstance(operation, py_ast.UnpackSequence):
            return tuple(
                local
                for local in operation.targets
                if isinstance(local, py_ast.Local)
            )
        if isinstance(operation, py_ast.AnnAssign):
            if operation.value is not None and isinstance(operation.target, py_ast.Local):
                return (operation.target,)
            return ()
        if isinstance(operation, py_ast.InputBlock):
            return tuple(
                input_.lcl
                for input_ in getattr(operation, "inputs", ())
                if isinstance(getattr(input_, "lcl", None), py_ast.Local)
            )
        if isinstance(operation, py_ast.Phi) and isinstance(
            getattr(operation, "target", None), py_ast.Local
        ):
            return (operation.target,)
        return ()

    def _materialize_unpack_targets(
        self,
        procedure: object,
        operation: py_ast.UnpackSequence,
    ) -> None:
        sources = self.locations_for_expression(procedure, operation.expr)
        for index, target in enumerate(operation.targets):
            if not isinstance(target, py_ast.Local):
                continue
            values: list[HeapLocation] = []
            for source in sources:
                exact = self.heap.dynamic_subscript_location(source, f"[{index}]")
                wildcard = self.heap.dynamic_subscript_location(
                    source,
                    DYNAMIC_SUBSCRIPT_WILDCARD,
                )
                values.extend(self.state.read(exact, fallback=()))
                values.extend(self.state.read(wildcard, fallback=()))
                values.extend(self.state.read_contained(wildcard))
            if not values:
                values.extend(sources)
                values.append(self._external_value_location(procedure))
            self._bind_runtime_local(
                procedure,
                target,
                tuple(dict.fromkeys(values)),
            )

    def _materialize_return_values(
        self,
        procedure: object,
        operation: py_ast.Return,
        returns: tuple[HeapLocation, ...],
    ) -> None:
        # HeapEffect exposes a flat return set for procedure summaries, but a
        # direct call with multiple result variables needs the values grouped
        # by result position.  Re-evaluate the expressions here and preserve
        # that grouping through branch joins.
        del returns
        code_parameters = getattr(procedure, "codeparameters", None)
        if code_parameters is None:
            return
        returnparams = tuple(getattr(code_parameters, "returnparams", ()))
        expression_locations = tuple(
            self.locations_for_expression(procedure, expression)
            for expression in getattr(operation, "exprs", ())
        )
        return_slots: list[tuple[HeapLocation, ...]] = []
        for index, target in enumerate(returnparams):
            if len(returnparams) == 1 and len(expression_locations) == 1:
                bind_locations = expression_locations[0]
            elif index < len(expression_locations):
                bind_locations = expression_locations[index]
            else:
                bind_locations = ()

            if not bind_locations:
                bind_locations = (
                    HeapLocation(
                        self.heap.return_object(
                            procedure,
                            index,
                            label=getattr(target, "name", None),
                        )
                    ),
                )
            return_slots.append(tuple(dict.fromkeys(bind_locations)))

            if isinstance(target, py_ast.Local):
                self.heap.bind_local_to_locations(
                    procedure,
                    target,
                    bind_locations,
                )
            # Any returned value is visible from outside the procedure,
            # including a slot represented by DoNotCare rather than a local.
            self.heap.mark_all_escaped(bind_locations)

        slots = tuple(return_slots)
        flat_returns = tuple(
            dict.fromkeys(
                location
                for slot in slots
                for location in slot
            )
        )
        self.state.set_return_slots(procedure, slots)
        self.state.set_returns(procedure, flat_returns)

    def _apply_writes(
        self,
        procedure: object,
        operation: object,
        writes: tuple[object, ...],
    ) -> None:
        value = self._stored_value_expression(operation)
        if value is not None:
            value_locations = self.locations_for_expression(procedure, value)
            if isinstance(operation, py_ast.SetSlice):
                value_locations = self._expand_contained_locations(
                    value_locations
                )
            # Don't return early when value_locations is empty: write()
            # handles STRONG+empty (pop to clear the binding) and
            # WEAK+empty (no-op) correctly.
        else:
            # No direct stored-value expression.  Check whether this operation
            # wraps a collection mutator call (e.g. ``list.append(x)``) whose
            # value arguments should be written to the container's wildcard
            # location generated by HeapEffectBuilder.collection_mutation().
            coll_value_locs = self._collection_mutator_value_locations(
                procedure, operation
            )
            if not coll_value_locs:
                return
            value_locations = coll_value_locs
        for write in writes:
            location = getattr(write, "location", None)
            policy = getattr(write, "policy", None)
            if not isinstance(location, HeapLocation):
                continue
            self.state.write(
                location,
                tuple(dict.fromkeys(value_locations)),
                (
                    UpdatePolicy.STRONG
                    if isinstance(operation, (py_ast.SetGlobal, py_ast.SetCellDeref))
                    else policy
                    if isinstance(policy, UpdatePolicy)
                    else UpdatePolicy.WEAK
                ),
            )
        if isinstance(operation, py_ast.SetSubscript):
            key_locations = self.locations_for_expression(
                procedure,
                operation.subscript,
            )
            if key_locations:
                roots = tuple(
                    dict.fromkeys(
                        HeapLocation(write.location.root)
                        for write in writes
                        if isinstance(getattr(write, "location", None), HeapLocation)
                    )
                )
                for root in roots:
                    self.state.write(
                        self.heap.dynamic_attribute_location(root, "__keys__"),
                        key_locations,
                        UpdatePolicy.WEAK,
                    )

    def _collection_mutator_value_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        """Extract value locations for collection mutator calls.

        When a ``Discard(MethodCall(container, "append", [value]))`` is
        processed, :meth:`HeapEffectBuilder.operation_effect` generates
        wildcard writes to the container but the write values are buried
        in the method-call arguments rather than in a ``value`` attribute.
        This helper extracts those value expressions and resolves them
        to heap locations.
        """
        call = self._call_expression(operation)
        if call is None:
            return ()
        call_name = resolve_call_name(call)
        if call_name is None or call_name not in self.collection_mutator_names:
            return ()
        model = self.intrinsics.collection_mutator(call_name)
        if model is None or not model.writes_value:
            return ()
        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall):
            value_exprs = model.value_args(actuals)
        else:
            remaining = actuals[1:] if len(actuals) > 1 else ()
            value_exprs = model.value_args(remaining)
        return self._expand_contained_locations(
            tuple(
                loc
                for val_expr in value_exprs
                for loc in self.locations_for_expression(procedure, val_expr)
            )
        )

    def _apply_collection_reorder(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        """Move every currently stored element into the wildcard may-set."""
        call = self._call_expression(operation)
        container = None
        if isinstance(operation, (py_ast.SetSlice, py_ast.DeleteSlice, py_ast.DeleteSubscript)):
            container = operation.expr
        elif call is not None:
            model = self.intrinsics.collection_mutator(resolve_call_name(call))
            if model is None or not model.reorders_values:
                return
            actuals = tuple(actual_argument_expressions(call))
            container = (
                call.expr
                if isinstance(call, py_ast.MethodCall)
                else actuals[0]
                if actuals
                else None
            )
        else:
            return
        if container is None:
            return
        evaluated = self._last_call_operands.get(id(call), {}) if call is not None else {}
        roots = evaluated.get(id(container))
        if roots is None:
            roots = self.locations_for_expression(procedure, container)
        for root in roots:
            wildcard = self.heap.dynamic_subscript_location(
                root,
                DYNAMIC_SUBSCRIPT_WILDCARD,
            )
            values = self.state.read_contained(wildcard)
            if values:
                self.state.write(wildcard, values, UpdatePolicy.WEAK)

    def _expand_contained_locations(
        self,
        roots: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        """Include values reachable as elements of possible iterable roots.

        This deliberately retains the roots too: append-like mutators store
        the argument object itself, while extend/update and slice assignment
        store values obtained by iterating it.  Using their union is a sound
        may-approximation for the shared mutator model.
        """
        expanded = list(roots)
        for root in roots:
            wildcard = self.heap.dynamic_subscript_location(
                root,
                DYNAMIC_SUBSCRIPT_WILDCARD,
            )
            expanded.extend(self.state.read_contained(wildcard))
        return tuple(dict.fromkeys(expanded))

    def _contained_values(
        self,
        roots: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        values: list[HeapLocation] = []
        for root in roots:
            values.extend(
                self.state.read_contained(
                    self.heap.dynamic_subscript_location(
                        root,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    )
                )
            )
        return tuple(dict.fromkeys(values))

    def _ordered_contained_values(
        self,
        roots: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        """Return known positional elements before wildcard remainder values."""
        values: list[HeapLocation] = []
        for root in roots:
            for index in range(self.heap.policy.max_index + 1):
                values.extend(
                    self.state.read(
                        self.heap.dynamic_subscript_location(root, f"[{index}]"),
                        fallback=(),
                    )
                )
            values.extend(
                self.state.read(
                    self.heap.dynamic_subscript_location(
                        root,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    ),
                    fallback=(),
                )
            )
        return tuple(values)

    def _apply_deletes(self, deletes: tuple[HeapLocation, ...]) -> None:
        for deleted in deletes:
            self.state.delete(deleted)

    def _effective_deletes(
        self,
        operation: object,
        deletes: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        return self.effect_builder.definite_delete_locations(operation, deletes)

    def _handle_local_delete(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        """Handle ``del x`` — break aliasing and remove the local's heap state."""
        if not isinstance(operation, py_ast.Delete):
            return
        self._clear_runtime_local(procedure, operation.lcl)

    def _materialize_collection_literal_values(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        expr = self._assigned_expression(operation)
        if not isinstance(
            expr,
            (py_ast.BuildTuple, py_ast.BuildList, py_ast.BuildSet, py_ast.BuildMap),
        ):
            return
        for argument in getattr(expr, "args", ()):
            self.locations_for_expression(procedure, argument)
        targets = assigned_locals(operation)
        target_locations = tuple(
            location
            for target in targets
            for location in self.heap.locations_for_local(procedure, target)
        )
        value_exprs = self._collection_literal_values(expr)
        for location in target_locations:
            if location.root.kind is HeapObjectKind.ALLOCATION:
                # Write literal element values into the container's heap state
                # so subsequent reads and transitive escape propagation can
                # find them when the container itself escapes.
                self._write_collection_literal_elements(
                    procedure, location, expr, value_exprs
                )

    def _materialize_function_default_values(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        expr = self._assigned_expression(operation)
        if not isinstance(expr, py_ast.MakeFunction):
            return
        targets = assigned_locals(operation)
        target_locations = tuple(
            location
            for target in targets
            for location in self.heap.locations_for_local(procedure, target)
        )
        default_locations = tuple(
            location
            for default in getattr(expr, "defaults", ())
            for location in self.locations_for_expression(procedure, default)
        )
        if not default_locations:
            return
        for location in target_locations:
            defaults_location = self.heap.dynamic_attribute_location(
                location,
                "__defaults__",
            )
            self.state.write(
                defaults_location,
                tuple(dict.fromkeys(default_locations)),
                UpdatePolicy.STRONG,
            )

    def _write_collection_literal_elements(
        self,
        procedure: object,
        container: HeapLocation,
        expr: object,
        value_exprs: tuple[object, ...],
    ) -> None:
        if isinstance(expr, py_ast.BuildMap):
            keys = tuple(expr.args[0::2])
            for key_expr, val_expr in zip(keys, value_exprs):
                key_locations = self.locations_for_expression(
                    procedure,
                    key_expr,
                )
                if key_locations:
                    self.state.write(
                        self.heap.dynamic_attribute_location(
                            container,
                            "__keys__",
                        ),
                        key_locations,
                        UpdatePolicy.WEAK,
                    )
                subscript = self.effect_builder._constant_subscript(key_expr)
                key_loc = self.heap.dynamic_subscript_location(
                    container,
                    subscript or DYNAMIC_SUBSCRIPT_WILDCARD,
                )
                val_locs = self.locations_for_expression(procedure, val_expr)
                if val_locs:
                    self.state.write(
                        key_loc,
                        val_locs,
                        (
                            UpdatePolicy.STRONG
                            if subscript
                            else UpdatePolicy.WEAK
                        ),
                    )
        elif isinstance(expr, py_ast.BuildSet):
            set_loc = self.heap.dynamic_subscript_location(
                container, DYNAMIC_SUBSCRIPT_WILDCARD
            )
            all_val_locs: list[HeapLocation] = []
            for val_expr in value_exprs:
                all_val_locs.extend(
                    self.locations_for_expression(procedure, val_expr)
                )
            if all_val_locs:
                self.state.write(
                    set_loc, tuple(dict.fromkeys(all_val_locs)), UpdatePolicy.WEAK
                )
        else:
            for index, val_expr in enumerate(value_exprs):
                index_loc = self.heap.dynamic_subscript_location(
                    container, f"[{index}]"
                )
                val_locs = self.locations_for_expression(procedure, val_expr)
                if index_loc and val_locs:
                    self.state.write(
                        index_loc, val_locs, UpdatePolicy.STRONG
                    )

    @staticmethod
    def _collection_literal_values(expr: object) -> tuple[object, ...]:
        if isinstance(expr, py_ast.BuildMap):
            return tuple(expr.args[1::2])
        return tuple(getattr(expr, "args", ()))

    def _stored_value_expression(self, operation: object) -> object | None:
        values = self.effect_builder._stored_value_expressions(operation)
        if values:
            return values[0]
        collection_value = self.effect_builder.dynamic_subscript_value(operation)
        if collection_value is not None:
            return collection_value
        dynamic_attr_value = self.effect_builder._dynamic_setattr_value(operation)
        if dynamic_attr_value is not None:
            return dynamic_attr_value
        return None

    @staticmethod
    def _assigned_expression(operation: object) -> object | None:
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            return operation.expr
        if isinstance(operation, py_ast.AnnAssign):
            return operation.value
        return None

    @staticmethod
    def _call_expression(operation: object) -> object | None:
        expr = _TransferOpsMixin._assigned_expression(operation)
        if isinstance(expr, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return expr
        wrapped = getattr(operation, "expr", None)
        if isinstance(wrapped, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return wrapped
        if isinstance(operation, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return operation
        return None

