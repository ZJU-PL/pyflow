"""Definition and external-boundary transfer methods."""

from __future__ import annotations
from pyflow.analysis.ir_utils import (
    class_cell,
    code_closure_cells,
    code_definition_annotations,
    resolve_call_name,
)
from pyflow.language.python import ast as py_ast
from ..domain.abstraction import HeapEnvironment
from ..model import HeapLocation, UpdatePolicy


class _DefinitionTransferMixin:
    """Internal mixin composed by HeapTransferEngine."""

    def _apply_definition_transfer(
        self,
        procedure: object,
        operation: object,
        *,
        related_locations: tuple[HeapLocation, ...] | None = None,
    ) -> HeapLocation | None:
        if isinstance(operation, py_ast.TypeAlias):
            deferred_state = self._capture_flow_state()
            value_locations = self.locations_for_expression(
                procedure,
                operation.value,
            )
            parameter_locations = self._merge_expression_locations(
                procedure,
                *getattr(operation, "params", ()),
            )
            alias = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    operation,
                    label=f"type alias {operation.name}",
                    context=self._current_context,
                )
            )
            if value_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(alias, "__value__"),
                    value_locations,
                    UpdatePolicy.STRONG,
                )
            if parameter_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(alias, "__type_params__"),
                    parameter_locations,
                    UpdatePolicy.STRONG,
                )
            # PEP 695 aliases evaluate their value lazily.  Preserve both the
            # deferred state and the state in which the value has been forced;
            # clients can therefore soundly analyze programs regardless of
            # whether a later operation materializes ``__value__``.
            forced_state = self._capture_flow_state()
            self._restore_flow_state(
                self._join_flow_states((deferred_state, forced_state))
            )
            alias_values = (alias,)
            if self._is_module_scope(procedure):
                target = self.effect_builder.global_location(
                    procedure,
                    operation.name,
                )
                self.state.write(target, alias_values, UpdatePolicy.STRONG)
                self.heap.mark_all_escaped(alias_values)
                self.state.mark_escaped(alias_values)
            self._bind_definition_local(
                procedure,
                operation.name,
                alias_values,
            )
            return alias
        if not isinstance(operation, (py_ast.FunctionDef, py_ast.ClassDef)):
            return None

        label = (
            f"function {operation.name}"
            if isinstance(operation, py_ast.FunctionDef)
            else f"class {operation.name}"
        )
        definition = HeapLocation(
            self.heap.allocation_object(
                procedure,
                operation,
                label=label,
                context=self._current_context,
            )
        )
        default_locations: list[HeapLocation] = []
        if isinstance(operation, py_ast.FunctionDef):
            defaults = tuple(getattr(operation.code.codeparameters, "defaults", ()))
            for index, default in enumerate(defaults):
                locations = self.locations_for_expression(procedure, default)
                self._definition_default_locations[(id(operation.code), index)] = (
                    locations
                )
                default_locations.extend(locations)

        related_expressions = self._definition_header_expressions(operation)
        if related_locations is None:
            related_locations = tuple(
                dict.fromkeys(
                    location
                    for expression in related_expressions
                    for location in self.locations_for_expression(
                        procedure,
                        expression,
                    )
                )
            )
        decorator_kind = self._definition_decorator_kind(operation)
        decorated_or_dynamic = ()
        if getattr(operation, "decorators", ()) and decorator_kind == "dynamic":
            decorated_or_dynamic = (self._external_value_location(procedure),)
        values = tuple(dict.fromkeys((definition, *decorated_or_dynamic)))
        if isinstance(operation, py_ast.ClassDef):
            self._class_definitions[(self._module_owner(procedure), operation.name)] = (
                definition
            )
            self._class_locations_by_root[definition.root] = definition
            self._class_locations_by_definition[id(operation)] = definition
        if self._is_module_scope(procedure):
            target = self.effect_builder.global_location(
                procedure,
                operation.name,
            )
            self.state.write(target, values, UpdatePolicy.STRONG)
            self.heap.mark_all_escaped(values)
            self.state.mark_escaped(values)
        self._bind_definition_local(procedure, operation.name, values)

        if default_locations:
            self.state.write(
                self.heap.dynamic_attribute_location(
                    definition,
                    "__defaults__",
                ),
                tuple(dict.fromkeys(default_locations)),
                UpdatePolicy.STRONG,
            )
        if isinstance(operation, py_ast.FunctionDef):
            closure_locations = tuple(
                dict.fromkeys(
                    self.effect_builder.cell_location(cell, procedure)
                    for cell in code_closure_cells(operation.code)
                )
            )
            if closure_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(
                        definition,
                        "__closure__",
                    ),
                    closure_locations,
                    UpdatePolicy.STRONG,
                )
            self._function_codes_by_root[definition.root] = operation.code
            self._function_binding_kinds[definition.root] = decorator_kind
            if getattr(operation, "decorators", ()) and decorator_kind == "dynamic":
                decorated = self._apply_known_definition_decorators(
                    procedure,
                    operation,
                    (definition,),
                )
                self._rebind_definition_value(
                    procedure,
                    operation.name,
                    decorated,
                )
        if isinstance(operation, py_ast.ClassDef):
            base_locations = self._merge_expression_locations(
                procedure,
                *getattr(operation, "bases", ()),
            )
            named_bases = tuple(
                self._class_definitions[(self._module_owner(procedure), base.name)]
                for base in getattr(operation, "bases", ())
                if isinstance(base, py_ast.Local)
                and (self._module_owner(procedure), base.name)
                in self._class_definitions
            )
            base_locations = tuple(dict.fromkeys((*base_locations, *named_bases)))
            if base_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(definition, "__bases__"),
                    base_locations,
                    UpdatePolicy.STRONG,
                )
            self._class_bases_by_root[definition.root] = base_locations
            implicit_class_cell = class_cell(operation)
            if implicit_class_cell is not None:
                self.state.write(
                    self.effect_builder.cell_location(
                        implicit_class_cell,
                        procedure,
                    ),
                    (definition,),
                    UpdatePolicy.STRONG,
                )
        if related_locations:
            self.state.write(
                self.heap.dynamic_attribute_location(
                    definition,
                    "__definition_inputs__",
                ),
                related_locations,
                UpdatePolicy.STRONG,
            )
        return definition

    def _apply_known_definition_decorators(
        self,
        procedure: object,
        operation: object,
        initial: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        current = initial
        for decorator_expression in reversed(
            tuple(getattr(operation, "decorators", ()))
        ):
            decorator_locations = self.locations_for_expression(
                procedure,
                decorator_expression,
            )
            results: list[HeapLocation] = []
            complete = bool(decorator_locations)
            for decorator in decorator_locations:
                code = self._function_codes_by_root.get(decorator.root)
                receivers: tuple[HeapLocation, ...] = ()
                if code is None:
                    bound = self._bound_methods_by_root.get(decorator.root)
                    if bound is not None:
                        code, receivers = bound
                if code is None:
                    complete = False
                    continue
                actual_groups = (receivers, current) if receivers else (current,)
                results.extend(
                    self._evaluate_known_code(
                        procedure,
                        code,
                        actual_groups,
                    )
                )
            current = (
                tuple(dict.fromkeys(results))
                if complete and results
                else (self._external_value_location(procedure),)
            )
        return current

    def _rebind_definition_value(
        self,
        procedure: object,
        name: str,
        values: tuple[HeapLocation, ...],
    ) -> None:
        if self._is_module_scope(procedure):
            self.state.write(
                self.effect_builder.global_location(procedure, name),
                values,
                UpdatePolicy.STRONG,
            )
        self._bind_definition_local(procedure, name, values)

    def _definition_decorator_kind(self, operation: object) -> str:
        decorators = tuple(getattr(operation, "decorators", ()))
        if not decorators:
            return "instance"
        recognized = None
        for decorator in decorators:
            name = resolve_call_name(decorator)
            if name is None:
                name = self.effect_builder._constant_string(decorator)
            short = name.rsplit(".", 1)[-1] if isinstance(name, str) else None
            if short in {"staticmethod", "classmethod", "property"}:
                recognized = short
            else:
                return "dynamic"
        return recognized or "dynamic"

    def _is_module_scope(self, procedure: object) -> bool:
        return (
            isinstance(procedure, py_ast.Code)
            and id(procedure) not in self._lexical_parents
        )

    def _module_owner(self, procedure: object) -> object:
        explicit = getattr(procedure, "module", None)
        if explicit is not None:
            return explicit
        cached = self._module_owners.get(id(procedure))
        if cached is not None:
            return cached
        parent = self._lexical_parents.get(id(procedure))
        if parent is not None:
            owner = self._module_owner(parent)
            self._module_owners[id(procedure)] = owner
            return owner
        origin = getattr(getattr(procedure, "annotation", None), "origin", ()) or ()
        for item in origin:
            if isinstance(item, str) and item.startswith("source("):
                payload = item[len("source(") :].rstrip(")")
                filename = payload.rsplit(":", 1)[0]
                owner = ("source-module", filename)
                self._module_owners[id(procedure)] = owner
                return owner
        owner = ("code-module", id(procedure))
        self._module_owners[id(procedure)] = owner
        return owner

    def _bind_definition_local(
        self,
        procedure: object,
        name: str,
        locations: tuple[HeapLocation, ...],
    ) -> None:
        key = (id(procedure), name)
        local = self._definition_locals.get(key)
        if local is None:
            local = py_ast.Local(name)
            self._definition_locals[key] = local
        self._bind_runtime_local(procedure, local, locations)

    def _scope_members(
        self,
        procedure: object,
        environment: HeapEnvironment,
    ) -> dict[str, tuple[HeapLocation, ...]]:
        members: dict[str, list[HeapLocation]] = {}
        procedure_id = id(procedure)
        keys = set(environment.storage_overrides) | set(environment.allocation_sites)
        for key in keys:
            if key[0] != procedure_id:
                continue
            name = environment.local_names.get(key)
            if not name:
                continue
            storage = self.heap._environment_storage(environment, key)
            members.setdefault(name, []).extend(
                self.heap.location_for_raw(raw) for raw in storage
            )
        return {
            name: tuple(dict.fromkeys(locations))
            for name, locations in members.items()
            if locations
        }

    @staticmethod
    def _definition_header_expressions(operation: object) -> tuple[object, ...]:
        expressions: list[object] = []
        if isinstance(operation, py_ast.FunctionDef):
            expressions.extend(code_definition_annotations(operation.code))
        if isinstance(operation, py_ast.ClassDef):
            expressions.extend(getattr(operation, "bases", ()))
            expressions.extend(
                (
                    keyword[1]
                    if isinstance(keyword, tuple) and len(keyword) == 2
                    else keyword
                )
                for keyword in getattr(operation, "keywords", ())
            )
        expressions.extend(getattr(operation, "decorators", ()))
        type_params = getattr(operation, "type_params", None)
        if type_params is not None:
            expressions.append(type_params)
        return tuple(expressions)

    def _apply_external_boundary_transfer(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        expressions: list[object] = []
        if isinstance(operation, py_ast.OutputBlock):
            expressions.extend(
                output.expr
                for output in getattr(operation, "outputs", ())
                if getattr(output, "expr", None) is not None
            )
        elif isinstance(operation, py_ast.Output):
            expressions.append(operation.expr)
        elif isinstance(operation, py_ast.Print):
            expressions.extend(
                expression
                for expression in (operation.target, operation.expr)
                if expression is not None
            )
        if not expressions:
            return
        escaped = tuple(
            dict.fromkeys(
                location
                for expression in expressions
                for location in self.locations_for_expression(procedure, expression)
            )
        )
        self.heap.mark_all_escaped(escaped)
        self.state.mark_escaped(escaped)
