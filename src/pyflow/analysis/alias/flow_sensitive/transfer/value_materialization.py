"""Assignment, return, and literal value materialization."""

from __future__ import annotations

from pyflow.language.python.ir_metadata import assigned_locals
from pyflow.language.python import ast as py_ast

from ..model import HeapLocation, HeapObjectKind, UpdatePolicy
from ..semantics.effects import DYNAMIC_SUBSCRIPT_WILDCARD


class _ValueMaterializationMixin:
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
            module_name = self._resolved_import_module_name(procedure, expr)
            module = self.heap.module_object(module_name, label=module_name)
            imported = [HeapLocation(module)]
            if not getattr(expr, "fromlist", None) and "." in expr.name:
                top_level = expr.name.split(".", 1)[0]
                if all(
                    getattr(target, "name", None) == top_level for target in targets
                ):
                    imported = [
                        HeapLocation(
                            self.heap.module_object(top_level, label=top_level)
                        )
                    ]
                else:
                    imported = [HeapLocation(module)]
            if getattr(expr, "fromlist", None):
                for imported_name in getattr(expr, "fromlist", ()):
                    name = getattr(imported_name, "name", imported_name)
                    if name == "*":
                        self.precision_degradations.append(
                            (expr, "star-import-namespace")
                        )
                        unknown = self._external_value_location(procedure)
                        self.state.write(
                            self.heap.dynamic_attribute_location(
                                HeapLocation(module),
                                "*",
                            ),
                            (unknown,),
                            UpdatePolicy.WEAK,
                        )
                        break
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
            self._pending_call_results[
                self._program_point_identity(procedure, operation)
            ] = (targets, slots)
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

    def _resolved_import_module_name(
        self,
        procedure: object,
        expression: py_ast.Import,
    ) -> str:
        if not getattr(expression, "level", 0):
            return expression.name
        owner_name = self._module_name_for_owner(self._module_owner(procedure))
        if not owner_name:
            return expression.name or f"relative:{expression.level}"
        package = owner_name.split(".")[:-1]
        climb = max(int(expression.level) - 1, 0)
        if climb:
            package = package[:-climb] if climb < len(package) else []
        if expression.name:
            package.extend(expression.name.split("."))
        return ".".join(package) or expression.name or owner_name

    @staticmethod
    def _direct_assigned_locals(operation: object) -> tuple[py_ast.Local, ...]:
        if isinstance(operation, py_ast.Assign):
            return tuple(
                local for local in operation.lcls if isinstance(local, py_ast.Local)
            )
        if isinstance(operation, py_ast.UnpackSequence):
            return tuple(
                local for local in operation.targets if isinstance(local, py_ast.Local)
            )
        if isinstance(operation, py_ast.AnnAssign):
            if operation.value is not None and isinstance(
                operation.target, py_ast.Local
            ):
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
            dict.fromkeys(location for slot in slots for location in slot)
        )
        self.state.set_return_slots(procedure, slots)
        self.state.set_returns(procedure, flat_returns)

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
                        (UpdatePolicy.STRONG if subscript else UpdatePolicy.WEAK),
                    )
        elif isinstance(expr, py_ast.BuildSet):
            set_loc = self.heap.dynamic_subscript_location(
                container, DYNAMIC_SUBSCRIPT_WILDCARD
            )
            all_val_locs: list[HeapLocation] = []
            for val_expr in value_exprs:
                all_val_locs.extend(self.locations_for_expression(procedure, val_expr))
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
                    self.state.write(index_loc, val_locs, UpdatePolicy.STRONG)

    @staticmethod
    def _collection_literal_values(expr: object) -> tuple[object, ...]:
        if isinstance(expr, py_ast.BuildMap):
            return tuple(expr.args[1::2])
        return tuple(getattr(expr, "args", ()))
