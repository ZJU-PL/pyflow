"""Check annotations, generic arguments, and literal container contexts."""

from __future__ import annotations

import ast
import collections.abc as cabc
from dataclasses import replace

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NONE_TYPE,
    CallableType,
    Instance,
    LiteralType,
    NeverType,
    NoneType,
    ProperType,
    TupleType,
    TypeType,
    TypeVarType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import _expression_name, _span
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue


class CompatibilityInference(InferenceComponent):
    """Check annotations, generic arguments, and literal container contexts."""

    @staticmethod
    def _is_empty_dict_value(value: AbstractTypeValue) -> bool:
        return bool(value.types) and all(
            isinstance(candidate, Instance)
            and candidate.type.raw_type is dict
            and len(candidate.args) >= 2
            and isinstance(candidate.args[0], NeverType)
            and isinstance(candidate.args[1], NeverType)
            for candidate in value.types
        )

    def _runtime_value_type(self, value: AbstractTypeValue) -> ProperType:
        """Proper type for a runtime value, keeping class-object alternatives.

        ``public_type()`` flattens a runtime class object to its instance type.
        Containers built from class objects (dict keyword values, variadic
        argument tuples) must retain ``type[...]`` so they are checked against
        class-object annotations instead of instances.
        """
        typ = value.public_type() or ANY

        def wrap(item: ProperType) -> ProperType:
            return TypeType(item) if isinstance(item, Instance) else item

        if not value.class_targets:
            return typ
        if isinstance(typ, Instance):
            return TypeType(typ)
        if isinstance(typ, UnionType):
            return UnionType(tuple(wrap(item) for item in typ.items))
        return typ

    def _is_type_variable_annotation(self, node, type_variables=None) -> bool:
        """Whether *node* is a bare type-variable reference."""
        if not isinstance(node, ast.Name):
            return False
        variables = self.engine._type_vars if type_variables is None else type_variables
        return node.id in variables

    def _is_substituted_type_variable_annotation(
        self, node, value: AbstractTypeValue, type_variables=None
    ) -> bool:
        """A bare type-variable annotation analyzed under a concrete substitution.

        Base-class methods are analyzed for each subclass specialization.  A
        body that is not genuinely parameterized (for example one reading a
        concrete class attribute) must not be checked against an arbitrary
        subclass type argument.
        """
        if not self._is_type_variable_annotation(node, type_variables):
            return False
        return not isinstance(value.public_type(), TypeVarType)

    def _check_typed_dict_update(
        self,
        typ: Instance,
        fields: dict[str, ProperType],
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        call_node: ast.Call,
    ) -> None:
        """Validate ``TypedDict.update`` keys and values against the declaration."""
        severity = "error" if self.engine.options.strict_annotations else "warning"

        def literal_child(name: str) -> ast.expr | None:
            if not call_node.args or not isinstance(call_node.args[0], ast.Dict):
                return None
            for key_node, value_node in zip(call_node.args[0].keys, call_node.args[0].values):
                if isinstance(key_node, ast.Constant) and key_node.value == name:
                    return value_node
            return None

        def check(name: object, value: AbstractTypeValue, node: ast.AST) -> None:
            if not isinstance(name, str):
                return
            if name not in fields:
                self.engine._add_diagnostic(
                    "annotation-mismatch",
                    f"TypedDict {typ} has unexpected key {name!r}",
                    node=node,
                    severity=severity,
                )
                return
            self._check_annotation_compatibility(
                value,
                AbstractTypeValue.from_type(fields[name]),
                node,
                context=f"TypedDict key {name}",
            )

        for argument in arguments:
            for shape in argument.dict_shapes or ():
                for name, value_type in shape:
                    check(
                        name,
                        AbstractTypeValue.from_type(value_type),
                        literal_child(name) if isinstance(name, str) else call_node,
                    )
        for name, value in keywords.items():
            check(name, value, call_node)

    def _check_annotation_compatibility(
        self,
        inferred: AbstractTypeValue,
        annotated: AbstractTypeValue,
        node: ast.AST,
        *,
        context: str,
    ) -> None:
        expected = annotated.public_type()
        if (
            expected is None
            or not inferred.types
            or annotated.unknown
            or self.engine._declaration_rules._has_unresolved_annotation(expected)
            or self.engine._declaration_rules._contains_type_var(expected)
        ):
            return
        inspected_node = (
            node.value
            if isinstance(node, (ast.AnnAssign, ast.Assign, ast.Return)) and node.value is not None
            else node
        )
        expected_parts = expected.items if isinstance(expected, UnionType) else (expected,)
        has_mapping_expectation = any(
            isinstance(part, Instance)
            and (
                part.type.raw_type in {dict, cabc.Mapping, cabc.MutableMapping}
                or (
                    part.type.is_protocol
                    and bool(self.engine.type_system.get_members(part.type))
                    and all(
                        hasattr(dict, m) for m in self.engine.type_system.get_members(part.type)
                    )
                )
            )
            for part in expected_parts
        )
        if has_mapping_expectation:
            filtered_types = frozenset(
                t
                for t in inferred.types
                if not (
                    isinstance(t, Instance)
                    and t.type.raw_type is dict
                    and len(t.args) >= 2
                    and isinstance(t.args[0], NeverType)
                    and isinstance(t.args[1], NeverType)
                )
            )
            if len(filtered_types) < len(inferred.types):
                if not filtered_types:
                    return
                inferred = replace(inferred, types=filtered_types)
        constructor = (
            _expression_name(inspected_node.func)
            if isinstance(inspected_node, ast.Call) and isinstance(inspected_node.func, ast.Name)
            else None
        )
        if constructor in {"list", "set", "frozenset", "dict"}:
            # Contextual typing for fresh container constructors: the literal
            # is checked against the expected element type, not invariantly.
            for part in expected_parts:
                if not isinstance(part, Instance):
                    continue
                if constructor == "dict":
                    if part.type.raw_type not in {dict, cabc.Mapping, cabc.MutableMapping}:
                        continue
                    if len(part.args) < 2:
                        return
                    actuals = [
                        typ
                        for typ in inferred.types
                        if isinstance(typ, Instance)
                        and typ.type.raw_type is dict
                        and len(typ.args) >= 2
                    ]
                    if actuals and all(
                        self.engine.type_system.is_subtype(
                            self.engine._value_rules._proper_instance(str), part.args[0]
                        )
                        and self.engine.type_system.is_subtype(typ.args[1], part.args[1])
                        for typ in actuals
                    ):
                        return
                else:
                    raw = {"list": list, "set": set, "frozenset": frozenset}[constructor]
                    if part.type.raw_type is not raw:
                        continue
                    if not part.args:
                        return
                    actuals = [
                        typ
                        for typ in inferred.types
                        if isinstance(typ, Instance) and typ.type.raw_type is raw and typ.args
                    ]
                    if actuals and all(
                        self.engine.type_system.is_subtype(typ.args[0], part.args[0])
                        for typ in actuals
                    ):
                        return
        expected_literals = self._literal_expected_values(expected)
        if expected_literals is not None and inferred.literal_values:
            if inferred.literal_values.issubset(expected_literals):
                return
            self.engine._add_diagnostic(
                "annotation-mismatch",
                f"Inferred {sorted(map(self._format_literal_value, inferred.literal_values))} "
                f"is incompatible with annotated {expected} for {context}",
                node=node,
                severity="error" if self.engine.options.strict_annotations else "warning",
            )
            return
        if expected_literals is not None:
            # Without literal evidence for the inferred value, we cannot prove
            # that it violates the literal constraint.
            return
        typed_dict_expected = (
            expected
            if isinstance(expected, Instance) and expected.type.typed_dict_fields is not None
            else next(
                (
                    part
                    for part in expected_parts
                    if isinstance(part, Instance) and part.type.typed_dict_fields is not None
                ),
                None,
            )
        )
        if typed_dict_expected is not None:
            expected = typed_dict_expected
            if (
                inferred.types
                and not inferred.dict_shapes
                and all(
                    isinstance(candidate, Instance)
                    and candidate.type.raw_type is dict
                    and len(candidate.args) >= 2
                    and isinstance(candidate.args[0], NeverType)
                    and isinstance(candidate.args[1], NeverType)
                    for candidate in inferred.types
                )
            ):
                missing = expected.type.required_keys
                if missing:
                    self.engine._add_diagnostic(
                        "annotation-mismatch",
                        f"TypedDict {expected} has missing keys {sorted(missing)} "
                        "and unexpected keys []",
                        node=node,
                        severity="error" if self.engine.options.strict_annotations else "warning",
                    )
                return
            if inferred.dict_shapes and all(
                isinstance(candidate, Instance) and candidate.type.raw_type is dict
                for candidate in inferred.types
            ):
                fields = expected.type.typed_dict_fields
                literal_nodes: dict[str, ast.expr] = {}
                if isinstance(inspected_node, ast.Dict):
                    for key, value in zip(inspected_node.keys, inspected_node.values):
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            literal_nodes[key.value] = value
                for shape in inferred.dict_shapes:
                    actual = dict(shape)
                    missing = expected.type.required_keys - actual.keys()
                    extra = actual.keys() - fields.keys()
                    if missing or extra:
                        self.engine._add_diagnostic(
                            "annotation-mismatch",
                            f"TypedDict {expected} has missing keys {sorted(missing)} "
                            f"and unexpected keys {sorted(extra)}",
                            node=node,
                            severity=(
                                "error" if self.engine.options.strict_annotations else "warning"
                            ),
                        )
                    for name in actual.keys() & fields.keys():
                        child = literal_nodes.get(name)
                        child_span = None if child is None else _span(child)
                        recorded_child = (
                            self.engine._expressions.get(child_span) if child_span else None
                        )
                        actual_value = (
                            recorded_child
                            if recorded_child is not None
                            else AbstractTypeValue.from_type(actual[name])
                        )
                        if isinstance(child, ast.Constant):
                            actual_value = AbstractTypeValue.from_type(
                                actual[name], literal_values=frozenset((child.value,))
                            )
                        self._check_annotation_compatibility(
                            actual_value,
                            AbstractTypeValue.from_type(fields[name]),
                            child or node,
                            context=f"TypedDict key {name}",
                        )
                return
        if self._expected_contains_literal(expected):
            self._check_literal_container_elements(expected, inspected_node, context)
            return
        if (
            isinstance(expected, Instance)
            and len(inferred.types) > 1
            and expected.args
            and all(
                isinstance(candidate, Instance)
                and candidate.type == expected.type
                and len(candidate.args) == len(expected.args)
                and all(
                    self.engine.type_system.is_subtype(actual, wanted)
                    for actual, wanted in zip(candidate.args, expected.args)
                )
                for candidate in inferred.types
            )
        ):
            # A flow join of alternative container branches is compatible
            # with the corresponding joined element annotation.
            return
        if isinstance(expected, Instance) and expected.args and inferred.element_dict_shapes:
            element_expected = expected.args[0]
            if (
                isinstance(element_expected, Instance)
                and element_expected.type.typed_dict_fields is not None
            ):
                fields = element_expected.type.typed_dict_fields
                for shape in inferred.element_dict_shapes:
                    actual = dict(shape)
                    missing = element_expected.type.required_keys - actual.keys()
                    extra = actual.keys() - fields.keys()
                    if missing or extra:
                        self.engine._add_diagnostic(
                            "annotation-mismatch",
                            f"TypedDict {element_expected} has missing keys {sorted(missing)} "
                            f"and unexpected keys {sorted(extra)}",
                            node=node,
                            severity=(
                                "error" if self.engine.options.strict_annotations else "warning"
                            ),
                        )
                    for name in actual.keys() & fields.keys():
                        self._check_annotation_compatibility(
                            AbstractTypeValue.from_type(actual[name]),
                            AbstractTypeValue.from_type(fields[name]),
                            node,
                            context=f"TypedDict key {name}",
                        )
                return
        incompatible = []
        for candidate in inferred.types:
            if self.engine._declaration_rules._has_unresolved_annotation(
                candidate
            ) or self.engine._declaration_rules._contains_type_var(candidate):
                continue
            if self._has_unresolved_ancestry(candidate):
                # Part of the class hierarchy lives in an unmodelled third-party
                # base, so incompatibility cannot be established either way.
                continue
            if (
                isinstance(candidate, Instance)
                and isinstance(expected, Instance)
                and candidate.type == expected.type
                and not candidate.args
                and expected.args
            ):
                candidate = Instance(candidate.type, (ANY,) * len(expected.args))
            if (
                isinstance(candidate, Instance)
                and isinstance(expected, Instance)
                and candidate.type == expected.type
                and not expected.args
                and candidate.args
            ):
                expected = Instance(expected.type, (ANY,) * len(candidate.args))
            if isinstance(candidate, UnionType) and isinstance(expected, Instance):
                container_items = candidate.items
                if all(
                    isinstance(item, Instance)
                    and item.type == expected.type
                    and len(item.args) == len(expected.args)
                    and all(
                        self.engine.type_system.is_subtype(actual, wanted)
                        for actual, wanted in zip(item.args, expected.args)
                    )
                    for item in container_items
                ):
                    candidate = expected
            expected_parts = expected.items if isinstance(expected, UnionType) else (expected,)
            if (
                isinstance(candidate, Instance)
                and not candidate.args
                and any(
                    isinstance(part, Instance) and candidate.type == part.type and part.args
                    for part in expected_parts
                )
            ):
                target_part = next(
                    part
                    for part in expected_parts
                    if isinstance(part, Instance) and candidate.type == part.type and part.args
                )
                candidate = Instance(candidate.type, (ANY,) * len(target_part.args))
            if isinstance(candidate, Instance) and any(
                isinstance(part, Instance) and candidate.type == part.type and not part.args
                for part in expected_parts
            ):
                continue
            if (
                isinstance(candidate, (Instance, TupleType))
                and inferred.class_targets
                and any(
                    isinstance(part, (TypeType, CallableType))
                    or (isinstance(part, Instance) and part.type.raw_type in {type, cabc.Callable})
                    for part in expected_parts
                )
            ):
                candidate = TypeType(candidate)
            try:
                compatible = (
                    isinstance(candidate, Instance)
                    and isinstance(expected, Instance)
                    and self._generic_arguments_compatible(candidate, expected)
                ) or self.engine.type_system.is_subtype(candidate, expected)
                if not compatible and self._fresh_collection_context(node):
                    expected_parts = (
                        expected.items if isinstance(expected, UnionType) else (expected,)
                    )
                    compatible = any(
                        isinstance(candidate, Instance)
                        and isinstance(part, Instance)
                        and candidate.type.raw_type is part.type.raw_type
                        and candidate.type.raw_type in {list, set, frozenset, dict}
                        and candidate.args
                        and len(candidate.args) == len(part.args)
                        and self._fresh_container_compatible(candidate, part, inspected_node)
                        for part in expected_parts
                    )
            except (AssertionError, KeyError, TypeError):
                compatible = candidate == expected
            if not compatible:
                incompatible.append(candidate)
        if incompatible:
            self.engine._add_diagnostic(
                "annotation-mismatch",
                f"Inferred {', '.join(map(str, incompatible))} is incompatible "
                f"with annotated {expected} for {context}",
                node=node,
                severity="error" if self.engine.options.strict_annotations else "warning",
            )

    def _has_unresolved_ancestry(self, typ: ProperType) -> bool:
        """Whether a class, or a nested element class, has an unknowable base."""
        if isinstance(typ, Instance):
            if getattr(typ.type, "has_unresolved_bases", False):
                return True
            if getattr(typ.type.raw_type, "__pyflow_unresolved_external__", False):
                return True
            return any(self._has_unresolved_ancestry(argument) for argument in typ.args)
        if isinstance(typ, UnionType):
            return any(self._has_unresolved_ancestry(item) for item in typ.items)
        if isinstance(typ, TypeType):
            return self._has_unresolved_ancestry(typ.item)
        if isinstance(typ, CallableType):
            if typ.return_type is not None and self._has_unresolved_ancestry(typ.return_type):
                return True
            return any(
                self._has_unresolved_ancestry(argument) for argument in (typ.arg_types or ())
            )
        return False

    def _fresh_container_compatible(
        self, actual: ProperType, wanted: ProperType, node: ast.AST | None = None
    ) -> bool:
        """Compare a freshly written container literal with its expected type.

        Nested literals are contextually typed in Python: ``[[None]]`` is a
        valid ``list[list[str | None]]``.  Plain invariance would reject the
        inner ``list[None]``, so widen recursively for fresh literals only.
        An existing mutable value inside a fresh literal remains invariant.
        """
        if self.engine.type_system.is_subtype(actual, wanted):
            return True
        if isinstance(actual, UnionType):
            return all(
                self._fresh_container_compatible(item, wanted, node) for item in actual.items
            )
        if isinstance(wanted, UnionType):
            return any(
                self._fresh_container_compatible(actual, item, node) for item in wanted.items
            )
        if not (isinstance(actual, Instance) and isinstance(wanted, Instance)):
            return False
        raw = actual.type.raw_type
        if raw is not wanted.type.raw_type or raw not in {list, set, frozenset, dict}:
            return False
        if not actual.args or len(actual.args) != len(wanted.args):
            return False
        children = None
        if isinstance(node, (ast.List, ast.Set)) and raw in {list, set}:
            children = [(element, wanted.args[0]) for element in node.elts]
        elif isinstance(node, (ast.ListComp, ast.SetComp)) and raw in {list, set}:
            children = [(node.elt, wanted.args[0])]
        elif (
            isinstance(node, ast.Dict) and raw is dict and all(key is not None for key in node.keys)
        ):
            children = [
                (child, expected)
                for key, value in zip(node.keys, node.values)
                for child, expected in ((key, wanted.args[0]), (value, wanted.args[1]))
            ]
        elif isinstance(node, ast.DictComp) and raw is dict:
            children = [(node.key, wanted.args[0]), (node.value, wanted.args[1])]
        if children is not None:
            for child, expected in children:
                recorded = self.engine._expressions.get(_span(child))
                if recorded is None or isinstance(child, ast.Starred):
                    break
                child_type = self._runtime_value_type(recorded)
                if self._fresh_collection_context(child):
                    if not self._fresh_container_compatible(child_type, expected, child):
                        return False
                elif not self.engine.type_system.is_subtype(child_type, expected):
                    return False
            else:
                return True
        # Without syntax proving that an inner container is fresh, only the
        # outer container may widen; its elements keep their usual variance.
        return all(
            self.engine.type_system.is_subtype(actual_arg, wanted_arg)
            for actual_arg, wanted_arg in zip(actual.args, wanted.args)
        )

    def _generic_arguments_compatible(
        self,
        candidate: Instance,
        expected: Instance,
    ) -> bool:
        """Compare invariant generic arguments, treating bare containers as Any-like."""
        if candidate.type != expected.type or not candidate.args or not expected.args:
            return False
        if len(candidate.args) != len(expected.args):
            return False
        for actual, wanted in zip(candidate.args, expected.args):
            if isinstance(actual, NeverType):
                continue
            if isinstance(actual, Instance) and isinstance(wanted, Instance):
                if actual.type == wanted.type and (not actual.args or not wanted.args):
                    continue
                if actual.type == wanted.type and self._generic_arguments_compatible(
                    actual, wanted
                ):
                    continue
            if isinstance(actual, TupleType) and isinstance(wanted, TupleType):
                if wanted.unknown_size and wanted.args == (ANY,):
                    continue
                if actual.unknown_size and actual.args == (ANY,):
                    continue
                if self.engine.type_system.is_subtype(actual, wanted):
                    continue
            if not (
                self.engine.type_system.is_subtype(actual, wanted)
                and self.engine.type_system.is_subtype(wanted, actual)
            ):
                return False
        return True

    @staticmethod
    def _format_literal_value(value: object) -> str:
        if isinstance(value, tuple) and len(value) == 3 and value[0] == "enum":
            return f"{value[1]}.{value[2]}"
        return repr(value)

    @staticmethod
    def _expected_contains_literal(expected: ProperType) -> bool:
        if isinstance(expected, LiteralType):
            return True
        if isinstance(expected, UnionType):
            return any(
                CompatibilityInference._expected_contains_literal(item) for item in expected.items
            )
        if isinstance(expected, TupleType):
            return any(
                CompatibilityInference._expected_contains_literal(item) for item in expected.args
            )
        if isinstance(expected, Instance):
            return any(
                CompatibilityInference._expected_contains_literal(item) for item in expected.args
            )
        return False

    def _check_literal_container_elements(
        self,
        expected: ProperType,
        node: ast.AST | None,
        context: str,
    ) -> None:
        if node is None:
            return
        if isinstance(expected, Instance):
            raw = expected.type.raw_type
            if (
                raw in {list, set, frozenset}
                and expected.args
                and isinstance(node, (ast.List, ast.Set, ast.Tuple))
            ):
                for element in node.elts:
                    if isinstance(element, ast.Constant):
                        self._check_annotation_compatibility(
                            self._literal_constant_value(element.value),
                            AbstractTypeValue.from_type(expected.args[0]),
                            element,
                            context=f"{context} element",
                        )
                return
            if raw is dict and len(expected.args) >= 2 and isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant):
                        self._check_annotation_compatibility(
                            self._literal_constant_value(key.value),
                            AbstractTypeValue.from_type(expected.args[0]),
                            key,
                            context=f"{context} key",
                        )
                    if isinstance(value, ast.Constant):
                        self._check_annotation_compatibility(
                            self._literal_constant_value(value.value),
                            AbstractTypeValue.from_type(expected.args[1]),
                            value,
                            context=f"{context} value",
                        )
                return
        if isinstance(expected, TupleType) and isinstance(node, ast.Tuple):
            for actual, wanted, element in zip(node.elts, expected.args, node.elts):
                if isinstance(actual, ast.Constant):
                    self._check_annotation_compatibility(
                        self._literal_constant_value(actual.value),
                        AbstractTypeValue.from_type(wanted),
                        element,
                        context=f"{context} element",
                    )

    def _literal_constant_value(self, value: object) -> AbstractTypeValue:
        base = (
            NONE_TYPE if value is None else self.engine._value_rules._proper_instance(type(value))
        )
        return AbstractTypeValue.from_type(base, literal_values=frozenset((value,)))

    @staticmethod
    def _literal_expected_values(expected: ProperType) -> frozenset[object] | None:
        if isinstance(expected, LiteralType):
            return frozenset((expected.value,))
        if isinstance(expected, UnionType):
            values: set[object] = set()
            saw_literal = False
            for item in expected.items:
                if isinstance(item, LiteralType):
                    values.add(item.value)
                    saw_literal = True
                elif isinstance(item, NoneType):
                    values.add(None)
                else:
                    # A non-literal alternative may accept values that are not
                    # represented by the literal subset.
                    return None
            return frozenset(values) if saw_literal else None
        return None

    @staticmethod
    def _fresh_collection_context(node):
        func_node = getattr(
            node,
            "_function_node",
            node if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else None,
        )
        params = set()
        assigned_fresh = set()
        if func_node is not None:
            params = {
                arg.arg
                for arg in getattr(func_node.args, "args", [])
                + getattr(func_node.args, "posonlyargs", [])
                + getattr(func_node.args, "kwonlyargs", [])
            }

        def fresh(expression):
            if isinstance(
                expression, (ast.List, ast.Set, ast.Dict, ast.ListComp, ast.SetComp, ast.DictComp)
            ):
                return True
            if (
                isinstance(expression, ast.Call)
                and isinstance(expression.func, ast.Name)
                and expression.func.id in {"list", "set", "dict", "frozenset", "tuple"}
            ):
                return True
            if (
                isinstance(expression, ast.BinOp)
                and isinstance(expression.op, (ast.Add, ast.Mult))
                and (fresh(expression.left) or fresh(expression.right))
            ):
                return True
            if (
                isinstance(expression, ast.IfExp)
                and fresh(expression.body)
                and fresh(expression.orelse)
            ):
                return True
            if isinstance(expression, ast.Name) and func_node is not None:
                return expression.id in assigned_fresh and expression.id not in params
            return False

        if func_node is not None:
            for stmt in getattr(func_node, "body", ()):
                if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                    val = stmt.value
                    if val is not None and fresh(val):
                        targets = [stmt.target] if isinstance(stmt, ast.AnnAssign) else stmt.targets
                        for t in targets:
                            if isinstance(t, ast.Name) and t.id not in params:
                                assigned_fresh.add(t.id)

        # Call arguments and other bare expressions are checked against the
        # argument node itself rather than an enclosing statement.
        if fresh(node):
            return True
        if isinstance(node, (ast.Return, ast.AnnAssign, ast.Assign)):
            return fresh(node.value)
        if func_node is None:
            return False
        returns = []

        def collect(statement):
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                return
            if isinstance(statement, ast.Return):
                returns.append(statement.value)
            for child in ast.iter_child_nodes(statement):
                collect(child)

        for statement in func_node.body:
            collect(statement)
        return bool(returns) and all(
            fresh(value)
            or value is None
            or (isinstance(value, ast.Constant) and value.value is None)
            for value in returns
        )

    @staticmethod
    def _call_argument_node(node, function, name):
        if not isinstance(node, ast.Call):
            return None
        arguments = function.node.args
        positional = [*arguments.posonlyargs, *arguments.args]
        if function.owner is not None and function.method_kind != "static" and positional:
            # The receiver is already bound and is not present in node.args.
            positional = positional[1:]
        if name in {argument.arg for argument in positional}:
            index = next(i for i, argument in enumerate(positional) if argument.arg == name)
            return node.args[index] if index < len(node.args) else None
        return next(
            (keyword.value for keyword in node.keywords if keyword.arg == name),
            None,
        )
