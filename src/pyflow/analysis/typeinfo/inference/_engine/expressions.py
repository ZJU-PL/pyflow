"""Evaluate expressions and expand positional and keyword arguments."""

from __future__ import annotations

import ast
import collections.abc as cabc
from dataclasses import replace
from typing import Iterable, cast

from pyflow.analysis.typeinfo.core.typesystem import ANY, NEVER, NONE_TYPE, TupleType, TypeType
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import (
    _FunctionInfo,
    _all_arguments,
    _expression_name,
)
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue, join_all
from pyflow.analysis.typeinfo.resolution.annotations import (
    BuiltinTypeLookup,
    TypeLookup,
    resolve_annotation,
)


class ExpressionInference(InferenceComponent):
    """Evaluate expressions and expand positional and keyword arguments."""

    def _evaluate_expression(
        self,
        node: ast.expr,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        value: AbstractTypeValue
        if isinstance(node, ast.Constant):
            base = (
                NONE_TYPE
                if node.value is None
                else self.engine._value_rules._proper_instance(type(node.value))
            )
            value = AbstractTypeValue.from_type(base, literal_values=frozenset((node.value,)))
        elif isinstance(node, ast.Name):
            value = self.engine._member_rules._name_value(node.id, environment, scope)
        elif isinstance(node, ast.List):
            evaluated = [
                self._evaluate_expression(
                    item, environment, scope=scope, current_function=current_function
                )
                for item in node.elts
            ]
            element = self.engine._value_rules._join_many_values(evaluated)
            value = (
                element
                if self.engine._value_rules._is_never_value(element)
                else self.engine._value_rules._instance(
                    list,
                    NEVER if not node.elts else (element.runtime_type() or ANY),
                )
            )
            shapes = {shape for item in evaluated for shape in (item.dict_shapes or ())}
            if shapes:
                value = replace(value, element_dict_shapes=frozenset(shapes))
        elif isinstance(node, ast.Set):
            element = self._evaluate_many(node.elts, environment, scope, current_function)
            value = (
                element
                if self.engine._value_rules._is_never_value(element)
                else self.engine._value_rules._instance(set, element.runtime_type() or ANY)
            )
        elif isinstance(node, ast.Tuple):
            evaluated = [
                self._evaluate_expression(
                    item,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
                for item in node.elts
            ]
            if any(self.engine._value_rules._is_never_value(item) for item in evaluated):
                value = AbstractTypeValue.from_type(NEVER)
            else:
                value = AbstractTypeValue.from_type(
                    TupleType(tuple(item.runtime_type() or ANY for item in evaluated))
                )
        elif isinstance(node, ast.Dict):
            evaluated_keys = [
                (
                    None
                    if item is None
                    else self._evaluate_expression(
                        item, environment, scope=scope, current_function=current_function
                    )
                )
                for item in node.keys
            ]
            evaluated_values = [
                self._evaluate_expression(
                    item, environment, scope=scope, current_function=current_function
                )
                for item in node.values
            ]
            key_parts: list[AbstractTypeValue] = []
            value_parts: list[AbstractTypeValue] = []
            for key_node, key_value, item_value in zip(node.keys, evaluated_keys, evaluated_values):
                if key_node is None:
                    mapping_key, mapping_value = self.engine._value_rules._mapping_key_value(
                        item_value
                    )
                    key_parts.append(mapping_key)
                    value_parts.append(mapping_value)
                else:
                    assert key_value is not None
                    key_parts.append(self.engine._value_rules._dict_key_value(key_value))
                    value_parts.append(item_value)
            keys = join_all(key_parts, self.engine.type_system)
            values = join_all(value_parts, self.engine.type_system)
            if not node.keys:
                value = self.engine._value_rules._instance(dict, NEVER, NEVER)
            elif self.engine._value_rules._is_never_value(
                keys
            ) or self.engine._value_rules._is_never_value(values):
                value = AbstractTypeValue.from_type(NEVER)
            else:
                value = self.engine._value_rules._instance(
                    dict,
                    keys.runtime_type() or ANY,
                    values.runtime_type() or ANY,
                )
                if all(
                    isinstance(key, ast.Constant) and isinstance(key.value, str)
                    for key in node.keys
                ):
                    fields = {
                        key.value: item.runtime_type() or ANY
                        for key, item in zip(node.keys, evaluated_values)
                    }
                    value = replace(
                        value,
                        dict_shapes=frozenset((tuple(sorted(fields.items())),)),
                    )
        elif isinstance(node, ast.BinOp):
            left = self._evaluate_expression(
                node.left, environment, scope=scope, current_function=current_function
            )
            right = self._evaluate_expression(
                node.right, environment, scope=scope, current_function=current_function
            )
            value = (
                AbstractTypeValue.from_type(NEVER)
                if self.engine._value_rules._is_never_value(left)
                or self.engine._value_rules._is_never_value(right)
                else (
                    self.engine._operator_rules._type_union_value(left, right)
                    if isinstance(node.op, ast.BitOr)
                    else None
                )
                or self.engine._operator_rules._operator_result(
                    node,
                    left,
                    right,
                    self.engine._operator_rules._binary_protocol_names(node.op),
                    environment,
                )
                or self.engine._operator_rules._binary_result(left, right, node.op)
            )
            if isinstance(node.op, ast.Mod):
                self.engine._operator_rules._check_percent_format(node, left, right)
        elif isinstance(node, ast.UnaryOp):
            operand = self._evaluate_expression(
                node.operand,
                environment,
                scope=scope,
                current_function=current_function,
            )
            if self.engine._value_rules._is_never_value(operand):
                value = operand
            elif isinstance(node.op, ast.Not):
                value = self.engine._value_rules._instance(bool)
            else:
                unary_methods = {
                    ast.UAdd: "__pos__",
                    ast.USub: "__neg__",
                    ast.Invert: "__invert__",
                }
                method = next(
                    (name for kind, name in unary_methods.items() if isinstance(node.op, kind)),
                    None,
                )
                value = (
                    self.engine._operator_rules._operator_result(
                        node,
                        operand,
                        None,
                        (method, None),
                        environment,
                    )
                    if method is not None
                    else None
                )
                if isinstance(
                    node.op, (ast.UAdd, ast.USub, ast.Invert)
                ) and self.engine._operator_rules._all_bool_values(operand):
                    value = self.engine._value_rules._instance(int)
                elif value is None:
                    value = operand
                if isinstance(node.op, (ast.UAdd, ast.USub)) and value is not None:
                    # ``-IntFlag.X`` is a plain int (``~X`` keeps the flag).
                    value = self.engine._operator_rules._project_scalar_subclass(value)
                if isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)) and operand.literal_values:
                    transformed: set[object] = set()
                    for literal in operand.literal_values:
                        try:
                            if isinstance(node.op, ast.UAdd):
                                transformed.add(+literal)  # type: ignore[operator]
                            elif isinstance(node.op, ast.USub):
                                transformed.add(-literal)  # type: ignore[operator]
                            else:
                                transformed.add(~literal)  # type: ignore[operator]
                        except TypeError:
                            transformed.clear()
                            break
                    if transformed:
                        base = value.public_type() or operand.public_type() or ANY
                        value = AbstractTypeValue.from_type(
                            base, literal_values=frozenset(transformed)
                        )
        elif isinstance(node, ast.Compare):
            value = self.engine._operator_rules._comparison_result(
                node,
                environment,
                scope,
                current_function,
            )
        elif isinstance(node, ast.BoolOp):
            contributions = []
            branch = environment
            for position, item in enumerate(node.values):
                before_keys = set(branch)
                operand = self._evaluate_expression(
                    item, branch, scope=scope, current_function=current_function
                )
                for k in list(branch.keys()):
                    if k not in before_keys or branch[k] != environment.get(k):
                        environment[k] = branch[k]
                if self.engine._value_rules._is_never_value(operand):
                    contributions.append(operand)
                    break
                # A non-final operand of ``or`` contributes only when truthy.
                # In particular, Optional[T] or [] cannot return None.
                contribution = (
                    self.engine._value_rules._remove_none(operand)
                    if isinstance(node.op, ast.Or) and position < len(node.values) - 1
                    else operand
                )
                if not contribution.is_bottom:
                    contributions.append(contribution)
                branch = self.engine._narrowing_rules._narrow_environment(
                    item, branch, truthy=isinstance(node.op, ast.And)
                )
            value = self.engine._value_rules._join_normal_results(contributions)
        elif isinstance(node, ast.IfExp):
            test = self._evaluate_expression(
                node.test, environment, scope=scope, current_function=current_function
            )
            if self.engine._value_rules._is_never_value(test):
                value = test
            else:
                left = self._evaluate_expression(
                    node.body,
                    self.engine._narrowing_rules._narrow_environment(
                        node.test, environment, truthy=True
                    ),
                    scope=scope,
                    current_function=current_function,
                )
                right = self._evaluate_expression(
                    node.orelse,
                    self.engine._narrowing_rules._narrow_environment(
                        node.test, environment, truthy=False
                    ),
                    scope=scope,
                    current_function=current_function,
                )
                value = self.engine._value_rules._join_normal_results((left, right))
        elif isinstance(node, ast.Call):
            value = self.engine._call_rules._evaluate_call(
                node, environment, scope, current_function
            )
        elif isinstance(node, ast.Attribute):
            qualified = _expression_name(node)
            root = qualified.split(".", 1)[0] if qualified is not None else None
            external_value: AbstractTypeValue | None = None
            if qualified is not None and root is not None and root not in environment:
                imported = self.engine._value_rules._resolve_import_name(qualified)
                if imported is not None and root in self.engine._imports:
                    external = self.engine._member_rules._external_member_type(imported)
                    builtin_class = False
                    if external is None and "." in imported:
                        # Stdlib class members are resolved without importing
                        # analysed code (``datetime.date``, ``uuid.UUID``).
                        # Without this, ``[datetime.date]`` degraded to
                        # ``list[Any]`` even though ``x = datetime.date`` was
                        # handled by the type-alias path.
                        external = BuiltinTypeLookup()(imported)
                        builtin_class = external is not None
                    if external is not None:
                        if isinstance(external, TypeType):
                            external = external.item
                        external_value = AbstractTypeValue.from_type(
                            external,
                            class_target=self.engine._member_rules._external_class_target(
                                external,
                                imported.rsplit(".", 1)[-1],
                                builtin_class=builtin_class,
                            ),
                        )
                    if external_value is None:
                        external_value = self.engine._stdlib_rules._stdlib_global_value(imported)
            if external_value is not None:
                value = external_value
            else:
                base = self._evaluate_expression(
                    node.value,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
                value = environment.get(ast.unparse(node))
                if value is None:
                    if self.engine._value_rules._is_never_value(base):
                        value = base
                    else:
                        value = self.engine._member_rules._attribute_value(base, node.attr)
        elif isinstance(node, ast.Slice):
            self._evaluate_many(
                [value for value in (node.lower, node.upper, node.step) if value is not None],
                environment,
                scope,
                current_function,
            )
            value = self.engine._value_rules._instance(slice)
        elif isinstance(node, ast.Starred):
            inner = self._evaluate_expression(
                node.value, environment, scope=scope, current_function=current_function
            )
            value = self.engine._value_rules._iterable_element(inner)
        elif isinstance(node, ast.Subscript):
            base = self._evaluate_expression(
                node.value,
                environment,
                scope=scope,
                current_function=current_function,
            )
            index = self._evaluate_expression(
                node.slice,
                environment,
                scope=scope,
                current_function=current_function,
            )
            value = (
                AbstractTypeValue.from_type(NEVER)
                if self.engine._value_rules._is_never_value(base)
                or self.engine._value_rules._is_never_value(index)
                else environment.get(
                    ast.unparse(node),
                    self.engine._value_rules._subscript_value(base, node.slice, index_value=index),
                )
            )
            if (
                not base.types
                and base.unknown
                and value.unknown
                and isinstance(node.slice, (ast.Slice, ast.Tuple))
                and not self.engine._value_rules._is_typing_special_form(node.value)
            ):
                self.engine._add_diagnostic(
                    "unsupported-expression",
                    f"No type model for {type(node).__name__} of an unknown value",
                    node=node,
                    affects_completeness=True,
                )
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            local_env = self.engine._flow_rules._comprehension_environment(
                node.generators, environment, scope, current_function
            )
            element = self._evaluate_expression(
                node.elt,
                local_env,
                scope=scope,
                current_function=current_function,
            )
            self.engine._flow_rules._propagate_comprehension_walrus(
                node, local_env, environment, current_function
            )
            if isinstance(node, ast.GeneratorExp):
                value = self.engine._value_rules._instance(
                    cabc.Generator,
                    element.public_type() or ANY,
                    NONE_TYPE,
                    NONE_TYPE,
                )
            else:
                raw = set if isinstance(node, ast.SetComp) else list
                value = self.engine._value_rules._instance(raw, element.public_type() or ANY)
                if element.dict_shapes:
                    value = replace(value, element_dict_shapes=frozenset(element.dict_shapes))
        elif isinstance(node, ast.DictComp):
            local_env = self.engine._flow_rules._comprehension_environment(
                node.generators, environment, scope, current_function
            )
            key = self._evaluate_expression(
                node.key, local_env, scope=scope, current_function=current_function
            )
            item = self._evaluate_expression(
                node.value, local_env, scope=scope, current_function=current_function
            )
            self.engine._flow_rules._propagate_comprehension_walrus(
                node, local_env, environment, current_function
            )
            value = self.engine._value_rules._instance(
                dict, key.public_type() or ANY, item.public_type() or ANY
            )
        elif isinstance(node, ast.Lambda):
            qualified = f"{scope}.<lambda@{node.lineno}:{node.col_offset}>"
            info = self.engine._functions.get(qualified)
            if info is None:
                parameters = [arg.arg for arg in _all_arguments(node.args)]
                info = _FunctionInfo(qualified, node, parameters)
                positional = [*node.args.posonlyargs, *node.args.args]
                for argument, default in zip(
                    positional[-len(node.args.defaults) :], node.args.defaults
                ):
                    info.default_parameters[argument.arg] = default
                for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                    if default is not None:
                        info.default_parameters[argument.arg] = default
                self.engine._functions[qualified] = info
            value = self.engine._function_rules._function_value(info)
        elif isinstance(node, ast.NamedExpr):
            value = self._evaluate_expression(
                node.value,
                environment,
                scope=scope,
                current_function=current_function,
            )
            self.engine._flow_rules._assign_target(
                node.target, value, environment, current_function
            )
        elif isinstance(node, ast.Await):
            awaited = self._evaluate_expression(
                node.value,
                environment,
                scope=scope,
                current_function=current_function,
            )
            value = (
                awaited
                if self.engine._value_rules._is_never_value(awaited)
                else self.engine._value_rules._unwrap_single_generic(awaited)
            )
        elif isinstance(node, (ast.Yield, ast.YieldFrom)):
            yielded = (
                AbstractTypeValue.from_type(NONE_TYPE)
                if node.value is None
                else self._evaluate_expression(
                    node.value,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
            )
            if isinstance(node, ast.YieldFrom):
                yielded = self.engine._value_rules._iterable_element(yielded)
            self.engine._observed_yields.append(yielded)
            # The value of a yield expression is the value sent by the caller,
            # not the yielded object.
            value = AbstractTypeValue.unresolved()
        elif isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    self._evaluate_expression(
                        part.value, environment, scope=scope, current_function=current_function
                    )
                    if part.format_spec is not None:
                        self._evaluate_expression(
                            part.format_spec,
                            environment,
                            scope=scope,
                            current_function=current_function,
                        )
                else:
                    self._evaluate_expression(
                        part, environment, scope=scope, current_function=current_function
                    )
            value = self.engine._value_rules._instance(str)
        else:
            value = AbstractTypeValue.unresolved()
            self.engine._add_diagnostic(
                "unsupported-expression",
                f"No type model for {type(node).__name__}",
                node=node,
                affects_completeness=True,
            )

        self.engine._record_expression(node, value)
        return value

    def _star_expansion(
        self,
        node: ast.Starred,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> list[AbstractTypeValue] | None:
        """Expand a starred call argument when its arity is statically known."""
        if isinstance(node.value, (ast.List, ast.Tuple)):
            return [
                self._evaluate_expression(
                    item,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
                for item in node.value.elts
                if not isinstance(item, ast.Starred)
            ]
        value = self._evaluate_expression(
            node.value,
            environment,
            scope=scope,
            current_function=current_function,
        )
        parts = self.engine._operator_rules._flatten_union_parts(value)
        if len(parts) == 1 and isinstance(parts[0], TupleType) and not parts[0].unknown_size:
            return [AbstractTypeValue.from_type(item) for item in parts[0].args]
        return None

    def _keyword_expansion(
        self,
        mapping: AbstractTypeValue,
    ) -> dict[str, AbstractTypeValue] | None:
        """Expand a ``**mapping`` when its string-key layout is known."""
        shapes = mapping.dict_shapes
        if not shapes or len(shapes) != 1:
            return None
        expanded: dict[str, AbstractTypeValue] = {}
        for key, value in next(iter(shapes)):
            if not isinstance(key, str):
                return None
            expanded[key] = AbstractTypeValue.from_type(value)
        return expanded

    def _evaluate_many(
        self,
        nodes: Iterable[ast.expr],
        environment: dict[str, AbstractTypeValue],
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        values = [
            self._evaluate_expression(
                node,
                environment,
                scope=scope,
                current_function=current_function,
            )
            for node in nodes
        ]
        if any(self.engine._value_rules._is_never_value(value) for value in values):
            return AbstractTypeValue.from_type(NEVER)
        return join_all(
            values,
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )

    def _evaluate_type_expression(self, node: ast.expr) -> AbstractTypeValue:
        if isinstance(node, ast.Tuple):
            return join_all(
                (self._evaluate_type_expression(item) for item in node.elts),
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
        try:
            annotation = ast.unparse(node)
        except Exception:
            return AbstractTypeValue.unresolved()
        return AbstractTypeValue.from_type(
            resolve_annotation(
                annotation,
                cast(TypeLookup, self.engine._declaration_rules._lookup_annotation_type),
                aliases=self.engine._declaration_rules._annotation_aliases(),
                type_parameters={
                    name: tuple(parameters)
                    for name, parameters in self.engine._alias_type_variables.items()
                },
            )
        )
