"""Analyze function bodies, recursion, summaries, and decorators."""

from __future__ import annotations

import ast
import collections.abc as cabc
import contextlib
from typing import Iterable

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NEVER,
    NONE_TYPE,
    CallableType,
    Instance,
    ProperType,
    TupleType,
    TypeType,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import (
    _ClassInfo,
    _FunctionInfo,
    _SpecializationKey,
    _all_arguments,
    _expression_name,
)
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue, join_all
from pyflow.analysis.typeinfo.inference.models import FunctionSpecialization, FunctionSummary
from pyflow.analysis.typeinfo.resolution.typing_syntax import substitute_type_vars


class FunctionInference(InferenceComponent):
    """Analyze function bodies, recursion, summaries, and decorators."""

    def _analyse_function(self, function: _FunctionInfo) -> None:
        for key in sorted(
            function.specializations,
            key=self._specialization_key_fingerprint,
        ):
            previous = function.specializations[key]
            function.specializations[key] = self._analyse_function_context(
                function,
                dict(previous.parameters),
                widened=key.widened,
                collect_specializations=True,
            )

        fallback_parameters = self._fallback_parameters(function)
        fallback = self._analyse_function_context(
            function,
            fallback_parameters,
            collect_specializations=False,
        )
        ordered_specializations = tuple(
            function.specializations[key]
            for key in sorted(
                function.specializations,
                key=self._specialization_key_fingerprint,
            )
        )
        summary_return = (
            function.effective_return
            if function.effective_return is not None
            else fallback.return_value
        )
        if (
            function.effective_return is None
            and function.summary is not None
            and self._is_recursive_function(function)
        ):
            # Recursive summaries must be monotone across fixed-point
            # iterations.  Otherwise a branch that consumes the function's own
            # previous summary can alternate between a narrow and a widened
            # result and never converge (ansible.playbook.role).
            summary_return = self.engine._value_rules._join(
                summary_return, function.summary.return_value
            )
        overload_signatures: list[CallableType] = []
        for overload in function.overloads:
            signature = self._function_value(overload).public_type()
            if isinstance(signature, CallableType):
                overload_signatures.append(signature)
        function.summary = FunctionSummary(
            qualified_name=function.qualified_name,
            parameters=fallback.parameter_map,
            return_value=summary_return,
            yield_value=fallback.yield_value,
            return_dependencies=self.engine._call_rules._return_dependencies(function),
            is_async=isinstance(function.node, ast.AsyncFunctionDef),
            is_generator=function.is_generator_source or not fallback.yield_value.is_bottom,
            method_kind=function.method_kind,
            declared_return=function.explicit_return is not None,
            specializations=ordered_specializations,
            overloads=tuple(overload_signatures),
        )

    def _refresh_mutual_recursion(self) -> None:
        """Mark functions that participate in any recursion cycle."""
        if self.engine._recursion_graph_size == len(self.engine._functions):
            return
        graph: dict[str, set[str]] = {}
        for name, info in self.engine._functions.items():
            callees: set[str] = set()
            for node in ast.walk(info.node):
                if not isinstance(node, ast.Call):
                    continue
                callee = _expression_name(node.func)
                if callee is None:
                    continue
                # ``self.method(...)`` / ``cls.method(...)``
                if isinstance(node.func, ast.Attribute) and info.owner is not None:
                    method = self.engine._member_rules._class_method(info.owner, node.func.attr)
                    if method is not None and method != name:
                        callees.add(method)
                    continue
                target = self.engine._value_rules._resolve_lexical_function(
                    callee, info.qualified_name
                )
                if target is not None and target != name:
                    callees.add(target)
            graph[name] = callees
        for start, callees in graph.items():
            stack = list(callees)
            seen: set[str] = set()
            while stack:
                current = stack.pop()
                if current == start:
                    self.engine._mutual_recursion.add(start)
                    break
                if current in seen:
                    continue
                seen.add(current)
                stack.extend(graph.get(current, ()))
        self.engine._recursion_graph_size = len(self.engine._functions)

    def _is_recursive_function(self, function: _FunctionInfo) -> bool:
        if function.qualified_name in self.engine._mutual_recursion:
            return True
        cached = self.engine._recursive_functions.get(function.qualified_name)
        if cached is not None:
            return cached
        short_name = getattr(function.node, "name", "")
        recursive = False
        if short_name:
            for node in ast.walk(function.node):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                if isinstance(target, ast.Name) and target.id == short_name:
                    recursive = True
                    break
                if isinstance(target, ast.Attribute) and target.attr == short_name:
                    recursive = True
                    break
        self.engine._recursive_functions[function.qualified_name] = recursive
        return recursive

    def _fallback_parameters(self, function: _FunctionInfo) -> dict[str, AbstractTypeValue]:
        parameters: dict[str, AbstractTypeValue] = {}
        for index, name in enumerate(function.parameter_names):
            explicit = function.explicit_parameters.get(name)
            if explicit is not None and not explicit.unknown:
                parameters[name] = self._body_parameter_value(function, name, explicit)
                continue
            evidence = function.parameter_evidence.get(name, AbstractTypeValue.bottom())
            pending = self.engine._pending_parameter_evidence.get(
                (function.qualified_name, name), AbstractTypeValue.bottom()
            )
            combined = self.engine._value_rules._join(evidence, pending)
            if not combined.is_bottom:
                parameters[name] = combined
            elif function.owner is not None and function.method_kind != "static" and index == 0:
                parameters[name] = AbstractTypeValue.from_type(
                    self.engine._classes[function.owner].instance,
                    class_target=function.owner if function.method_kind == "class" else None,
                )
            else:
                default = function.default_parameters.get(name)
                if default is not None:
                    parameters[name] = self.engine._expression_rules._evaluate_expression(
                        default,
                        self.engine._module_environment,
                        scope=function.qualified_name,
                        current_function=None,
                    )
                else:
                    parameters[name] = function.documented_parameters.get(
                        name, AbstractTypeValue.unresolved()
                    )
        return parameters

    def _body_parameter_value(
        self,
        function: _FunctionInfo,
        name: str,
        value: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Project a parameter annotation to the object visible in the body.

        ``*args: T`` binds a tuple of ``T`` and ``**kwargs: T`` binds a
        ``dict[str, T]``.  Call signatures keep the element type, but body
        analysis must see the container.
        """
        arguments = function.node.args
        if arguments.vararg is not None and arguments.vararg.arg == name:
            annotation = arguments.vararg.annotation
            if isinstance(annotation, ast.Attribute) and annotation.attr == "args":
                # ParamSpec.args already describes the whole positional
                # argument tuple; wrapping it again produces
                # tuple[tuple[...], ...] and corrupts forwarded calls.
                return AbstractTypeValue.from_type(TupleType((ANY,), unknown_size=True))
            if any(
                isinstance(typ, TupleType)
                or (isinstance(typ, Instance) and typ.type.raw_type is tuple)
                for typ in value.types
            ):
                return value
            return AbstractTypeValue.from_type(
                TupleType((value.public_type() or ANY,), unknown_size=True)
            )
        if arguments.kwarg is not None and arguments.kwarg.arg == name:
            annotation = arguments.kwarg.annotation
            if isinstance(annotation, ast.Attribute) and annotation.attr == "kwargs":
                return self.engine._value_rules._instance(
                    dict, self.engine._value_rules._proper_instance(str), ANY
                )
            if any(isinstance(typ, Instance) and typ.type.raw_type is dict for typ in value.types):
                return value
            return self.engine._value_rules._instance(
                dict, self.engine._value_rules._proper_instance(str), value.public_type() or ANY
            )
        return value

    @staticmethod
    def _contains_yield(node: ast.AST) -> bool:
        stack: list[tuple[ast.AST, bool]] = [(node, True)]
        while stack:
            child, root = stack.pop()
            if not root and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                continue
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                return True
            stack.extend((item, False) for item in ast.iter_child_nodes(child))
        return False

    def _interface_stub(self, function):
        node = function.node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        marked = any(
            (
                self.engine._value_rules._qualified_callee_name(
                    item.func if isinstance(item, ast.Call) else item
                )
                or ""
            )
            in {
                "abc.abstractmethod",
                "abstractmethod",
                "typing.overload",
                "typing_extensions.overload",
                "overload",
            }
            for item in node.decorator_list
        )
        owner = self.engine._classes.get(function.owner)
        marked = marked or bool(
            owner
            and any(
                base in {"typing.Protocol", "typing_extensions.Protocol", "Protocol"}
                for base in owner.bases
            )
        )

        def empty(statement):
            if isinstance(statement, ast.Pass):
                return True
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                return statement.value.value is Ellipsis or isinstance(statement.value.value, str)
            if isinstance(statement, ast.Raise):
                value = statement.exc.func if isinstance(statement.exc, ast.Call) else statement.exc
                return isinstance(value, ast.Name) and value.id == "NotImplementedError"
            return False

        has_ellipsis = any(
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is Ellipsis
            for statement in node.body
        )
        is_stub_file = bool(getattr(self, "_filename", "").endswith(".pyi"))
        has_docstring_only = bool(
            node.body
            and all(
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
                for statement in node.body
            )
        )
        # An ellipsis body is the conventional in-source stub form.  It is
        # common outside protocols and overloads (generic classes, interfaces
        # awaiting implementation), and must not be treated as ``return None``.
        return all(empty(statement) for statement in node.body) and (
            marked or has_ellipsis or is_stub_file or has_docstring_only
        )

    def _class_is_metaclass(self, class_info: _ClassInfo) -> bool:
        return any(
            base.rsplit(".", 1)[-1] in {"type", "ABCMeta"} for base in class_info.bases
        ) or any(
            method in class_info.methods for method in {"__subclasscheck__", "__instancecheck__"}
        )

    def _analyse_function_context(
        self,
        function: _FunctionInfo,
        parameters: dict[str, AbstractTypeValue],
        *,
        widened: bool = False,
        collect_specializations: bool,
    ) -> FunctionSpecialization:
        environment: dict[str, AbstractTypeValue] = {}
        environment.update(function.closure_evidence)
        substitutions = self.engine._call_rules._generic_substitutions(function, parameters)
        input_parameters: dict[str, AbstractTypeValue] = {}
        for name in function.parameter_names:
            actual = parameters.get(name)
            if actual is None:
                default = function.default_parameters.get(name)
                if default is not None:
                    actual = self.engine._expression_rules._evaluate_expression(
                        default,
                        self.engine._module_environment,
                        scope=function.qualified_name,
                        current_function=None,
                    )
                else:
                    actual = AbstractTypeValue.unresolved()
            explicit = function.explicit_parameters.get(name)
            if explicit is not None:
                explicit_type = explicit.public_type()
                if explicit_type is not None and substitutions:
                    explicit_type = substitute_type_vars(explicit_type, substitutions)
                types = frozenset(() if explicit_type is None else (explicit_type,))
                unknown = explicit.unknown
                if unknown:
                    # A partially unresolved annotation is still useful evidence.
                    # Keep its known alternatives and the default/call-site
                    # evidence, but never let the default replace the annotation.
                    is_vararg = bool(
                        function.node.args.vararg and function.node.args.vararg.arg == name
                    )
                    is_kwarg = bool(
                        function.node.args.kwarg and function.node.args.kwarg.arg == name
                    )
                    if is_vararg:
                        elem_types = self.engine._value_rules._iterable_element(actual).types
                        types = frozenset(set(types) | set(elem_types))
                    elif is_kwarg:
                        kw_val_types = set()
                        for typ in actual.types:
                            if isinstance(typ, Instance) and len(typ.args) > 1:
                                kw_val_types.add(typ.args[1])
                        types = frozenset(set(types) | kw_val_types)
                    else:
                        types = frozenset(set(types) | set(actual.types))
                    unknown = True
                value = AbstractTypeValue(
                    types=types,
                    unknown=unknown,
                    callable_targets=actual.callable_targets,
                    class_targets=actual.class_targets,
                )
                value = self._body_parameter_value(function, name, value)
            else:
                # Call-site evidence already binds *args/**kwargs to their
                # container shape; wrapping it again would double the element.
                value = actual
            if (
                function.parameter_names.index(name) == 0
                and function.owner is not None
                and function.method_kind != "static"
                and self._class_is_metaclass(self.engine._classes[function.owner])
            ):
                value = AbstractTypeValue.from_type(
                    TypeType(self.engine._value_rules._proper_instance(object))
                )
            environment[name] = value
            input_parameters[name] = value
            for argument in (
                *function.node.args.posonlyargs,
                *function.node.args.args,
                *function.node.args.kwonlyargs,
            ):
                if argument.arg == name:
                    self.engine._record_expression(argument, value)
                    break

        node = function.node
        previous_mode = self.engine._collect_specializations
        previous_vars = self.engine._type_vars
        previous_owner = self.engine._annotation_owner
        previous_substitutions = self.engine._annotation_substitutions
        previous_current_function = self.engine._current_function_info
        self.engine._annotation_substitutions = substitutions
        self.engine._current_function_info = function
        self.engine._type_vars = {**previous_vars, **function.type_variables}
        self.engine._annotation_owner = function.owner
        self.engine._collect_specializations = collect_specializations
        self.engine._observed_yields = []
        interface_stub = self._interface_stub(function)
        try:
            if isinstance(node, ast.Lambda):
                return_value = self.engine._expression_rules._evaluate_expression(
                    node.body,
                    environment,
                    scope=function.qualified_name,
                    current_function=function,
                )
                yields = AbstractTypeValue.bottom()
            else:
                outcome = self.engine._flow_rules._execute_block(
                    node.body,
                    environment,
                    scope=function.qualified_name,
                    current_function=function,
                )
                body_environment = outcome.environment
                returns = list(outcome.returns)
                if not outcome.terminated:
                    # An abstract/protocol/stub body (``...``) carries no
                    # runtime return value.  Treating it as ``None`` makes
                    # callers appear to return None and produces bogus
                    # annotation mismatches; leave the result unknown instead.
                    if not interface_stub:
                        returns.append(AbstractTypeValue.from_type(NONE_TYPE))
                elif not returns:
                    returns.append(AbstractTypeValue.from_type(NEVER))
                return_value = join_all(
                    returns,
                    self.engine.type_system,
                    max_union_size=self.engine.options.max_union_size,
                )
                yields = join_all(
                    [*outcome.yields, *self.engine._observed_yields],
                    self.engine.type_system,
                    max_union_size=self.engine.options.max_union_size,
                )
        finally:
            self.engine._collect_specializations = previous_mode
            self.engine._type_vars = previous_vars
            self.engine._annotation_owner = previous_owner
            self.engine._annotation_substitutions = previous_substitutions
            self.engine._current_function_info = previous_current_function

        if function.explicit_return is not None:
            explicit_return = function.explicit_return
            returned_type = explicit_return.public_type()
            if returned_type is not None and substitutions:
                explicit_return = AbstractTypeValue.from_type(
                    substitute_type_vars(returned_type, substitutions)
                )
            if interface_stub:
                return_value = explicit_return
            elif function.is_generator_source and yields.is_bottom:
                # A path-insensitive pass may miss a yield inside a branch or
                # loop.  The syntax still makes the function a generator.
                return_value = explicit_return
            elif not yields.is_bottom:
                self._check_generator_annotation(function, explicit_return, yields, return_value)
                # Callers receive the generator object described by the
                # annotation; the element type lives in ``yield_value``.
                return_value = explicit_return
            else:
                if not self.engine._compatibility_rules._is_substituted_type_variable_annotation(
                    function.node.returns, explicit_return, function.type_variables
                ):
                    # A bare type variable is a placeholder.  Checking it
                    # against one concrete specialization reports spurious
                    # mismatches in generic base-class methods.
                    self.engine._compatibility_rules._check_annotation_compatibility(
                        return_value,
                        explicit_return,
                        self._return_check_node(function.node),
                        context=f"return of {function.qualified_name}",
                    )
                return_value = explicit_return
        elif (
            return_value.unknown
            and not return_value.types
            and function.documented_return is not None
        ):
            # Documentation supplies a fallback; concrete body/call evidence
            # and explicit annotations take precedence over it.
            return_value = function.documented_return

        mutated_parameters: list[tuple[str, AbstractTypeValue]] = []
        if not isinstance(node, ast.Lambda):
            for name in function.parameter_names:
                original = input_parameters[name]
                final = body_environment.get(name, original)
                if self.engine._value_rules._is_widened_container(original, final):
                    mutated_parameters.append((name, final))
        return FunctionSpecialization(
            parameters=tuple((name, input_parameters[name]) for name in function.parameter_names),
            return_value=self.engine._value_rules._bound_type_depth(return_value),
            yield_value=self.engine._value_rules._bound_type_depth(yields),
            widened=widened,
            mutated_parameters=tuple(mutated_parameters),
        )

    @staticmethod
    def _return_check_node(node: ast.AST) -> ast.AST:
        returns: list[ast.Return] = []

        def walk(statements: Iterable[ast.stmt]) -> None:
            for statement in statements:
                if isinstance(
                    statement,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
                ):
                    continue
                if isinstance(statement, ast.Return):
                    returns.append(statement)
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.stmt):
                        walk((child,))

        walk(getattr(node, "body", ()))
        if len(returns) == 1:
            returns[0]._function_node = node
            return returns[0]
        return node

    def _check_generator_annotation(self, function, annotation, yields, returned):
        expected = annotation.public_type()
        asynchronous = isinstance(function.node, ast.AsyncFunctionDef)
        allowed = (
            {cabc.AsyncIterator, cabc.AsyncIterable, cabc.AsyncGenerator}
            if asynchronous
            else {cabc.Iterator, cabc.Iterable, cabc.Generator}
        )
        if isinstance(expected, Instance) and expected.type.raw_type in allowed:
            if expected.args:
                self.engine._compatibility_rules._check_annotation_compatibility(
                    yields,
                    AbstractTypeValue.from_type(expected.args[0]),
                    function.node,
                    context=f"yield of {function.qualified_name}",
                )
            if expected.type.raw_type is cabc.Generator and len(expected.args) == 3:
                self.engine._compatibility_rules._check_annotation_compatibility(
                    returned,
                    AbstractTypeValue.from_type(expected.args[2]),
                    function.node,
                    context=f"generator return of {function.qualified_name}",
                )
        else:
            wrapper = self.engine._value_rules._instance(
                cabc.AsyncIterator if asynchronous else cabc.Iterator, yields.public_type() or ANY
            )
            self.engine._compatibility_rules._check_annotation_compatibility(
                wrapper, annotation, function.node, context=f"return of {function.qualified_name}"
            )

    def _commit_pending_evidence(self) -> None:
        for (target, parameter), value in self.engine._pending_parameter_evidence.items():
            function = self.engine._functions.get(target)
            if function is None or parameter in function.explicit_parameters:
                continue
            old = function.parameter_evidence.get(parameter, AbstractTypeValue.bottom())
            function.parameter_evidence[parameter] = old.join(
                value,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
        for (owner, attribute), value in self.engine._pending_attributes.items():
            if not value.types and not value.callable_targets and not value.class_targets:
                # The attribute exists at runtime even when its value is
                # unknown (``self.data = np.asarray(data)`` with an untyped
                # parameter).  Recording it as ``Any`` keeps the member table
                # complete instead of reporting it as missing.
                value = AbstractTypeValue.from_type(ANY)
            class_info = self.engine._classes[owner]
            old = class_info.attributes.get(attribute, AbstractTypeValue.bottom())
            class_info.attributes[attribute] = old.join(
                value,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
            class_info.instance.type.members[attribute] = (
                class_info.attributes[attribute].public_type() or ANY
            )
            self.engine.type_system.invalidate_subtype_caches()

    def _fingerprint(self) -> tuple[object, ...]:
        functions = tuple(
            (
                name,
                self._environment_fingerprint(info.parameter_evidence),
                self._environment_fingerprint(info.closure_evidence),
                tuple(
                    (
                        key.widened,
                        tuple(
                            (parameter, self._value_fingerprint(value))
                            for parameter, value in key.parameters
                        ),
                        tuple(
                            (parameter, self._value_fingerprint(value))
                            for parameter, value in specialization.parameters
                        ),
                        self._value_fingerprint(specialization.return_value),
                        self._value_fingerprint(specialization.yield_value),
                        tuple(
                            (name, self._value_fingerprint(value))
                            for name, value in specialization.mutated_parameters
                        ),
                    )
                    for key, specialization in sorted(
                        info.specializations.items(),
                        key=lambda item: self._specialization_key_fingerprint(item[0]),
                    )
                ),
                self._environment_fingerprint(info.widened_parameters),
                self._summary_fingerprint(info.summary),
            )
            for name, info in sorted(self.engine._functions.items())
        )
        classes = tuple(
            (name, self._environment_fingerprint(info.attributes))
            for name, info in sorted(self.engine._classes.items())
        )
        return functions, classes

    @staticmethod
    def _value_fingerprint(value: AbstractTypeValue) -> tuple[object, ...]:
        return (
            tuple(sorted(str(typ) for typ in value.types)),
            value.unknown,
            (
                value.sequence_items is not None,
                tuple(
                    FunctionInference._value_fingerprint(item)
                    for item in (value.sequence_items or ())
                ),
            ),
            tuple(sorted(value.callable_targets)),
            tuple(sorted(value.class_targets)),
            (
                value.dict_shapes is not None,
                tuple(
                    sorted(
                        tuple((name, str(typ)) for name, typ in shape)
                        for shape in (value.dict_shapes or ())
                    )
                ),
            ),
        )

    def _environment_fingerprint(
        self, environment: dict[str, AbstractTypeValue]
    ) -> tuple[object, ...]:
        return tuple(
            (name, self._value_fingerprint(value)) for name, value in sorted(environment.items())
        )

    def _specialization_key_fingerprint(self, key: _SpecializationKey) -> tuple[object, ...]:
        return (
            key.widened,
            tuple((name, self._value_fingerprint(value)) for name, value in key.parameters),
        )

    def _summary_fingerprint(self, summary: FunctionSummary | None) -> tuple[object, ...] | None:
        if summary is None:
            return None
        return (
            self._environment_fingerprint(summary.parameters),
            self._value_fingerprint(summary.return_value),
            self._value_fingerprint(summary.yield_value),
            tuple(sorted(summary.return_dependencies)),
            summary.is_async,
            summary.is_generator,
        )

    def _refresh_effective_returns(self) -> None:
        """Recompute decorator results after all class methods are known."""
        for function in self.engine._functions.values():
            decorators = getattr(function.node, "decorator_list", ())
            if not decorators:
                continue
            computed = self._decorator_effective_return(
                function.node,
                function.qualified_name.rpartition(".")[0],
            )
            if computed is not None:
                function.effective_return = computed
            extras = self._decorator_extra_keywords(
                function.node,
                function.qualified_name.rpartition(".")[0],
            )
            if extras:
                function.extra_keywords.update(extras)

    def _decorator_extra_keywords(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        parent: str,
    ) -> dict[str, AbstractTypeValue]:
        """Collect keyword-only parameters added by a decorator wrapper."""
        original = {argument.arg for argument in _all_arguments(node.args)}
        extras: dict[str, AbstractTypeValue] = {}
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = self.engine._value_rules._qualified_callee_name(target)
            if name is None:
                continue
            local = self.engine._value_rules._resolve_lexical_function(name, parent)
            if local is None:
                local = self.engine._value_rules._resolve_lexical_function(
                    name.rsplit(".", 1)[-1], parent
                )
            if local is None:
                candidate = f"{parent}.{name}"
                if candidate in self.engine._functions:
                    local = candidate
            if local is None:
                continue
            for wrapper in self.engine._functions.values():
                if not wrapper.qualified_name.startswith(f"{local}."):
                    continue
                if not isinstance(wrapper.node, ast.FunctionDef):
                    continue
                short = wrapper.qualified_name.rsplit(".", 1)[-1]
                if short not in {"wrapper", "inner", "decorated"}:
                    continue
                arguments = wrapper.node.args
                if arguments.vararg is None and arguments.kwarg is None:
                    continue
                for argument in arguments.kwonlyargs:
                    if argument.arg in original:
                        continue
                    annotation = (
                        self.engine._declaration_rules._annotation_value(argument.annotation)
                        if argument.annotation is not None
                        else AbstractTypeValue.unresolved()
                    )
                    extras.setdefault(argument.arg, annotation)
        return extras

    def _decorator_effective_return(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, parent: str
    ) -> AbstractTypeValue | None:
        """Return the decorated callable's result type for simple decorators."""
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            func_expr = call.func if call is not None else decorator
            name = self.engine._value_rules._qualified_callee_name(func_expr)
            if name is None:
                continue
            if name.rsplit(".", 1)[-1] in {
                "abstractmethod",
                "abstractclassmethod",
                "abstractstaticmethod",
                "abstractproperty",
                "overload",
                "final",
                "no_type_check",
                "deprecated",
                "override",
                "type_check_only",
            }:
                # These decorators annotate/check the function; they do not
                # replace its callable result type.
                continue
            local = self.engine._value_rules._resolve_lexical_function(name, parent)
            if local is None:
                local = self.engine._value_rules._resolve_lexical_function(
                    name.rsplit(".", 1)[-1], parent
                )
            if local is not None and self._decorator_preserves_signature(
                self.engine._functions[local]
            ):
                # ``functools.wraps`` copies ``__wrapped__`` metadata, so the
                # decorated callable keeps its own signature.  Using the
                # wrapper's ``Callable[..., Any]`` would erase it.
                continue
            decorator_type: ProperType | None
            if local is not None:
                decorator_type = self._function_value(self.engine._functions[local]).public_type()
            else:
                imported = self.engine._value_rules._resolve_import_name(name) or name
                decorator_type = self.engine._member_rules._external_type(imported)
            if not isinstance(decorator_type, CallableType):
                # A callable class decorator (``@Deco``) replaces the
                # decorated function with an instance.  The call result is
                # the return type of that class's ``__call__`` method.
                if call is None:
                    class_name = self.engine._class_aliases.get(
                        name
                    ) or self.engine._class_aliases.get(name.rsplit(".", 1)[-1])
                    call_method = (
                        self.engine._member_rules._class_method(class_name, "__call__")
                        if class_name is not None
                        else None
                    )
                    if call_method is not None:
                        signature = self._function_value(
                            self.engine._functions[call_method]
                        ).public_type()
                        if (
                            isinstance(signature, CallableType)
                            and signature.return_type is not None
                            and not self.engine._declaration_rules._contains_type_var(
                                signature.return_type
                            )
                        ):
                            return AbstractTypeValue.from_type(signature.return_type)
                    member = None
                    if isinstance(decorator_type, TypeType) and isinstance(
                        decorator_type.item, Instance
                    ):
                        member = decorator_type.item.type.members.get("__call__")
                    elif isinstance(decorator_type, Instance):
                        member = decorator_type.type.members.get("__call__")
                    if (
                        isinstance(member, CallableType)
                        and member.return_type is not None
                        and not self.engine._declaration_rules._contains_type_var(
                            member.return_type
                        )
                    ):
                        return AbstractTypeValue.from_type(member.return_type)
                continue
            value: ProperType = decorator_type.return_type
            unwraps = 2 if call is not None else 1
            for _ in range(unwraps):
                if not isinstance(value, CallableType):
                    value = None  # type: ignore[assignment]
                    break
                value = value.return_type
            if value is not None and not self.engine._declaration_rules._contains_type_var(value):
                return AbstractTypeValue.from_type(value)
        return None

    def _decorator_preserves_signature(self, function: _FunctionInfo) -> bool:
        """Detect the ``functools.wraps`` passthrough decorator pattern."""
        node = function.node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        positional = [*node.args.posonlyargs, *node.args.args]
        if len(positional) != 1:
            return False
        parameter = positional[0].arg
        for statement in node.body:
            if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in statement.decorator_list:
                if not isinstance(decorator, ast.Call) or not decorator.args:
                    continue
                name = self.engine._value_rules._qualified_callee_name(decorator.func) or ""
                if not name.endswith("wraps"):
                    continue
                first = decorator.args[0]
                if isinstance(first, ast.Name) and first.id == parameter:
                    return True
        return False

    def _function_value(self, function: _FunctionInfo) -> AbstractTypeValue:
        parameters: list[ProperType] = []
        for name in function.parameter_names:
            explicit = function.explicit_parameters.get(name)
            evidence = function.parameter_evidence.get(name)
            parameter = explicit or evidence or function.documented_parameters.get(name)
            parameter_type = None if parameter is None else parameter.public_type()
            parameters.append(parameter_type or ANY)
        if function.effective_return is not None:
            returns = function.effective_return.public_type() or ANY
        elif function.explicit_return is not None:
            returns = function.explicit_return.public_type() or ANY
        elif function.summary is not None:
            returns = function.summary.return_type or ANY
        elif function.documented_return is not None:
            returns = function.documented_return.public_type() or ANY
        else:
            returns = ANY
        generator = function.is_generator_source or (
            function.summary is not None and function.summary.is_generator
        )
        if generator and function.effective_return is None:
            yield_value = (
                function.summary.yield_value
                if function.summary is not None
                else AbstractTypeValue.unresolved()
            )
            element = (
                yield_value.public_type()
                if yield_value is not None and not yield_value.is_bottom
                else None
            ) or ANY
            decorators = {
                self.engine._value_rules._qualified_callee_name(decorator)
                for decorator in getattr(function.node, "decorator_list", ())
            }
            if "contextlib.contextmanager" in decorators:
                returns = self.engine._value_rules._proper_instance(
                    contextlib.AbstractContextManager, element
                )
            elif "contextlib.asynccontextmanager" in decorators:
                returns = self.engine._value_rules._proper_instance(
                    contextlib.AbstractAsyncContextManager, element
                )
            elif not (
                isinstance(returns, Instance)
                and returns.type.raw_type
                in {
                    cabc.Generator,
                    cabc.AsyncGenerator,
                    cabc.Iterator,
                    cabc.AsyncIterator,
                    cabc.Iterable,
                    cabc.AsyncIterable,
                }
            ):
                if isinstance(function.node, ast.AsyncFunctionDef):
                    returns = self.engine._value_rules._proper_instance(
                        cabc.AsyncGenerator, element, ANY
                    )
                else:
                    returns = self.engine._value_rules._proper_instance(
                        cabc.Generator, element, ANY, NONE_TYPE
                    )
        if isinstance(function.node, ast.AsyncFunctionDef) and not generator:
            if not (isinstance(returns, Instance) and returns.type.raw_type is cabc.Coroutine):
                returns = self.engine._value_rules._proper_instance(
                    cabc.Coroutine, ANY, ANY, returns
                )
        if function.method_kind == "static" and function.owner is not None:
            # A static method has no receiver, so ``Self`` is bound to the
            # class that declares it.
            owner_info = self.engine._classes.get(function.owner)
            if owner_info is not None:
                self_binding = {"Self": owner_info.instance}
                returns = substitute_type_vars(returns, self_binding)
                if parameters is not None:
                    parameters = [substitute_type_vars(item, self_binding) for item in parameters]
        arguments = getattr(function.node, "args", None)
        if arguments is not None and (
            arguments.vararg is not None or arguments.kwarg is not None or arguments.kwonlyargs
        ):
            # ``Callable[[...], R]`` cannot encode *args, **kwargs, or
            # keyword-only parameters.  Ellipsis is the honest projection.
            parameters = None
        signature = CallableType(None if parameters is None else tuple(parameters), returns)
        if function.overloads:
            overload_signatures = []
            for overload in function.overloads:
                overload_signature = self._function_value(overload).public_type()
                if isinstance(overload_signature, CallableType):
                    overload_signatures.append(overload_signature)
            if overload_signatures:
                signature = CallableType(
                    signature.arg_types,
                    signature.return_type,
                    overloads=tuple(overload_signatures),
                )
        return AbstractTypeValue.from_type(
            signature,
            callable_target=function.qualified_name,
        )

    def _is_cli_entrypoint(self, function: _FunctionInfo) -> bool:
        for deco in getattr(function.node, "decorator_list", ()):
            target = deco.func if isinstance(deco, ast.Call) else deco
            name = (self.engine._value_rules._qualified_callee_name(target) or "").rsplit(".", 1)[
                -1
            ]
            qname = self.engine._value_rules._qualified_callee_name(target) or ""
            if qname.startswith("click.") or name in {"command", "group"}:
                return True
        return False
