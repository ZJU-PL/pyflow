"""Resolve calls, bind arguments, specialize functions, and substitute generics."""

from __future__ import annotations

import ast
import collections.abc as cabc
import contextlib
import itertools
import weakref

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NEVER,
    NONE_TYPE,
    CallableType,
    Instance,
    ProperType,
    TupleType,
    TypeType,
    TypeVarType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import (
    _ClassInfo,
    _FunctionInfo,
    _SpecializationKey,
    _expression_name,
)
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue, join_all
from pyflow.analysis.typeinfo.inference.models import FunctionSpecialization
from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup
from pyflow.analysis.typeinfo.resolution.typing_syntax import (
    collect_type_vars,
    substitute_type_vars,
)

_ELEMENT_PROTOCOLS = frozenset(
    {
        "_typeshed.SupportsLenAndGetItem",
        "_typeshed.SupportsGetItem",
        "collections.abc.Iterable",
        "collections.abc.Iterator",
        "collections.abc.Sequence",
        "collections.abc.Collection",
        "collections.abc.Container",
        "collections.abc.Reversible",
        "collections.abc.Set",
        "typing.Iterable",
        "typing.Iterator",
        "typing.Sequence",
        "typing.Collection",
        "typing.Container",
        "typing.Reversible",
        "typing.Set",
    }
)


class CallInference(InferenceComponent):
    """Resolve calls, bind arguments, specialize functions, and substitute generics."""

    def _evaluate_call(
        self,
        node: ast.Call,
        environment: dict[str, AbstractTypeValue],
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        previous_positional = self.engine._call_unknown_positional
        previous_keywords = self.engine._call_unknown_keywords
        self.engine._call_unknown_positional = False
        self.engine._call_unknown_keywords = False
        try:
            return self._evaluate_call_impl(
                node, environment, scope=scope, current_function=current_function
            )
        finally:
            self.engine._call_unknown_positional = previous_positional
            self.engine._call_unknown_keywords = previous_keywords

    def _evaluate_call_impl(
        self,
        node: ast.Call,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        arguments: list[AbstractTypeValue] = []
        for argument in node.args:
            if isinstance(argument, ast.Starred):
                expanded = self.engine._expression_rules._star_expansion(
                    argument, environment, scope=scope, current_function=current_function
                )
                if expanded is None:
                    # ``_star_expansion`` already evaluated the operand.
                    # Its length is unknown, so do not bind the iterable
                    # itself as one positional argument.
                    self.engine._call_unknown_positional = True
                else:
                    arguments.extend(expanded)
            else:
                arguments.append(
                    self.engine._expression_rules._evaluate_expression(
                        argument,
                        environment,
                        scope=scope,
                        current_function=current_function,
                    )
                )
        keywords: dict[str, AbstractTypeValue] = {}
        for keyword in node.keywords:
            if keyword.arg is None:
                mapping = self.engine._expression_rules._evaluate_expression(
                    keyword.value,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
                expanded_keywords = self.engine._expression_rules._keyword_expansion(mapping)
                if expanded_keywords is None:
                    self.engine._call_unknown_keywords = True
                else:
                    keywords.update(expanded_keywords)
            else:
                keywords[keyword.arg] = self.engine._expression_rules._evaluate_expression(
                    keyword.value,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
        if any(self.engine._value_rules._is_never_value(value) for value in arguments) or any(
            self.engine._value_rules._is_never_value(value) for value in keywords.values()
        ):
            return AbstractTypeValue.from_type(NEVER)

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "super"
            and not self.engine._member_rules._name_is_shadowed(node.func.id, environment, scope)
        ):
            super_value = self.engine._member_rules._super_value(
                node, environment, current_function
            )
            if super_value is not None:
                return super_value

        qualified_callee = self.engine._value_rules._qualified_callee_name(node.func)
        root = (_expression_name(node.func) or "").split(".", 1)[0]
        root_shadowed = (
            root in self.engine._value_assignments
            or root in self.engine._class_aliases
            or root in self.engine._function_names
            or (current_function is not None and root in environment)
        )
        if root not in environment:
            if (
                qualified_callee in {"typing.cast", "typing_extensions.cast"}
                and len(node.args) >= 2
            ):
                return self.engine._declaration_rules._annotation_value(node.args[0])
            if (
                qualified_callee in {"typing.NewType", "typing_extensions.NewType"}
                and len(node.args) >= 2
            ):
                wrapped = (
                    self.engine._declaration_rules._annotation_value(node.args[1]).public_type()
                    or ANY
                )
                return AbstractTypeValue.from_type(CallableType((wrapped,), wrapped))
        if (
            qualified_callee
            in {
                "sys.exit",
                "os._exit",
                "typing.assert_never",
                "typing_extensions.assert_never",
                "pytest.fail",
                "pytest.skip",
                "pytest.xfail",
                "werkzeug.exceptions.abort",
                "flask.abort",
                "flask.helpers.abort",
            }
            and (callee_name := _expression_name(node.func)) is not None
            and self.engine._value_rules._resolve_import_name(callee_name) is not None
        ):
            root = callee_name.split(".", 1)[0]
            # Imports do not occupy the local value environment; parameters
            # and assignments do, and must shadow these external call models.
            if root not in environment:
                return AbstractTypeValue.from_type(NEVER)
        # A dynamic unpack supplies an unknown number of iterables to zip.
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "zip"
            and any(isinstance(arg, ast.Starred) for arg in node.args)
        ):
            elements = [
                self.engine._value_rules._iterable_element(argument) for argument in arguments
            ]
            element = join_all(elements, self.engine.type_system).public_type() or ANY
            return self.engine._value_rules._instance(zip, TupleType((element,), unknown_size=True))
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)
        ):
            from pyflow.analysis.typeinfo.resolution.format_strings import check_str_format

            for issue in check_str_format(
                node.func.value.value,
                len(arguments),
                set(keywords),
            ):
                self.engine._add_diagnostic(
                    "format-string-mismatch",
                    issue,
                    node=node,
                )
        if qualified_callee is not None and not root_shadowed:
            modelled = self._model_external_call(qualified_callee, arguments, keywords, node)
            if modelled is not None:
                return modelled
        if (
            isinstance(node.func, ast.Attribute)
            and qualified_callee is not None
            and not root_shadowed
        ):
            # Attribute-style module access (import pathlib;
            # pathlib.Path(...)) or imported names (from pathlib import Path; Path(...))
            # are common and should construct the class when a builtin annotation lookup
            # or an external fact knows it.
            external_class = self.engine._member_rules._external_type(qualified_callee)
            if external_class is None:
                external_class = BuiltinTypeLookup()(qualified_callee)
            if isinstance(external_class, TypeType):
                external_class = external_class.item
            if isinstance(external_class, Instance):
                return AbstractTypeValue.from_type(external_class)
            if isinstance(external_class, CallableType):
                selected = self._select_callable_overload(external_class, arguments)
                return AbstractTypeValue.from_type(
                    self._specialize_callable_return(
                        selected if selected is not None else external_class,
                        arguments,
                    )
                )
        if isinstance(node.func, ast.Name) and not self.engine._member_rules._name_is_shadowed(
            node.func.id, environment, scope
        ):
            builtin_result = self.engine._builtin_rules._call_builtin(
                node.func.id, arguments, keywords, call_node=node
            )
            if builtin_result is not None:
                return builtin_result

        if isinstance(node.func, ast.Attribute):
            base = self.engine._expression_rules._evaluate_expression(
                node.func.value,
                environment,
                scope=scope,
                current_function=current_function,
            )
            if self.engine._value_rules._is_never_value(base):
                return base
            method_result = self.engine._builtin_rules._call_attribute(
                node.func,
                base,
                arguments,
                keywords,
                environment,
                call_node=node,
            )
            if method_result is not None:
                return method_result

        callee = self.engine._expression_rules._evaluate_expression(
            node.func,
            environment,
            scope=scope,
            current_function=current_function,
        )
        if self.engine._value_rules._is_never_value(callee):
            return callee
        results: list[AbstractTypeValue] = []
        for class_target in callee.class_targets:
            results.append(
                self.engine._member_rules._instantiate_class_target(
                    class_target,
                    callee.types,
                    arguments,
                    keywords,
                    node,
                )
            )
        self.engine._last_argument_mutations = []
        for target in callee.callable_targets:
            results.append(self._apply_function(target, arguments, keywords, node=node))
            called = self.engine._functions.get(target)
            if called is not None:
                for name in called.mutated_closure_names:
                    closure_value = called.closure_evidence.get(name)
                    if closure_value is not None:
                        environment[name] = closure_value
                if called.nonlocal_names:
                    parent = self.engine._flow_rules._enclosing_function(called)
                    if parent is current_function:
                        for name in called.nonlocal_names:
                            closure_value = parent.closure_evidence.get(name)
                            if closure_value is not None:
                                environment[name] = closure_value
                for name in called.global_names:
                    global_value = self.engine._module_environment.get(name)
                    if global_value is not None and (
                        current_function is None or name in current_function.global_names
                    ):
                        environment[name] = global_value
        for argument_node, final in self.engine._last_argument_mutations:
            self.engine._flow_rules._update_environment_receiver(environment, argument_node, final)
        self.engine._last_argument_mutations = []
        if not callee.class_targets:
            for typ in callee.types:
                if not isinstance(typ, Instance):
                    continue
                class_info = self.engine._classes.get(typ.type.full_name)
                if class_info is None:
                    continue
                call_method = self.engine._member_rules._class_method(
                    class_info.qualified_name, "__call__"
                )
                if call_method is not None:
                    function = self.engine._functions[call_method]
                    call_arguments = (
                        arguments
                        if function.method_kind == "static"
                        else [AbstractTypeValue.from_type(typ), *arguments]
                    )
                    results.append(
                        self._apply_function(
                            call_method,
                            call_arguments,
                            keywords,
                            node=node,
                        )
                    )
        if not callee.callable_targets and not callee.class_targets:
            for typ in callee.types:
                if isinstance(typ, CallableType):
                    selected = self._select_callable_overload(typ, arguments)
                    results.append(
                        AbstractTypeValue.from_type(
                            self._specialize_callable_return(
                                selected if selected is not None else typ,
                                arguments,
                            )
                        )
                    )
                elif (
                    isinstance(typ, Instance)
                    and typ.type.raw_type is weakref.ReferenceType
                    and typ.args
                ):
                    # ``weakref.ref(obj)()`` returns the target or None when
                    # the referent has been collected.
                    results.append(
                        self.engine._value_rules._join(
                            AbstractTypeValue.from_type(typ.args[0]),
                            AbstractTypeValue.from_type(NONE_TYPE),
                        )
                    )
        if results:
            return join_all(
                results,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
        if self.engine._operator_rules._contains_any(callee):
            return AbstractTypeValue.from_type(ANY)
        return AbstractTypeValue.unresolved()

    def _specialize_callable_return(
        self,
        signature: CallableType,
        arguments: list[AbstractTypeValue],
    ) -> ProperType:
        """Bind method/function type variables for an external callable."""
        substitutions: dict[str, ProperType] = {}
        fixed: set[str] = set()
        if signature.arg_types is not None:
            for formal, actual in zip(signature.arg_types, arguments):
                actual_type = actual.public_type()
                if actual_type is not None:
                    self._match_type_variables(formal, actual_type, substitutions, fixed)
        returned = (
            substitute_type_vars(signature.return_type, substitutions)
            if substitutions
            else signature.return_type
        )
        return self._default_unsolved_type_vars(returned, substitutions)

    def _default_unsolved_type_vars(
        self,
        typ: ProperType,
        substitutions: dict[str, ProperType],
    ) -> ProperType:
        """Replace type variables that argument matching could not solve.

        A leaked ``_T`` is not a usable type: mypy erases unsolved variables
        to their value restriction (or ``Any``).  Keep the inferred parts and
        erase only the variables that remain free.
        """
        if isinstance(typ, TypeVarType):
            if typ.name in substitutions:
                return typ
            if typ.bound is not None:
                return typ.bound
            if typ.constraints:
                return UnionType(tuple(typ.constraints))
            return ANY
        if isinstance(typ, Instance) and typ.args:
            args = tuple(self._default_unsolved_type_vars(item, substitutions) for item in typ.args)
            return typ if args == typ.args else Instance(typ.type, args)
        if isinstance(typ, UnionType):
            items = tuple(
                self._default_unsolved_type_vars(item, substitutions) for item in typ.items
            )
            return typ if items == typ.items else UnionType(items)
        if isinstance(typ, TupleType):
            args = tuple(self._default_unsolved_type_vars(item, substitutions) for item in typ.args)
            return typ if args == typ.args else TupleType(args, unknown_size=typ.unknown_size)
        if isinstance(typ, TypeType):
            item = self._default_unsolved_type_vars(typ.item, substitutions)
            return typ if item == typ.item else TypeType(item)
        if isinstance(typ, CallableType):
            args = (
                tuple(
                    self._default_unsolved_type_vars(item, substitutions) for item in typ.arg_types
                )
                if typ.arg_types is not None
                else None
            )
            returned = self._default_unsolved_type_vars(typ.return_type, substitutions)
            if args == typ.arg_types and returned == typ.return_type:
                return typ
            return CallableType(args, returned, overloads=typ.overloads)
        return typ

    def _model_external_call(
        self,
        qualified_name: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        node: ast.Call,
    ) -> AbstractTypeValue | None:
        for provider in self.engine.call_model_providers:
            try:
                result = provider.infer_call(qualified_name, arguments, keywords)
            except Exception as exc:  # noqa: BLE001 - provider isolation boundary
                self.engine._add_diagnostic(
                    "call-model-error",
                    f"Call model for {qualified_name} failed: {exc}",
                    node=node,
                    affects_completeness=True,
                )
                continue
            if result is not None:
                return result
        modelled = self.engine._stdlib_rules._model_stdlib_call(
            qualified_name, arguments, keywords, node=node
        )
        if modelled is not None:
            return modelled
        return None

    def _check_call_arity(
        self,
        function: _FunctionInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        target: str,
        node: ast.AST | None,
    ) -> None:
        arguments_node = function.node.args
        positional = [*arguments_node.posonlyargs, *arguments_node.args]
        if (
            not self.engine._call_unknown_positional
            and arguments_node.vararg is None
            and len(arguments) > len(positional)
        ):
            self.engine._add_diagnostic(
                "call-arity-mismatch",
                f"Too many positional arguments for {target}",
                node=node or function.node,
                severity="warning",
            )
        bound = self._bind_call_arguments(function, arguments, keywords)
        missing = self._required_parameter_names(function) - bound.keys()
        if missing and not (
            self.engine._call_unknown_positional or self.engine._call_unknown_keywords
        ):
            if not (
                not arguments
                and not keywords
                and self.engine._function_rules._is_cli_entrypoint(function)
            ):
                self.engine._add_diagnostic(
                    "call-arity-mismatch",
                    f"Missing required arguments for {target}: {sorted(missing)}",
                    node=node or function.node,
                    severity="warning",
                )
        positional_only = {argument.arg for argument in arguments_node.posonlyargs}
        known = {argument.arg for argument in (*positional, *arguments_node.kwonlyargs)}
        known.update(function.extra_keywords)
        for name in keywords:
            if name in positional_only:
                self.engine._add_diagnostic(
                    "call-arity-mismatch",
                    f"Positional-only argument {name!r} passed by keyword to {target}",
                    node=node or function.node,
                    severity="warning",
                )
            elif (
                name not in known
                and arguments_node.kwarg is None
                and not self.engine._call_unknown_keywords
            ):
                self.engine._add_diagnostic(
                    "call-arity-mismatch",
                    f"Unexpected keyword argument {name!r} for {target}",
                    node=node or function.node,
                    severity="warning",
                )

    def _apply_function(
        self,
        target: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        *,
        node: ast.AST | None = None,
    ) -> AbstractTypeValue:
        function = self.engine._functions.get(target)
        if function is None:
            external = self.engine._member_rules._external_type(target)
            if isinstance(external, CallableType):
                return AbstractTypeValue.from_type(
                    self._specialize_callable_return(external, arguments)
                )
            return AbstractTypeValue.unresolved()
        selected = self._select_overload(function, arguments, keywords)
        if selected is not None:
            return self._apply_overload(target, selected, arguments, keywords, node)
        union_overloads = self._apply_union_overloads(target, function, arguments, keywords, node)
        if union_overloads is not None:
            return union_overloads
        self.engine._last_argument_mutations = []
        self._check_call_arity(function, arguments, keywords, target, node)
        bound_arguments = self._bind_call_arguments(function, arguments, keywords)
        substitutions = self._generic_substitutions(function, bound_arguments)
        for name, annotated in function.explicit_parameters.items():
            actual = bound_arguments.get(name)
            if actual is None:
                continue
            if function.node.args.vararg and name == function.node.args.vararg.arg:
                actual = self.engine._value_rules._iterable_element(actual)
            elif function.node.args.kwarg and name == function.node.args.kwarg.arg:
                actual = join_all(
                    (
                        AbstractTypeValue.from_type(typ.args[1])
                        for typ in actual.types
                        if isinstance(typ, Instance) and len(typ.args) > 1
                    ),
                    self.engine.type_system,
                )
            expected = annotated.public_type()
            if expected is not None:
                for variable in collect_type_vars(expected):
                    actual_type = substitutions.get(variable.name)
                    constraint = variable.bound or (
                        UnionType(variable.constraints) if variable.constraints else None
                    )
                    if actual_type is not None and constraint is not None:
                        self.engine._compatibility_rules._check_annotation_compatibility(
                            AbstractTypeValue.from_type(actual_type),
                            AbstractTypeValue.from_type(constraint),
                            node or function.node,
                            context=f"type variable {variable.name} of {target}",
                        )
            if expected is not None and substitutions:
                annotated = AbstractTypeValue.from_type(
                    substitute_type_vars(expected, substitutions)
                )
            argument_node = self.engine._compatibility_rules._call_argument_node(
                node, function, name
            )
            self.engine._compatibility_rules._check_annotation_compatibility(
                actual,
                annotated,
                argument_node or node or function.node,
                context=f"argument {name} of {target}",
            )
        for name, value in bound_arguments.items():
            self._queue_parameter_evidence(target, name, value)
        if self.engine._collect_specializations:
            specialization = self._register_specialization(function, bound_arguments)
        else:
            key, _ = self._specialization_key(function, bound_arguments)
            specialization = function.specializations.get(key)
        if specialization is not None and function.owner is None and isinstance(node, ast.Call):
            for name, final in specialization.mutated_parameters:
                argument_node = self.engine._compatibility_rules._call_argument_node(
                    node, function, name
                )
                if argument_node is not None:
                    self.engine._last_argument_mutations.append((argument_node, final))
        if (
            function.explicit_return is None
            and function.summary is not None
            and len(function.summary.return_dependencies) == 1
        ):
            dependency = next(iter(function.summary.return_dependencies))
            if dependency in bound_arguments:
                return self._wrap_call_result(
                    function, bound_arguments[dependency], substitutions=substitutions
                )
        if function.effective_return is not None:
            returned = function.effective_return.public_type() or ANY
            if substitutions:
                returned = substitute_type_vars(returned, substitutions)
            return self._wrap_call_result(
                function, AbstractTypeValue.from_type(returned), substitutions=substitutions
            )
        if function.explicit_return is not None:
            substitutions = self._generic_substitutions(function, bound_arguments)
            returned = function.explicit_return.public_type()
            if returned is not None and substitutions:
                returned = substitute_type_vars(returned, substitutions)
                return self._wrap_call_result(
                    function, AbstractTypeValue.from_type(returned), substitutions=substitutions
                )
            return self._wrap_call_result(
                function, function.explicit_return, substitutions=substitutions
            )
        if specialization is not None:
            return self._wrap_call_result(
                function,
                specialization.return_value,
                yield_value=specialization.yield_value,
                substitutions=substitutions,
            )
        if function.summary is not None:
            return self._wrap_call_result(
                function, function.summary.return_value, substitutions=substitutions
            )
        if function.documented_return is not None:
            return self._wrap_call_result(
                function, function.documented_return, substitutions=substitutions
            )
        return AbstractTypeValue.unresolved()

    def _apply_union_overloads(
        self,
        target: str,
        function: _FunctionInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        node: ast.AST | None,
    ) -> AbstractTypeValue | None:
        """Apply overloads across all alternatives of union arguments.

        A single overload need not accept an entire union when distinct
        overloads cover its alternatives.  Select an overload for each
        combination and join the results only when every combination is
        covered; otherwise let the implementation signature validate the
        call as usual.
        """
        if not function.overloads:
            return None

        def alternatives(value: AbstractTypeValue) -> list[AbstractTypeValue]:
            typ = value.public_type()
            if isinstance(typ, UnionType) and len(typ.items) > 1:
                return [AbstractTypeValue.from_type(item) for item in typ.items]
            return [value]

        positional_alternatives = [alternatives(value) for value in arguments]
        keyword_names = list(keywords)
        keyword_alternatives = [alternatives(keywords[name]) for name in keyword_names]
        has_union = any(len(items) > 1 for items in positional_alternatives) or any(
            len(items) > 1 for items in keyword_alternatives
        )
        if not has_union:
            return None

        axes = [*positional_alternatives, *keyword_alternatives]
        combinations = 1
        for axis in axes:
            combinations *= len(axis)
            if combinations > self.engine.options.max_union_size:
                return None

        results: list[AbstractTypeValue] = []
        for combination in itertools.product(*axes):
            split_arguments = list(combination[: len(arguments)])
            split_keywords = dict(zip(keyword_names, combination[len(arguments) :]))
            overload = self._select_overload(function, split_arguments, split_keywords)
            if overload is None:
                actual = ", ".join(
                    str(value.public_type() or "Any")
                    for value in [*split_arguments, *split_keywords.values()]
                )
                self.engine._add_diagnostic(
                    "annotation-mismatch",
                    f"No overload of {target} accepts arguments ({actual})",
                    node=node or function.node,
                    severity=("error" if self.engine.options.strict_annotations else "warning"),
                )
                return None
            results.append(
                self._apply_overload(target, overload, split_arguments, split_keywords, node)
            )
        return join_all(
            results,
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )

    def _select_overload(
        self,
        function: _FunctionInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> _FunctionInfo | None:
        for overload in function.overloads:
            arguments_node = overload.node.args
            positional = [*arguments_node.posonlyargs, *arguments_node.args]
            positional_only = {argument.arg for argument in arguments_node.posonlyargs}
            accepted_keywords = {
                argument.arg
                for argument in (
                    *arguments_node.posonlyargs,
                    *arguments_node.args,
                    *arguments_node.kwonlyargs,
                )
            }
            if arguments_node.kwarg is None and any(
                name not in accepted_keywords for name in keywords
            ):
                continue
            if any(name in positional_only for name in keywords):
                continue
            if arguments_node.vararg is None and len(arguments) > len(positional):
                continue
            bound = self._bind_call_arguments(overload, arguments, keywords)
            if any(name not in bound for name in self._required_parameter_names(overload)):
                continue
            accepted = True
            for name, annotated in overload.explicit_parameters.items():
                actual = bound.get(name)
                if actual is None or actual.unknown:
                    continue
                expected = annotated.public_type()
                actual_type = actual.public_type()
                if expected is None or actual_type is None:
                    continue
                if self._is_unresolved_external_type(expected) and not isinstance(
                    expected, Instance
                ):
                    continue
                if self._is_unresolved_external_type(expected):
                    # Protocol parameters from stubs carry type variables and
                    # unknown module names.  When the protocol's members are
                    # known, check structurally instead of accepting every
                    # actual type (which selects the wrong overload).
                    if not self._protocol_is_checkable(expected):
                        continue
                # An overload must accept every possible value of a union
                # argument.  ``is_maybe_subtype`` deliberately accepts a
                # union when any member matches, which can select one narrow
                # overload and then report a false mismatch for the other
                # alternatives.
                if self.engine.type_system.is_subtype(actual_type, expected):
                    continue
                expected_literals = self.engine._compatibility_rules._literal_expected_values(
                    expected
                )
                if (
                    expected_literals is not None
                    and actual.literal_values
                    and actual.literal_values.issubset(expected_literals)
                ):
                    continue
                accepted = False
                break
            if accepted:
                return overload
        return None

    @staticmethod
    def _required_parameter_names(function: _FunctionInfo) -> set[str]:
        arguments = function.node.args
        positional = [*arguments.posonlyargs, *arguments.args]
        required = positional[: -len(arguments.defaults)] if arguments.defaults else positional
        names = {argument.arg for argument in required}
        names.update(
            argument.arg
            for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults)
            if default is None
        )
        return names

    def _select_callable_overload(
        self,
        callable_type: CallableType,
        arguments: list[AbstractTypeValue],
    ) -> CallableType | None:
        if not callable_type.overloads:
            return None
        for overload in callable_type.overloads:
            if overload.arg_types is None:
                return overload
            if len(arguments) > len(overload.arg_types):
                continue
            accepted = True
            for actual, expected in zip(arguments, overload.arg_types):
                actual_type = actual.public_type()
                if actual_type is None or actual.unknown:
                    continue
                if self._is_unresolved_external_type(expected) and not isinstance(
                    expected, Instance
                ):
                    continue
                if self._is_unresolved_external_type(expected):
                    # Protocol parameters from stubs carry type variables and
                    # unknown module names.  When the protocol's members are
                    # known, check structurally instead of accepting every
                    # actual type (which selects the wrong overload).
                    if not self._protocol_is_checkable(expected):
                        continue
                if self.engine.type_system.is_subtype(actual_type, expected):
                    continue
                expected_literals = self.engine._compatibility_rules._literal_expected_values(
                    expected
                )
                if (
                    expected_literals is not None
                    and actual.literal_values
                    and actual.literal_values.issubset(expected_literals)
                ):
                    continue
                accepted = False
                break
            if accepted:
                return overload
        return None

    def _protocol_is_checkable(self, typ: ProperType) -> bool:
        """Whether ``typ`` is a protocol whose full member shape is known."""
        if not isinstance(typ, Instance) or not typ.type.is_protocol:
            return False
        members = self.engine.type_system.get_members(typ.type)
        if not members:
            return False
        from pyflow.analysis.typeinfo.core.typesystem import ANY as _ANY

        for name, member in members.items():
            if name.startswith("__") and name.endswith("__") and member == _ANY:
                continue
            if member == _ANY:
                return False
        return True

    @staticmethod
    def _is_unresolved_external_type(typ: ProperType) -> bool:
        if isinstance(typ, TypeVarType):
            # Generic overload parameters are resolved by the selected
            # overload's substitutions; do not reject the candidate upfront.
            return True
        if isinstance(typ, Instance):
            if getattr(typ.type.raw_type, "__pyflow_unresolved_external__", False):
                return True
            if typ.type.full_name.startswith(("_typeshed.", "typing._SpecialForm")):
                return True
            return any(CallInference._is_unresolved_external_type(item) for item in typ.args)
        if isinstance(typ, (UnionType, TupleType)):
            return any(
                CallInference._is_unresolved_external_type(item)
                for item in (typ.items if isinstance(typ, UnionType) else typ.args)
            )
        return False

    def _apply_overload(
        self,
        target: str,
        overload: _FunctionInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        node: ast.AST | None,
    ) -> AbstractTypeValue:
        self._check_call_arity(overload, arguments, keywords, target, node)
        bound = self._bind_call_arguments(overload, arguments, keywords)
        substitutions = self._generic_substitutions(overload, bound)
        for name, annotated in overload.explicit_parameters.items():
            actual = bound.get(name)
            expected = annotated.public_type()
            if actual is None or expected is None:
                continue
            if substitutions:
                expected = substitute_type_vars(expected, substitutions)
            self.engine._compatibility_rules._check_annotation_compatibility(
                actual,
                AbstractTypeValue.from_type(expected),
                node or overload.node,
                context=f"argument {name} of {target}",
            )
        for name, value in bound.items():
            self._queue_parameter_evidence(target, name, value)
        returned = (
            overload.explicit_return
            or overload.effective_return
            or overload.documented_return
            or AbstractTypeValue.unresolved()
        )
        returned_type = returned.public_type()
        if returned_type is not None and substitutions:
            returned_type = substitute_type_vars(returned_type, substitutions)
            returned = AbstractTypeValue.from_type(returned_type)
        return self._wrap_call_result(overload, returned, substitutions=substitutions)

    def _wrap_call_result(
        self,
        function: _FunctionInfo,
        returned: AbstractTypeValue,
        *,
        yield_value: AbstractTypeValue | None = None,
        substitutions: dict[str, ProperType] | None = None,
    ) -> AbstractTypeValue:
        if function.effective_return is not None:
            # Callers pass the (already substituted) effective return.
            return returned
        summary = function.summary
        effective_yield = yield_value
        if effective_yield is None and summary is not None and summary.is_generator:
            effective_yield = summary.yield_value
        if effective_yield is not None and not effective_yield.is_bottom:
            element = effective_yield.public_type() or ANY
            if substitutions:
                element = substitute_type_vars(element, substitutions)
            decorators = {
                self.engine._value_rules._qualified_callee_name(decorator)
                for decorator in getattr(function.node, "decorator_list", ())
            }
            if "contextlib.contextmanager" in decorators:
                return self.engine._value_rules._instance(
                    contextlib.AbstractContextManager, element
                )
            if "contextlib.asynccontextmanager" in decorators:
                return self.engine._value_rules._instance(
                    contextlib.AbstractAsyncContextManager, element
                )
            for returned_type in returned.types:
                if isinstance(returned_type, Instance) and returned_type.type.raw_type in {
                    cabc.Generator,
                    cabc.AsyncGenerator,
                }:
                    # Preserve the explicit Generator[Y, S, R] annotation;
                    # rebuilding Iterator[Y] would lose ``send`` and return
                    # types that callers may rely on.
                    return returned
            if isinstance(function.node, ast.AsyncFunctionDef):
                return self.engine._value_rules._instance(cabc.AsyncGenerator, element, ANY)
            return self.engine._value_rules._instance(cabc.Generator, element, ANY, NONE_TYPE)
        if isinstance(function.node, ast.AsyncFunctionDef):
            result = returned.public_type() or ANY
            return self.engine._value_rules._instance(cabc.Coroutine, ANY, ANY, result)
        return returned

    def _specialization_key(
        self,
        function: _FunctionInfo,
        bound_arguments: dict[str, AbstractTypeValue],
    ) -> tuple[_SpecializationKey, dict[str, AbstractTypeValue]]:
        parameters = self._call_context_parameters(function, bound_arguments)
        key = _SpecializationKey(
            tuple((name, parameters[name]) for name in function.parameter_names)
        )
        return key, parameters

    def _register_specialization(
        self,
        function: _FunctionInfo,
        bound_arguments: dict[str, AbstractTypeValue],
    ) -> FunctionSpecialization:
        key, parameters = self._specialization_key(function, bound_arguments)
        existing = function.specializations.get(key)
        if existing is not None:
            return existing

        normal_count = sum(not candidate.widened for candidate in function.specializations)
        if normal_count < self.engine.options.max_specializations_per_function:
            specialization = FunctionSpecialization(
                parameters=key.parameters,
                return_value=AbstractTypeValue.bottom(),
            )
            function.specializations[key] = specialization
            return specialization

        widened_key = _SpecializationKey(widened=True)
        for name, value in parameters.items():
            previous_value = function.widened_parameters.get(name, AbstractTypeValue.bottom())
            function.widened_parameters[name] = self.engine._value_rules._join(
                previous_value, value
            )
        widened_parameters = tuple(
            (name, function.widened_parameters[name]) for name in function.parameter_names
        )
        previous_specialization = function.specializations.get(widened_key)
        specialization = FunctionSpecialization(
            parameters=widened_parameters,
            return_value=(
                AbstractTypeValue.bottom()
                if previous_specialization is None
                else previous_specialization.return_value
            ),
            yield_value=(
                AbstractTypeValue.bottom()
                if previous_specialization is None
                else previous_specialization.yield_value
            ),
            widened=True,
        )
        function.specializations[widened_key] = specialization
        self.engine._add_diagnostic(
            "specialization-budget-exceeded",
            f"{function.qualified_name} exceeded its "
            f"{self.engine.options.max_specializations_per_function}-context budget; "
            "additional calls are analyzed in a widened context",
            node=function.node,
        )
        return specialization

    def _call_context_parameters(
        self,
        function: _FunctionInfo,
        bound_arguments: dict[str, AbstractTypeValue],
    ) -> dict[str, AbstractTypeValue]:
        parameters: dict[str, AbstractTypeValue] = {}
        for index, name in enumerate(function.parameter_names):
            actual = bound_arguments.get(name)
            if actual is not None:
                parameters[name] = self._normalize_context_value(actual)
            elif function.owner is not None and function.method_kind != "static" and index == 0:
                parameters[name] = AbstractTypeValue.from_type(
                    self.engine._classes[function.owner].instance,
                    class_target=function.owner if function.method_kind == "class" else None,
                )
            else:
                explicit = function.explicit_parameters.get(name)
                if explicit is not None:
                    parameters[name] = explicit
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

    @staticmethod
    def _normalize_context_value(
        value: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Remove evolving display-only callable signatures from context keys.

        User-defined callable identity is carried by ``callable_targets``.  Its
        synthesized ``CallableType`` return annotation changes as inference
        converges and must not manufacture a fresh specialization each round.
        """
        if not value.callable_targets:
            return value
        return AbstractTypeValue(
            types=frozenset(typ for typ in value.types if not isinstance(typ, CallableType)),
            unknown=value.unknown,
            callable_targets=value.callable_targets,
            class_targets=value.class_targets,
            dict_shapes=value.dict_shapes,
        )

    def _bind_call_arguments(
        self,
        function: _FunctionInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> dict[str, AbstractTypeValue]:
        node_arguments = function.node.args
        positional_names = [arg.arg for arg in (*node_arguments.posonlyargs, *node_arguments.args)]
        positional_only = {arg.arg for arg in node_arguments.posonlyargs}
        keyword_only = {arg.arg for arg in node_arguments.kwonlyargs}
        bound: dict[str, AbstractTypeValue] = {}

        for index, value in enumerate(arguments[: len(positional_names)]):
            bound[positional_names[index]] = value

        extra_positional = arguments[len(positional_names) :]
        if node_arguments.vararg is not None and extra_positional:
            element = join_all(
                (
                    AbstractTypeValue.from_type(
                        self.engine._compatibility_rules._runtime_value_type(value)
                    )
                    for value in extra_positional
                ),
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
            element_type = element.public_type() or ANY
            bound[node_arguments.vararg.arg] = AbstractTypeValue.from_type(
                TupleType((element_type,), unknown_size=True)
            )

        unmatched_keywords: list[AbstractTypeValue] = []
        for name, value in keywords.items():
            if name in function.extra_keywords:
                continue
            if name in positional_names and name not in positional_only:
                bound[name] = value
            elif name in keyword_only:
                bound[name] = value
            else:
                unmatched_keywords.append(value)

        if node_arguments.kwarg is not None and unmatched_keywords:
            values = join_all(
                unmatched_keywords,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
            bound[node_arguments.kwarg.arg] = self.engine._value_rules._instance(
                dict,
                self.engine._value_rules._proper_instance(str),
                values.public_type() or ANY,
            )
        if self.engine._call_unknown_positional or self.engine._call_unknown_keywords:
            for name in self._required_parameter_names(function):
                if name in bound:
                    continue
                if name in keyword_only:
                    if self.engine._call_unknown_keywords:
                        bound[name] = AbstractTypeValue.unresolved()
                elif name in positional_names:
                    if self.engine._call_unknown_positional or self.engine._call_unknown_keywords:
                        bound[name] = AbstractTypeValue.unresolved()
        if (
            self.engine._call_unknown_positional
            and node_arguments.vararg is not None
            and node_arguments.vararg.arg not in bound
        ):
            bound[node_arguments.vararg.arg] = AbstractTypeValue.from_type(
                TupleType((ANY,), unknown_size=True)
            )
        if (
            self.engine._call_unknown_keywords
            and node_arguments.kwarg is not None
            and node_arguments.kwarg.arg not in bound
        ):
            bound[node_arguments.kwarg.arg] = self.engine._value_rules._instance(
                dict, self.engine._value_rules._proper_instance(str), ANY
            )
        return bound

    def _return_dependencies(self, function: _FunctionInfo) -> frozenset[str]:
        """Find direct parameter-to-return relations for context precision."""
        if isinstance(function.node, ast.Lambda):
            if isinstance(function.node.body, ast.Name):
                name = function.node.body.id
                if name in function.parameter_names:
                    return frozenset((name,))
            return frozenset()
        dependencies: set[str] = set()
        mutated: set[str] = set()
        saw_return = False
        invalid = False

        def visit(node: ast.AST, *, root: bool = False) -> None:
            nonlocal saw_return, invalid
            if invalid:
                return
            if not root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                if node.id in function.parameter_names:
                    mutated.add(node.id)
            elif (
                isinstance(node, ast.ExceptHandler)
                and node.name is not None
                and node.name in function.parameter_names
            ):
                mutated.add(node.name)
            if isinstance(node, ast.Return):
                saw_return = True
                if isinstance(node.value, ast.Name) and node.value.id in function.parameter_names:
                    dependencies.add(node.value.id)
                else:
                    invalid = True
                return
            for child in ast.iter_child_nodes(node):
                visit(child)

        visit(function.node, root=True)
        if not saw_return or invalid:
            return frozenset()
        # A parameter that is reassigned or mutated no longer carries its
        # call-site type through to the return value.
        return frozenset(dependencies - mutated)

    def _generic_constructor_args(
        self,
        class_info: _ClassInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> tuple[ProperType, ...] | None:
        """Infer generics for dataclass/NamedTuple constructors without __init__."""
        if class_info.instance.type.tuple_fields is not None:
            field_names = list(class_info.instance.type.tuple_fields)
        else:
            field_names = [name for name in class_info.attributes if not name.startswith("_")]
        substitutions: dict[str, ProperType] = {}
        fixed: set[str] = set()
        for name, value in zip(field_names, arguments):
            annotation = class_info.attributes.get(name)
            formal = None if annotation is None else annotation.public_type()
            actual = value.public_type()
            if formal is not None and actual is not None:
                self._match_type_variables(formal, actual, substitutions, fixed)
        for name, value in keywords.items():
            annotation = class_info.attributes.get(name)
            formal = None if annotation is None else annotation.public_type()
            actual = value.public_type()
            if formal is not None and actual is not None:
                self._match_type_variables(formal, actual, substitutions, fixed)
        if not class_info.type_variables:
            return None
        if not substitutions:
            return tuple(ANY for _ in class_info.type_variables)
        return tuple(substitutions.get(name, ANY) for name in class_info.type_variables)

    def _generic_substitutions(
        self,
        function: _FunctionInfo,
        actuals: dict[str, AbstractTypeValue],
    ) -> dict[str, ProperType]:
        substitutions: dict[str, ProperType] = {}
        fixed: set[str] = set()
        if function.method_kind == "static" and function.owner is not None:
            # A static method has no receiver; ``Self`` is the declaring class.
            owner_info = self.engine._classes.get(function.owner)
            if owner_info is not None:
                substitutions["Self"] = owner_info.instance
                fixed.add("Self")
        if function.owner and function.method_kind != "static" and function.parameter_names:
            receiver = actuals.get(function.parameter_names[0])
            if receiver is not None:
                substitutions["Self"] = (
                    receiver.public_type() or self.engine._classes[function.owner].instance
                )
                for typ in receiver.types:
                    if isinstance(typ, Instance):
                        receiver_info = self.engine._classes.get(typ.type.full_name)
                        if receiver_info is not None:
                            if (
                                function.owner != typ.type.full_name
                                and getattr(function.node, "name", "") != "__init__"
                            ):
                                substitutions.update(receiver_info.type_var_bindings)
                            for k, v in receiver_info.type_var_bindings.items():
                                if not isinstance(v, TypeVarType):
                                    substitutions[k] = v
                                    fixed.add(k)
                        for parameter, argument in zip(typ.type.type_parameters, typ.args):
                            self._match_type_variables(parameter, argument, substitutions, fixed)
        vararg_name = (
            function.node.args.vararg.arg if function.node.args.vararg is not None else None
        )
        kwarg_name = function.node.args.kwarg.arg if function.node.args.kwarg is not None else None
        for name, formal_value in function.explicit_parameters.items():
            formal = formal_value.public_type()
            actual = actuals.get(name)
            if formal is None or actual is None:
                continue
            if name == vararg_name:
                # ``*args: T`` binds T from each element, not from the tuple.
                actual = self.engine._value_rules._iterable_element(actual)
            elif name == kwarg_name:
                actual = join_all(
                    (
                        AbstractTypeValue.from_type(typ.args[1])
                        for typ in actual.types
                        if isinstance(typ, Instance) and len(typ.args) > 1
                    ),
                    self.engine.type_system,
                )
            actual_type = actual.public_type()
            if (
                actual_type is not None
                and isinstance(formal, TypeType)
                and actual.class_targets
                and isinstance(actual_type, Instance)
            ):
                # Class objects are represented internally as Instance +
                # class_targets; ``type[T]`` matching needs the explicit form.
                actual_type = TypeType(actual_type)
            if (
                actual_type is not None
                and isinstance(formal, CallableType)
                and actual.class_targets
            ):
                # ``apply(str)`` passes a class object where a ``Callable``
                # is expected; without a constructor signature the type
                # variables that only appear in the callable's return type
                # stay unbound and leak into the result.
                constructor = self._constructor_callable_type(actual_type)
                if constructor is not None:
                    self._match_type_variables(formal, constructor, substitutions, fixed)
                    continue
            if actual_type is not None:
                self._match_type_variables(formal, actual_type, substitutions, fixed)
        if substitutions:
            chained = {}
            for k, v in substitutions.items():
                chained[k] = substitute_type_vars(v, substitutions)
            return chained
        return substitutions

    def _match_type_variables(
        self,
        formal: ProperType,
        actual: ProperType,
        substitutions: dict[str, ProperType],
        fixed: set[str] | None = None,
    ) -> None:
        fixed = fixed or set()
        if isinstance(formal, TypeVarType):
            if formal.name in fixed:
                return
            value = actual
            if formal.constraints:
                matched = [
                    constraint
                    for constraint in formal.constraints
                    if self.engine.type_system.is_subtype(actual, constraint)
                ]
                value = matched[0] if matched else ANY
            elif formal.bound is not None and not self.engine.type_system.is_subtype(
                actual, formal.bound
            ):
                value = ANY
            existing = substitutions.get(formal.name)
            if existing is None or isinstance(existing, TypeVarType):
                substitutions[formal.name] = value
            else:
                joined = self.engine._value_rules._join(
                    AbstractTypeValue.from_type(existing),
                    AbstractTypeValue.from_type(value),
                ).public_type()
                if joined is not None:
                    substitutions[formal.name] = joined
            return
        if isinstance(formal, UnionType):
            for item in formal.items:
                if isinstance(item, TypeVarType):
                    self._match_type_variables(item, actual, substitutions, fixed)
                elif item == actual or self.engine.type_system.is_subtype(actual, item):
                    self._match_type_variables(item, actual, substitutions, fixed)
            return
        if isinstance(formal, TypeType) and isinstance(actual, TypeType):
            self._match_type_variables(formal.item, actual.item, substitutions, fixed)
            return
        if isinstance(formal, CallableType) and isinstance(actual, CallableType):
            if formal.return_type is not None and actual.return_type is not None:
                self._match_type_variables(
                    formal.return_type, actual.return_type, substitutions, fixed
                )
            if formal.arg_types is not None and actual.arg_types is not None:
                for formal_arg, actual_arg in zip(formal.arg_types, actual.arg_types):
                    self._match_type_variables(formal_arg, actual_arg, substitutions, fixed)
            return
        if isinstance(formal, Instance) and isinstance(actual, TupleType):
            # ``tuple`` is a dedicated type, so the Instance/Instance projection
            # below never runs for ``Sequence[T]`` parameters bound to tuple
            # arguments.
            target = formal.type.raw_type
            if (
                target
                in {
                    cabc.Iterable,
                    cabc.Iterator,
                    cabc.Collection,
                    cabc.Sequence,
                    cabc.Reversible,
                    cabc.Container,
                    cabc.Set,
                    cabc.AsyncIterable,
                    cabc.AsyncIterator,
                }
                and formal.args
            ):
                items = actual.args
                element: ProperType
                if len(items) > 1:
                    element = UnionType(tuple(items))
                elif items:
                    element = items[0]
                else:
                    element = ANY
                self._match_type_variables(formal.args[0], element, substitutions, fixed)
            return
        if (
            isinstance(formal, Instance)
            and formal.args
            and isinstance(actual, (Instance, TupleType))
        ):
            if formal.type.full_name in _ELEMENT_PROTOCOLS:
                element = self._iterable_protocol_element(actual)
                self._match_type_variables(formal.args[0], element, substitutions, fixed)
                return
        if isinstance(formal, Instance) and isinstance(actual, Instance):
            if formal.type.is_protocol and formal.args and formal.type is not actual.type:
                self._match_protocol_type_variables(formal, actual, substitutions, fixed)
            if formal.type.raw_type is actual.type.raw_type:
                for formal_arg, actual_arg in zip(formal.args, actual.args):
                    self._match_type_variables(formal_arg, actual_arg, substitutions, fixed)
                return

            # A TypeVar may appear under an abstract container annotation while
            # the call supplies a concrete container (``Sequence[T]`` versus
            # ``list[int]``).  Project the concrete type parameters onto the
            # abstract shape instead of requiring identical raw classes.
            target = formal.type.raw_type
            iterable_targets = {
                cabc.Iterable,
                cabc.Iterator,
                cabc.Collection,
                cabc.Sequence,
                cabc.Reversible,
                cabc.Container,
                cabc.Set,
                cabc.AsyncIterable,
                cabc.AsyncIterator,
            }
            mapping_targets = {cabc.Mapping, cabc.MutableMapping}
            if target in iterable_targets and formal.args:
                raw = actual.type.raw_type
                if raw is dict and actual.args:
                    element = actual.args[0]
                elif raw is str:
                    element = self.engine._value_rules._proper_instance(str)
                elif raw is bytes:
                    element = self.engine._value_rules._proper_instance(int)
                elif raw is range:
                    element = self.engine._value_rules._proper_instance(int)
                else:
                    element = actual.args[0] if actual.args else ANY
                self._match_type_variables(formal.args[0], element, substitutions, fixed)
            elif target in mapping_targets and len(formal.args) >= 2:
                if actual.type.raw_type is dict and len(actual.args) >= 2:
                    self._match_type_variables(formal.args[0], actual.args[0], substitutions, fixed)
                    self._match_type_variables(formal.args[1], actual.args[1], substitutions, fixed)
        elif isinstance(formal, TupleType) and isinstance(actual, TupleType):
            for formal_arg, actual_arg in zip(formal.args, actual.args):
                self._match_type_variables(formal_arg, actual_arg, substitutions, fixed)

    def _match_protocol_type_variables(
        self,
        formal: Instance,
        actual: Instance,
        substitutions: dict[str, ProperType],
        fixed: set[str],
    ) -> None:
        """Solve protocol type variables from the protocol's members.

        mypy derives constraints structurally (``constraints.py``): matching
        ``_SupportsCeil[_T]`` against ``float`` binds ``_T`` from
        ``float.__ceil__() -> int``.  Without this, overloads whose parameter
        is a generic protocol return a leaked type variable.
        """
        parameters = formal.type.type_parameters
        if not parameters:
            return
        pair = (formal.type.full_name, actual.type.full_name)
        stack = self.engine._protocol_match_stack
        if pair in stack:
            return
        stack.add(pair)
        try:
            formal_members = self.engine.type_system.get_members(formal.type)
            actual_members = self.engine.type_system.get_members(actual.type)
            member_substitutions: dict[str, ProperType] = {}
            for name, formal_member in formal_members.items():
                actual_member = actual_members.get(name)
                if actual_member is None:
                    continue
                self._match_type_variables(
                    formal_member, actual_member, member_substitutions, fixed
                )
            for parameter, argument in zip(parameters, formal.args):
                value = member_substitutions.get(parameter.name)
                if value is None or isinstance(value, TypeVarType):
                    continue
                self._match_type_variables(argument, value, substitutions, fixed)
        finally:
            stack.discard(pair)

    def _iterable_protocol_element(self, actual: ProperType) -> ProperType:
        """Project the element type used by sequence-like protocols."""
        if isinstance(actual, TupleType):
            if not actual.args:
                return ANY
            return actual.args[0] if len(actual.args) == 1 else UnionType(actual.args)
        if not isinstance(actual, Instance):
            return ANY
        raw = actual.type.raw_type
        if raw is str:
            return actual
        if raw in {bytes, range}:
            return self.engine._value_rules._proper_instance(int)
        if raw is dict and len(actual.args) >= 2:
            return actual.args[0]
        if actual.args:
            return actual.args[0]
        return ANY

    def _constructor_callable_type(self, instance: ProperType) -> CallableType | None:
        """Project a class object onto the callable shape of its constructor."""
        if isinstance(instance, TypeType):
            instance = instance.item
        if not isinstance(instance, Instance):
            return None
        class_info = self.engine._classes.get(instance.type.full_name)
        if class_info is None:
            # Builtins and unanalysed classes: keep the result type and accept
            # any arguments rather than guessing a signature.
            return CallableType(None, instance)
        target = self.engine._member_rules._class_method(class_info.qualified_name, "__init__")
        if target is None:
            target = self.engine._member_rules._class_method(class_info.qualified_name, "__new__")
        if target is None:
            return CallableType(None, instance)
        signature = self.engine._function_rules._function_value(
            self.engine._functions[target]
        ).public_type()
        if not isinstance(signature, CallableType):
            return CallableType(None, instance)
        parameters = signature.arg_types
        if parameters:
            parameters = parameters[1:]
        return CallableType(parameters, instance)

    def _queue_parameter_evidence(
        self, target: str, parameter: str, value: AbstractTypeValue
    ) -> None:
        if not value.types and not value.callable_targets and not value.class_targets:
            return
        key = (target, parameter)
        old = self.engine._pending_parameter_evidence.get(key, AbstractTypeValue.bottom())
        self.engine._pending_parameter_evidence[key] = self.engine._value_rules._join(old, value)
