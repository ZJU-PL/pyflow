"""Discover imports, classes, functions, aliases, and annotation types."""

from __future__ import annotations

import ast
import re
from typing import Iterable, cast

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    CallableType,
    Instance,
    LiteralType,
    ProperType,
    TupleType,
    TypeType,
    TypeVarType,
    UnionType,
    Variance,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import (
    _ClassInfo,
    _FunctionInfo,
    _all_arguments,
    _expression_name,
)
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue
from pyflow.analysis.typeinfo.resolution.annotations import (
    BuiltinTypeLookup,
    TypeLookup,
    _is_typing_surface_name,
    resolve_annotation,
)
from pyflow.analysis.typeinfo.resolution.docstring_types import resolve_documented_type
from pyflow.analysis.typeinfo.resolution.docstrings import (
    search_param_in_docstr,
    search_return_in_docstr,
)
from pyflow.analysis.typeinfo.resolution.imports import iter_module_imports


class DeclarationInference(InferenceComponent):
    """Discover imports, classes, functions, aliases, and annotation types."""

    def _collect_imports(self, tree: ast.Module) -> None:
        for node in iter_module_imports(tree.body):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    self.engine._imports[local] = alias.name if alias.asname else local
                    self.engine._module_names.add(self.engine._imports[local])
                    self.engine._module_names.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    module = (
                        self.engine.project_context.resolve_import_name(
                            self.engine._module_name,
                            module or None,
                            node.level,
                            current_path=self.engine._filename,
                        )
                        or module
                    )
                for alias in node.names:
                    if alias.name == "*":
                        if module:
                            self.engine._star_imports.append(module)
                        continue
                    local = alias.asname or alias.name
                    self.engine._imports[local] = f"{module}.{alias.name}" if module else alias.name

    def _collect_declarations(
        self,
        statements: Iterable[ast.stmt],
        *,
        parent: str,
        owner: str | None = None,
    ) -> None:
        for node in statements:
            if isinstance(node, ast.ClassDef):
                qualified = f"{parent}.{node.name}"
                class_info = self.engine._classes[qualified]
                previous_owner = self.engine._annotation_owner
                previous_vars = dict(self.engine._type_vars)
                self.engine._annotation_owner = qualified
                for base_node in node.bases:
                    if isinstance(base_node, ast.Subscript):
                        for parameter in ast.walk(base_node.slice):
                            if (
                                isinstance(parameter, ast.Name)
                                and parameter.id in self.engine._type_vars
                            ):
                                class_info.type_variables[parameter.id] = self.engine._type_vars[
                                    parameter.id
                                ]
                        if not class_info.type_variables:
                            resolved = self._annotation_value(base_node).public_type()
                            if isinstance(resolved, Instance) and resolved.args:
                                base_info = self.engine._classes.get(resolved.type.full_name)
                                if base_info is not None and base_info.type_variables:
                                    class_info.type_variables = dict(base_info.type_variables)
                class_info.instance.type.type_parameters = tuple(class_info.type_variables.values())
                self.engine._type_vars.update(class_info.type_variables)
                for base_node in node.bases:
                    head = base_node.value if isinstance(base_node, ast.Subscript) else base_node
                    head_name = _expression_name(head)
                    head_last = head_name.rsplit(".", 1)[-1] if head_name else ""
                    if not isinstance(base_node, ast.Subscript) and head_last not in {
                        "list",
                        "set",
                        "frozenset",
                        "dict",
                        "tuple",
                        "List",
                        "Set",
                        "FrozenSet",
                        "Dict",
                        "Tuple",
                    }:
                        # Avoid evaluating synthetic bases such as
                        # ``TypedDict``/``Protocol`` here; that would emit
                        # spurious unresolved-annotation diagnostics.
                        continue
                    resolved_base = self._annotation_value(base_node).public_type()
                    if (
                        isinstance(resolved_base, Instance)
                        and isinstance(resolved_base.type.raw_type, type)
                        and resolved_base.type.raw_type in {list, set, frozenset, dict, tuple}
                    ):
                        raw_base = resolved_base.type.raw_type
                        base_args = resolved_base.args
                        if not base_args:
                            # ``class L(list)`` still behaves like a list of
                            # unknown element type for subscripting.
                            base_args = (ANY, ANY) if raw_base is dict else (ANY,)
                        class_info.builtin_base = (raw_base, base_args)
                    if not isinstance(base_node, ast.Subscript):
                        continue
                    if not isinstance(resolved_base, Instance):
                        continue
                    base_info = self.engine._classes.get(resolved_base.type.full_name)
                    if base_info is None:
                        continue
                    bindings = dict(base_info.type_var_bindings)
                    template = list(base_info.type_variables)
                    if template and resolved_base.args:
                        bindings.update(zip(template, resolved_base.args))
                    class_info.type_var_bindings.update(bindings)
                for base in class_info.bases:
                    base_info = self.engine._classes.get(base)
                    if base_info and base_info.instance.type.typed_dict_fields is not None:
                        class_info.instance.type.typed_dict_fields = dict(
                            base_info.instance.type.typed_dict_fields
                        )
                        class_info.instance.type.required_keys = (
                            base_info.instance.type.required_keys
                        )
                        class_info.attributes.update(base_info.attributes)
                decorator_texts = {
                    ast.unparse(item.func if isinstance(item, ast.Call) else item)
                    for item in node.decorator_list
                }
                decorator_names = {text.rsplit(".", 1)[-1] for text in decorator_texts}
                is_dataclass = "dataclass" in decorator_names
                is_attrs = any(
                    text == "attr.s" or text.startswith("attrs.") or text.startswith("attr.")
                    for text in decorator_texts
                )
                base_names = {base.rsplit(".", 1)[-1] for base in class_info.bases}
                is_model_class = bool(base_names & {"BaseModel", "BaseSettings", "Struct"})
                all_keyword_only = any(
                    keyword.arg == "kw_only"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for item in node.decorator_list
                    if isinstance(item, ast.Call)
                    for keyword in item.keywords
                )
                for base in class_info.bases:
                    base_info = self.engine._classes.get(base)
                    if base_info is not None:
                        class_info.constructor_fields.update(base_info.constructor_fields)
                        class_info.field_defaults.update(base_info.field_defaults)
                        class_info.keyword_only_fields.update(base_info.keyword_only_fields)
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        if self._is_dataclass_pseudo_annotation(item.annotation):
                            continue
                        val_annotation = self._annotation_value(item.annotation)
                        is_bare = (
                            isinstance(item.annotation, ast.Name)
                            and item.annotation.id in {"Final", "ClassVar"}
                        ) or (
                            isinstance(item.annotation, ast.Attribute)
                            and item.annotation.attr in {"Final", "ClassVar"}
                        )
                        if is_bare and item.value is not None:
                            val_annotation = self.engine._expression_rules._evaluate_expression(
                                item.value, {}, scope=qualified, current_function=None
                            )
                        class_info.attributes[item.target.id] = val_annotation
                        if (
                            is_dataclass or is_attrs or is_model_class
                        ) and not self._is_class_var_annotation(item.annotation):
                            field_name = item.target.id
                            has_default = item.value is not None
                            init_field = True
                            field_kw_only = all_keyword_only
                            if isinstance(item.value, ast.Call):
                                callee = ast.unparse(item.value.func).rsplit(".", 1)[-1]
                                if callee in {"field", "ib", "attrib"}:
                                    for keyword in item.value.keywords:
                                        if keyword.arg == "init" and isinstance(
                                            keyword.value, ast.Constant
                                        ):
                                            init_field = keyword.value.value is not False
                                        elif keyword.arg in {
                                            "default",
                                            "default_factory",
                                            "factory",
                                        }:
                                            has_default = True
                                        elif keyword.arg == "kw_only" and isinstance(
                                            keyword.value, ast.Constant
                                        ):
                                            field_kw_only = keyword.value.value is True
                            if init_field:
                                class_info.constructor_fields[field_name] = val_annotation
                                if has_default:
                                    class_info.field_defaults.add(field_name)
                                if field_kw_only:
                                    class_info.keyword_only_fields.add(field_name)
                self._collect_declarations(
                    node.body,
                    parent=qualified,
                    owner=qualified,
                )
                descriptor = class_info.instance.type
                descriptor.members.update(
                    {
                        name: value.public_type() or ANY
                        for name, value in class_info.attributes.items()
                    }
                )
                if descriptor.typed_dict_fields is not None:
                    descriptor.typed_dict_fields.update(descriptor.members)
                    required = set(descriptor.required_keys)
                    total = not any(
                        keyword.arg == "total"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is False
                        for keyword in node.keywords
                    )
                    for item in node.body:
                        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                            wrapper = (
                                self.engine._value_rules._qualified_callee_name(
                                    item.annotation.value
                                )
                                if isinstance(item.annotation, ast.Subscript)
                                else ""
                            ) or ""
                            if wrapper.endswith("Required") and not wrapper.endswith("NotRequired"):
                                required.add(item.target.id)
                            elif wrapper.endswith("NotRequired"):
                                required.discard(item.target.id)
                            elif total:
                                required.add(item.target.id)
                    descriptor.required_keys = frozenset(required)
                if descriptor.tuple_fields is not None:
                    descriptor.tuple_fields = tuple(class_info.attributes)
                for name, target in class_info.methods.items():
                    signature = self.engine._function_rules._function_value(
                        self.engine._functions[target]
                    ).public_type()
                    if isinstance(signature, CallableType):
                        descriptor.members[name] = (
                            signature.return_type
                            if name in class_info.properties
                            else CallableType(
                                (
                                    signature.arg_types
                                    if self.engine._functions[target].method_kind == "static"
                                    else signature.arg_types[1:] if signature.arg_types else ()
                                ),
                                signature.return_type,
                            )
                        )
                self.engine._annotation_owner = previous_owner
                self.engine._type_vars = previous_vars
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                previous_vars = dict(self.engine._type_vars)
                self.engine._type_vars.update(self._pep695_type_variables(node))
                qualified = f"{parent}.{node.name}"
                accessor = next(
                    (
                        decorator.attr
                        for decorator in node.decorator_list
                        if isinstance(decorator, ast.Attribute)
                        and decorator.attr in {"setter", "deleter"}
                        and isinstance(decorator.value, ast.Name)
                        and decorator.value.id == node.name
                    ),
                    "",
                )
                getter = any(
                    (self.engine._value_rules._qualified_callee_name(decorator) or "").rsplit(
                        ".", 1
                    )[-1]
                    in {"property", "cached_property"}
                    for decorator in node.decorator_list
                    if not isinstance(decorator, ast.Call)
                )
                if owner and accessor:
                    qualified += f".<{accessor}>"
                parameters = [arg.arg for arg in _all_arguments(node.args)]
                info = _FunctionInfo(
                    qualified_name=qualified,
                    node=node,
                    parameter_names=parameters,
                    owner=owner,
                    type_variables=dict(self.engine._type_vars),
                )
                decorators = {
                    self.engine._value_rules._qualified_callee_name(item)
                    for item in node.decorator_list
                }
                if decorators & {"staticmethod", "builtins.staticmethod"}:
                    info.method_kind = "static"
                elif node.name == "__init_subclass__" or decorators & {
                    "classmethod",
                    "builtins.classmethod",
                }:
                    info.method_kind = "class"
                for arg in _all_arguments(node.args):
                    if arg.annotation is not None:
                        info.explicit_parameters[arg.arg] = self._annotation_value(arg.annotation)
                positional = [*node.args.posonlyargs, *node.args.args]
                if node.args.defaults:
                    for arg, default in zip(
                        positional[-len(node.args.defaults) :], node.args.defaults
                    ):
                        info.default_parameters[arg.arg] = default
                for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                    if default is not None:
                        info.default_parameters[arg.arg] = default
                if node.returns is not None:
                    info.explicit_return = self._annotation_value(node.returns)
                docstring = ast.get_docstring(node)
                if docstring:

                    def resolve_hint(text: str) -> ProperType | None:
                        return self._annotation_value(ast.Constant(value=text)).public_type()

                    for arg in _all_arguments(node.args):
                        if arg.annotation is None:
                            hint = resolve_documented_type(
                                search_param_in_docstr(docstring, arg.arg), resolve_hint
                            )
                            if hint is not None:
                                info.documented_parameters[arg.arg] = AbstractTypeValue.from_type(
                                    hint
                                )
                    if node.returns is None:
                        hint = resolve_documented_type(
                            search_return_in_docstr(docstring), resolve_hint
                        )
                        if hint is not None:
                            info.documented_return = AbstractTypeValue.from_type(hint)
                info.global_names = {
                    name
                    for statement in node.body
                    if isinstance(statement, ast.Global)
                    for name in statement.names
                }
                info.nonlocal_names = {
                    name
                    for statement in node.body
                    if isinstance(statement, ast.Nonlocal)
                    for name in statement.names
                }
                info.is_generator_source = self.engine._function_rules._contains_yield(node)
                if node.returns is not None and isinstance(node.returns, ast.Subscript):
                    guard_callee = self.engine._value_rules._qualified_callee_name(
                        node.returns.value
                    ) or (node.returns.value.id if isinstance(node.returns.value, ast.Name) else "")
                    guard_short = guard_callee.rsplit(".", 1)[-1]
                    if guard_short in {"TypeGuard", "TypeIs"}:
                        guard_target = self.engine._expression_rules._evaluate_type_expression(
                            node.returns.slice
                        )
                        first_param = info.parameter_names[0] if info.parameter_names else None
                        if first_param and not guard_target.unknown:
                            info.type_guard_target = (
                                first_param,
                                guard_target,
                                guard_short == "TypeIs",
                            )
                # ``overload`` is frequently re-exported from a project
                # module (``from ._types import overload``), so match the
                # short decorator name as well.
                is_overload = any(
                    name is not None and name.rsplit(".", 1)[-1] == "overload"
                    for name in decorators
                )
                if is_overload:
                    self.engine._overloads.setdefault(qualified, []).append(info)
                    if qualified not in self.engine._functions:
                        self.engine._functions[qualified] = info
                else:
                    info.overloads = list(self.engine._overloads.get(qualified, ()))
                    self.engine._functions[qualified] = info
                for decorator in node.decorator_list:
                    target = decorator.func if isinstance(decorator, ast.Call) else decorator
                    if not (
                        isinstance(target, ast.Attribute)
                        and target.attr in {"register", "dispatch"}
                    ):
                        continue
                    base_name = _expression_name(target.value)
                    if base_name is None:
                        continue
                    base = self.engine._value_rules._resolve_lexical_function(base_name, parent)
                    if base is None:
                        # ``@dispatcher.register`` on a method resolves to the
                        # class-qualified method, which lexical lookup skips
                        # because it belongs to an owner.
                        method_candidate = f"{parent}.{base_name}"
                        if method_candidate in self.engine._functions:
                            base = method_candidate
                    if base is not None and base != qualified:
                        self.engine._functions[base].overloads.append(info)
                        # Several registrations commonly share the ``_``
                        # placeholder name; keep each one analysable.
                        self.engine._functions.setdefault(f"{qualified}@{node.lineno}", info)
                info.effective_return = self.engine._function_rules._decorator_effective_return(
                    node, parent
                )
                self.engine._function_names.add(node.name)
                self.engine._function_nodes[id(node)] = qualified
                if owner is not None and not accessor:
                    self.engine._classes[owner].methods[node.name] = qualified
                    if getter:
                        self.engine._classes[owner].properties[node.name] = qualified
                    if node.name == "__init__" and parameters:
                        templates = self.engine._classes[owner].attribute_templates
                        for statement in ast.walk(node):
                            if isinstance(statement, ast.AnnAssign):
                                targets = [statement.target]
                                template = self._annotation_value(statement.annotation)
                            elif isinstance(statement, ast.Assign) and isinstance(
                                statement.value, ast.Name
                            ):
                                targets = statement.targets
                                template = info.explicit_parameters.get(statement.value.id)
                                if template is not None:
                                    template = self.engine._function_rules._body_parameter_value(
                                        info, statement.value.id, template
                                    )
                            else:
                                continue
                            for target in targets:
                                if (
                                    template is not None
                                    and isinstance(target, ast.Attribute)
                                    and isinstance(target.value, ast.Name)
                                    and target.value.id == parameters[0]
                                ):
                                    templates[target.attr] = template
                self._collect_declarations(
                    node.body,
                    parent=qualified,
                    owner=None,
                )
                self.engine._type_vars = previous_vars

    @staticmethod
    def _is_class_var_annotation(node: ast.expr) -> bool:
        base = node.value if isinstance(node, ast.Subscript) else node
        name = _expression_name(base) or ""
        return name.rsplit(".", 1)[-1] == "ClassVar"

    @staticmethod
    def _is_dataclass_pseudo_annotation(node: ast.expr) -> bool:
        base = node.value if isinstance(node, ast.Subscript) else node
        name = _expression_name(base) or ""
        return name.rsplit(".", 1)[-1] in {"KW_ONLY", "InitVar"}

    @staticmethod
    def _extract_match_args(node: ast.ClassDef) -> tuple[str, ...] | None:
        """Return a literal ``__match_args__`` declaration from a class body."""
        for item in node.body:
            target: ast.expr | None = None
            value: ast.expr | None = None
            if isinstance(item, ast.Assign) and len(item.targets) == 1:
                target = item.targets[0]
                value = item.value
            elif isinstance(item, ast.AnnAssign):
                target = item.target
                value = item.value
            if (
                isinstance(target, ast.Name)
                and target.id == "__match_args__"
                and isinstance(value, (ast.Tuple, ast.List))
                and all(
                    isinstance(element, ast.Constant) and isinstance(element.value, str)
                    for element in value.elts
                )
            ):
                return tuple(element.value for element in value.elts)
        return None

    def _precollect_classes(
        self,
        statements: Iterable[ast.stmt],
        *,
        parent: str,
    ) -> None:
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._precollect_classes(node.body, parent=f"{parent}.{node.name}")
                continue
            if not isinstance(node, ast.ClassDef):
                continue
            qualified = f"{parent}.{node.name}"
            bases = tuple(
                base_name
                for base in node.bases
                if (base_name := self.engine._value_rules._resolve_class_expression(base))
                is not None
            )
            self.engine._classes[qualified] = _ClassInfo(
                qualified,
                self.engine._value_rules._synthetic_instance(qualified),
                bases=bases,
                match_args=self._extract_match_args(node),
            )
            self.engine._class_aliases[node.name] = qualified
            descriptor = self.engine._classes[qualified].instance.type
            # Source classes rebuild their structure on every analysis pass.
            # Clear fields left by a previous revision of this module (for
            # example a NamedTuple or TypedDict that is now a plain class).
            # Stub descriptors are refreshed separately and keep their
            # incrementally populated members.
            descriptor.members.clear()
            descriptor.instance_attributes.clear()
            descriptor.attributes.clear()
            descriptor.typed_dict_fields = None
            descriptor.required_keys = frozenset()
            descriptor.tuple_fields = None
            descriptor.type_parameters = ()
            descriptor.has_unresolved_bases = False
            descriptor.is_protocol = any(base.rsplit(".", 1)[-1] == "Protocol" for base in bases)
            if any(base.rsplit(".", 1)[-1] == "TypedDict" for base in bases):
                descriptor.typed_dict_fields = {}
            if any(base.rsplit(".", 1)[-1] == "NamedTuple" for base in bases):
                descriptor.tuple_fields = ()
            variables = self._pep695_type_variables(node)
            for base_node in node.bases:
                if isinstance(base_node, ast.Subscript):
                    resolved_base = self._annotation_value(base_node).public_type()
                    if isinstance(resolved_base, Instance):
                        base_info = self.engine._classes.get(resolved_base.type.full_name)
                        if base_info is not None:
                            bindings = dict(base_info.type_var_bindings)
                            template = list(base_info.type_variables)
                            if template and resolved_base.args:
                                bindings.update(zip(template, resolved_base.args))
                            self.engine._classes[qualified].type_var_bindings.update(bindings)
                    for parameter in ast.walk(base_node.slice):
                        if (
                            isinstance(parameter, ast.Name)
                            and parameter.id in self.engine._type_vars
                        ):
                            variables[parameter.id] = self.engine._type_vars[parameter.id]
                    if not variables:
                        # ``class IntBox(Box[int])`` inherits Box's type
                        # parameters; constructor inference below binds them
                        # from the inherited __init__ arguments.
                        resolved = self._annotation_value(base_node).public_type()
                        if isinstance(resolved, Instance) and resolved.args:
                            base_info = self.engine._classes.get(resolved.type.full_name)
                            if base_info is not None and base_info.type_variables:
                                variables = dict(base_info.type_variables)
            self.engine._classes[qualified].type_variables = variables
            descriptor.type_parameters = tuple(variables.values())
            for base in bases:
                base_type = self._lookup_annotation_type(base)
                if not isinstance(base_type, Instance):
                    # The base could not be resolved to a class at all.
                    descriptor.has_unresolved_bases = True
                    continue
                self.engine.type_system.add_subclass_edge(
                    super_class=base_type.type,
                    sub_class=self.engine._classes[qualified].instance.type,
                )
                if getattr(
                    base_type.type.raw_type,
                    "__pyflow_unresolved_external__",
                    False,
                ):
                    # Members and ancestry of this base are unknown, so
                    # structural checks must stay conservative.
                    descriptor.has_unresolved_bases = True
                if base_type.type.typed_dict_fields is not None:
                    descriptor.typed_dict_fields = dict(base_type.type.typed_dict_fields)
                    descriptor.required_keys = base_type.type.required_keys
            enum_kind = next(
                (
                    kind
                    for base in bases
                    if (kind := self.engine._member_rules._enum_base_kind(base)) is not None
                ),
                None,
            )
            if enum_kind in {"IntEnum", "IntFlag"}:
                self.engine.type_system.add_subclass_edge(
                    super_class=self.engine.type_system.to_class_descriptor(int),
                    sub_class=self.engine._classes[qualified].instance.type,
                )
            elif enum_kind == "StrEnum":
                self.engine.type_system.add_subclass_edge(
                    super_class=self.engine.type_system.to_class_descriptor(str),
                    sub_class=self.engine._classes[qualified].instance.type,
                )
            if enum_kind is not None:
                self.engine._classes[qualified].instance.type.enum_kind = enum_kind
                for item in node.body:
                    targets: list[ast.expr] = []
                    if isinstance(item, ast.Assign):
                        targets = list(item.targets)
                    elif isinstance(item, ast.AnnAssign):
                        targets = [item.target]
                    for target in targets:
                        if isinstance(target, ast.Name) and not target.id.startswith("_"):
                            self.engine._classes[qualified].enum_values.setdefault(
                                target.id, AbstractTypeValue.from_type(ANY)
                            )
            self._precollect_classes(node.body, parent=qualified)

    def _collect_type_variables(self, statements: Iterable[ast.stmt]) -> None:
        for node in statements:
            if isinstance(node, ast.If):
                self._collect_type_variables(node.body)
                self._collect_type_variables(node.orelse)
                continue
            if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                self._collect_type_variables(node.body)
                for handler in node.handlers:
                    self._collect_type_variables(handler.body)
                self._collect_type_variables(node.orelse)
                self._collect_type_variables(node.finalbody)
                continue
            if isinstance(node, getattr(ast, "TypeAlias", ())):
                self.engine._type_aliases[node.name.id] = node.value
                self.engine._alias_type_variables[node.name.id] = self._pep695_type_variables(node)
                continue
            if isinstance(node, ast.ClassDef):
                self._collect_type_variables(node.body)
                continue
            if (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.value is not None
                and self.engine._value_rules._qualified_callee_name(node.annotation)
                in {"typing.TypeAlias", "typing_extensions.TypeAlias"}
            ):
                self.engine._type_aliases[node.target.id] = node.value
                continue
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            value = node.value
            if isinstance(target, ast.Name) and self._is_type_alias_expression(value):
                self.engine._type_aliases[target.id] = value
                continue
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Call)
                and self.engine._value_rules._qualified_callee_name(value.func)
                in {"typing.NewType", "typing_extensions.NewType"}
                and len(value.args) >= 2
            ):
                if self._register_new_type(target.id, value):
                    continue
                self.engine._type_aliases[target.id] = value.args[1]
                continue
            if not (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Call)
                and isinstance(value.func, (ast.Name, ast.Attribute))
                and self.engine._value_rules._qualified_callee_name(value.func)
                in {"TypeVar", "typing.TypeVar", "typing_extensions.TypeVar"}
            ):
                if isinstance(target, ast.Name):
                    self.engine._value_assignments.add(target.id)
                continue
            constraints = tuple(
                resolved
                for argument in value.args[1:]
                if (
                    resolved := self.engine._expression_rules._evaluate_type_expression(
                        argument
                    ).public_type()
                )
                is not None
            )
            bound = None
            variance = Variance.INVARIANT
            for keyword in value.keywords:
                if keyword.arg == "bound":
                    bound = self.engine._expression_rules._evaluate_type_expression(
                        keyword.value
                    ).public_type()
                elif (
                    keyword.arg == "covariant"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value
                ):
                    variance = Variance.COVARIANT
                elif (
                    keyword.arg == "contravariant"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value
                ):
                    variance = Variance.CONTRAVARIANT
            self.engine._type_vars[target.id] = TypeVarType(
                target.id,
                constraints=constraints,
                bound=bound,
                variance=variance,
            )

    def _register_new_type(self, name: str, call: ast.Call) -> bool:
        """Model ``Name = NewType("Name", Base)`` as a distinct nominal type.

        mypy keeps ``NewType`` result types nominally distinct while allowing
        them to flow to the wrapped type.  Treating the call as a plain alias
        (the previous behaviour) erased that distinction everywhere.
        """
        base = self._lookup_annotation_type(ast.unparse(call.args[1]))
        if not isinstance(base, Instance):
            return False
        base_raw = base.type.raw_type
        if not isinstance(base_raw, type):
            return False
        qualified = f"{self.engine._module_name}.{name}"
        existing = self.engine._classes.get(qualified)
        if existing is not None:
            return existing.newtype_base is not None
        try:
            raw = type(name, (base_raw,), {"__module__": self.engine._module_name})
        except TypeError:
            return False
        self.engine._synthetic_types[qualified] = raw
        descriptor = self.engine.type_system.to_class_descriptor(raw)
        descriptor.members.clear()
        descriptor.instance_attributes.clear()
        descriptor.attributes.clear()
        descriptor.has_unresolved_bases = False
        class_info = _ClassInfo(
            qualified,
            Instance(descriptor),
            bases=(base.type.full_name,),
            newtype_base=base,
        )
        self.engine._classes[qualified] = class_info
        self.engine._class_aliases[name] = qualified
        self.engine.type_system.add_subclass_edge(super_class=base.type, sub_class=descriptor)
        return True

    def _is_type_alias_expression(self, node: ast.expr) -> bool:
        """Recognize type syntax without treating ordinary indexing as an alias."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self._is_type_alias_expression(node.left) and self._is_type_alias_expression(
                node.right
            )
        if isinstance(node, ast.Constant):
            # ``X = None`` is a common sentinel value, not a type alias.
            # Treating it as one makes every later ``Y = X`` resolve to NoneType.
            return False
        base = node.value if isinstance(node, ast.Subscript) else node
        name = _expression_name(base)
        if name is None:
            return False
        if name in self.engine._value_assignments or name in self.engine._function_names:
            # A local value/function shadows a builtin type name.
            return False
        if self.engine._value_rules._resolve_import_name(name) in self.engine._module_names:
            # ``import time`` binds a module, even though a bare ``time``
            # annotation means ``datetime.time``.
            return False
        if name in self.engine._class_aliases:
            class_info = self.engine._classes.get(self.engine._class_aliases[name])
            if self.engine._member_rules._is_enum_class_info(class_info):
                return False
            return True
        if name in self.engine._type_aliases or name in self.engine._type_vars:
            return True
        qualified = self.engine._value_rules._qualified_callee_name(base) or name
        if qualified.startswith(("typing.", "typing_extensions.", "collections.abc.")):
            return True
        return BuiltinTypeLookup()(qualified) is not None

    def _pep695_type_variables(self, node: ast.AST) -> dict[str, TypeVarType]:
        variables = {}
        for parameter in getattr(node, "type_params", ()):
            bound_node = getattr(parameter, "bound", None)
            constraints = ()
            bound = None
            if isinstance(bound_node, ast.Tuple):
                constraints = tuple(
                    self._annotation_value(item).public_type() or ANY for item in bound_node.elts
                )
            elif bound_node is not None:
                bound = self._annotation_value(bound_node).public_type()
            variables[parameter.name] = TypeVarType(
                parameter.name, bound=bound, constraints=constraints
            )
        return variables

    def _annotation_value(self, node: ast.expr) -> AbstractTypeValue:
        if isinstance(node, ast.Starred) or (
            isinstance(node, ast.Subscript)
            and self.engine._value_rules._qualified_callee_name(node.value)
            in {
                "Unpack",
                "typing.Unpack",
                "typing_extensions.Unpack",
            }
        ):
            # Variadic parameter annotations are not fully modelled yet.
            # Treat them as gradual evidence instead of re-specializing the
            # same call until project inference hits its iteration limit.
            return AbstractTypeValue.from_type(ANY)
        try:
            text = ast.unparse(node)
        except Exception:
            return AbstractTypeValue.unresolved()
        resolved = resolve_annotation(
            text,
            cast(TypeLookup, self._lookup_annotation_type),
            aliases=self._annotation_aliases(),
            type_parameters={
                name: tuple(parameters)
                for name, parameters in self.engine._alias_type_variables.items()
            },
        )
        if resolved is None:
            # A bare, dotted annotation name that resolves to nothing at all is
            # the mypy ``name-defined`` case (undefined class/alias).  Nested
            # forms stay silent: partial resolution is common for typing
            # constructs PyFlow does not model yet.
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", text):
                self.engine._add_diagnostic(
                    "name-defined",
                    f'Name "{text}" is not defined',
                    node=node,
                )
            return AbstractTypeValue.unresolved()
        missing_external, unresolved_project = self._unresolved_annotation_kinds(resolved)
        if missing_external:
            # A dependency that is not installed is a gradual type, exactly
            # like mypy: the fact we *do* know (``MapAdapter | None`` keeps the
            # ``None``) survives, the unknown part becomes ``Any``, and the
            # module is still fully analysed.
            resolved = self._replace_missing_external(resolved)
            self.engine._add_diagnostic(
                "missing-external-type",
                f"No external type facts for annotation {text}",
                node=node,
            )
        if unresolved_project:
            self.engine._add_diagnostic(
                "unresolved-annotation",
                f"Could not resolve annotation {text}",
                node=node,
                affects_completeness=True,
            )
        uncertain = missing_external or unresolved_project
        return AbstractTypeValue.from_type(resolved, unknown=uncertain)

    def _annotation_aliases(self):
        aliases = {}
        for name, target in self.engine._imports.items():
            if (
                name in self.engine._class_aliases
                or f"{self.engine._module_name}.{name}" in self.engine._functions
            ):
                continue
            aliases[name] = self._typing_reexport_alias(target) or target
        return aliases

    def _typing_reexport_alias(self, target: str) -> str | None:
        """Map ``from ._types import Union`` back to ``typing.Union``."""
        module_name, _, attribute = target.rpartition(".")
        if not module_name or not _is_typing_surface_name(attribute):
            return None
        resolution = self.engine.project_context.find_module(module_name)
        if resolution is None or resolution.path is None:
            return None
        return f"typing.{attribute}"

    def _unresolved_annotation_kinds(self, typ) -> tuple[bool, bool]:
        """Classify unresolved placeholders in a resolved annotation.

        Returns ``(missing_external, unresolved_project)``.  A placeholder for
        an importable-but-absent third-party module is a gradual ``Any``; a
        placeholder for a project (or stdlib) symbol means analysis failed and
        the result must stay ``partial``.
        """
        missing = False
        project = False
        for full_name in self._unresolved_annotation_names(typ):
            module_name, separator, _ = full_name.rpartition(".")
            if separator and self.engine.project_context.find_module(module_name) is None:
                missing = True
            else:
                project = True
        return missing, project

    @staticmethod
    def _unresolved_annotation_names(typ) -> list[str]:
        names: list[str] = []
        if isinstance(typ, Instance):
            if getattr(typ.type.raw_type, "__pyflow_unresolved_external__", False):
                names.append(typ.type.full_name)
            for item in typ.args:
                names.extend(DeclarationInference._unresolved_annotation_names(item))
        elif isinstance(typ, (UnionType, TupleType)):
            for item in typ.items if isinstance(typ, UnionType) else typ.args:
                names.extend(DeclarationInference._unresolved_annotation_names(item))
        elif isinstance(typ, TypeType):
            names.extend(DeclarationInference._unresolved_annotation_names(typ.item))
        elif isinstance(typ, CallableType):
            names.extend(DeclarationInference._unresolved_annotation_names(typ.return_type))
            for item in typ.arg_types or ():
                names.extend(DeclarationInference._unresolved_annotation_names(item))
        return names

    @staticmethod
    def _replace_missing_external(typ):
        """Replace unresolved external placeholders with ``Any``."""
        if isinstance(typ, Instance):
            if getattr(typ.type.raw_type, "__pyflow_unresolved_external__", False):
                return ANY
            if not typ.args:
                return typ
            args = tuple(DeclarationInference._replace_missing_external(item) for item in typ.args)
            return typ if args == typ.args else Instance(typ.type, args)
        if isinstance(typ, UnionType):
            items = tuple(
                DeclarationInference._replace_missing_external(item) for item in typ.items
            )
            return typ if items == typ.items else UnionType(items)
        if isinstance(typ, TupleType):
            args = tuple(DeclarationInference._replace_missing_external(item) for item in typ.args)
            return typ if args == typ.args else TupleType(args, unknown_size=typ.unknown_size)
        if isinstance(typ, TypeType):
            item = DeclarationInference._replace_missing_external(typ.item)
            return typ if item == typ.item else TypeType(item)
        if isinstance(typ, CallableType):
            args = (
                tuple(
                    DeclarationInference._replace_missing_external(item) for item in typ.arg_types
                )
                if typ.arg_types is not None
                else None
            )
            returned = DeclarationInference._replace_missing_external(typ.return_type)
            if args == typ.arg_types and returned == typ.return_type:
                return typ
            return CallableType(args, returned, overloads=typ.overloads)
        return typ

    @staticmethod
    def _has_unresolved_annotation(typ):
        if isinstance(typ, Instance):
            return bool(getattr(typ.type.raw_type, "__pyflow_unresolved_external__", False)) or any(
                DeclarationInference._has_unresolved_annotation(item) for item in typ.args
            )
        if isinstance(typ, (UnionType, TupleType)):
            return any(
                DeclarationInference._has_unresolved_annotation(item)
                for item in (typ.items if isinstance(typ, UnionType) else typ.args)
            )
        if isinstance(typ, TypeType):
            return DeclarationInference._has_unresolved_annotation(typ.item)
        if isinstance(typ, CallableType):
            return DeclarationInference._has_unresolved_annotation(typ.return_type) or any(
                DeclarationInference._has_unresolved_annotation(item)
                for item in typ.arg_types or ()
            )
        return False

    @staticmethod
    def _contains_type_var(typ) -> bool:
        if isinstance(typ, TypeVarType):
            return True
        if isinstance(typ, Instance):
            return any(DeclarationInference._contains_type_var(item) for item in typ.args)
        if isinstance(typ, (UnionType, TupleType)):
            return any(
                DeclarationInference._contains_type_var(item)
                for item in (typ.items if isinstance(typ, UnionType) else typ.args)
            )
        if isinstance(typ, TypeType):
            return DeclarationInference._contains_type_var(typ.item)
        if isinstance(typ, CallableType):
            return DeclarationInference._contains_type_var(typ.return_type) or any(
                DeclarationInference._contains_type_var(item) for item in typ.arg_types or ()
            )
        return False

    def _lookup_annotation_type(self, name: str) -> ProperType | None:
        normalized = name.rsplit(".", 1)[-1]
        if normalized in self.engine._annotation_substitutions:
            return self.engine._annotation_substitutions[normalized]
        if normalized == "Self" and self.engine._annotation_owner:
            return TypeVarType(
                "Self", bound=self.engine._classes[self.engine._annotation_owner].instance
            )
        if name in self.engine._type_aliases and name not in self.engine._resolving_aliases:
            self.engine._resolving_aliases.add(name)
            previous_vars = self.engine._type_vars
            self.engine._type_vars = {
                **previous_vars,
                **self.engine._alias_type_variables.get(name, {}),
            }
            try:
                return self._annotation_value(self.engine._type_aliases[name]).public_type()
            finally:
                self.engine._type_vars = previous_vars
                self.engine._resolving_aliases.remove(name)
        type_var = self.engine._type_vars.get(name) or self.engine._type_vars.get(normalized)
        if type_var is not None:
            return type_var
        local = self.engine._class_aliases.get(name) or self.engine._class_aliases.get(normalized)
        if local is not None:
            return self.engine._classes[local].instance

        class_name, separator, member_name = name.rpartition(".")
        if separator:
            resolved_class_name = class_name
            if resolved_class_name not in self.engine._classes:
                resolved_class_name = self.engine._class_aliases.get(class_name, class_name)
            class_info = self.engine._classes.get(resolved_class_name)
            if (
                class_info is not None
                and class_info.enum_values
                and member_name in class_info.enum_values
            ):
                return LiteralType(
                    ("enum", class_info.qualified_name, member_name),
                    class_info.instance,
                )

        imported = self.engine._value_rules._resolve_import_name(name)
        if imported is not None:
            external = self.engine._member_rules._external_type(imported)
            if external is not None:
                if isinstance(external, TypeType):
                    external = external.item
                if (
                    isinstance(external, CallableType)
                    and external.arg_types
                    and len(external.arg_types) == 1
                    and external.return_type == external.arg_types[0]
                ):
                    # Cross-module ``NewType`` aliases are exposed as their
                    # identity constructor; annotations should use the wrapped
                    # type.
                    external = external.arg_types[0]
                return external
            builtin = BuiltinTypeLookup()(imported)
            if builtin is not None:
                external = self.engine._member_rules._external_type(imported)
                if external is not None:
                    if isinstance(external, TypeType):
                        external = external.item
                    if (
                        isinstance(external, CallableType)
                        and external.arg_types
                        and len(external.arg_types) == 1
                        and external.return_type == external.arg_types[0]
                    ):
                        external = external.arg_types[0]
                    return external
                return builtin
            # ``from ._types import Pattern`` style re-exports resolve to a
            # synthetic placeholder otherwise; retry the typing spelling so
            # stdlib typing/collections names keep their real types.
            target_module, _, attribute = imported.rpartition(".")
            if (
                target_module
                and _is_typing_surface_name(attribute)
                and self.engine.project_context.find_module(target_module) is not None
            ):
                typing_builtin = BuiltinTypeLookup()(f"typing.{attribute}")
                if typing_builtin is not None:
                    return typing_builtin
            return self.engine._value_rules._synthetic_instance(imported, unresolved=True)

        external = self.engine._member_rules._external_type(name)
        if external is not None:
            if isinstance(external, TypeType):
                external = external.item
            return external
        builtin = BuiltinTypeLookup()(name)
        if builtin is not None:
            return builtin
        qualified = f"{self.engine._module_name}.{name}"
        if qualified in self.engine._classes:
            return self.engine._classes[qualified].instance
        return None

    def _declaration_environment(self) -> dict[str, AbstractTypeValue]:
        environment: dict[str, AbstractTypeValue] = {}
        module_prefix = f"{self.engine._module_name}."
        for name, class_info in self.engine._classes.items():
            remainder = name.removeprefix(module_prefix)
            if "." not in remainder:
                environment[remainder] = AbstractTypeValue.from_type(
                    class_info.instance,
                    class_target=name,
                )
        for name, function in self.engine._functions.items():
            remainder = name.removeprefix(module_prefix)
            if "." not in remainder:
                environment[remainder] = self.engine._function_rules._function_value(function)
        return environment

    def _refresh_class_member_signatures(self) -> None:
        """Refresh descriptor members after unannotated methods are summarized."""
        for class_info in self.engine._classes.values():
            for name, target in class_info.methods.items():
                function = self.engine._functions.get(target)
                if function is None:
                    continue
                if function.explicit_return is not None and all(
                    parameter in function.explicit_parameters
                    for parameter in function.parameter_names
                ):
                    # Fully annotated signatures are deterministic; only
                    # methods whose member type depends on inferred summaries
                    # need a refresh on every fixed-point pass.
                    continue
                signature = self.engine._function_rules._function_value(function).public_type()
                if not isinstance(signature, CallableType):
                    continue
                if name in class_info.properties:
                    class_info.instance.type.members[name] = signature.return_type
                elif function.method_kind == "static":
                    class_info.instance.type.members[name] = signature
                else:
                    overloads = tuple(
                        CallableType(
                            overload.arg_types[1:] if overload.arg_types else (),
                            overload.return_type,
                        )
                        for overload in signature.overloads
                    )
                    class_info.instance.type.members[name] = CallableType(
                        signature.arg_types[1:] if signature.arg_types else (),
                        signature.return_type,
                        overloads=overloads,
                    )
        self.engine.type_system.invalidate_subtype_caches()
