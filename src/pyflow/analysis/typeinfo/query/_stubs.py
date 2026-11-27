"""Stub module collection and declaration resolution mixin for TypeInfoService."""

from __future__ import annotations

import ast

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NONE_TYPE,
    CallableType,
    Instance,
    ProperType,
    TypeType,
    TypeVarType,
    UnionType,
)
from pyflow.analysis.typeinfo.query.models import (
    ClassTypeInfo,
    FunctionTypeInfo,
    TypeFact,
)
from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup
from pyflow.language.modules.type_stubs import (
    StubAliasInfo,
    StubClassInfo,
    StubFunctionInfo,
    StubImportInfo,
    StubInfo,
    StubTypeVarInfo,
)

from ._helpers import (
    _annotation_to_str,
    _split_annotation_arguments,
    _stub_variance,
)


class _StubCollectionMixin:
    """Collect and resolve ``.pyi`` stub modules, aliases, TypeVars, and classes."""

    def _collect_stub_module(
        self,
        module_name: str,
        path: str,
        info: StubInfo,
    ) -> None:
        facts = self._module_facts.setdefault(module_name, {})
        module_functions = self._functions.setdefault(module_name, {})
        imports = self._stub_import_aliases(module_name, path, info.imports)
        self._module_imports[module_name] = imports
        if info.exports is not None:
            self._module_all[module_name] = info.exports

        module_aliases = self._module_class_aliases.setdefault(module_name, {})
        for cls in info.classes:
            qualified_name = f"{module_name}.{cls.name}"
            self._class_aliases[cls.name] = qualified_name
            module_aliases[cls.name] = qualified_name

        self._module_stub_type_vars[module_name] = {
            declaration.name: declaration for declaration in info.type_vars
        }
        self._module_stub_aliases[module_name] = {alias.name: alias for alias in info.aliases}
        self._module_type_aliases.setdefault(module_name, {})

        stub_collect_missing = self._module_may_be_project(module_name)
        for cls in info.classes:
            class_info = self._class_info_from_stub(
                module_name,
                cls,
                imports,
                collect_missing=stub_collect_missing,
            )
            self._classes[class_info.name] = class_info
            facts[cls.name] = TypeFact(
                name=cls.name,
                typ=class_info.typ,
                raw_annotation=class_info.name,
                source="stub",
                kind="class",
            )

        functions_by_name: dict[str, list[StubFunctionInfo]] = {}
        for function in info.functions:
            functions_by_name.setdefault(function.name, []).append(function)
        for name, declarations in functions_by_name.items():
            infos = [
                self._function_info_from_stub(
                    function,
                    module_name=module_name,
                    imports=imports,
                    collect_missing=stub_collect_missing,
                )
                for function in declarations
            ]
            module_functions[name] = infos[0]
            returns: list[ProperType] = []
            for info_item in infos:
                if info_item.returns is None or info_item.returns in returns:
                    continue
                returns.append(info_item.returns)
            if len(returns) > 1:
                callable_type: ProperType = CallableType(
                    None,
                    UnionType(tuple(returns)),
                    overloads=tuple(self._callable_type(item) for item in infos),
                )
                raw_annotation = "overload"
            else:
                callable_type = self._callable_type(infos[0])
                raw_annotation = declarations[0].returns
            facts[name] = TypeFact(
                name=name,
                typ=callable_type,
                raw_annotation=raw_annotation,
                source="stub",
                kind="function",
            )

        for name, annotation in info.variables:
            facts[name] = TypeFact(
                name=name,
                typ=self._resolve_annotation(
                    annotation,
                    module_name=module_name,
                    imports=imports,
                    collect_missing=stub_collect_missing,
                ),
                raw_annotation=annotation,
                source="stub",
                kind="variable",
            )

        for alias in info.aliases:
            alias_type = self._resolve_stub_definition(module_name, alias.name)
            if alias_type is None:
                continue
            facts[alias.name] = TypeFact(
                name=alias.name,
                typ=alias_type,
                raw_annotation=alias.value,
                source="stub",
                kind="function" if isinstance(alias_type, CallableType) else "variable",
            )

        for local_name, qualified_name in imports.items():
            if local_name in facts:
                continue
            imported_type = self._lookup_project_type(
                qualified_name,
                allow_synthetic=False,
                collect_missing=False,
            )
            if imported_type is None:
                imported_type = BuiltinTypeLookup()(qualified_name)
            if imported_type is not None:
                facts[local_name] = TypeFact(
                    name=local_name,
                    typ=imported_type,
                    raw_annotation=qualified_name,
                    source="import",
                    kind="import",
                )
            elif "." in qualified_name:
                target_mod = qualified_name.rsplit(".", 1)[0]
                if self._module_should_be_collected(target_mod):
                    self._lazy_stub_imports.add((module_name, local_name))
                    facts[local_name] = TypeFact(
                        name=local_name,
                        typ=ANY,
                        raw_annotation=qualified_name,
                        source="import",
                        kind="import",
                    )

    def _resolve_stub_definition(self, module_name: str, name: str) -> ProperType | None:
        """Resolve a module-local stub TypeVar or alias, with cycle protection."""
        cached = self._module_type_aliases.get(module_name, {}).get(name)
        if cached is not None:
            return cached
        key = (module_name, name)
        if key in self._resolving_stub_aliases:
            return None
        declaration = self._module_stub_type_vars.get(module_name, {}).get(name)
        alias = self._module_stub_aliases.get(module_name, {}).get(name)
        if declaration is None and alias is None:
            return None
        self._resolving_stub_aliases.add(key)
        try:
            if declaration is not None:
                resolved = self._resolve_stub_type_var(module_name, declaration)
            else:
                assert alias is not None
                resolved = self._resolve_stub_alias_type(module_name, alias)
            if resolved is not None:
                self._module_type_aliases.setdefault(module_name, {})[name] = resolved
            return resolved
        finally:
            self._resolving_stub_aliases.discard(key)

    def _resolve_stub_type_var(
        self,
        module_name: str,
        declaration: StubTypeVarInfo,
    ) -> ProperType | None:
        imports = self._module_imports.get(module_name, {})
        if declaration.kind != "typevar":
            return ANY
        if declaration.default is not None:
            resolved = self._resolve_annotation(
                declaration.default,
                module_name=module_name,
                imports=imports,
            )
            if resolved is not None:
                return resolved
        constraints = [
            resolved
            for constraint in declaration.constraints
            if (
                resolved := self._resolve_annotation(
                    constraint,
                    module_name=module_name,
                    imports=imports,
                )
            )
            is not None
        ]
        if constraints:
            return TypeVarType(
                declaration.name,
                constraints=tuple(dict.fromkeys(constraints)),
                variance=_stub_variance(declaration),
            )
        if declaration.bound is not None:
            bound = self._resolve_annotation(
                declaration.bound,
                module_name=module_name,
                imports=imports,
            )
            return TypeVarType(
                declaration.name,
                bound=bound,
                variance=_stub_variance(declaration),
            )
        return TypeVarType(declaration.name, variance=_stub_variance(declaration))

    def _resolve_stub_alias_type(
        self,
        module_name: str,
        alias: StubAliasInfo,
    ) -> ProperType | None:
        value = alias.value.strip()
        if not value or value == "...":
            return None
        imports = self._module_imports.get(module_name, {})
        resolved = self._resolve_annotation(
            value,
            module_name=module_name,
            imports=imports,
        )
        if resolved is not None:
            return resolved
        return self._resolve_stub_value_expression(module_name, value, imports)

    def _resolve_stub_value_expression(
        self,
        module_name: str,
        expression: str,
        imports: dict[str, str],
    ) -> ProperType | None:
        try:
            node = ast.parse(expression, mode="eval").body
        except (SyntaxError, ValueError):
            return None
        return self._resolve_stub_expression_node(module_name, node, imports)

    def _resolve_stub_expression_node(
        self,
        module_name: str,
        node: ast.expr,
        imports: dict[str, str],
    ) -> ProperType | None:
        if isinstance(node, ast.Name):
            fact = self._module_facts.get(module_name, {}).get(node.id)
            if fact is not None and fact.typ is not None:
                return fact.typ
            return self._lookup_type(node.id, module_name=module_name, imports=imports)
        if isinstance(node, ast.Attribute):
            base = self._resolve_stub_expression_node(module_name, node.value, imports)
            return self._stub_member_type(base, node.attr)
        if isinstance(node, ast.Constant):
            value = node.value
            if value is None:
                return NONE_TYPE
            raw = {bool: bool, int: int, float: float, complex: complex, str: str, bytes: bytes}
            for raw_type, annotation in raw.items():
                if isinstance(value, raw_type) and not (
                    raw_type is int and isinstance(value, bool)
                ):
                    return self._synthetic_builtin(annotation)
            return None
        if isinstance(node, ast.Subscript):
            return self._resolve_annotation(
                _annotation_to_str(node),
                module_name=module_name,
                imports=imports,
            )
        if isinstance(node, ast.Call):
            name = _annotation_to_str(node.func).rsplit(".", 1)[-1]
            if name in {"NewType", "TypeAliasType"} and len(node.args) >= 2:
                return self._resolve_annotation(
                    _annotation_to_str(node.args[1]),
                    module_name=module_name,
                    imports=imports,
                )
            return None
        return None

    def _stub_member_type(self, base: ProperType | None, attribute: str) -> ProperType | None:
        if isinstance(base, TypeType):
            base = base.item
        if not isinstance(base, Instance):
            return None
        class_info = self._classes.get(base.type.full_name)
        if class_info is None:
            return self._class_member_type(base.type.full_name, attribute)
        member = class_info.typ.type.members.get(attribute)
        from_members = member is not None
        if member is None:
            member = self._class_member_type(base.type.full_name, attribute)
        method = class_info.methods.get(attribute)
        if isinstance(member, CallableType):
            arguments = member.arg_types
            if (
                not from_members
                and method is not None
                and method.method_kind != "static"
                and arguments
            ):
                arguments = tuple(arguments[1:])
            return CallableType(
                arguments,
                member.return_type,
                overloads=member.overloads,
            )
        return member

    def _synthetic_builtin(self, raw_type: type) -> ProperType:
        return Instance(self.type_system.to_class_descriptor(raw_type))

    def _stub_import_aliases(
        self,
        module_name: str,
        path: str,
        imports_raw: list[StubImportInfo],
    ) -> dict[str, str]:
        imports: dict[str, str] = {}
        for item in imports_raw:
            if not item.is_from:
                for imported_name, asname in item.names:
                    local = asname or imported_name.split(".")[0]
                    imports[local] = imported_name if asname else local
                continue

            source_module = self.project_context.resolve_import_name(
                module_name,
                item.module or "",
                item.level,
                current_path=path,
            )
            if not source_module:
                continue
            for imported_name, asname in item.names:
                if imported_name == "*":
                    self.collect_module(source_module)
                    exported_names = self._module_all.get(source_module)
                    if exported_names is None:
                        exported_names = frozenset(
                            name
                            for name in self._module_facts.get(source_module, {})
                            if not name.startswith("_")
                        )
                    for exported_name in exported_names:
                        imports[exported_name] = f"{source_module}.{exported_name}"
                    continue
                local = asname or imported_name
                imports[local] = f"{source_module}.{imported_name}"
        return imports

    def _function_info_from_stub(
        self,
        function: StubFunctionInfo,
        *,
        module_name: str,
        imports: dict[str, str],
        collect_missing: bool = True,
    ) -> FunctionTypeInfo:
        raw_params = {name: annotation for name, annotation in function.params}
        decorators = {decorator.rsplit(".", 1)[-1] for decorator in function.decorators}
        return FunctionTypeInfo(
            name=function.name,
            params={
                name: self._resolve_annotation(
                    annotation,
                    module_name=module_name,
                    imports=imports,
                    collect_missing=collect_missing,
                )
                for name, annotation in raw_params.items()
            },
            returns=self._resolve_annotation(
                function.returns,
                module_name=module_name,
                imports=imports,
                collect_missing=collect_missing,
            ),
            raw_params=raw_params,
            raw_returns=function.returns,
            source="stub",
            is_property=bool(decorators & {"property", "cached_property"}),
            method_kind=(
                "static"
                if "staticmethod" in decorators
                else "class" if "classmethod" in decorators else "instance"
            ),
        )

    def _class_info_from_stub(
        self,
        module_name: str,
        cls: StubClassInfo,
        imports: dict[str, str],
        *,
        collect_missing: bool = True,
    ) -> ClassTypeInfo:
        qualified_name = f"{module_name}.{cls.name}"
        members = {
            name: TypeFact(
                name=name,
                typ=self._resolve_annotation(
                    annotation,
                    module_name=module_name,
                    imports=imports,
                    collect_missing=collect_missing,
                ),
                raw_annotation=annotation,
                source="stub",
                kind="class_var",
            )
            for name, annotation in cls.class_vars
        }
        class_typ = self._synthetic_instance(qualified_name)
        if any(base.rsplit(".", 1)[-1].partition("[")[0] == "Protocol" for base in cls.bases):
            class_typ.type.is_protocol = True
        type_parameters: list[TypeVarType] = []
        for base in cls.bases:
            head, _, rest = base.partition("[")
            if not rest:
                continue
            generic_base = head.rsplit(".", 1)[-1] in {"Generic", "Protocol"}
            parameters = (
                _split_annotation_arguments(rest.rsplit("]", 1)[0]) if rest.endswith("]") else []
            )
            for parameter in parameters:
                resolved = self._resolve_stub_definition(module_name, parameter.strip())
                if isinstance(resolved, TypeVarType) and resolved not in type_parameters:
                    type_parameters.append(resolved)
            if generic_base:
                continue
        if type_parameters:
            class_typ.type.type_parameters = tuple(type_parameters)
        grouped_methods: dict[str, list[FunctionTypeInfo]] = {}
        for method in cls.methods:
            method_info = self._specialize_self_method(
                self._function_info_from_stub(
                    method,
                    module_name=module_name,
                    imports=imports,
                    collect_missing=collect_missing,
                ),
                class_typ,
            )
            grouped_methods.setdefault(method.name, []).append(method_info)
        methods = {name: infos[0] for name, infos in grouped_methods.items()}
        for method_name, infos in grouped_methods.items():
            method_info = infos[0]
            callables: list[CallableType] = []
            for method_signature in infos:
                signature = self._callable_type(method_signature)
                arguments = signature.arg_types
                if arguments and method_signature.method_kind != "static":
                    arguments = arguments[1:]
                callables.append(CallableType(arguments, signature.return_type))
            if method_info.is_property:
                class_typ.type.members[method_name] = method_info.returns or ANY
            elif len(callables) > 1:
                class_typ.type.members[method_name] = CallableType(
                    None,
                    UnionType(
                        tuple(
                            dict.fromkeys(callable_type.return_type for callable_type in callables)
                        )
                    ),
                    overloads=tuple(callables),
                )
            else:
                class_typ.type.members[method_name] = callables[0]
            member_type = class_typ.type.members[method_name]
            members[method_name] = TypeFact(
                name=method_name,
                typ=member_type,
                raw_annotation=(
                    method_info.raw_returns if method_info.is_property else str(member_type)
                ),
                source="stub",
                kind="method",
            )
        return ClassTypeInfo(
            name=qualified_name,
            typ=class_typ,
            bases=tuple(
                resolved
                for raw_base in cls.bases
                if (
                    resolved := self._resolve_annotation(
                        raw_base,
                        module_name=module_name,
                        imports=imports,
                    )
                )
                is not None
            ),
            raw_bases=tuple(cls.bases),
            members=members,
            methods=methods,
            source="stub",
        )
