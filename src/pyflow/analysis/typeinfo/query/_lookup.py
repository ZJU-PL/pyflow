"""Cross-module type lookup, inheritance, Self specialization, and scope filtering."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    CallableType,
    Instance,
    ProperType,
    TupleType,
    TypeType,
    UnionType,
)
from pyflow.analysis.typeinfo.query.models import (
    ClassTypeInfo,
    FunctionTypeInfo,
    TypeFact,
)
from pyflow.analysis.typeinfo.resolution.annotations import (
    BuiltinTypeLookup,
    TypeLookup,
    resolve_annotation,
)
from pyflow.analysis.typeinfo.resolution.typing_syntax import substitute_type_vars
from pyflow.language.modules.type_stubs import StubDiagnostic

from ._helpers import (
    _SELF_ANNOTATIONS,
    _runtime_stdlib_class,
    _top_level_package_dir,
)


class _TypeLookupMixin:
    """Resolve annotations, cross-module references, class members, and PEP 561 boundaries."""

    _SELF_ANNOTATIONS = _SELF_ANNOTATIONS

    def _resolve_reexported_member(
        self,
        module_name: str,
        name: str,
        seen: set[tuple[str, str]] | None = None,
        *,
        collect_missing: bool = True,
    ) -> tuple[str, str] | None:
        """Follow ``from x import y`` aliases to the defining module member."""
        key = (module_name, name)
        use_cache = seen is None and not collect_missing
        if use_cache and key in self._reexport_cache:
            return self._reexport_cache[key]
        seen = set() if seen is None else seen
        if key in seen:
            return None
        seen.add(key)
        if collect_missing:
            if (
                module_name not in self._collected_modules
                and module_name not in self._collecting_modules
                and len(self._collection_stack) < self._max_collection_depth
                and self._module_should_be_collected(module_name)
            ):
                self.collect_module(module_name)
        elif module_name not in self._collected_modules:
            if use_cache:
                self._reexport_cache[key] = None
            return None
        target = self._module_imports.get(module_name, {}).get(name)
        if target is None:
            fact = self._module_facts.get(module_name, {}).get(name)
            if (
                fact is not None
                and fact.kind == "import"
                and fact.raw_annotation
                and "." in fact.raw_annotation
                and all(part.isidentifier() for part in fact.raw_annotation.split("."))
            ):
                target = fact.raw_annotation
        if not target or "." not in target:
            if use_cache:
                self._reexport_cache[key] = None
            return None
        target_module, _, target_name = target.rpartition(".")
        nested = self._resolve_reexported_member(
            target_module, target_name, seen, collect_missing=collect_missing
        )
        resolved = nested or (target_module, target_name)
        if use_cache:
            self._reexport_cache[key] = resolved
        return resolved

    def _ensure_class_loaded(self, class_name: str) -> ClassTypeInfo | None:
        info = self._classes.get(class_name)
        if info is not None:
            return info
        module_name, separator, _ = class_name.rpartition(".")
        if (
            separator
            and module_name not in self._collected_modules
            and module_name not in self._collecting_modules
            and len(self._collection_stack) < self._max_collection_depth
            and self._module_should_be_collected(module_name)
        ):
            self.collect_module(module_name)
        return self._classes.get(class_name)

    def _class_members_with_inheritance(
        self, class_name: str, seen: set[str] | None = None
    ) -> dict[str, TypeFact]:
        seen = set() if seen is None else seen
        if class_name in seen:
            return {}
        seen.add(class_name)
        info = self._ensure_class_loaded(class_name)
        if info is None:
            return {}
        members: dict[str, TypeFact] = {}
        for base in info.bases:
            if isinstance(base, Instance):
                inherited = self._class_members_with_inheritance(base.type.full_name, seen)
                substitutions = {
                    parameter.name: argument
                    for parameter, argument in zip(base.type.type_parameters, base.args)
                }
                if substitutions:
                    inherited = {
                        name: replace(
                            fact,
                            typ=(
                                substitute_type_vars(fact.typ, substitutions)
                                if fact.typ is not None
                                else None
                            ),
                        )
                        for name, fact in inherited.items()
                    }
                members.update(inherited)
        members.update(info.members)
        return members

    def _class_method_info(
        self, class_name: str, method_name: str, seen: set[str] | None = None
    ) -> FunctionTypeInfo | None:
        seen = set() if seen is None else seen
        if class_name in seen:
            return None
        seen.add(class_name)
        info = self._ensure_class_loaded(class_name)
        if info is None:
            return None
        method = info.methods.get(method_name)
        if method is not None:
            return method
        for base in info.bases:
            if isinstance(base, Instance):
                found = self._class_method_info(base.type.full_name, method_name, seen)
                if found is not None:
                    return found
        return None

    def _resolve_annotation(
        self,
        annotation: str | None,
        *,
        module_name: str | None = None,
        imports: dict[str, str] | None = None,
        collect_missing: bool = True,
    ) -> ProperType | None:
        if annotation is None:
            return None
        lookup = cast(
            TypeLookup,
            lambda name: self._lookup_type(
                name,
                module_name=module_name,
                imports=imports or {},
                collect_missing=collect_missing,
            ),
        )
        return resolve_annotation(annotation, lookup)

    def _lookup_type(
        self,
        name: str,
        *,
        module_name: str | None = None,
        imports: dict[str, str],
        collect_missing: bool = True,
    ) -> ProperType | None:
        if name in {"Self", "typing.Self", "typing_extensions.Self"}:
            return self._synthetic_instance("typing_extensions.Self")
        imported = self._resolve_imported_type_name(name, imports)
        if imported is not None:
            if imported in {"typing.Self", "typing_extensions.Self"}:
                return self._synthetic_instance("typing_extensions.Self")
            effective_collect = collect_missing or (
                imported == "_typeshed"
                or imported.startswith(("_typeshed.", "collections.abc.", "_collections_abc."))
            )
            resolved = self._lookup_project_type(
                imported,
                allow_synthetic=True,
                collect_missing=effective_collect,
            )
            if resolved is not None:
                return resolved
            builtin = BuiltinTypeLookup()(imported)
            if builtin is not None:
                return builtin

        normalized = name.rsplit(".", 1)[-1]
        if module_name is not None:
            aliases = self._module_class_aliases.get(module_name, {})
            alias = aliases.get(name) or aliases.get(normalized)
            if alias is not None:
                return self._synthetic_instance(alias)
        else:
            alias = self._class_aliases.get(name) or self._class_aliases.get(normalized)
            if alias is not None:
                return self._synthetic_instance(alias)
        if module_name is None:
            for class_name, class_info in self._classes.items():
                if name == class_name or normalized == class_name.rsplit(".", 1)[-1]:
                    return class_info.typ
        else:
            stub_definition = self._resolve_stub_definition(module_name, name)
            if stub_definition is not None:
                return stub_definition

        builtin = BuiltinTypeLookup()(name)
        if builtin is not None:
            return builtin

        if module_name is not None:
            resolved = self._lookup_project_type(
                f"{module_name}.{name}",
                allow_synthetic=False,
                collect_missing=collect_missing,
            )
            if resolved is not None:
                return resolved
        return None

    def _resolve_imported_type_name(
        self,
        name: str,
        imports: dict[str, str],
    ) -> str | None:
        imported = imports.get(name)
        if imported is not None:
            return imported

        prefix, separator, rest = name.partition(".")
        if not separator:
            return None
        imported_prefix = imports.get(prefix)
        if imported_prefix is None:
            return None
        return f"{imported_prefix}.{rest}"

    def _module_should_be_collected(self, module_name: str) -> bool:
        """Whether a name can be safely loaded as a type source."""
        cached = self._should_collect_cache.get(module_name)
        if cached is not None:
            return cached
        result = (
            self._module_may_be_project(module_name)
            or self.stub_resolver.resolve_path(module_name) is not None
            or self._third_party_typed(module_name) is True
        )
        self._should_collect_cache[module_name] = result
        return result

    def _third_party_typed(self, module_name: str) -> bool | None:
        """Whether an installed module is a PEP 561 typed package."""
        if module_name in self._third_party_kind:
            kind = self._third_party_kind[module_name]
            return None if kind is None else kind == "typed"
        resolution = self._find_module(module_name)
        if resolution is None or resolution.path is None:
            self._third_party_kind[module_name] = None
            return None
        path = Path(resolution.path)
        if self._is_stdlib_source(str(path)):
            self._third_party_kind[module_name] = None
            return None
        if self._module_may_be_project(module_name):
            self._third_party_kind[module_name] = None
            return None
        package_root = _top_level_package_dir(path)
        if package_root is None:
            self._third_party_kind[module_name] = "untyped"
            return False
        kind = "typed" if (package_root / "py.typed").is_file() else "untyped"
        self._third_party_kind[module_name] = kind
        return kind == "typed"

    def _summary_type(self, qualified_name: str) -> ProperType | None:
        summary = self._function_summaries.get(qualified_name)
        if summary is None:
            return None
        cached = self._summary_type_cache.get(qualified_name)
        if cached is not None and cached[0] is summary:
            return cached[1]
        parameters = tuple(value.public_type() or ANY for value in summary.parameters.values())
        callable_type = CallableType(parameters, summary.return_type or ANY)
        self._summary_type_cache[qualified_name] = (summary, callable_type)
        return callable_type

    def _replace_self_type(self, typ: ProperType | None, class_type: Instance) -> ProperType | None:
        """Recursively replace ``Self`` inside a stub type."""
        if typ is None:
            return None
        if isinstance(typ, Instance):
            if typ.type.full_name in {"Self", "typing.Self", "typing_extensions.Self"}:
                return class_type
            if not typ.args:
                return typ
            args = tuple(self._replace_self_type(item, class_type) or ANY for item in typ.args)
            return typ if args == typ.args else Instance(typ.type, args)
        if isinstance(typ, UnionType):
            items = tuple(self._replace_self_type(item, class_type) or ANY for item in typ.items)
            return typ if items == typ.items else UnionType(items)
        if isinstance(typ, TupleType):
            args = tuple(self._replace_self_type(item, class_type) or ANY for item in typ.args)
            return typ if args == typ.args else TupleType(args, unknown_size=typ.unknown_size)
        if isinstance(typ, TypeType):
            item = self._replace_self_type(typ.item, class_type) or ANY
            return typ if item == typ.item else TypeType(item)
        if isinstance(typ, CallableType):
            arguments = typ.arg_types
            replaced_arguments = (
                tuple(self._replace_self_type(item, class_type) or ANY for item in arguments)
                if arguments is not None
                else None
            )
            replaced_return = self._replace_self_type(typ.return_type, class_type) or ANY
            if replaced_arguments == arguments and replaced_return == typ.return_type:
                return typ
            return CallableType(replaced_arguments, replaced_return, overloads=typ.overloads)
        return typ

    def _specialize_self_method(
        self, method: FunctionTypeInfo, class_type: Instance
    ) -> FunctionTypeInfo:
        returns = (
            class_type
            if method.raw_returns in self._SELF_ANNOTATIONS
            else self._replace_self_type(method.returns, class_type)
        )
        params: dict[str, ProperType | None] = {}
        for name, value in method.params.items():
            raw = method.raw_params.get(name)
            params[name] = (
                class_type
                if raw in self._SELF_ANNOTATIONS
                else self._replace_self_type(value, class_type)
            )
        if returns == method.returns and params == method.params:
            return method
        return replace(method, params=params, returns=returns)

    def _class_member_type(
        self,
        class_name: str,
        member: str,
        seen: set[str] | None = None,
        *,
        receiver_class: str | None = None,
    ) -> ProperType | None:
        seen = set() if seen is None else seen
        if class_name in seen:
            return None
        seen.add(class_name)
        receiver_class = receiver_class or class_name
        info = self._ensure_class_loaded(class_name)
        if info is None:
            return None
        method = info.methods.get(member)
        if method is not None:
            receiver = self._classes.get(receiver_class)
            receiver_type = receiver.typ if receiver is not None else None
            if method.raw_returns in self._SELF_ANNOTATIONS and receiver_type is not None:
                returns = receiver_type
            else:
                returns = (
                    self._replace_self_type(method.returns, receiver_type)
                    if receiver_type is not None
                    else method.returns
                )
            if method.is_property:
                return returns
            parameters = tuple(
                (self._replace_self_type(parameter, receiver_type) if receiver_type else parameter)
                or ANY
                for parameter in method.params.values()
            )
            if method.method_kind == "static":
                return CallableType(None, returns or ANY)
            return CallableType(parameters, returns or ANY)
        fact = info.members.get(member)
        if fact is not None:
            return fact.typ
        for base in info.bases:
            if isinstance(base, Instance):
                found = self._class_member_type(
                    base.type.full_name,
                    member,
                    seen,
                    receiver_class=receiver_class,
                )
                if found is not None:
                    substitutions = {
                        parameter.name: argument
                        for parameter, argument in zip(base.type.type_parameters, base.args)
                    }
                    if substitutions:
                        found = substitute_type_vars(found, substitutions)
                    return found
        owner_mod = class_name.rpartition(".")[0]
        if owner_mod in self._deferred_inference_modules:
            self._ensure_inferred(owner_mod)
            descriptor = self.type_system.class_descriptor(class_name)
            if descriptor is not None and member in descriptor.members:
                return descriptor.members[member]
        return None

    def _lookup_project_type(
        self,
        qualified_name: str,
        *,
        allow_synthetic: bool,
        collect_missing: bool = True,
    ) -> ProperType | None:
        if (
            qualified_name in self._active_project_lookups
            or len(self._active_project_lookups) >= 32
        ):
            return None
        self._active_project_lookups.add(qualified_name)
        try:
            return self._lookup_project_type_impl(
                qualified_name,
                allow_synthetic=allow_synthetic,
                collect_missing=collect_missing,
            )
        finally:
            self._active_project_lookups.discard(qualified_name)

    def _lookup_project_type_impl(
        self,
        qualified_name: str,
        *,
        allow_synthetic: bool,
        collect_missing: bool = True,
    ) -> ProperType | None:
        class_alias = self._class_aliases.get(qualified_name)
        if class_alias and class_alias != qualified_name:
            aliased = self._lookup_project_type(
                class_alias,
                allow_synthetic=allow_synthetic,
                collect_missing=collect_missing,
            )
            if aliased is not None:
                return aliased

        class_info = self._classes.get(qualified_name)
        if class_info is not None:
            return class_info.typ

        module_name, separator, attr = qualified_name.rpartition(".")
        if not separator:
            return None

        parts = qualified_name.split(".")
        if collect_missing:
            for index in range(len(parts) - 1, 0, -1):
                candidate = ".".join(parts[:index])
                if candidate in self._collected_modules:
                    break
                if len(self._collection_stack) >= self._max_collection_depth:
                    if not self._depth_limit_warning_emitted:
                        self._depth_limit_warning_emitted = True
                        self._add_collection_diagnostic(
                            StubDiagnostic(
                                code="type_collection_depth_exceeded",
                                category="type_inference",
                                module_name=self._collection_stack[-1],
                                message=(
                                    "Stopped lazy project collection at the depth limit; "
                                    "the inferred type closure is partial"
                                ),
                                severity="warning",
                            )
                        )
                    return ANY
                if self._module_should_be_collected(candidate):
                    self.collect_module(candidate)
                    break

        class_info = self._classes.get(qualified_name)
        if class_info is not None:
            return class_info.typ

        for index in range(len(parts) - 1, 0, -1):
            class_prefix = ".".join(parts[:index])
            if class_prefix not in self._classes:
                if (
                    class_prefix in self._collected_modules
                    or class_prefix in self._collecting_modules
                ):
                    continue
                prefix_module, _, prefix_name = class_prefix.rpartition(".")
                if prefix_module and prefix_name:
                    reexported = self._resolve_reexported_member(
                        prefix_module,
                        prefix_name,
                        collect_missing=collect_missing,
                    )
                    if reexported is not None:
                        target = f"{reexported[0]}.{reexported[1]}"
                        remainder = ".".join(parts[index:])
                        if target != class_prefix:
                            target_name = f"{target}.{remainder}" if remainder else target
                            resolved = self._lookup_project_type(
                                target_name,
                                allow_synthetic=allow_synthetic,
                                collect_missing=collect_missing,
                            )
                            if resolved is not None:
                                return resolved
                continue
            member = ".".join(parts[index:])
            found = self._class_member_type(class_prefix, member)
            if found is not None:
                return found
            break

        stub_fact = self._module_facts.get(module_name, {}).get(attr)
        if stub_fact is not None and stub_fact.source == "stub":
            return stub_fact.typ

        summary = self._summary_type(qualified_name)
        if summary is not None:
            return summary

        result = self._inference_results.get(module_name)
        partial = module_name in self._failed_modules or (
            result is not None and result.status == "partial"
        )
        if partial:
            dependents = [name for name in self._collection_stack[-1:] if name != module_name]
            for dependent in dependents:
                self._add_collection_diagnostic(
                    StubDiagnostic(
                        code="type_dependency_partial",
                        category="type_inference",
                        module_name=dependent,
                        message=f"Type information for dependency {module_name!r} is partial",
                        severity="warning",
                    )
                )

        fact = self._module_facts.get(module_name, {}).get(attr)
        if (
            collect_missing
            and module_name in self._deferred_inference_modules
            and (
                (
                    fact is None
                    and qualified_name not in self._collected_modules
                    and qualified_name not in self._collecting_modules
                    and not self._module_may_be_project(qualified_name)
                )
                or (
                    fact is not None
                    and fact.kind == "function"
                    and module_name in self._functions
                    and attr in self._functions[module_name]
                    and self._functions[module_name][attr].returns is None
                )
            )
        ):
            self._ensure_inferred(module_name)
            summary = self._summary_type(qualified_name)
            if summary is not None:
                return summary
            fact = self._module_facts.get(module_name, {}).get(attr)
        if fact is not None:
            if (
                fact.source == "import"
                and fact.typ is ANY
                and fact.raw_annotation
                and fact.raw_annotation != qualified_name
            ):
                is_lazy_stub = (module_name, attr) in self._lazy_stub_imports
                if is_lazy_stub and not collect_missing:
                    resolved_import = self._lookup_project_type(
                        fact.raw_annotation,
                        allow_synthetic=allow_synthetic,
                        collect_missing=False,
                    )
                    if resolved_import is not None:
                        self._lazy_stub_imports.discard((module_name, attr))
                        self._module_facts[module_name][attr] = TypeFact(
                            name=fact.name,
                            typ=resolved_import,
                            raw_annotation=fact.raw_annotation,
                            source=fact.source,
                            kind=fact.kind,
                        )
                        return resolved_import
                    return None
                if is_lazy_stub:
                    self._lazy_stub_imports.discard((module_name, attr))
                resolved_import = self._lookup_project_type(
                    fact.raw_annotation,
                    allow_synthetic=allow_synthetic,
                    collect_missing=collect_missing,
                )
                if resolved_import is None and is_lazy_stub:
                    self._module_facts.get(module_name, {}).pop(attr, None)
                    fact = None
                elif resolved_import is not None and resolved_import != fact.typ:
                    self._module_facts[module_name][attr] = TypeFact(
                        name=fact.name,
                        typ=resolved_import,
                        raw_annotation=fact.raw_annotation,
                        source=fact.source,
                        kind=fact.kind,
                    )
                    return resolved_import
            if fact is not None:
                return fact.typ

        dynamic_getattr = self._functions.get(module_name, {}).get("__getattr__")
        if dynamic_getattr is not None and dynamic_getattr.returns is not None:
            return dynamic_getattr.returns

        if partial:
            return ANY

        if allow_synthetic and self._find_module(module_name) is not None:
            return self._synthetic_instance(qualified_name)
        return None

    def _synthetic_instance(self, full_name: str) -> Instance:
        raw_type = self._synthetic_types.get(full_name)
        if raw_type is None:
            raw_type = _runtime_stdlib_class(full_name)
        if raw_type is tuple:
            raw_type = None
        if raw_type is None:
            module_name, _, class_name = full_name.rpartition(".")
            raw_type = type(class_name, (), {"__module__": module_name})
        self._synthetic_types[full_name] = raw_type
        return Instance(self.type_system.to_class_descriptor(raw_type))

    def _is_known_class_name(self, qualified_name: str) -> bool:
        """Return whether ``qualified_name`` denotes a class, not a callable."""
        cached = self._known_class_cache.get(qualified_name)
        if cached is not None:
            return cached
        if qualified_name in self._classes:
            self._known_class_cache[qualified_name] = True
            return True
        builtin = BuiltinTypeLookup()(qualified_name)
        if isinstance(builtin, Instance) or isinstance(builtin, TypeType):
            self._known_class_cache[qualified_name] = True
            return True
        module_name, _, _ = qualified_name.rpartition(".")
        if not module_name or any(part[:1].isupper() for part in module_name.split(".")):
            self._known_class_cache[qualified_name] = False
            return False
        if not self._module_may_be_project(module_name):
            self._known_class_cache[qualified_name] = False
            return False
        resolution = self._find_module(module_name)
        if resolution is None or resolution.path is None:
            self._known_class_cache[qualified_name] = False
            return False
        roots = (self.project_context.path, *self.project_context.module_identity.workspace_roots)
        try:
            path = Path(resolution.path).resolve()
            if not any(path.is_relative_to(Path(root).resolve()) for root in roots):
                self._known_class_cache[qualified_name] = False
                return False
        except OSError:
            self._known_class_cache[qualified_name] = False
            return False
        self.collect_module(module_name)
        result = qualified_name in self._classes
        self._known_class_cache[qualified_name] = result
        return result

    def _module_may_be_project(self, module_name: str) -> bool:
        """Cheaply rule out stdlib, third-party, and dotted non-module names."""
        parts = module_name.split(".")
        if not parts or any(not part for part in parts):
            return False
        if self.project_context.source_files:
            rel = "/".join(parts)
            suffixes = (f"/{rel}.py", f"/{rel}.pyi", f"/{rel}/__init__.py", f"/{rel}/__init__.pyi")
            for source_path in self.project_context.source_files:
                normalized = source_path.replace("\\", "/")
                if normalized.endswith(suffixes) or normalized in {
                    f"{rel}.py",
                    f"{rel}.pyi",
                    f"{rel}/__init__.py",
                    f"{rel}/__init__.pyi",
                }:
                    return True
        roots = (
            self.project_context.path,
            *self.project_context.module_identity.workspace_roots,
            *(Path(item) for item in self.project_context.added_sys_path),
        )
        for root in roots:
            root_path = Path(root)
            for base in (root_path, root_path / "src"):
                if len(parts) == 1:
                    first = parts[0]
                    if (
                        (base / first).is_dir()
                        or (base / f"{first}.py").is_file()
                        or (base / f"{first}.pyi").is_file()
                    ):
                        return True
                else:
                    parent = base.joinpath(*parts[:-1])
                    if not parent.is_dir():
                        continue
                    leaf = parts[-1]
                    if (
                        (parent / leaf).is_dir()
                        or (parent / f"{leaf}.py").is_file()
                        or (parent / f"{leaf}.pyi").is_file()
                    ):
                        return True
        return False
