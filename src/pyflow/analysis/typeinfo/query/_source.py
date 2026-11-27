"""Source module loading, AST extraction, and static-inference integration mixin."""

from __future__ import annotations

import ast
import tokenize
from functools import lru_cache
from pathlib import Path

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NONE_TYPE,
    CallableType,
    Instance,
    ProperType,
    TupleType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference.engine import StaticTypeInferenceEngine
from pyflow.analysis.typeinfo.query.models import (
    ClassTypeInfo,
    FunctionTypeInfo,
    TypeFact,
)
from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup
from pyflow.analysis.typeinfo.resolution.docstring_types import resolve_documented_type
from pyflow.analysis.typeinfo.resolution.docstrings import (
    search_param_in_docstr,
    search_return_in_docstr,
)
from pyflow.language.source_compat import parse_python_source

from ._helpers import (
    _UNSET,
    _annotation_to_str,
    _expr_name,
    _iter_arguments,
    _module_statements,
    _stdlib_root,
    _strip_annotation_wrapper,
)


class _SourceCollectionMixin:
    """Load Python source files, collect declarations, and run static inference."""

    def _find_module(self, module_name: str):
        key = (
            self.project_context.path,
            len(self.project_context.source_files),
            tuple(self.project_context.added_sys_path),
        )
        if self._find_module_cache_key != key:
            self._find_module_cache.clear()
            self._find_module_cache_key = key
        cached = self._find_module_cache.get(module_name, _UNSET)
        if cached is not _UNSET:
            return cached
        resolution = self.project_context.find_module(module_name)
        self._find_module_cache[module_name] = resolution
        return resolution

    def _refresh_import_facts(self, *, module_name: str | None = None) -> bool:
        """Resolve stub import aliases after cyclic stub collections finish."""
        if self._refreshing_import_facts:
            return False
        self._refreshing_import_facts = True
        changed_any = False
        changed_all: set[str] = set()
        try:
            changed_modules: set[str] | None = None
            for pass_index in range(3):
                changed = False
                next_changed_modules: set[str] = set()
                lookup_cache: dict[str, ProperType | None] = {}
                if module_name is not None:
                    items = (
                        [(module_name, self._module_facts[module_name])]
                        if module_name in self._module_facts
                        else []
                    )
                else:
                    items = list(self._module_facts.items())
                for mod_name, facts in items:
                    if self._third_party_kind.get(mod_name) == "typed":
                        continue
                    for name, fact in list(facts.items()):
                        if fact.source != "import" or not fact.raw_annotation:
                            continue
                        raw_target = fact.raw_annotation
                        if raw_target == f"{mod_name}.{name}":
                            continue
                        # On subsequent fixpoint passes, only re-check still-unresolved
                        # imports or aliases targeting a module updated in the prior pass.
                        if pass_index > 0 and changed_modules is not None:
                            target_mod = raw_target.rpartition(".")[0]
                            if fact.typ is not ANY and target_mod not in changed_modules:
                                continue
                        # Fast path: already resolved to its exact ClassTypeInfo.
                        existing_cls = self._classes.get(raw_target)
                        if existing_cls is not None and fact.typ == existing_cls.typ:
                            continue
                        if raw_target in lookup_cache:
                            resolved = lookup_cache[raw_target]
                        else:
                            resolved = self._lookup_project_type(
                                raw_target,
                                allow_synthetic=False,
                                collect_missing=False,
                            )
                            lookup_cache[raw_target] = resolved
                        if resolved is not None and resolved != fact.typ:
                            self._lazy_stub_imports.discard((mod_name, name))
                            facts[name] = TypeFact(
                                name=fact.name,
                                typ=resolved,
                                raw_annotation=raw_target,
                                source=fact.source,
                                kind=fact.kind,
                            )
                            changed = True
                            changed_any = True
                            next_changed_modules.add(mod_name)
                            changed_all.add(mod_name)
                if not changed:
                    break
                changed_modules = next_changed_modules
        finally:
            self._last_refreshed_import_modules = frozenset(changed_all)
            self._refreshing_import_facts = False
        return changed_any

    def _load_module_source(
        self,
        module_name: str,
        path: str | None,
    ) -> tuple[str | None, str | None]:
        if path is None:
            resolution = self._find_module(module_name)
            if resolution is not None:
                path = resolution.path
        if path is None:
            return None, None
        stub_path = self.stub_resolver.resolve_path(module_name, script_path=path)
        if stub_path is not None:
            try:
                if stub_path in self.project_context.source_files:
                    return self.project_context.source_files[stub_path], stub_path
                with tokenize.open(stub_path) as stub_file:
                    return stub_file.read(), stub_path
            except OSError:
                pass

        if self._is_stdlib_source(path):
            return None, path
        if self._third_party_typed(module_name) is False:
            return None, path
        if path in self.project_context.source_files:
            return self.project_context.source_files[path], path
        try:
            with tokenize.open(path) as source_file:
                return source_file.read(), path
        except OSError:
            return None, path

    @staticmethod
    @lru_cache(maxsize=4096)
    def _is_stdlib_source(path: str) -> bool:
        """Whether ``path`` points into the active interpreter's stdlib."""
        stdlib_root = _stdlib_root()
        if stdlib_root is None:
            return False
        try:
            source_path = Path(path).resolve()
            relative = source_path.relative_to(stdlib_root)
        except (OSError, ValueError):
            return False
        return not any(part in {"site-packages", "dist-packages"} for part in relative.parts)

    def _collect_source_module(
        self,
        module_name: str,
        source: str,
        path: str | None,
    ) -> None:
        tree = parse_python_source(source, path or module_name)
        exported_names: frozenset[str] | None = None
        for statement in tree.body:
            if not (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == "__all__"
            ):
                continue
            try:
                names = ast.literal_eval(statement.value)
            except (ValueError, TypeError, SyntaxError):
                names = None
            if isinstance(names, (list, tuple, set)) and all(
                isinstance(name, str) for name in names
            ):
                exported_names = frozenset(names)
        self._module_all[module_name] = exported_names

        defined_names: set[str] = set(exported_names or ())
        for stmt in _module_statements(tree):
            if isinstance(stmt, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                defined_names.add(stmt.name)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                defined_names.add(stmt.target.id)
            elif isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    for sub in ast.walk(target):
                        if isinstance(sub, ast.Name):
                            defined_names.add(sub.id)
            elif isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    defined_names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    if alias.name != "*":
                        defined_names.add(alias.asname or alias.name)
            elif hasattr(ast, "TypeAlias") and isinstance(stmt, ast.TypeAlias):
                if isinstance(stmt.name, ast.Name):
                    defined_names.add(stmt.name.id)
        self._module_defined_names[module_name] = frozenset(defined_names)

        facts = self._module_facts.setdefault(module_name, {})
        functions = self._functions.setdefault(module_name, {})
        local_classes: set[str] = set()
        imports = self._collect_import_aliases(module_name, tree, path)
        module_aliases = self._module_class_aliases.setdefault(module_name, {})
        self._module_imports[module_name] = imports
        for node in _module_statements(tree):
            if isinstance(node, ast.ClassDef):
                qualified_name = f"{module_name}.{node.name}"
                self._class_aliases[node.name] = qualified_name
                module_aliases[node.name] = qualified_name

        is_third_party = self._third_party_typed(module_name) is True
        collect_missing = not is_third_party
        grouped_functions: dict[str, list[FunctionTypeInfo]] = {}
        statements = list(_module_statements(tree))
        for node in statements:
            if isinstance(node, ast.ClassDef):
                local_classes.add(node.name)
                class_info = self._class_info_from_source(
                    module_name,
                    node,
                    imports,
                    collect_missing=collect_missing,
                )
                self._classes[class_info.name] = class_info
                facts[node.name] = TypeFact(
                    name=node.name,
                    typ=class_info.typ,
                    raw_annotation=class_info.name,
                    source="annotation",
                    kind="class",
                )
        # Collect module-level type aliases (PEP 695 ``type X = ...`` and
        # ``X: TypeAlias = ...``) before functions and annotated variables so
        # forward references within the same module resolve immediately even
        # when static inference is disabled.
        for node in statements:
            if (
                hasattr(ast, "TypeAlias")
                and isinstance(node, ast.TypeAlias)
                and isinstance(node.name, ast.Name)
            ):
                raw_annotation = _annotation_to_str(node.value)
                alias_type = self._resolve_annotation(
                    raw_annotation,
                    module_name=module_name,
                    imports=imports,
                    collect_missing=collect_missing,
                )
                facts[node.name.id] = TypeFact(
                    name=node.name.id,
                    typ=alias_type,
                    raw_annotation=raw_annotation,
                    source="annotation",
                    kind="variable",
                )
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                raw_annotation = _annotation_to_str(node.annotation)
                head = raw_annotation.split("[", 1)[0].rsplit(".", 1)[-1]
                if head in {"TypeAlias", "TypeAliasType"} and node.value is not None:
                    raw_value = _annotation_to_str(node.value)
                    alias_type = self._resolve_annotation(
                        raw_value,
                        module_name=module_name,
                        imports=imports,
                        collect_missing=collect_missing,
                    )
                    facts[node.target.id] = TypeFact(
                        name=node.target.id,
                        typ=alias_type,
                        raw_annotation=raw_value,
                        source="annotation",
                        kind="variable",
                    )
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                grouped_functions.setdefault(node.name, []).append(
                    self._function_info_from_source(
                        node,
                        module_name=module_name,
                        imports=imports,
                        source="annotation",
                        collect_missing=collect_missing,
                    )
                )
        for function_name, infos in grouped_functions.items():
            overloads = [item for item in infos if item.is_overload]
            implementation = next((item for item in reversed(infos) if not item.is_overload), None)
            chosen = implementation or infos[-1]
            functions[function_name] = chosen
            if overloads:
                callables = tuple(self._callable_type(item) for item in overloads)
                returns = list(dict.fromkeys(call.return_type for call in callables))
                combined: ProperType = (
                    returns[0] if len(returns) == 1 else UnionType(tuple(returns))
                )
                member_type: ProperType = CallableType(None, combined, overloads=callables)
            else:
                member_type = self._callable_type(chosen)
            facts[function_name] = TypeFact(
                name=function_name,
                typ=member_type,
                raw_annotation=function_name,
                source=chosen.source,
                kind="function",
            )

        for node in _module_statements(tree):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                raw_annotation = _annotation_to_str(node.annotation)
                head = raw_annotation.split("[", 1)[0].rsplit(".", 1)[-1]
                member_type_opt: ProperType | None = None
                if head in {"TypeAlias", "TypeAliasType"} and node.value is not None:
                    raw_annotation = _annotation_to_str(node.value)
                    member_type_opt = self._resolve_annotation(
                        raw_annotation,
                        module_name=module_name,
                        imports=imports,
                        collect_missing=collect_missing,
                    )
                elif head in {"Final", "ClassVar"}:
                    inner = _strip_annotation_wrapper(raw_annotation, head)
                    if inner not in {None, "", "Any"}:
                        member_type_opt = self._resolve_annotation(
                            inner,
                            module_name=module_name,
                            imports=imports,
                            collect_missing=collect_missing,
                        )
                        raw_annotation = inner
                    elif node.value is not None:
                        member_type_opt = self._infer_expr_type(
                            node.value,
                            module_name,
                            local_classes,
                            imports,
                        )
                else:
                    member_type_opt = self._resolve_annotation(
                        raw_annotation,
                        module_name=module_name,
                        imports=imports,
                        collect_missing=collect_missing,
                    )
                if member_type_opt is None and node.value is not None:
                    member_type_opt = self._infer_expr_type(
                        node.value,
                        module_name,
                        local_classes,
                        imports,
                    )
                facts[node.target.id] = TypeFact(
                    name=node.target.id,
                    typ=member_type_opt,
                    raw_annotation=raw_annotation,
                    source="annotation",
                    kind="variable",
                )
            elif isinstance(node, ast.Assign):
                inferred = self._infer_expr_type(
                    node.value,
                    module_name,
                    local_classes,
                    imports,
                )
                if inferred is None:
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        facts[target.id] = TypeFact(
                            name=target.id,
                            typ=inferred,
                            raw_annotation=str(inferred),
                            source="inferred",
                            kind="variable",
                        )

        for local_name, qualified_name in imports.items():
            if local_name in facts:
                continue
            if is_third_party:
                imported_type = self._lookup_project_type(
                    qualified_name,
                    allow_synthetic=False,
                    collect_missing=False,
                )
                if imported_type is None:
                    imported_type = BuiltinTypeLookup()(qualified_name)
                facts[local_name] = TypeFact(
                    name=local_name,
                    typ=imported_type or ANY,
                    raw_annotation=qualified_name,
                    source="import",
                    kind="import",
                )
                continue
            imported_type = self._lookup_project_type(
                qualified_name,
                allow_synthetic=False,
            )
            if imported_type is None:
                imported_type = BuiltinTypeLookup()(qualified_name)
            target_mod = qualified_name.rsplit(".", 1)[0]
            if imported_type is not None or self._find_module(target_mod) is not None:
                facts[local_name] = TypeFact(
                    name=local_name,
                    typ=imported_type or ANY,
                    raw_annotation=qualified_name,
                    source="import",
                    kind="import",
                )

        if self.enable_static_inference and not is_third_party:
            self._module_sources[module_name] = (source, path)
            if len(self._collection_stack) <= 1:
                self._deferred_inference_modules.discard(module_name)
                self._refresh_import_facts(
                    module_name=module_name if len(self._collecting_modules) > 1 else None
                )
                self._collect_inferred_source_facts(module_name, source, path)
            else:
                self._deferred_inference_modules.add(module_name)

    def _collect_inferred_source_facts(
        self,
        module_name: str,
        source: str,
        path: str | None,
    ) -> None:
        self._module_sources[module_name] = (source, path)
        pushed = module_name not in self._collecting_modules
        if pushed:
            self._collecting_modules.add(module_name)
            self._collection_stack.append(module_name)
        try:
            engine = StaticTypeInferenceEngine(
                self.project_context,
                type_system=self.type_system,
                external_symbol_resolver=self._resolve_inference_external_symbol,
                call_model_providers=self.call_model_providers,
                options=self.inference_options,
            )
            result = engine.infer_source(module_name, source, filename=path)
        finally:
            if pushed:
                self._collecting_modules.discard(module_name)
                if self._collection_stack and self._collection_stack[-1] == module_name:
                    self._collection_stack.pop()
                else:
                    self._collection_stack = [
                        name for name in self._collection_stack if name != module_name
                    ]
        self._inference_results[module_name] = result
        for qualified_name, summary in result.functions.items():
            self._function_summaries[qualified_name] = summary
        if not self._refreshing_inference:
            self._needs_refresh = True
        self._invalidate_external_symbol_cache(module_name)
        facts = self._module_facts.setdefault(module_name, {})
        prefix = f"{module_name}."
        for qualified_name, symbol in result.symbols.items():
            local_name = qualified_name.removeprefix(prefix)
            if "." in local_name or symbol.typ is None:
                continue
            existing = facts.get(local_name)
            if (
                existing is not None
                and existing.source in {"annotation", "stub"}
                and existing.typ is not None
                and not (
                    isinstance(existing.typ, Instance)
                    and existing.typ.type.full_name
                    in {"typing.TypeAlias", "typing_extensions.TypeAlias"}
                )
            ):
                continue
            facts[local_name] = TypeFact(
                name=local_name,
                typ=symbol.typ,
                raw_annotation=str(symbol.typ),
                source="static_inference",
                kind=existing.kind if existing is not None else "variable",
            )

        functions = self._functions.setdefault(module_name, {})
        for qualified_name, summary in result.functions.items():
            local_name = qualified_name.removeprefix(prefix)
            if "." in local_name or local_name not in functions:
                continue
            existing_function = functions[local_name]
            params = dict(existing_function.params)
            raw_params = dict(existing_function.raw_params)
            for name, value in summary.parameters.items():
                if name in params and (
                    params[name] is None
                    or name in self._documented_parameters.get((module_name, local_name), set())
                ):
                    params[name] = value.public_type()
                    public_type = value.public_type()
                    raw_params[name] = None if public_type is None else str(public_type)
            returns = existing_function.returns or summary.return_type
            if (
                module_name,
                local_name,
            ) in self._documented_returns and summary.return_type is not None:
                returns = summary.return_type
            raw_returns = existing_function.raw_returns
            if (
                raw_returns is None or (module_name, local_name) in self._documented_returns
            ) and returns is not None:
                raw_returns = str(returns)
            updated = FunctionTypeInfo(
                name=existing_function.name,
                params=params,
                returns=returns,
                raw_params=raw_params,
                raw_returns=raw_returns,
                source=(
                    existing_function.source
                    if existing_function.source in {"annotation", "stub", "docstring"}
                    else "static_inference"
                ),
            )
            functions[local_name] = updated
            old_fact = facts.get(local_name)
            facts[local_name] = TypeFact(
                name=local_name,
                typ=self._callable_type(updated),
                raw_annotation=updated.raw_returns,
                source=updated.source,
                kind="function" if old_fact is None else old_fact.kind,
            )

    def _refresh_stale_annotation_checks(self) -> None:
        """Re-run modules whose annotation checks may predate their dependencies."""
        if self._refreshing_inference or not self._needs_refresh:
            return
        self._needs_refresh = False
        stale = [
            name
            for name, result in self._inference_results.items()
            if name in self._module_sources
            and any(item.code == "annotation-mismatch" for item in result.diagnostics)
        ]
        if not stale:
            return
        self._refreshing_inference = True
        try:
            for module_name in stale:
                source, path = self._module_sources[module_name]
                self._collect_inferred_source_facts(module_name, source, path)
        finally:
            self._refreshing_inference = False

    def _ensure_refreshed(self) -> None:
        if self._collecting_modules or self._refreshing_inference:
            return
        self._refresh_stale_annotation_checks()

    def _resolve_inference_external_symbol(
        self,
        qualified_name: str,
    ) -> ProperType | None:
        module_name, separator, name = qualified_name.rpartition(".")
        if not separator:
            return None
        if module_name in self._collecting_modules:
            fact = self._module_facts.get(module_name, {}).get(name)
            return None if fact is None else fact.typ
        if qualified_name in self._external_symbol_cache:
            return self._external_symbol_cache[qualified_name]
        resolved = self._lookup_project_type(qualified_name, allow_synthetic=False)
        if module_name not in self._collecting_modules:
            self._external_symbol_cache[qualified_name] = resolved
        return resolved

    def _collect_import_aliases(
        self,
        module_name: str,
        tree: ast.Module,
        path: str | None,
    ) -> dict[str, str]:
        imports: dict[str, str] = {}
        for node in _module_statements(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    imports[local] = alias.name if alias.asname else local
            elif isinstance(node, ast.ImportFrom):
                source_module = self.project_context.resolve_import_name(
                    module_name,
                    node.module or "",
                    int(getattr(node, "level", 0) or 0),
                    current_path=path,
                )
                if not source_module:
                    continue
                for alias in node.names:
                    if alias.name == "*":
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
                    local = alias.asname or alias.name
                    imports[local] = f"{source_module}.{alias.name}"
        return imports

    def _class_info_from_source(
        self,
        module_name: str,
        node: ast.ClassDef,
        imports: dict[str, str],
        *,
        collect_missing: bool = True,
    ) -> ClassTypeInfo:
        members: dict[str, TypeFact] = {}
        methods: dict[str, FunctionTypeInfo] = {}
        qualified_name = f"{module_name}.{node.name}"
        class_typ = self._synthetic_instance(qualified_name)
        for stmt in node.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                annotation_name = _annotation_to_str(stmt.annotation)
                base_name = annotation_name.split("[", 1)[0].rsplit(".", 1)[-1]
                if base_name in {"KW_ONLY", "InitVar"}:
                    continue
                raw_annotation = annotation_name
                members[stmt.target.id] = TypeFact(
                    name=stmt.target.id,
                    typ=self._resolve_annotation(
                        raw_annotation,
                        module_name=module_name,
                        imports=imports,
                        collect_missing=collect_missing,
                    ),
                    raw_annotation=raw_annotation,
                    source="annotation",
                    kind="class_var",
                )
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorator_names = {
                    ast.unparse(decorator).rsplit(".", 1)[-1] for decorator in stmt.decorator_list
                }
                if (
                    decorator_names & {"setter", "deleter"}
                    and stmt.name in methods
                    and methods[stmt.name].is_property
                ):
                    continue
                method_info = self._specialize_self_method(
                    self._function_info_from_source(
                        stmt,
                        module_name=module_name,
                        imports=imports,
                        source="annotation",
                        symbol_name=f"{node.name}.{stmt.name}",
                        collect_missing=collect_missing,
                    ),
                    class_typ,
                )
                methods[stmt.name] = method_info
                member_type = (
                    method_info.returns
                    if method_info.is_property
                    else self._callable_type(method_info)
                )
                members[stmt.name] = TypeFact(
                    name=stmt.name,
                    typ=member_type,
                    raw_annotation=(
                        method_info.raw_returns if method_info.is_property else str(member_type)
                    ),
                    source=method_info.source,
                    kind="property" if method_info.is_property else "method",
                )
        raw_bases = tuple(_annotation_to_str(base) for base in node.bases)
        return ClassTypeInfo(
            name=qualified_name,
            typ=class_typ,
            bases=tuple(
                resolved
                for raw_base in raw_bases
                if (
                    resolved := self._resolve_annotation(
                        raw_base,
                        module_name=module_name,
                        imports=imports,
                        collect_missing=collect_missing,
                    )
                )
                is not None
            ),
            raw_bases=raw_bases,
            members=members,
            methods=methods,
            source="annotation",
        )

    def _function_info_from_source(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        module_name: str,
        imports: dict[str, str],
        source: str,
        symbol_name: str | None = None,
        collect_missing: bool = True,
    ) -> FunctionTypeInfo:
        raw_params: dict[str, str | None] = {}
        params: dict[str, ProperType | None] = {}
        for arg in _iter_arguments(node.args):
            raw = _annotation_to_str(arg.annotation) if arg.annotation is not None else None
            raw_params[arg.arg] = raw
            params[arg.arg] = self._resolve_annotation(
                raw,
                module_name=module_name,
                imports=imports,
                collect_missing=collect_missing,
            )
        if node.args.vararg is not None:
            raw = (
                _annotation_to_str(node.args.vararg.annotation)
                if node.args.vararg.annotation is not None
                else None
            )
            raw_params[f"*{node.args.vararg.arg}"] = raw
            params[f"*{node.args.vararg.arg}"] = self._resolve_annotation(
                raw,
                module_name=module_name,
                imports=imports,
                collect_missing=collect_missing,
            )
        if node.args.kwarg is not None:
            raw = (
                _annotation_to_str(node.args.kwarg.annotation)
                if node.args.kwarg.annotation is not None
                else None
            )
            raw_params[f"**{node.args.kwarg.arg}"] = raw
            params[f"**{node.args.kwarg.arg}"] = self._resolve_annotation(
                raw,
                module_name=module_name,
                imports=imports,
                collect_missing=collect_missing,
            )
        raw_returns = _annotation_to_str(node.returns) if node.returns is not None else None
        returns = self._resolve_annotation(
            raw_returns,
            module_name=module_name,
            imports=imports,
            collect_missing=collect_missing,
        )
        docstring = ast.get_docstring(node)
        used_documentation = False
        documentation_key = (module_name, symbol_name or node.name)
        if docstring:

            def resolve_hint(text: str) -> ProperType | None:
                return self._resolve_annotation(
                    text,
                    module_name=module_name,
                    imports=imports,
                    collect_missing=collect_missing,
                )

            for name in params:
                if raw_params[name] is not None:
                    continue
                hints = search_param_in_docstr(docstring, name.lstrip("*"))
                hint = resolve_documented_type(hints, resolve_hint)
                if hint is not None:
                    params[name] = hint
                    raw_params[name] = " | ".join(hints)
                    used_documentation = True
                    self._documented_parameters.setdefault(documentation_key, set()).add(name)
            if node.returns is None:
                hints = list(search_return_in_docstr(docstring))
                hint = resolve_documented_type(hints, resolve_hint)
                if hint is not None:
                    returns = hint
                    raw_returns = " | ".join(hints)
                    used_documentation = True
                    self._documented_returns.add(documentation_key)
        decorators = {
            ast.unparse(decorator).rsplit(".", 1)[-1] for decorator in node.decorator_list
        }
        return FunctionTypeInfo(
            name=node.name,
            params=params,
            returns=returns,
            raw_params=raw_params,
            raw_returns=raw_returns,
            source="docstring" if used_documentation else source,
            is_property=bool(decorators & {"property", "cached_property"}),
            is_overload="overload" in decorators,
            method_kind=(
                "static"
                if "staticmethod" in decorators
                else "class" if "classmethod" in decorators else "instance"
            ),
        )

    def _infer_expr_type(
        self,
        node: ast.expr,
        module_name: str,
        local_classes: set[str],
        imports: dict[str, str],
    ) -> ProperType | None:
        if isinstance(node, ast.Constant):
            if node.value is None:
                return NONE_TYPE
            return Instance(self.type_system.to_class_descriptor(type(node.value)))
        if isinstance(node, ast.List):
            return Instance(self.type_system.to_class_descriptor(list))
        if isinstance(node, ast.Dict):
            return Instance(self.type_system.to_class_descriptor(dict))
        if isinstance(node, ast.Tuple):
            return TupleType(())
        if isinstance(node, ast.Set):
            return Instance(self.type_system.to_class_descriptor(set))
        if isinstance(node, ast.Name):
            if node.id in local_classes:
                return self._synthetic_instance(f"{module_name}.{node.id}")
            imported = self._resolve_imported_type_name(node.id, imports)
            if imported is not None and self._is_known_class_name(imported):
                return self._synthetic_instance(imported)
        if isinstance(node, ast.Call):
            callee = _expr_name(node.func)
            if callee is None:
                return None
            if callee in local_classes:
                return self._synthetic_instance(f"{module_name}.{callee}")
            imported = imports.get(callee)
            if imported is None:
                imported = self._resolve_imported_type_name(callee, imports)
            if imported is not None and self._is_known_class_name(imported):
                return self._synthetic_instance(imported)
        return None
