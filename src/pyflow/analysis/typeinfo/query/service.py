"""Minimal type-information service.

This module provides a small orchestration layer over the existing typeinfo
facilities.  It resolves public facts to the shared ``typesystem`` model while
preserving raw annotation text for diagnostics and display.
"""

from __future__ import annotations

import ast
import importlib
import sys
import sysconfig
import tokenize
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator, cast

from pyflow.language.source_compat import parse_python_source

from pyflow.analysis.typeinfo.resolution.annotations import (
    BuiltinTypeLookup,
    TypeLookup,
    resolve_annotation,
)
from pyflow.analysis.typeinfo.query.models import (
    ClassTypeInfo,
    FunctionTypeInfo,
    TypeFact,
)
from pyflow.language.modules.type_stubs import (
    StubAliasInfo,
    StubClassInfo,
    StubDiagnostic,
    StubFunctionInfo,
    StubImportInfo,
    StubInfo,
    StubResolver,
    StubTypeVarInfo,
)
from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NONE_TYPE,
    CallableType,
    Instance,
    ProperType,
    TupleType,
    TypeType,
    TypeSystem,
    TypeVarType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference.engine import (
    InferenceOptions,
    StaticTypeInferenceEngine,
)
from pyflow.analysis.typeinfo.inference.project_config import load_inference_options
from pyflow.analysis.typeinfo.inference.call_models import CallModelProvider
from pyflow.analysis.typeinfo.inference.models import InferenceDiagnostic, ModuleInferenceResult
from pyflow.analysis.typeinfo.resolution.docstrings import (
    search_param_in_docstr,
    search_return_in_docstr,
)
from pyflow.analysis.typeinfo.resolution.docstring_types import resolve_documented_type
from pyflow.analysis.typeinfo.resolution.typing_syntax import (
    substitute_type_vars,
)
from pyflow.language.modules.project_resolution import ProjectContext


@lru_cache(maxsize=1)
def _stdlib_root() -> Path | None:
    try:
        stdlib = sysconfig.get_paths().get("stdlib")
        return Path(stdlib).resolve() if stdlib else None
    except (KeyError, OSError, ValueError):
        return None


_UNSET = object()


class TypeInfoService:
    """Collect and query lightweight type information for Python modules."""

    def __init__(
        self,
        project_context: ProjectContext | None = None,
        *,
        typeshed_roots: list[str | Path] | None = None,
        python_version: tuple[int, int] | None = None,
        enable_static_inference: bool = True,
        call_model_providers: Iterable[CallModelProvider] = (),
        inference_options: InferenceOptions | None = None,
    ) -> None:
        self.project_context = project_context or ProjectContext(None)
        self.type_system = TypeSystem()
        self.type_system.enable_numeric_tower()
        self.stub_resolver = StubResolver(
            self.project_context,
            typeshed_roots=typeshed_roots,
            python_version=python_version,
        )
        self._module_facts: dict[str, dict[str, TypeFact]] = {}
        self._functions: dict[str, dict[str, FunctionTypeInfo]] = {}
        self._classes: dict[str, ClassTypeInfo] = {}
        self._class_aliases: dict[str, str] = {}
        self._module_class_aliases: dict[str, dict[str, str]] = {}
        self._synthetic_types: dict[str, type] = {}
        self._collected_modules: set[str] = set()
        self._collecting_modules: set[str] = set()
        self._collection_stack: list[str] = []
        self._max_collection_depth = 32
        self._depth_limit_warning_emitted = False
        self.enable_static_inference = enable_static_inference
        self.inference_options = (
            inference_options
            if inference_options is not None
            else load_inference_options(self.project_context.path)
        )
        self.call_model_providers = tuple(call_model_providers)
        self._inference_results: dict[str, ModuleInferenceResult] = {}
        self._function_summaries: dict[str, object] = {}
        self._deferred_inference_modules: set[str] = set()
        self._module_sources: dict[str, tuple[str, str | None]] = {}
        self._module_all: dict[str, frozenset[str] | None] = {}
        self._module_imports: dict[str, dict[str, str]] = {}
        self._module_stub_type_vars: dict[str, dict[str, StubTypeVarInfo]] = {}
        self._module_stub_aliases: dict[str, dict[str, StubAliasInfo]] = {}
        self._module_type_aliases: dict[str, dict[str, ProperType]] = {}
        self._resolving_stub_aliases: set[tuple[str, str]] = set()
        self._active_project_lookups: set[str] = set()
        self._refreshing_inference = False
        self._refreshing_import_facts = False
        self._needs_refresh = False
        self._collection_diagnostics: list[StubDiagnostic] = []
        self._failed_modules: set[str] = set()
        # PEP 561 classification cache: module name -> "typed"/"untyped"
        # third-party source (``None`` for project/stub/stdlib modules).
        self._third_party_kind: dict[str, str | None] = {}
        self._should_collect_cache: dict[str, bool] = {}
        self._known_class_cache: dict[str, bool] = {}
        self._external_symbol_cache: dict[str, ProperType | None] = {}
        self._find_module_cache: dict[str, object] = {}
        self._find_module_cache_key: tuple[object, ...] | None = None
        self._lazy_stub_imports: set[tuple[str, str]] = set()
        self._documented_parameters: dict[tuple[str, str], set[str]] = {}
        self._documented_returns: set[tuple[str, str]] = set()

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

    def collect_module(
        self,
        module_name: str,
        *,
        source: str | None = None,
        path: str | None = None,
    ) -> None:
        """Collect source and stub facts for a module."""
        if module_name in {"typing", "typing_extensions"} and source is None and path is None:
            # The engine owns builtins and typing special forms; re-reading
            # their stubs would shadow TupleType/Union/Optional handling.
            # A project-local module with the same name is still analyzed.
            resolution = self._find_module(module_name)
            if (
                resolution is None
                or resolution.path is None
                or self._is_stdlib_source(resolution.path)
                or resolution.path.endswith(".pyi")
            ):
                self._collected_modules.add(module_name)
                return
        if module_name in self._collected_modules or module_name in self._collecting_modules:
            return
        if not self._collecting_modules:
            self._depth_limit_warning_emitted = False
        self._collecting_modules.add(module_name)
        self._collection_stack.append(module_name)
        completed = False
        try:
            try:
                if source is None:
                    source, path = self._load_module_source(module_name, path)
                if source is not None and not (path is not None and str(path).endswith(".pyi")):
                    # Stubs are declarations, not implementation source.  The
                    # resolver parses them below; treating a .pyi as ordinary
                    # Python would run the full inference engine on every
                    # typeshed module and mark their dependencies partial.
                    self._collect_source_module(module_name, source, path)
            except Exception as exc:
                self._record_collection_failure(module_name, "type_source_failed", exc, path)

            # A broken source analysis must not prevent authoritative stub
            # facts from being collected, and vice versa.
            try:
                resolved_stub = self.stub_resolver.resolve(module_name, script_path=path)
                if resolved_stub is not None:
                    self._collect_stub_module(
                        module_name,
                        resolved_stub.path,
                        resolved_stub.info,
                    )
            except Exception as exc:
                self._record_collection_failure(module_name, "type_stub_failed", exc, path)

            self._collected_modules.add(module_name)
            self._external_symbol_cache.clear()
            completed = True
        finally:
            self._collecting_modules.discard(module_name)
            if self._collection_stack and self._collection_stack[-1] == module_name:
                self._collection_stack.pop()
            else:
                self._collection_stack = [
                    name for name in self._collection_stack if name != module_name
                ]
            if completed and not self._collecting_modules:
                self.type_system.invalidate_subtype_caches()
                self._known_class_cache.clear()
                if self._refresh_import_facts() and self.enable_static_inference:
                    cached = self._module_sources.get(module_name)
                    if cached is not None:
                        self._collect_inferred_source_facts(module_name, *cached)
            # Inference may replace the result while recursively resolving a
            # dependency. Attach collection diagnostics to the final result.
            if completed:
                for diagnostic in self._collection_diagnostics:
                    if diagnostic.module_name != module_name:
                        continue
                    result = self._inference_results.setdefault(
                        module_name, ModuleInferenceResult(module_name, converged=False)
                    )
                    item = InferenceDiagnostic(
                        diagnostic.code,
                        diagnostic.message,
                        severity=diagnostic.severity,
                        affects_completeness=True,
                    )
                    if item not in result.diagnostics:
                        result.diagnostics.append(item)

    def _refresh_import_facts(self, *, module_name: str | None = None) -> bool:
        """Resolve stub import aliases after cyclic stub collections finish."""
        if self._refreshing_import_facts:
            return False
        self._refreshing_import_facts = True
        changed_any = False
        try:
            for _ in range(3):
                changed = False
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
                        resolved = self._lookup_project_type(
                            fact.raw_annotation,
                            allow_synthetic=False,
                            collect_missing=False,
                        )
                        if resolved is not None and resolved != fact.typ:
                            self._lazy_stub_imports.discard((mod_name, name))
                            facts[name] = TypeFact(
                                name=fact.name,
                                typ=resolved,
                                raw_annotation=fact.raw_annotation,
                                source=fact.source,
                                kind=fact.kind,
                            )
                            changed = True
                            changed_any = True
                if not changed:
                    break
        finally:
            self._refreshing_import_facts = False
        return changed_any

    def _record_collection_failure(
        self, module_name: str, code: str, exc: Exception, path: str | None
    ) -> None:
        self._failed_modules.add(module_name)
        diagnostic = StubDiagnostic(
            code=code,
            category="type_inference",
            module_name=module_name,
            message=f"{type(exc).__name__}: {exc}",
            path=path,
            severity="error",
        )
        if diagnostic not in self._collection_diagnostics:
            self._collection_diagnostics.append(diagnostic)

    def type_of(self, module_name: str, name: str) -> ProperType | None:
        """Return the best known type for ``module.name``."""
        fact = self.fact_of(module_name, name)
        return fact.typ if fact is not None else None

    def fact_of(self, module_name: str, name: str) -> TypeFact | None:
        """Return the best known type fact for ``module.name``.

        Dotted names (``module.Class.member``) are resolved through the class
        member table when they are not top-level module facts.
        """
        self._ensure_collected(module_name)
        self._ensure_refreshed()
        facts = self._module_facts.get(module_name, {})
        fact = facts.get(name)
        if module_name in self._deferred_inference_modules and (
            fact is None
            or (
                fact.kind == "function"
                and module_name in self._functions
                and name in self._functions[module_name]
                and self._functions[module_name][name].returns is None
            )
        ):
            self._ensure_inferred(module_name)
            facts = self._module_facts.get(module_name, {})
            fact = facts.get(name)
        if fact is not None:
            if (
                fact.source == "import"
                and fact.typ is ANY
                and fact.raw_annotation
                and fact.raw_annotation != f"{module_name}.{name}"
            ):
                is_lazy_stub = (module_name, name) in self._lazy_stub_imports
                if is_lazy_stub:
                    self._lazy_stub_imports.discard((module_name, name))
                resolved = self._lookup_project_type(
                    fact.raw_annotation,
                    allow_synthetic=False,
                )
                if resolved is None and is_lazy_stub:
                    facts.pop(name, None)
                    return None
                if resolved is not None and resolved != fact.typ:
                    fact = TypeFact(
                        name=fact.name,
                        typ=resolved,
                        raw_annotation=fact.raw_annotation,
                        source=fact.source,
                        kind=fact.kind,
                    )
                    facts[name] = fact
            return fact
        if "." not in name:
            return None
        typ = self._lookup_project_type(f"{module_name}.{name}", allow_synthetic=False)
        if typ is None:
            return None
        return TypeFact(
            name=name,
            typ=typ,
            raw_annotation=str(typ),
            source="inference",
            kind="member",
        )

    def signature_of(
        self,
        module_name: str,
        name: str,
    ) -> FunctionTypeInfo | None:
        """Return function signature information for ``module.name``."""
        self._ensure_collected(module_name)
        self._ensure_refreshed()
        function = self._functions.get(module_name, {}).get(name)
        if (
            function is not None
            and module_name in self._deferred_inference_modules
            and (
                function.returns is None
                or any(param_type is None for param_type in function.params.values())
            )
        ):
            self._ensure_inferred(module_name)
            function = self._functions.get(module_name, {}).get(name)
        if function is not None:
            return function
        reexported = self._resolve_reexported_member(module_name, name)
        if reexported is not None and reexported != (module_name, name):
            module_name, name = reexported
            self._ensure_collected(module_name)
            self._ensure_refreshed()
            function = self._functions.get(module_name, {}).get(name)
            if function is not None:
                return function
        if "." not in name:
            return None
        class_name, _, method_name = name.rpartition(".")
        qualified_class = (
            class_name
            if class_name.startswith(f"{module_name}.")
            else f"{module_name}.{class_name}"
        )
        if qualified_class not in self._classes:
            self._lookup_project_type(qualified_class, allow_synthetic=False)
        if qualified_class not in self._classes:
            owner_module, _, owner_name = qualified_class.rpartition(".")
            reexported = self._resolve_reexported_member(owner_module, owner_name)
            if reexported is not None:
                qualified_class = f"{reexported[0]}.{reexported[1]}"
        return self._class_method_info(qualified_class, method_name)

    def class_info(self, qualified_name: str) -> ClassTypeInfo | None:
        """Return collected class information for ``qualified_name``."""
        self._ensure_refreshed()
        if qualified_name not in self._classes:
            module_name, _, class_name = qualified_name.rpartition(".")
            if module_name and class_name:
                self._ensure_collected(module_name)
                if qualified_name not in self._classes:
                    self._lookup_project_type(qualified_name, allow_synthetic=False)
        return self._classes.get(qualified_name)

    def members_of(self, qualified_name: str) -> dict[str, TypeFact]:
        """Return known members for a module or class."""
        self._ensure_refreshed()
        if qualified_name in self._classes:
            return self._class_members_with_inheritance(qualified_name)
        if qualified_name not in self._module_facts:
            # ``pkg.models.Client`` names a class, not a module.  Load the
            # longest importable module prefix first so the class can be found.
            prefix = qualified_name
            while "." in prefix:
                prefix = prefix.rpartition(".")[0]
                if self._find_module(prefix) is not None:
                    self.collect_module(prefix)
                    break
        if qualified_name in self._classes:
            return self._class_members_with_inheritance(qualified_name)
        module_name, _, attribute = qualified_name.rpartition(".")
        if module_name:
            # ``pkg.Client`` is often only an alias created by ``from .core
            # import Client``; follow the alias to the defining class.
            reexported = self._resolve_reexported_member(module_name, attribute)
            if reexported is not None:
                target = f"{reexported[0]}.{reexported[1]}"
                if target in self._classes:
                    return self._class_members_with_inheritance(target)
        self._ensure_collected(qualified_name)
        self._ensure_inferred(qualified_name)
        return dict(self._module_facts.get(qualified_name, {}))

    def _resolve_reexported_member(
        self,
        module_name: str,
        name: str,
        seen: set[tuple[str, str]] | None = None,
        *,
        collect_missing: bool = True,
    ) -> tuple[str, str] | None:
        """Follow ``from x import y`` aliases to the defining module member."""
        seen = set() if seen is None else seen
        key = (module_name, name)
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
            return None
        target_module, _, target_name = target.rpartition(".")
        nested = self._resolve_reexported_member(
            target_module, target_name, seen, collect_missing=collect_missing
        )
        return nested or (target_module, target_name)

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

    def diagnostics(self) -> list[StubDiagnostic]:
        """Return source, inference, and stub-resolution diagnostics."""
        self._ensure_refreshed()
        diagnostics = [*self.stub_resolver.get_diagnostics(), *self._collection_diagnostics]
        for module_name, result in self._inference_results.items():
            for item in result.diagnostics:
                if any(
                    d.module_name == module_name
                    and d.code == item.code
                    and d.message == item.message
                    for d in diagnostics
                ):
                    continue
                diagnostics.append(
                    StubDiagnostic(
                        code=item.code,
                        category="type_inference",
                        module_name=module_name,
                        message=item.message,
                        severity=item.severity,
                        lineno=item.span.lineno if item.span is not None else None,
                        col_offset=(item.span.col_offset if item.span is not None else None),
                    )
                )
        return diagnostics

    def inference_result(
        self,
        module_name: str,
    ) -> ModuleInferenceResult | None:
        """Return the standalone static-inference result for a module."""
        self._ensure_collected(module_name)
        self._ensure_inferred(module_name)
        self._ensure_refreshed()
        return self._inference_results.get(module_name)

    def _ensure_inferred(self, module_name: str) -> None:
        """Run deferred intra-module static inference for a dependency on demand."""
        if (
            not self.enable_static_inference
            or module_name not in self._deferred_inference_modules
            or module_name in self._collecting_modules
        ):
            return
        cached = self._module_sources.get(module_name)
        if cached is None:
            self._deferred_inference_modules.discard(module_name)
            return
        self._deferred_inference_modules.discard(module_name)
        if len(self._collection_stack) >= self._max_collection_depth:
            return
        self._collecting_modules.add(module_name)
        self._collection_stack.append(module_name)
        try:
            self._refresh_import_facts(module_name=module_name)
            self._collect_inferred_source_facts(module_name, *cached)
        except Exception as exc:
            self._record_collection_failure(module_name, "type_source_failed", exc, cached[1])
        finally:
            self._collecting_modules.discard(module_name)
            if self._collection_stack and self._collection_stack[-1] == module_name:
                self._collection_stack.pop()
            else:
                self._collection_stack = [
                    name for name in self._collection_stack if name != module_name
                ]

    def _ensure_collected(self, module_name: str) -> None:
        if module_name not in self._collected_modules:
            self.collect_module(module_name)

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
        # A stub, when available, is the authoritative and much cheaper input
        # for external modules.  In particular, avoid parsing a full stdlib
        # implementation merely to recover its public signatures.
        stub_path = self.stub_resolver.resolve_path(module_name, script_path=path)
        if stub_path is not None:
            try:
                if stub_path in self.project_context.source_files:
                    return self.project_context.source_files[stub_path], stub_path
                with tokenize.open(stub_path) as stub_file:
                    return stub_file.read(), stub_path
            except OSError:
                pass

        # The interpreter's stdlib implementation is not a typing source.
        # If no typeshed/project stub is available, leave it unresolved instead
        # of recursively interpreting large implementation modules.
        if self._is_stdlib_source(path):
            return None, path
        if self._third_party_typed(module_name) is False:
            # mypy only reads inline annotations from packages that declare
            # ``py.typed``; an untyped dependency behaves like ``Any``.
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
        for node in _module_statements(tree):
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
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
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
                # Typed source packages use ``@overload`` heavily (pydantic's
                # ``Field``); mypy dispatches on those declarations instead of
                # the implementation body.
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
                member_type: ProperType | None = None
                if head in {"TypeAlias", "TypeAliasType"} and node.value is not None:
                    raw_annotation = _annotation_to_str(node.value)
                    member_type = self._resolve_annotation(
                        raw_annotation,
                        module_name=module_name,
                        imports=imports,
                        collect_missing=collect_missing,
                    )
                elif head in {"Final", "ClassVar"}:
                    inner = _strip_annotation_wrapper(raw_annotation, head)
                    if inner not in {None, "", "Any"}:
                        member_type = self._resolve_annotation(
                            inner,
                            module_name=module_name,
                            imports=imports,
                            collect_missing=collect_missing,
                        )
                        raw_annotation = inner
                    elif node.value is not None:
                        member_type = self._infer_expr_type(
                            node.value,
                            module_name,
                            local_classes,
                            imports,
                        )
                else:
                    member_type = self._resolve_annotation(
                        raw_annotation,
                        module_name=module_name,
                        imports=imports,
                        collect_missing=collect_missing,
                    )
                if member_type is None and node.value is not None:
                    member_type = self._infer_expr_type(
                        node.value,
                        module_name,
                        local_classes,
                        imports,
                    )
                facts[node.target.id] = TypeFact(
                    name=node.target.id,
                    typ=member_type,
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
                # Third-party ``py.typed`` packages (e.g. openai, pydantic)
                # often re-export hundreds of submodules from ``__init__.py``.
                # Keep their import facts lazy and resolve them on demand when
                # referenced instead of eagerly crawling the entire package.
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
            # Always run full body inference for the requested top-level module.
            # For transitively discovered project dependencies, keep AST
            # declarations (classes, methods, annotations, docstrings) eager and
            # defer body inference until an unannotated symbol is actually queried.
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
        engine = StaticTypeInferenceEngine(
            self.project_context,
            type_system=self.type_system,
            external_symbol_resolver=self._resolve_inference_external_symbol,
            call_model_providers=self.call_model_providers,
            options=self.inference_options,
        )
        result = engine.infer_source(module_name, source, filename=path)
        self._inference_results[module_name] = result
        for qualified_name, summary in result.functions.items():
            self._function_summaries[qualified_name] = summary
        if not self._refreshing_inference:
            self._needs_refresh = True
        self._external_symbol_cache.clear()
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
        """Re-run modules whose annotation checks may predate their dependencies.

        ``collect_module`` discovers the project import graph lazily.  A module
        can therefore be inferred before a class hierarchy or alias in a
        dependency is registered, which leaves a stale ``annotation-mismatch``
        that is no longer true once the whole closure has been collected.
        Re-infer only those modules after the closure is stable; this is
        bounded and avoids changing the normal single-module collection cost.
        """
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

        # Build class shapes before functions/variables: value aliases such as
        # ``random = _inst.random`` need both the class and the ``_inst`` fact.
        # Keep cross-stub annotation resolution lazy for non-project (typeshed)
        # stubs so importing ``os`` or ``asyncio`` does not transitively load
        # ~200 unrelated stdlib stubs; class bases and ``_typeshed`` aliases
        # still resolve eagerly and member lookups load classes on demand.
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
                # Stub overloads are declarations of one callable.  Keep a
                # union of their result types instead of silently keeping only
                # the first/last declaration, which can produce a definitely
                # wrong type for calls that select a different overload.
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

        # Resolve module-level aliases after variables exist.  This covers
        # value aliases (``random = _inst.random``) as well as type aliases.
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

        # Stub packages commonly re-export definitions from submodules.  Keep
        # those re-exports lazy so importing a stdlib stub such as ``os`` or
        # ``sys`` does not eagerly crawl hundreds of transitive typeshed files;
        # ``fact_of`` and ``_lookup_project_type_impl`` resolve them on demand.
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
            # ParamSpec/TypeVarTuple are not value types.
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
            # Keep the type variable instead of collapsing it to a union of
            # its constraints: generic substitution (``Generic[_T]``,
            # ``list[_T]``, method receivers) needs the variable identity.
            # Unsolved variables widen to their constraints in
            # ``_default_unsolved_type_vars``/``_match_type_variables``.
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
            # Class member callables already have the receiver removed;
            # ``_class_member_type`` returns the unbound signature.
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
        return Instance(
            self.type_system.to_class_descriptor(raw_type),
        )

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
                    # ``@prop.setter``/``@prop.deleter`` define an accessor for
                    # the property above.  Keep the getter's read type instead
                    # of replacing the property with a callable returning None.
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
            # Stub protocols must stay structural: nominal subtype checks
            # against the synthetic placeholder class would reject every
            # implementer (``math.ceil``'s ``_SupportsCeil`` overload).
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
            # ``class list(MutableSequence[_T])`` is generic over every type
            # variable that appears in its bases, not only over explicit
            # ``Generic[...]`` parameters (mypy's ``semanal_classprop``).
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

    def _callable_type(self, function_info: FunctionTypeInfo) -> CallableType:
        return_type = function_info.returns if function_info.returns is not None else ANY
        if any(name.startswith("*") for name in function_info.raw_params):
            return CallableType(None, return_type)
        return CallableType(
            tuple(typ if typ is not None else ANY for typ in function_info.params.values()),
            return_type,
        )

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
            alias = self._class_aliases.get(name) or self._class_aliases.get(
                normalized,
            )
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
        """Whether a name can be safely loaded as a type source.

        Mirrors mypy's module finder: project sources, ``.pyi`` stubs, and
        PEP 561 packages that ship a ``py.typed`` marker are typed sources.
        Installed packages without ``py.typed`` are treated as untyped
        (``Any``) instead of being parsed and half-analysed.
        """
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
        """Whether an installed module is a PEP 561 typed package.

        ``None`` means the module is not third-party (project, stub, stdlib,
        or unresolved).  Cached per module; the marker file is only checked
        for the top-level package directory.
        """
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
        parameters = tuple(value.public_type() or ANY for value in summary.parameters.values())
        return CallableType(parameters, summary.return_type or ANY)

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

    _SELF_ANNOTATIONS = frozenset({"Self", "typing.Self", "typing_extensions.Self"})

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

        # Ensure the defining module (or the module enclosing a dotted class
        # member) has been collected.  Project modules and stub-backed modules
        # are safe; arbitrary installed packages without stubs are not.
        parts = qualified_name.split(".")
        if collect_missing:
            for index in range(len(parts) - 1, 0, -1):
                candidate = ".".join(parts[:index])
                if candidate in self._collected_modules:
                    break
                if len(self._collection_stack) >= self._max_collection_depth:
                    if not self._depth_limit_warning_emitted:
                        self._depth_limit_warning_emitted = True
                        self._collection_diagnostics.append(
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

        # ``pkg.Class.method`` / ``pkg.Class.attr``: the last dot is not a
        # module boundary.  Find the longest known class prefix.
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
            # Stub declarations are authoritative.  Source inference may still
            # have a summary for the same implementation, but it cannot model
            # overload dispatch and would shadow the combined stub signature.
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
                diagnostic = StubDiagnostic(
                    code="type_dependency_partial",
                    category="type_inference",
                    module_name=dependent,
                    message=f"Type information for dependency {module_name!r} is partial",
                    severity="warning",
                )
                if diagnostic not in self._collection_diagnostics:
                    self._collection_diagnostics.append(diagnostic)

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
            # A failed import supplies no nominal-class evidence. Any also
            # prevents the engine from inventing a class for this symbol.
            return ANY

        if allow_synthetic and self._find_module(module_name) is not None:
            return self._synthetic_instance(qualified_name)
        return None

    def _synthetic_instance(self, full_name: str) -> Instance:
        raw_type = self._synthetic_types.get(full_name)
        if raw_type is None:
            raw_type = _runtime_stdlib_class(full_name)
        if raw_type is tuple:
            # ``tuple`` must be represented by ``TupleType``; keep a private
            # placeholder if a stub class named tuple is ever collected.
            raw_type = None
        if raw_type is None:
            module_name, _, class_name = full_name.rpartition(".")
            raw_type = type(class_name, (), {"__module__": module_name})
        self._synthetic_types[full_name] = raw_type
        return Instance(self.type_system.to_class_descriptor(raw_type))

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

    def _is_known_class_name(self, qualified_name: str) -> bool:
        """Return whether ``qualified_name`` denotes a class, not a callable.

        The syntactic collector sees only a call expression, so it must not
        assume that ``json.loads(...)`` constructs ``json.loads``.  Restrict
        the synthetic-instance fallback to names with class evidence.
        """

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
            # ``ProjectContext.get_sys_path`` inserts a top-level ``src``
            # directory for the common src layout.  Keep this guard in sync
            # with import resolution; otherwise project modules are never
            # collected lazily and their annotations degrade to synthetic or
            # unknown types.
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
                    # For dotted names such as ``mod.Class``, require every
                    # parent component to be an actual package directory;
                    # otherwise ``mod.py`` would match ``mod.Class`` as a
                    # project module and short-circuit collection of ``mod``.
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


_TYPE_CHECKING_NAMES = frozenset(
    {"TYPE_CHECKING", "typing.TYPE_CHECKING", "typing_extensions.TYPE_CHECKING"}
)


def _module_statements(tree: ast.Module | list[ast.stmt]) -> list[ast.stmt]:
    """Flatten ``if TYPE_CHECKING:`` blocks, which mypy always analyses.

    Libraries re-export their public API inside a ``TYPE_CHECKING`` guard so
    runtime imports stay lazy; ignoring those statements made names such as
    ``pydantic.BaseModel`` invisible even though the annotation exists.
    """
    statements = tree.body if isinstance(tree, ast.Module) else list(tree)
    result: list[ast.stmt] = []
    for statement in statements:
        result.append(statement)
        if isinstance(statement, ast.If) and _expr_name(statement.test) in _TYPE_CHECKING_NAMES:
            result.extend(_module_statements(statement.body))
    return result


def _stub_variance(declaration) -> "Variance":
    from pyflow.analysis.typeinfo.core.typesystem import Variance

    if declaration.covariant:
        return Variance.COVARIANT
    if declaration.contravariant:
        return Variance.CONTRAVARIANT
    return Variance.INVARIANT


def _top_level_package_dir(path: Path) -> Path | None:
    """Return the top-level package directory of an installed module."""
    try:
        parts = path.resolve().parts
    except OSError:
        return None
    for index, part in enumerate(parts):
        if part in {"site-packages", "dist-packages"}:
            if index + 1 < len(parts):
                return Path(*parts[: index + 2])
            return None
    return None


def _iter_arguments(args: ast.arguments) -> Iterator[ast.arg]:
    yield from args.posonlyargs
    yield from args.args
    yield from args.kwonlyargs


def _annotation_to_str(node: ast.expr) -> str:
    return ast.unparse(node)


def _expr_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expr_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _split_annotation_arguments(annotation: str) -> list[str]:
    """Split top-level comma-separated annotation arguments."""
    parts: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(annotation):
        if character in "[(":
            depth += 1
        elif character in "])":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            parts.append(annotation[start:index])
            start = index + 1
    tail = annotation[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _strip_annotation_wrapper(annotation: str, wrapper: str) -> str | None:
    """Return ``T`` from ``Wrapper[T]`` or ``None`` when unwrapped is absent."""
    head, _, rest = annotation.partition("[")
    if head.rsplit(".", 1)[-1] != wrapper or not rest:
        return None
    return rest[:-1].strip() or None


def _runtime_stdlib_class(full_name: str) -> type | None:
    """Return the real stdlib class named by *full_name*, when safely available.

    Typeshed describes runtime classes.  Using the actual class object keeps
    stub-derived instances interchangeable with PyFlow's builtin/stdlib models
    (``datetime.date``, ``types.MappingProxyType``, ...).  Third-party modules
    are left synthetic so analysis never imports arbitrary project code.
    """
    module_name, _, class_name = full_name.rpartition(".")
    if not module_name or not class_name:
        return None
    if module_name.split(".", 1)[0] not in sys.stdlib_module_names:
        return None
    try:
        module = importlib.import_module(module_name)
    except Exception:
        return None
    candidate = vars(module).get(class_name)
    if not isinstance(candidate, type):
        return None
    # Runtime aliases are common (``urllib.parse._ParseResultBase`` is
    # ``ParseResult``; ``_csv.Reader`` is ``_csv.reader``).  Only reuse the
    # class when its identity matches the stub declaration.
    # A few stdlib aliases intentionally expose a different runtime class
    # name (``types.TracebackType`` is ``traceback``).
    runtime_aliases = {
        "TracebackType": "traceback",
        # ``types.ModuleType`` is the runtime ``module`` class.  Keeping one
        # descriptor lets stub-derived annotations compare with objects coming
        # from ``sys.modules``.
        "ModuleType": "module",
    }
    expected_name = runtime_aliases.get(class_name, class_name)
    if candidate.__name__ != expected_name or candidate.__qualname__ != expected_name:
        return None
    return candidate
