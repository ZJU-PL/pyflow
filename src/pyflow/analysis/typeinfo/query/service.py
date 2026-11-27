"""Public type-information orchestration service.

Composes source collection (:mod:`._source`), stub resolution (:mod:`._stubs`),
and cross-module lookup/inheritance (:mod:`._lookup`) into a single query
facade backed by the shared :class:`TypeSystem`.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import time
from typing import Iterable

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    CallableType,
    ProperType,
    TypeSystem,
)
from pyflow.analysis.typeinfo.inference.call_models import CallModelProvider
from pyflow.analysis.typeinfo.inference.engine import InferenceOptions
from pyflow.analysis.typeinfo.inference.models import InferenceDiagnostic, ModuleInferenceResult
from pyflow.analysis.typeinfo.inference.project_config import load_inference_options
from pyflow.analysis.typeinfo.query.models import (
    ClassTypeInfo,
    FunctionTypeInfo,
    TypeFact,
)
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.language.modules.type_stubs import (
    StubAliasInfo,
    StubDiagnostic,
    StubResolver,
    StubTypeVarInfo,
)

from ._helpers import (
    _UNSET,
    _annotation_to_str,
    _expr_name,
    _iter_arguments,
    _module_statements,
    _runtime_stdlib_class,
    _split_annotation_arguments,
    _stdlib_root,
    _strip_annotation_wrapper,
    _stub_variance,
    _top_level_package_dir,
)
from ._lookup import _TypeLookupMixin
from ._source import _SourceCollectionMixin
from ._stubs import _StubCollectionMixin


class TypeInfoService(_SourceCollectionMixin, _StubCollectionMixin, _TypeLookupMixin):
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
        max_transitive_collected_modules: int | None = 128,
        max_transitive_inference_seconds: float | None = 2.0,
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
        self._max_transitive_collected_modules = max_transitive_collected_modules
        self._transitive_collected_count = 0
        self._max_transitive_inferred_modules = 16
        self._transitive_inferred_count = 0
        self._max_transitive_inference_seconds = max_transitive_inference_seconds
        self._transitive_inference_deadline: float | None = None
        self._depth_limit_warning_emitted = False
        self._collection_budget_warning_emitted = False
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
        self._module_defined_names: dict[str, frozenset[str]] = {}
        self._module_all: dict[str, frozenset[str] | None] = {}
        self._module_imports: dict[str, dict[str, str]] = {}
        self._module_stub_type_vars: dict[str, dict[str, StubTypeVarInfo]] = {}
        self._module_stub_aliases: dict[str, dict[str, StubAliasInfo]] = {}
        self._module_type_aliases: dict[str, dict[str, ProperType]] = {}
        self._resolving_stub_aliases: set[tuple[str, str]] = set()
        self._active_project_lookups: set[str] = set()
        self._refreshing_inference = False
        self._refreshing_import_facts = False
        self._imports_dirty = False
        self._last_refreshed_import_modules: frozenset[str] = frozenset()
        self._needs_refresh = False
        self._facts_epoch = 0
        self._module_checked_epoch: dict[str, int] = {}
        self._module_facts_epoch: dict[str, int] = {}
        self._module_dependency_epochs: dict[str, dict[str, int]] = {}
        self._recorded_deps_stack: list[dict[str, int]] = []
        self._collection_diagnostics: list[StubDiagnostic] = []
        self._collection_diagnostics_seen: set[StubDiagnostic] = set()
        self._collection_diagnostics_by_module: dict[str, list[StubDiagnostic]] = {}
        self._summary_type_cache: dict[str, tuple[object, CallableType]] = {}
        self._reexport_cache: dict[tuple[str, str], tuple[str, str] | None] = {}
        self._stub_annotation_cache: dict[tuple[str, str, bool], ProperType | None] = {}
        self._external_project_type_cache: dict[tuple[str, bool, bool], ProperType | None] = {}
        self._failed_modules: set[str] = set()
        self._third_party_kind: dict[str, str | None] = {}
        self._should_collect_cache: dict[str, bool] = {}
        self._known_class_cache: dict[str, bool] = {}
        self._external_symbol_cache: dict[str, ProperType | None] = {}
        self._may_be_project_cache: dict[str, bool] = {}
        self._may_be_project_cache_key: tuple[object, ...] | None = None
        self._find_module_cache: dict[str, object] = {}
        self._find_module_cache_key: tuple[object, ...] | None = None
        self._lazy_stub_imports: set[tuple[str, str]] = set()
        self._documented_parameters: dict[tuple[str, str], set[str]] = {}
        self._documented_returns: set[tuple[str, str]] = set()

    def _can_collect_transitively(self, module_name: str | None = None) -> bool:
        """Whether transitive dependency collection may still load additional modules."""
        if module_name is not None and (
            module_name in self._collected_modules or module_name in self._collecting_modules
        ):
            return False
        if len(self._collection_stack) >= self._max_collection_depth:
            return False
        if (
            self._max_transitive_collected_modules is not None
            and self._transitive_collected_count >= self._max_transitive_collected_modules
        ):
            if not self._collection_budget_warning_emitted and self._collection_stack:
                self._collection_budget_warning_emitted = True
                self._add_collection_diagnostic(
                    StubDiagnostic(
                        code="type_collection_budget_exceeded",
                        category="type_inference",
                        module_name=self._collection_stack[-1],
                        message=(
                            "Stopped lazy project collection at the module budget "
                            f"({self._max_transitive_collected_modules} transitive modules); "
                            "the inferred type closure is partial"
                        ),
                        severity="warning",
                    )
                )
            return False
        return True

    def collect_module(
        self,
        module_name: str,
        *,
        source: str | None = None,
        path: str | None = None,
    ) -> None:
        """Collect source and stub facts for a module."""
        if module_name in {"typing", "typing_extensions"} and source is None and path is None:
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
        is_transitive = bool(self._collecting_modules)
        if is_transitive:
            if not self._can_collect_transitively():
                return
            self._transitive_collected_count += 1
        else:
            self._depth_limit_warning_emitted = False
            if (
                self._max_transitive_inference_seconds is not None
                and self._max_transitive_inference_seconds > 0
                and self._transitive_inference_deadline is None
            ):
                self._transitive_inference_deadline = (
                    time.monotonic() + self._max_transitive_inference_seconds
                )
        self._collecting_modules.add(module_name)
        self._collection_stack.append(module_name)
        completed = False
        try:
            try:
                if source is None:
                    source, path = self._load_module_source(module_name, path)
                if source is not None and not (path is not None and str(path).endswith(".pyi")):
                    self._collect_source_module(module_name, source, path)
                    self._imports_dirty = True
            except Exception as exc:
                self._record_collection_failure(module_name, "type_source_failed", exc, path)

            try:
                resolved_stub = self.stub_resolver.resolve(module_name, script_path=path)
                if resolved_stub is not None:
                    self._collect_stub_module(
                        module_name,
                        resolved_stub.path,
                        resolved_stub.info,
                    )
                    self._imports_dirty = True
            except Exception as exc:
                self._record_collection_failure(module_name, "type_stub_failed", exc, path)

            self._collected_modules.add(module_name)
            self._facts_epoch += 1
            self._module_facts_epoch[module_name] = self._facts_epoch
            if module_name in self._module_checked_epoch:
                self._module_checked_epoch[module_name] = self._facts_epoch
            self._needs_refresh = True
            self._invalidate_external_symbol_cache(module_name)
            completed = True
        finally:
            self._collecting_modules.discard(module_name)
            if self._collection_stack and self._collection_stack[-1] == module_name:
                self._collection_stack.pop()
            else:
                self._collection_stack = [
                    name for name in self._collection_stack if name != module_name
                ]
            if not is_transitive:
                self._transitive_inference_deadline = None
            if completed and not self._collecting_modules:
                self.type_system.invalidate_subtype_caches()
                self._known_class_cache.clear()
                self._reexport_cache.clear()
                if (
                    self._imports_dirty
                    and self._refresh_import_facts()
                    and self.enable_static_inference
                    and module_name in self._last_refreshed_import_modules
                ):
                    cached = self._module_sources.get(module_name)
                    if cached is not None:
                        self._collect_inferred_source_facts(module_name, *cached)
            if completed:
                module_diags = self._collection_diagnostics_by_module.get(module_name, ())
                if module_diags:
                    result = self._inference_results.setdefault(
                        module_name, ModuleInferenceResult(module_name, converged=False)
                    )
                    existing_diags = set(result.diagnostics)
                    for diagnostic in module_diags:
                        item = InferenceDiagnostic(
                            diagnostic.code,
                            diagnostic.message,
                            severity=diagnostic.severity,
                            affects_completeness=True,
                        )
                        if item not in existing_diags:
                            existing_diags.add(item)
                            result.diagnostics.append(item)

    def _invalidate_external_symbol_cache(self, module_name: str) -> None:
        """Evict only cache entries affected by *module_name* (preserving stdlib/other caches)."""
        prefix = f"{module_name}."
        top_root = module_name.split(".", 1)[0]
        if self._external_project_type_cache:
            stale_project = [
                key
                for key, value in self._external_project_type_cache.items()
                if (
                    key[0] == module_name
                    or key[0].startswith(prefix)
                    or (
                        value is None
                        and (
                            key[0].split(".", 1)[0] == top_root
                            or self._module_may_be_project(key[0].rpartition(".")[0])
                        )
                    )
                )
            ]
            for key in stale_project:
                self._external_project_type_cache.pop(key, None)
        if self._stub_annotation_cache:
            stale_annot = [key for key in self._stub_annotation_cache if key[0] == module_name]
            for key in stale_annot:
                self._stub_annotation_cache.pop(key, None)
        if not self._external_symbol_cache:
            return
        stale = [
            key
            for key, value in self._external_symbol_cache.items()
            if value is None or key == module_name or key.startswith(prefix)
        ]
        for key in stale:
            self._external_symbol_cache.pop(key, None)

    def _add_collection_diagnostic(self, diagnostic: StubDiagnostic) -> None:
        """Record *diagnostic* once in O(1) time."""
        if diagnostic in self._collection_diagnostics_seen:
            return
        self._collection_diagnostics_seen.add(diagnostic)
        self._collection_diagnostics.append(diagnostic)
        self._collection_diagnostics_by_module.setdefault(diagnostic.module_name, []).append(
            diagnostic
        )

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
        self._add_collection_diagnostic(diagnostic)

    def type_of(self, module_name: str, name: str) -> ProperType | None:
        """Return the best known type for ``module.name``."""
        fact = self.fact_of(module_name, name)
        return fact.typ if fact is not None else None

    def fact_of(self, module_name: str, name: str) -> TypeFact | None:
        """Return the best known type fact for ``module.name``."""
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
            reexported = self._resolve_reexported_member(module_name, attribute)
            if reexported is not None:
                target = f"{reexported[0]}.{reexported[1]}"
                if target in self._classes:
                    return self._class_members_with_inheritance(target)
        self._ensure_collected(qualified_name)
        self._ensure_inferred(qualified_name)
        return dict(self._module_facts.get(qualified_name, {}))

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

    def _ensure_inferred(self, module_name: str, *, transitive: bool = False) -> None:
        """Run deferred intra-module static inference for a dependency on demand."""
        if (
            not self.enable_static_inference
            or module_name not in self._deferred_inference_modules
            or module_name in self._collecting_modules
        ):
            return
        if transitive and (
            len(self._collection_stack) >= 4
            or self._transitive_inferred_count >= self._max_transitive_inferred_modules
            or (
                self._transitive_inference_deadline is not None
                and time.monotonic() >= self._transitive_inference_deadline
            )
        ):
            return
        cached = self._module_sources.get(module_name)
        if cached is None:
            self._deferred_inference_modules.discard(module_name)
            return
        self._deferred_inference_modules.discard(module_name)
        if len(self._collection_stack) >= self._max_collection_depth:
            return
        infer_options: InferenceOptions | None = None
        if transitive:
            self._transitive_inferred_count += 1
            if self._transitive_inference_deadline is not None:
                remaining = max(0.05, self._transitive_inference_deadline - time.monotonic())
                existing = self.inference_options.max_seconds
                limit = (
                    min(existing, remaining) if existing is not None and existing > 0 else remaining
                )
                infer_options = replace(self.inference_options, max_seconds=limit)
        self._collecting_modules.add(module_name)
        self._collection_stack.append(module_name)
        try:
            self._refresh_import_facts(module_name=module_name)
            self._collect_inferred_source_facts(module_name, *cached, options=infer_options)
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

    def _callable_type(self, function_info: FunctionTypeInfo) -> CallableType:
        return_type = function_info.returns if function_info.returns is not None else ANY
        if any(name.startswith("*") for name in function_info.raw_params):
            return CallableType(None, return_type)
        return CallableType(
            tuple(typ if typ is not None else ANY for typ in function_info.params.values()),
            return_type,
        )


__all__ = [
    "TypeInfoService",
    "_UNSET",
    "_annotation_to_str",
    "_expr_name",
    "_iter_arguments",
    "_module_statements",
    "_runtime_stdlib_class",
    "_split_annotation_arguments",
    "_stdlib_root",
    "_strip_annotation_wrapper",
    "_stub_variance",
    "_top_level_package_dir",
]
