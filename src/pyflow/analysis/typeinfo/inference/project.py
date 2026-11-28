"""Project-wide orchestration for standalone static type inference."""

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import os
import time

import networkx as nx
import tokenize
from pathlib import Path
from typing import Iterable

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    CallableType,
    Instance,
    ProperType,
    TypeSystem,
    TypeType,
    TypeVarType,
)
from pyflow.analysis.typeinfo.inference.cache import (
    ProjectInferenceCache,
    options_fingerprint,
)
from pyflow.analysis.typeinfo.inference.project_config import load_inference_options
from pyflow.analysis.typeinfo.inference.engine import (
    InferenceOptions,
    StaticTypeInferenceEngine,
    _cached_parse,
)
from pyflow.analysis.typeinfo.inference.call_models import CallModelProvider
from pyflow.analysis.typeinfo.inference.models import (
    InferenceDiagnostic,
    ModuleInferenceResult,
    ProjectInferenceResult,
)
from pyflow.analysis.typeinfo.resolution.typeshed_resolver import (
    resolve_typeshed_declared_return,
    resolve_typeshed_symbol,
)
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.language.modules.workspace import DEFAULT_IGNORED_DIRS

_MISSING = object()


class ProjectTypeInferenceEngine:
    """Infer an import closure, including cycles, to a project fixed point."""

    def __init__(
        self,
        project_context: ProjectContext,
        *,
        type_system: TypeSystem | None = None,
        options: InferenceOptions | None = None,
        call_model_providers: Iterable[CallModelProvider] = (),
        max_project_iterations: int = 16,
        cache: ProjectInferenceCache | None = None,
        max_modules: int | None = None,
        time_budget_seconds: float | None = None,
    ) -> None:
        self.project_context = project_context
        self.cache = cache
        self.type_system = (
            type_system or (cache.type_system if cache is not None else None) or TypeSystem()
        )
        # Project configuration (``[tool.pyflow.typeinfo]``) applies unless
        # the caller supplies explicit options.
        self.options = options or load_inference_options(project_context.path)
        self.call_model_providers = tuple(call_model_providers)
        self.max_project_iterations = max_project_iterations
        self.max_modules = max_modules
        self.time_budget_seconds = time_budget_seconds
        self._find_module_cache: dict[str, object] = {}
        self._project_roots: tuple[Path, ...] | None = None

    def _find_module_cached(self, module_name: str):
        cached = self._find_module_cache.get(module_name, _MISSING)
        if cached is not _MISSING:
            return cached
        resolution = self.project_context.find_module(module_name)
        self._find_module_cache[module_name] = resolution
        return resolution

    def infer_project(
        self,
        entry_modules: Iterable[str],
        *,
        discover_imports: bool = True,
    ) -> ProjectInferenceResult:
        """Infer entry modules and, by default, their project import closure."""
        deadline = (
            time.monotonic() + self.time_budget_seconds
            if self.time_budget_seconds is not None and self.time_budget_seconds > 0
            else None
        )
        sources, paths, diagnostics, discovered_imports, load_time_limited = self._load_modules(
            entry_modules, discover_imports=discover_imports, deadline=deadline
        )
        results: dict[str, ModuleInferenceResult] = {}
        failed_modules: set[str] = set()
        converged = False
        iterations = 0
        importers: dict[str, set[str]] = {}
        imports: dict[str, set[str]] = {}
        for module_name, source in sources.items():
            cached_deps = discovered_imports.get(module_name)
            dependencies = (
                set(cached_deps)
                if cached_deps is not None
                else set(self._project_imports(module_name, source, paths[module_name] or ""))
            )
            imports[module_name] = dependencies
            for dependency in dependencies:
                importers.setdefault(dependency, set()).add(module_name)
        # Analysing dependencies before their importers means most modules see
        # final external facts on the second pass instead of the fifth.
        analysis_order = self._analysis_order(sources, imports)
        fingerprints = self._module_fingerprints(sources, imports) if self.cache else {}
        options_key = options_fingerprint(self.options) if self.cache else ""
        cached_modules: set[str] = set()
        if self.cache is not None:
            for module_name, fingerprint in fingerprints.items():
                if fingerprint is None:
                    continue
                cached = self.cache.get(module_name, fingerprint, options_key)
                if cached is not None:
                    results[module_name] = cached
                    cached_modules.add(module_name)
        source_set = set(sources)
        current_fingerprints: dict[str, tuple[object, ...]] = {
            module_name: self._module_fingerprint(result) for module_name, result in results.items()
        }
        seen_dep_fingerprints: dict[str, dict[str, tuple[object, ...] | None]] = {}
        observed_deps: dict[str, set[str]] = {module_name: set() for module_name in sources}
        targets = set(sources) - cached_modules
        if not targets:
            converged = True
        time_limited = load_time_limited
        typeshed_symbol_cache: dict[str, ProperType | None] = {}
        typeshed_return_cache: dict[str, bool | None] = {}

        def cached_typeshed_symbol(qname: str) -> ProperType | None:
            if qname in typeshed_symbol_cache:
                return typeshed_symbol_cache[qname]
            val = resolve_typeshed_symbol(qname)
            typeshed_symbol_cache[qname] = val
            return val

        def cached_typeshed_return(qname: str) -> bool | None:
            if qname in typeshed_return_cache:
                return typeshed_return_cache[qname]
            val = resolve_typeshed_declared_return(qname)
            typeshed_return_cache[qname] = val
            return val

        for iterations in range(1, self.max_project_iterations + 1):
            if not targets:
                converged = True
                break
            for module_name in [name for name in analysis_order if name in targets]:
                if deadline is not None and time.monotonic() >= deadline:
                    time_limited = True
                    break
                if module_name in failed_modules:
                    continue
                queried_modules: set[str] = set()
                local_ext_cache: dict[str, tuple[ProperType | None, tuple[str, ...]]] = {}
                local_decl_cache: dict[str, tuple[bool | None, tuple[str, ...]]] = {}

                def resolve_ext(
                    name: str,
                    q=queried_modules,
                    ec=local_ext_cache,
                ) -> ProperType | None:
                    cached_item = ec.get(name)
                    if cached_item is not None:
                        q.update(cached_item[1])
                        return cached_item[0]
                    hit_mods: set[str] = set()
                    val = self._external_type(
                        name,
                        results,
                        queried=hit_mods,
                        source_set=source_set,
                        typeshed_resolver=cached_typeshed_symbol,
                    )
                    q.update(hit_mods)
                    ec[name] = (val, tuple(hit_mods))
                    return val

                def resolve_decl(
                    name: str,
                    q=queried_modules,
                    dc=local_decl_cache,
                ) -> bool | None:
                    cached_item = dc.get(name)
                    if cached_item is not None:
                        q.update(cached_item[1])
                        return cached_item[0]
                    hit_mods: set[str] = set()
                    val = self._external_declared_return(
                        name,
                        results,
                        queried=hit_mods,
                        source_set=source_set,
                        typeshed_resolver=cached_typeshed_return,
                    )
                    q.update(hit_mods)
                    dc[name] = (val, tuple(hit_mods))
                    return val

                snapshot_before = {
                    dep: current_fingerprints.get(dep)
                    for dep in (imports.get(module_name, set()) | observed_deps[module_name])
                    if dep in source_set and dep != module_name
                }
                module_options = self.options
                if deadline is not None:
                    remaining = max(0.05, deadline - time.monotonic())
                    effective_limit = (
                        min(module_options.max_seconds, remaining)
                        if module_options.max_seconds is not None and module_options.max_seconds > 0
                        else remaining
                    )
                    module_options = replace(module_options, max_seconds=effective_limit)
                engine = StaticTypeInferenceEngine(
                    self.project_context,
                    type_system=self.type_system,
                    external_symbol_resolver=resolve_ext,
                    external_declared_return=resolve_decl,
                    call_model_providers=self.call_model_providers,
                    options=module_options,
                )
                try:
                    results[module_name] = engine.infer_source(
                        module_name,
                        sources[module_name],
                        filename=paths[module_name],
                    )
                except Exception as exc:
                    failed_modules.add(module_name)
                    diagnostic = InferenceDiagnostic(
                        code="module-inference-error",
                        message=f"{module_name}: {type(exc).__name__}: {exc}",
                        severity="error",
                    )
                    results[module_name] = ModuleInferenceResult(
                        module_name,
                        diagnostics=[diagnostic],
                        converged=False,
                    )
                observed_deps[module_name].update(queried_modules)
                for dep in queried_modules:
                    if dep != module_name and dep in source_set and dep not in snapshot_before:
                        snapshot_before[dep] = current_fingerprints.get(dep)
                seen_dep_fingerprints[module_name] = snapshot_before
                current_fingerprints[module_name] = self._module_fingerprint(results[module_name])
                if engine._time_budget_exceeded:
                    time_limited = True
                    break

            if time_limited:
                break

            next_targets: set[str] = set()
            for module_name in source_set:
                if module_name in failed_modules or module_name in cached_modules:
                    continue
                seen = seen_dep_fingerprints.get(module_name)
                if seen is None:
                    next_targets.add(module_name)
                    continue
                all_deps = (
                    imports.get(module_name, set()) | observed_deps[module_name]
                ) & source_set
                for dep in all_deps:
                    if dep == module_name:
                        continue
                    if current_fingerprints.get(dep) != seen.get(dep):
                        next_targets.add(module_name)
                        break
            if not next_targets:
                converged = True
                break
            targets = next_targets

        if self.cache is not None:
            for module_name, result in results.items():
                fingerprint = fingerprints.get(module_name)
                if fingerprint is not None:
                    self.cache.put(module_name, fingerprint, options_key, result)

        if time_limited:
            diagnostics.append(
                InferenceDiagnostic(
                    code="project-inference-time-budget-exceeded",
                    message=(
                        "Project inference reached the " f"{self.time_budget_seconds}s time budget"
                    ),
                )
            )
        elif not converged:
            diagnostics.append(
                InferenceDiagnostic(
                    code="project-inference-did-not-converge",
                    message=(
                        "Project inference reached the "
                        f"{self.max_project_iterations}-iteration limit"
                    ),
                )
            )
        for module_name, result in results.items():
            diagnostics.extend(
                InferenceDiagnostic(
                    code=item.code,
                    message=f"{module_name}: {item.message}",
                    severity=item.severity,
                    span=item.span,
                )
                for item in result.diagnostics
            )
        return ProjectInferenceResult(
            modules=results,
            diagnostics=diagnostics,
            iterations=iterations,
            converged=converged and all(r.converged for r in results.values()),
        )

    _IGNORED_NAMESPACE_DIRS = DEFAULT_IGNORED_DIRS

    def _load_modules(
        self,
        entry_modules: Iterable[str],
        *,
        discover_imports: bool,
        deadline: float | None = None,
    ) -> tuple[
        dict[str, str], dict[str, str], list[InferenceDiagnostic], dict[str, list[str]], bool
    ]:
        sources: dict[str, str] = {}
        paths: dict[str, str] = {}
        diagnostics: list[InferenceDiagnostic] = []
        discovered_imports: dict[str, list[str]] = {}
        pending = list(dict.fromkeys(entry_modules))
        pending_set = set(pending)
        time_limited = False
        while pending:
            if deadline is not None and sources and time.monotonic() >= deadline:
                time_limited = True
                break
            if self.max_modules is not None and len(sources) >= self.max_modules:
                diagnostics.append(
                    InferenceDiagnostic(
                        code="project-module-limit-reached",
                        message=(
                            "Stopped discovering project imports after "
                            f"{self.max_modules} modules"
                        ),
                    )
                )
                break
            module_name = pending.pop(0)
            pending_set.discard(module_name)
            if module_name in sources:
                continue
            resolution = self._find_module_cached(module_name)
            if resolution is None:
                diagnostics.append(
                    InferenceDiagnostic(
                        code="module-not-found",
                        message=f"Could not resolve module {module_name!r}",
                        severity="error",
                    )
                )
                continue
            path = resolution.path
            if path is None:
                if resolution.is_namespace and resolution.namespace_paths:
                    # PEP 420 packages have no ``__init__.py``.  Treat the
                    # package as an empty module and analyze its children.
                    sources[module_name] = ""
                    paths[module_name] = ""
                    discovered_imports[module_name] = []
                    for namespace_path in resolution.namespace_paths:
                        for current, directories, filenames in os.walk(namespace_path):
                            if deadline is not None and time.monotonic() >= deadline:
                                time_limited = True
                                break
                            directories[:] = sorted(
                                name
                                for name in directories
                                if name not in self._IGNORED_NAMESPACE_DIRS
                                and not name.startswith(".")
                            )
                            for filename in sorted(filenames):
                                if not filename.endswith(".py") or filename.startswith("."):
                                    continue
                                child = Path(current, filename)
                                child_name = self.project_context.module_name_from_path(child)
                                if (
                                    child_name
                                    and child_name not in sources
                                    and child_name not in pending_set
                                ):
                                    pending.append(child_name)
                                    pending_set.add(child_name)
                        if time_limited:
                            break
                    continue
                diagnostics.append(
                    InferenceDiagnostic(
                        code="module-path-missing",
                        message=f"Resolved module {module_name!r} has no source path",
                        severity="error",
                    )
                )
                continue
            # A sidecar stub describes the public type surface of a module
            # and takes precedence over its implementation during static
            # analysis.  ``ProjectContext`` resolves source modules first, so
            # select the adjacent stub here before reading the module.
            resolved_path = Path(path)
            if resolved_path.suffix == ".py":
                stub_path = resolved_path.with_suffix(".pyi")
                if stub_path.is_file():
                    path = str(stub_path)
            source = self.project_context.source_files.get(path)
            if source is None:
                try:
                    with tokenize.open(path) as source_file:
                        source = source_file.read()
                except (OSError, UnicodeError, SyntaxError) as exc:
                    diagnostics.append(
                        InferenceDiagnostic(
                            code="module-read-error",
                            message=f"{module_name}: {exc}",
                            severity="error",
                        )
                    )
                    continue
            sources[module_name] = source
            paths[module_name] = path
            if discover_imports:
                deps = self._project_imports(module_name, source, path)
                discovered_imports[module_name] = deps
                for imported in deps:
                    if imported not in sources and imported not in pending_set:
                        pending.append(imported)
                        pending_set.add(imported)
        return sources, paths, diagnostics, discovered_imports, time_limited

    def _project_imports(
        self,
        module_name: str,
        source: str,
        path: str,
    ) -> list[str]:
        try:
            tree = _cached_parse(source, path)
        except SyntaxError:
            return []
        imports: list[str] = []
        # Function-local imports are part of the dependency closure too.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported = self.project_context.resolve_import_name(
                    module_name,
                    node.module or "",
                    node.level,
                    current_path=path,
                )
                if imported:
                    imports.append(imported)
        roots = self._project_roots
        if roots is None:
            raw_roots = (
                self.project_context.path,
                *self.project_context.module_identity.workspace_roots,
            )
            roots = tuple(Path(root).resolve() for root in raw_roots)
            self._project_roots = roots
        discovered = []
        for name in dict.fromkeys(imports):
            resolution = self._find_module_cached(name)
            if resolution is None or resolution.path is None:
                continue
            resolved_path = Path(resolution.path).resolve()
            if any(resolved_path.is_relative_to(root) for root in roots):
                discovered.append(name)
        return discovered

    def _external_declared_return(
        self,
        qualified_name: str,
        results: dict[str, ModuleInferenceResult],
        *,
        queried: set[str] | None = None,
        source_set: set[str] | None = None,
        typeshed_resolver=None,
    ) -> bool | None:
        """Whether an external callable's return type comes from an annotation."""
        parts = qualified_name.split(".")
        for index in range(len(parts) - 1, 0, -1):
            module_name = ".".join(parts[:index])
            if queried is not None and source_set is not None and module_name in source_set:
                queried.add(module_name)
            result = results.get(module_name)
            if result is None:
                continue
            remainder = ".".join(parts[index:])
            summary = result.functions.get(qualified_name) or result.functions.get(remainder)
            if summary is not None:
                return summary.declared_return
        resolver = typeshed_resolver or resolve_typeshed_declared_return
        return resolver(qualified_name)

    def _external_type(
        self,
        qualified_name: str,
        results: dict[str, ModuleInferenceResult],
        *,
        queried: set[str] | None = None,
        source_set: set[str] | None = None,
        typeshed_resolver=None,
    ) -> ProperType | None:
        parts = qualified_name.split(".")
        for index in range(len(parts) - 1, 0, -1):
            module_name = ".".join(parts[:index])
            if queried is not None and source_set is not None and module_name in source_set:
                queried.add(module_name)
            result = results.get(module_name)
            if result is not None:
                remainder = ".".join(parts[index:])
                typ = result.type_of(qualified_name) or result.type_of(remainder)
                if typ is not None:
                    return typ
                summary = result.functions.get(qualified_name) or result.functions.get(remainder)
                if summary is not None:
                    parameters = tuple(
                        value.public_type() or ANY for value in summary.parameters.values()
                    )
                    return CallableType(
                        parameters,
                        summary.return_type or ANY,
                        overloads=summary.overloads,
                    )
                if "." in remainder:
                    class_name, _, attribute = remainder.partition(".")
                    class_type = result.type_of(class_name)
                    if isinstance(class_type, TypeType):
                        class_type = class_type.item
                    if isinstance(class_type, Instance):
                        for superclass in self.type_system.get_superclasses(class_type.type):
                            member = superclass.members.get(attribute)
                            if member is not None:
                                if (
                                    isinstance(member, CallableType)
                                    and isinstance(member.return_type, TypeVarType)
                                    and member.return_type.name == "Self"
                                ):
                                    # ``Self`` in an inherited method binds to
                                    # the class the caller asked about.
                                    return CallableType(
                                        member.arg_types,
                                        class_type,
                                        overloads=member.overloads,
                                    )
                                return member
        resolver = typeshed_resolver or resolve_typeshed_symbol
        return resolver(qualified_name)

    @staticmethod
    def _module_fingerprints(
        sources: dict[str, str],
        imports: dict[str, set[str]],
    ) -> dict[str, str | None]:
        """Merkle fingerprint per module, with import cycles condensed.

        Modules in one strongly connected component share a fingerprint built
        from all their sources plus the fingerprints of external dependencies,
        so a change anywhere in a cycle invalidates the whole component.
        """
        graph = nx.DiGraph()
        graph.add_nodes_from(sources)
        for module, dependencies in imports.items():
            for dependency in dependencies:
                if dependency in sources:
                    graph.add_edge(module, dependency)
        components = list(nx.strongly_connected_components(graph))
        component_of = {
            module: index for index, component in enumerate(components) for module in component
        }
        condensed = nx.condensation(graph, components)
        component_hash: dict[int, str] = {}
        for component_index in nx.topological_sort(condensed.reverse(copy=False)):
            members = sorted(components[component_index])
            payload = "\0".join(sources.get(member, "") for member in members)
            dependency_hashes = sorted(
                component_hash[successor]
                for successor in condensed.successors(component_index)
                if successor in component_hash
            )
            digest = hashlib.sha256(
                (payload + "\0" + ",".join(dependency_hashes)).encode("utf-8")
            ).hexdigest()
            component_hash[component_index] = digest
        return {module: component_hash[component_of[module]] for module in sources}

    @staticmethod
    def _analysis_order(
        modules: Iterable[str],
        imports: dict[str, set[str]],
    ) -> list[str]:
        """Order modules so that local dependencies are analysed first."""
        module_set = set(modules)
        remaining = {
            module: {
                dependency for dependency in imports.get(module, ()) if dependency in module_set
            }
            for module in module_set
        }
        ordered: list[str] = []
        while remaining:
            ready = sorted(module for module, deps in remaining.items() if not deps)
            if not ready:
                # Import cycles: fall back to a stable alphabetical order.
                ordered.extend(sorted(remaining))
                break
            for module in ready:
                ordered.append(module)
                del remaining[module]
            for deps in remaining.values():
                deps.difference_update(ready)
        return ordered

    @staticmethod
    def _module_fingerprint(result: ModuleInferenceResult) -> tuple[object, ...]:
        return (
            tuple((name, repr(symbol.value)) for name, symbol in sorted(result.symbols.items())),
            tuple((name, repr(summary)) for name, summary in sorted(result.functions.items())),
        )

    @classmethod
    def _fingerprint(
        cls,
        results: dict[str, ModuleInferenceResult],
    ) -> tuple[object, ...]:
        return tuple(
            (module_name, cls._module_fingerprint(result))
            for module_name, result in sorted(results.items())
        )

    @staticmethod
    def _dependent_modules(
        changed: set[str],
        importers: dict[str, set[str]],
    ) -> set[str]:
        targets = set(changed)
        stack = list(changed)
        while stack:
            module_name = stack.pop()
            for importer in importers.get(module_name, ()):
                if importer not in targets:
                    targets.add(importer)
                    stack.append(importer)
        return targets
