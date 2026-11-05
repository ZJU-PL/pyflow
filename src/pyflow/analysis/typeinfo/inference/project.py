"""Project-wide orchestration for standalone static type inference."""

from __future__ import annotations

import ast
import hashlib

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

    def infer_project(
        self,
        entry_modules: Iterable[str],
        *,
        discover_imports: bool = True,
    ) -> ProjectInferenceResult:
        """Infer entry modules and, by default, their project import closure."""
        sources, paths, diagnostics = self._load_modules(
            entry_modules, discover_imports=discover_imports
        )
        results: dict[str, ModuleInferenceResult] = {}
        failed_modules: set[str] = set()
        converged = False
        iterations = 0
        importers: dict[str, set[str]] = {}
        imports: dict[str, set[str]] = {}
        for module_name, source in sources.items():
            dependencies = set(self._project_imports(module_name, source, paths[module_name] or ""))
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
        previous: dict[str, tuple[object, ...]] = {}
        targets = set(sources) - cached_modules
        for iterations in range(1, self.max_project_iterations + 1):
            for module_name in [name for name in analysis_order if name in targets]:
                if module_name in failed_modules:
                    continue
                engine = StaticTypeInferenceEngine(
                    self.project_context,
                    type_system=self.type_system,
                    external_symbol_resolver=lambda name: self._external_type(name, results),
                    external_declared_return=lambda name: self._external_declared_return(
                        name, results
                    ),
                    call_model_providers=self.call_model_providers,
                    options=self.options,
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
            current = {
                module_name: self._module_fingerprint(result)
                for module_name, result in results.items()
            }
            if current == previous:
                converged = True
                break
            changed = {
                module_name
                for module_name, fingerprint in current.items()
                if previous.get(module_name) != fingerprint
            }
            previous = current
            # Only changed modules and their transitive importers can observe
            # different external facts on the next pass.
            targets = self._dependent_modules(changed, importers)

        if self.cache is not None:
            for module_name, result in results.items():
                fingerprint = fingerprints.get(module_name)
                if fingerprint is not None:
                    self.cache.put(module_name, fingerprint, options_key, result)

        if not converged:
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

    def _load_modules(
        self,
        entry_modules: Iterable[str],
        *,
        discover_imports: bool,
    ) -> tuple[dict[str, str], dict[str, str], list[InferenceDiagnostic]]:
        sources: dict[str, str] = {}
        paths: dict[str, str] = {}
        diagnostics: list[InferenceDiagnostic] = []
        pending = list(dict.fromkeys(entry_modules))
        while pending:
            module_name = pending.pop(0)
            if module_name in sources:
                continue
            resolution = self.project_context.find_module(module_name)
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
                    for namespace_path in resolution.namespace_paths:
                        for child in Path(namespace_path).rglob("*.py"):
                            if "__pycache__" in child.parts:
                                continue
                            child_name = self.project_context.module_name_from_path(child)
                            if child_name and child_name not in sources:
                                pending.append(child_name)
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
                pending.extend(
                    imported
                    for imported in self._project_imports(module_name, source, path)
                    if imported not in sources
                )
        return sources, paths, diagnostics

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
        roots = (self.project_context.path, *self.project_context.module_identity.workspace_roots)
        roots = tuple(Path(root).resolve() for root in roots)
        discovered = []
        for name in dict.fromkeys(imports):
            resolution = self.project_context.find_module(name)
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
    ) -> bool | None:
        """Whether an external callable's return type comes from an annotation."""
        parts = qualified_name.split(".")
        for index in range(len(parts) - 1, 0, -1):
            module_name = ".".join(parts[:index])
            result = results.get(module_name)
            if result is None:
                continue
            remainder = ".".join(parts[index:])
            summary = result.functions.get(qualified_name) or result.functions.get(remainder)
            if summary is not None:
                return summary.declared_return
        return resolve_typeshed_declared_return(qualified_name)

    def _external_type(
        self,
        qualified_name: str,
        results: dict[str, ModuleInferenceResult],
    ) -> ProperType | None:
        parts = qualified_name.split(".")
        for index in range(len(parts) - 1, 0, -1):
            module_name = ".".join(parts[:index])
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
        return resolve_typeshed_symbol(qualified_name)

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
