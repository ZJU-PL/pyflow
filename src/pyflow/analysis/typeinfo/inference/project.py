"""Project-wide orchestration for standalone static type inference."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

from pyflow.analysis.typeinfo.core.typesystem import ProperType, TypeSystem
from pyflow.analysis.typeinfo.inference.engine import (
    InferenceOptions,
    StaticTypeInferenceEngine,
)
from pyflow.analysis.typeinfo.inference.call_models import CallModelProvider
from pyflow.analysis.typeinfo.inference.models import (
    InferenceDiagnostic,
    ModuleInferenceResult,
    ProjectInferenceResult,
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
    ) -> None:
        self.project_context = project_context
        self.type_system = type_system or TypeSystem()
        self.options = options or InferenceOptions()
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
        converged = False
        iterations = 0
        for iterations in range(1, self.max_project_iterations + 1):
            before = self._fingerprint(results)
            for module_name in sorted(sources):
                engine = StaticTypeInferenceEngine(
                    self.project_context,
                    type_system=self.type_system,
                    external_symbol_resolver=lambda name: self._external_type(
                        name, results
                    ),
                    call_model_providers=self.call_model_providers,
                    options=self.options,
                )
                results[module_name] = engine.infer_source(
                    module_name,
                    sources[module_name],
                    filename=paths[module_name],
                )
            if self._fingerprint(results) == before:
                converged = True
                break

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
                diagnostics.append(
                    InferenceDiagnostic(
                        code="module-path-missing",
                        message=f"Resolved module {module_name!r} has no source path",
                        severity="error",
                    )
                )
                continue
            source = self.project_context.source_files.get(path)
            if source is None:
                try:
                    source = Path(path).read_text(encoding="utf-8")
                except OSError as exc:
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
                    for imported in self._project_imports(
                        module_name, source, path
                    )
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
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            return []
        imports: list[str] = []
        for node in tree.body:
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
        return [
            name
            for name in dict.fromkeys(imports)
            if self.project_context.find_module(name) is not None
        ]

    @staticmethod
    def _external_type(
        qualified_name: str,
        results: dict[str, ModuleInferenceResult],
    ) -> ProperType | None:
        for module_name in sorted(results, key=len, reverse=True):
            prefix = f"{module_name}."
            if qualified_name.startswith(prefix):
                return results[module_name].type_of(
                    qualified_name.removeprefix(prefix)
                )
        return None

    @staticmethod
    def _fingerprint(
        results: dict[str, ModuleInferenceResult],
    ) -> tuple[object, ...]:
        return tuple(
            (
                module_name,
                tuple(
                    (name, repr(symbol.value))
                    for name, symbol in sorted(result.symbols.items())
                ),
                tuple(
                    (name, repr(summary))
                    for name, summary in sorted(result.functions.items())
                ),
            )
            for module_name, result in sorted(results.items())
        )
