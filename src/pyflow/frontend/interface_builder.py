"""Build analysis entry-point declarations from Python source paths."""

from __future__ import annotations

import inspect
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence

from pyflow.api.entrypoints import (
    ClassDeclaration,
    ExistingWrapper,
    InterfaceDeclaration,
)
from pyflow.language.modules.imports import infer_analysis_root

from .resolution.dependencies import DependencyResolver
from .resolution.hierarchy import ClassHierarchy


@dataclass(frozen=True)
class InterfaceBuildOptions:
    """Explicit configuration for interface discovery.

    CLI callers convert their ``argparse`` namespace into this object so core
    frontend behavior does not depend on a CLI-shaped bag of attributes.
    """

    dependency_strategy: str = "auto"
    verbose: bool = False
    include_main_entry_points: bool = False
    search_paths: Optional[tuple[str, ...]] = None
    fail_on_diagnostics: bool = False
    max_diagnostics: Optional[int] = None
    max_runtime_fallback_ratio: Optional[float] = None

    @classmethod
    def from_namespace(cls, args) -> "InterfaceBuildOptions":
        search_paths = getattr(args, "search_paths", None)
        return cls(
            dependency_strategy=getattr(args, "dependency_strategy", "auto"),
            verbose=getattr(args, "verbose", False),
            include_main_entry_points=getattr(args, "include_main_entry_points", False),
            search_paths=(
                tuple(str(path) for path in search_paths)
                if search_paths is not None
                else None
            ),
            fail_on_diagnostics=getattr(args, "fail_on_diagnostics", False),
            max_diagnostics=getattr(args, "max_diagnostics", None),
            max_runtime_fallback_ratio=getattr(
                args, "max_runtime_fallback_ratio", None
            ),
        )


def _default_entry_args(callable_obj, *, skip_first: bool = False):
    try:
        signature = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        return (), ()

    parameters = list(signature.parameters.values())
    if skip_first and parameters:
        parameters = parameters[1:]

    args = []
    keywords = []
    for parameter in parameters:
        if parameter.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            args.append(ExistingWrapper(None))
        elif parameter.kind == inspect.Parameter.KEYWORD_ONLY:
            keywords.append((parameter.name, ExistingWrapper(None)))
    return tuple(args), tuple(keywords)


def _add_function_entries(
    interface: InterfaceDeclaration,
    functions: dict,
    file_path: str | Path,
    options: InterfaceBuildOptions,
) -> None:
    for function_name, function in functions.items():
        if function_name == "main" and not options.include_main_entry_points:
            if options.verbose:
                print(f"DEBUG: Skipping '{function_name}' as an entry point")
            continue

        args, keywords = _default_entry_args(function)
        interface.func.append((function, args, keywords))
        if options.verbose:
            print(f"Added function '{function_name}' from {file_path}")


def _add_class_entries(
    interface: InterfaceDeclaration,
    classes: dict,
    resolver: DependencyResolver,
    file_path: str | Path,
    options: InterfaceBuildOptions,
) -> None:
    for class_name, class_object in classes.items():
        declaration = ClassDeclaration(class_object)
        init_args, init_keywords = _default_entry_args(
            class_object.__init__, skip_first=True
        )
        declaration.init(*init_args, kwds=init_keywords)
        interface.cls.append(declaration)

        for method_name, method_info in resolver.get_public_method_specs(
            class_object
        ).items():
            if method_name.startswith("_"):
                continue
            if method_info.get("is_property", False):
                declaration.attr(method_name)
                continue

            skip_first = not method_info.get("is_staticmethod", False)
            method = getattr(class_object, method_name)
            if method_info.get("is_classmethod", False):
                method = getattr(method, "__func__", method)
            method_args, method_keywords = _default_entry_args(
                method, skip_first=skip_first
            )
            kind = (
                "staticmethod"
                if method_info.get("is_staticmethod", False)
                else (
                    "classmethod"
                    if method_info.get("is_classmethod", False)
                    else "instance"
                )
            )
            declaration.method(
                method_name,
                *method_args,
                kind=kind,
                kwds=method_keywords,
            )

        if options.verbose:
            print(f"Added class '{class_name}' from {file_path}")


def _report_resolver_state(
    resolver: DependencyResolver, options: InterfaceBuildOptions
) -> None:
    if not options.verbose:
        return

    missing = resolver.get_missing_dependencies()
    if missing:
        print("\nMissing dependencies report:")
        for module, importing_files in missing.items():
            print(f"  {module}: imported by {len(importing_files)} file(s)")

    telemetry = resolver.get_telemetry()
    if telemetry:
        print("\nDependency resolver telemetry:")
        for key in sorted(telemetry):
            print(f"  {key}: {telemetry[key]}")


def build_interface_from_paths(
    python_files: Iterable[str | Path],
    options: InterfaceBuildOptions,
    *,
    source_overrides: Optional[Mapping[str, str]] = None,
):
    """Build an interface and source map using explicit frontend options.

    ``source_overrides`` lets editor and other in-memory clients analyze a
    document snapshot without first writing it to disk.  Keys are normalized
    to their string path representation, matching the returned source map.
    """

    paths = list(python_files)
    interface = InterfaceDeclaration()
    source_files: dict[str, str] = {}
    analysis_root = infer_analysis_root(str(path) for path in paths)
    class_hierarchy = ClassHierarchy(verbose=options.verbose)
    search_paths: Sequence[str] = options.search_paths or tuple(sys.path)

    resolver = DependencyResolver(
        strategy=options.dependency_strategy,
        verbose=options.verbose,
        safe_modules=["math", "os", "sys", "re", "json", "datetime", "collections"],
        search_paths=list(search_paths),
        class_hierarchy=class_hierarchy,
        source_files=source_files,
        analysis_root=analysis_root,
        fail_on_diagnostics=options.fail_on_diagnostics,
        max_diagnostics=options.max_diagnostics,
        max_runtime_fallback_ratio=options.max_runtime_fallback_ratio,
    )

    overrides = {str(path): source for path, source in (source_overrides or {}).items()}

    # Register every source file up front so the project context's source map
    # is built once over the complete file set.  Registering incrementally
    # inside the extraction loop invalidated the source-map cache on every new
    # file, turning interface building into an O(n^2) rebuild over the project.
    for file_path in paths:
        try:
            source = overrides.get(str(file_path))
            if source is None:
                source = Path(file_path).read_text(
                    encoding="utf-8", errors="replace"
                )
            source_files[str(file_path)] = source
        except Exception:
            pass
    resolver.source_files.update(source_files)
    resolver.project_context.source_files.update(source_files)
    resolver.preload_sources(source_files)

    for file_path in paths:
        try:
            source = source_files[str(file_path)]
            functions = resolver.extract_functions(source, str(file_path))
            classes = resolver.get_module_classes(str(file_path))
            _add_function_entries(interface, functions, file_path, options)
            _add_class_entries(interface, classes, resolver, file_path, options)
            if options.verbose:
                print(
                    f"Found {len(functions)} functions and {len(classes)} "
                    f"classes in {file_path}"
                )
        except Exception as error:
            if options.verbose:
                print(f"Warning: Could not parse file {file_path}: {error}")

    _report_resolver_state(resolver, options)
    return interface, source_files


__all__ = [
    "InterfaceBuildOptions",
    "build_interface_from_paths",
]
