"""Context and session helpers for running PyFlow analyses."""

from __future__ import annotations

from dataclasses import dataclass
import ast
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.api.queries import QueryComponents, create_query_components
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.source import read_python_source
from pyflow.checker.common.diagnostics import CheckerDiagnostic
from pyflow.frontend.interface_builder import (
    InterfaceBuildOptions,
    build_interface_from_paths,
)
from pyflow.util.application.console import Console


@dataclass
class AnalysisSession:
    """Holds analysis state and semantic queries for detectors."""

    compiler: CompilerContext
    program: Program
    queries: QueryComponents
    sources_by_name: Dict[str, str]
    analysis_facts: object
    # Cross-module tracking
    func_to_file: Dict[str, str]  # Maps function name to its defining file
    file_imports: Dict[str, Dict[str, str]]  # Maps file -> {imported_name: source_file}
    all_source_code: Dict[str, str]  # Maps filename -> source code
    diagnostics: tuple[CheckerDiagnostic, ...] = ()

    @classmethod
    def from_paths(
        cls,
        paths: Sequence[Union[str, Path]],
        *,
        verbose: bool = False,
        recursive: bool = False,
        include: Optional[Iterable[str]] = None,
        exclude: Optional[Iterable[str]] = None,
    ) -> "AnalysisSession":
        console = Console(verbose=verbose)
        compiler = CompilerContext(console)
        program = Program()

        include = tuple(include or ("*.py",))
        exclude = tuple(exclude or ())

        python_files = cls._collect_files(paths, recursive, include, exclude)
        if not python_files:
            raise ValueError("No Python files found to analyze.")

        source_overrides = {}
        diagnostics = []
        for path in python_files:
            try:
                source_overrides[str(path)] = read_python_source(path)
            except (OSError, UnicodeError, SyntaxError) as error:
                diagnostics.append(
                    CheckerDiagnostic(
                        message=str(error),
                        code="ast-source-read-error",
                        affects_completeness=True,
                        filename=str(path),
                        operation="read",
                    )
                )
        program.interface, all_source_code = build_interface_from_paths(
            source_overrides,
            InterfaceBuildOptions(verbose=verbose),
            source_overrides=source_overrides,
        )
        compiler.extractor = Extractor(compiler, verbose=verbose, source_code=all_source_code)

        with console.scope("extraction"):
            extract_program(compiler, program)

        compiler.program = program

        queries = create_query_components(compiler, program)
        from pyflow.ir.core import AnalysisFacts

        analysis_facts = AnalysisFacts(program.ir)
        sources_by_name, func_to_file, file_imports = cls._collect_sources_and_imports(
            program, all_source_code
        )
        return cls(
            compiler=compiler,
            program=program,
            queries=queries,
            sources_by_name=sources_by_name,
            analysis_facts=analysis_facts,
            func_to_file=func_to_file,
            file_imports=file_imports,
            all_source_code=all_source_code,
            diagnostics=tuple(diagnostics),
        )

    @staticmethod
    def _collect_files(
        paths: Sequence[Union[str, Path]],
        recursive: bool,
        include: Tuple[str, ...],
        exclude: Tuple[str, ...],
    ) -> List[Path]:
        from fnmatch import fnmatch
        from pyflow.frontend.file_selection import discover_python_files, path_is_excluded

        def matches(name: str) -> bool:
            return any(fnmatch(name, pat) for pat in include)

        files: List[Path] = []
        for raw in paths:
            path = Path(raw)
            if path.is_file():
                if matches(path.name) and not path_is_excluded(path, exclude, path.parent):
                    files.append(path)
                continue
            if path.is_dir():
                iterator = discover_python_files(path, recursive=recursive, exclude=exclude)
                for candidate in iterator:
                    if matches(candidate.name):
                        files.append(candidate)
        return sorted(set(files))

    @staticmethod
    def _collect_sources_and_imports(
        program: Program, all_source_code: Dict[str, str]
    ) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, Dict[str, str]]]:
        """Map function names to source, track file origins and imports.

        Returns:
            name_to_source: Maps function name to its source code
            func_to_file: Maps function name to its defining file
            file_imports: Maps filename -> {imported_name: source_file}
        """
        name_to_source: Dict[str, str] = {}
        func_to_file: Dict[str, str] = {}
        file_imports: Dict[str, Dict[str, str]] = {}

        # AST source is authoritative: interface objects can carry only leaf
        # names and must never overwrite another file's definition.
        definitions: dict[str, list[tuple[str, str]]] = {}

        # Collect from AST with import tracking
        for filename, src in all_source_code.items():
            file_imports[filename] = {}
            module_name = f"{filename}::<module>"
            name_to_source[module_name] = src
            func_to_file[module_name] = filename
            try:
                tree = ast.parse(src)
            except (SyntaxError, RecursionError):
                continue

            # Track imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        file_imports[filename][alias.asname or alias.name] = alias.name
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        for alias in node.names:
                            imported = f"{node.module}.{alias.name}"
                            file_imports[filename][alias.asname or alias.name] = imported

            # Preserve lexical qualification. Security reports and call-graph
            # targets distinguish ``Class.method`` and nested functions, while
            # the old flat ``node.name`` map both lost that identity and
            # silently overwrote same-named methods from different classes.
            qualified_functions: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []

            class FunctionCollector(ast.NodeVisitor):
                def __init__(self) -> None:
                    self.scope: list[str] = []

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    self.scope.append(node.name)
                    self.generic_visit(node)
                    self.scope.pop()

                def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                    qualified_functions.append((".".join((*self.scope, node.name)), node))
                    self.scope.append(node.name)
                    self.generic_visit(node)
                    self.scope.pop()

                visit_FunctionDef = _visit_function
                visit_AsyncFunctionDef = _visit_function

            FunctionCollector().visit(tree)
            if qualified_functions:
                for qualified_name, node in qualified_functions:
                    if getattr(node, "lineno", None) and getattr(node, "end_lineno", None):
                        # Keep file coordinates and multiline string contents.
                        # A synthetic suite accommodates indented definitions
                        # without dedenting or re-rendering their source.
                        lines = src.splitlines(keepends=True)
                        prefix = "\n" * (node.lineno - 1)
                        if node.col_offset:
                            prefix = "\n" * (node.lineno - 2) + "if True:\n"
                        func_src = prefix + "".join(lines[node.lineno - 1 : node.end_lineno])
                    else:
                        func_src = ast.get_source_segment(src, node) or src
                    definitions.setdefault(qualified_name, []).append((filename, func_src))

        for name, definitions_for_name in definitions.items():
            for filename, source in definitions_for_name:
                identity = f"{filename}::{name}" if len(definitions_for_name) > 1 else name
                name_to_source[identity] = source
                func_to_file[identity] = filename

        return name_to_source, func_to_file, file_imports
