"""Context and session helpers for running PyFlow analyses."""

from __future__ import annotations

from dataclasses import dataclass
import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from pyflow.application.context import CompilerContext
from pyflow.application.pipeline import Pipeline
from pyflow.application.program import Program
from pyflow.api.queries import SemanticQueryService
from pyflow.frontend.programextractor import (
    Extractor,
    create_interface_from_paths,
    extractProgram,
)
from pyflow.util.application.console import Console


@dataclass
class AnalysisSession:
    """Holds analysis state and semantic queries for detectors."""

    compiler: CompilerContext
    program: Program
    queries: SemanticQueryService
    sources_by_name: Dict[str, str]
    store_graph: Optional[object]
    lifetime: Optional[object]
    # Cross-module tracking
    func_to_file: Dict[str, str]  # Maps function name to its defining file
    file_imports: Dict[str, Dict[str, str]]  # Maps file -> {imported_name: source_file}
    all_source_code: Dict[str, str]  # Maps filename -> source code

    @classmethod
    def from_paths(
        cls,
        paths: Sequence[Union[str, Path]],
        *,
        use_pass_manager: bool = True,
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

        arg_ns = SimpleNamespace(verbose=verbose, include=include, exclude=exclude)
        program.interface, all_source_code = create_interface_from_paths(
            python_files, arg_ns
        )
        compiler.extractor = Extractor(
            compiler, verbose=verbose, source_code=all_source_code
        )

        with console.scope("extraction"):
            extractProgram(compiler, program)

        pipeline = Pipeline(use_pass_manager=use_pass_manager)
        compiler.program = program
        with console.scope("analysis"):
            pipeline.run(program, compiler=compiler, name="semantic")

        queries = program.get_semantic_queries(compiler)
        store_graph = cls._maybe_get_store_graph(queries)
        lifetime = cls._maybe_get_lifetime(queries)
        sources_by_name, func_to_file, file_imports = cls._collect_sources_and_imports(
            program, all_source_code
        )
        return cls(
            compiler=compiler,
            program=program,
            queries=queries,
            sources_by_name=sources_by_name,
            store_graph=store_graph,
            lifetime=lifetime,
            func_to_file=func_to_file,
            file_imports=file_imports,
            all_source_code=all_source_code,
        )

    @staticmethod
    def _collect_files(
        paths: Sequence[Union[str, Path]],
        recursive: bool,
        include: Tuple[str, ...],
        exclude: Tuple[str, ...],
    ) -> List[Path]:
        from fnmatch import fnmatch

        def matches(name: str) -> bool:
            if any(fnmatch(name, pat) for pat in exclude):
                return False
            return any(fnmatch(name, pat) for pat in include)

        files: List[Path] = []
        for raw in paths:
            path = Path(raw)
            if path.is_file():
                if matches(path.name):
                    files.append(path)
                continue
            if path.is_dir():
                iterator = path.rglob("*.py") if recursive else path.glob("*.py")
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

        # Collect from interface (callable objects)
        #
        # Bug #18 fix: the original code called ``inspect.getsource(func_obj)``
        # unconditionally.  When ``func_obj`` is a PyFlow-internal proxy object
        # (e.g. ``_ASTFunctionProxy``) rather than a real Python function,
        # ``inspect.getsource`` raises ``TypeError`` (not ``OSError``), which
        # was caught, but more importantly it also raises ``OSError`` when the
        # source file is not available (e.g. built-in functions, C extensions,
        # or functions defined in a REPL).  The original ``except (OSError,
        # TypeError)`` clause was correct for those cases, but the code then
        # fell through to ``all_source_code[func_filename]`` using an empty
        # ``func_filename`` string, which would silently return the wrong
        # source (the first file in the dict, if any).
        #
        # The fix:
        # 1. Only call ``inspect.getsource`` on objects that are genuine Python
        #    functions/methods (i.e. have a ``__code__`` attribute).
        # 2. Derive ``func_filename`` from ``__code__.co_filename`` *before*
        #    attempting getsource, so the fallback path always has the right
        #    filename even when getsource fails.
        import inspect

        interface = getattr(program, "interface", None)
        funcs = getattr(interface, "func", []) if interface else []
        for func_obj, _ in funcs:
            name = getattr(func_obj, "__name__", None)
            if not name:
                continue

            # Derive the filename first (safe even for proxy objects).
            code_obj = getattr(func_obj, "__code__", None)
            func_filename = getattr(code_obj, "co_filename", "") or ""

            src = None
            # Only attempt inspect.getsource for real Python callables.
            if code_obj is not None and callable(func_obj):
                try:
                    src = inspect.getsource(func_obj)
                except (OSError, TypeError):
                    pass

            # Fallback: use the whole file source if we have it.
            if not src and func_filename and func_filename in all_source_code:
                src = all_source_code[func_filename]

            if src:
                name_to_source[name] = src
                func_to_file[name] = func_filename

        # Collect from AST with import tracking
        for filename, src in all_source_code.items():
            file_imports[filename] = {}
            try:
                tree = ast.parse(src)
            except SyntaxError:
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
                            file_imports[filename][
                                alias.asname or alias.name
                            ] = imported

            # Collect functions
            func_nodes = [
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            if func_nodes:
                for node in func_nodes:
                    if node.name in name_to_source:
                        continue
                    if getattr(node, "lineno", None) and getattr(
                        node, "end_lineno", None
                    ):
                        lines = src.splitlines()
                        func_src = "\n".join(lines[node.lineno - 1 : node.end_lineno])
                    else:
                        func_src = ast.get_source_segment(src, node) or src
                    name_to_source[node.name] = func_src
                    func_to_file[node.name] = filename

        return name_to_source, func_to_file, file_imports

    # --------------------------------------------------------------- analysis
    @staticmethod
    def _maybe_get_store_graph(queries: SemanticQueryService) -> Optional[object]:
        from pyflow.application.errors import TemporaryLimitation

        try:
            return queries.get_store_graph()
        except TemporaryLimitation:
            return None
        except Exception:
            return None

    @staticmethod
    def _maybe_get_lifetime(queries: SemanticQueryService) -> Optional[object]:
        from pyflow.application.errors import TemporaryLimitation

        try:
            return queries.get_lifetime()
        except TemporaryLimitation:
            return None
        except Exception:
            return None
