"""Context and session helpers for running PyFlow analyses."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from pyflow.application.context import CompilerContext
from pyflow.application.pipeline import Pipeline
from pyflow.application.program import Program
from pyflow.application.queries.service import SemanticQueryService
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
        sources_by_name = cls._collect_sources(program, all_source_code)
        return cls(
            compiler=compiler,
            program=program,
            queries=queries,
            sources_by_name=sources_by_name,
            store_graph=store_graph,
            lifetime=lifetime,
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
    def _collect_sources(program: Program, all_source_code: Dict[str, str]) -> Dict[str, str]:
        """Map function names to their defining source text when available."""
        name_to_source: Dict[str, str] = {}
        interface = getattr(program, "interface", None)
        funcs = getattr(interface, "func", []) if interface else []
        for func_obj, _ in funcs:
            name = getattr(func_obj, "__name__", None)
            if not name:
                continue
            try:
                import inspect

                src = inspect.getsource(func_obj)
            except (OSError, TypeError):
                src = None
            if not src:
                filename = getattr(func_obj, "__code__", None)
                filename = getattr(filename, "co_filename", None)
                if filename and filename in all_source_code:
                    src = all_source_code[filename]
            if src:
                name_to_source[name] = src
        return name_to_source

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
