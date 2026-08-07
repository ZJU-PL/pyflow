"""
CPG construction convenience — one-call entry points.

Wraps the full pipeline: Python source → CFG → PDG → CPG.
Supports single-file and directory-level construction with import resolution.
"""

from __future__ import annotations

import os
from pathlib import Path
from time import monotonic
from typing import Any, Dict, Optional, Sequence

from pyflow.application import context
from pyflow.analysis.callgraph.callgraph import CallGraph
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cfg import transform as cfg_transform
from pyflow.ir.pdg import construct_pdg
from pyflow.ir.cpg.graph import CodePropertyGraph

DEFAULT_CPG_EXCLUDE_DIRS = (
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "site-packages",
    "venv",
)

SECURITY_CPG_EXCLUDE_DIRS = DEFAULT_CPG_EXCLUDE_DIRS + (
    "test",
    "tests",
    "third_party",
    "vendor",
)


def _discover_python_files(
    root: Path,
    *,
    recursive: bool,
    excluded: frozenset[str],
    deadline: float | None,
) -> list[Path]:
    """Discover Python files while pruning excluded directory subtrees."""

    files: list[Path] = []
    if not recursive:
        try:
            entries = sorted(root.iterdir(), key=lambda path: path.name)
        except OSError:
            return files
        for path in entries:
            if deadline is not None and monotonic() >= deadline:
                break
            if path.is_file() and path.suffix == ".py":
                files.append(path)
        return files

    for current, dirnames, filenames in os.walk(root):
        if deadline is not None and monotonic() >= deadline:
            break
        dirnames[:] = sorted(name for name in dirnames if name not in excluded)
        for filename in sorted(filenames):
            if deadline is not None and monotonic() >= deadline:
                return files
            if filename.endswith(".py"):
                files.append(Path(current, filename))
    return files


def build_cpg_from_directory(
    directory: str,
    *,
    recursive: bool = True,
    resolve_imports: bool = True,
    exclude_dirs: Sequence[str] = DEFAULT_CPG_EXCLUDE_DIRS,
    deadline: float | None = None,
    **kwargs,
) -> CodePropertyGraph:
    """Build a unified :class:`CodePropertyGraph` from all Python files
    in a directory.

    Discovers ``.py`` files, builds a CPG per file, and optionally
    resolves intra-project imports to wire ``CALL`` edges across files.

    Parameters
    ----------
    directory:
        Path to the directory to scan.
    recursive:
        Whether to recurse into subdirectories.
    resolve_imports:
        Compatibility option retained for callers. Cross-file edges are now
        derived only from resolvable call-site syntax, never from imports
        alone.
    **kwargs:
        Passed through to :func:`build_cpg` for each file.

    Returns
    -------
    CodePropertyGraph
        A unified CPG spanning all discovered files.
    """
    root = Path(directory).resolve()
    excluded = frozenset(exclude_dirs)
    files = _discover_python_files(
        root,
        recursive=recursive,
        excluded=excluded,
        deadline=deadline,
    )
    if not files:
        return CodePropertyGraph()

    sources: Dict[str, str] = {}
    for f in files:
        if deadline is not None and monotonic() >= deadline:
            break
        try:
            sources[str(f)] = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    if not sources:
        return CodePropertyGraph()

    compiler = context.CompilerContext(None)
    try:
        compiler.extractor = Extractor(compiler, verbose=False)
        program = compiler.extractor.extract_from_multiple_files(
            sources, deadline=deadline
        )
    except Exception as error:
        cpg = CodePropertyGraph()
        cpg.add_construction_diagnostic(
            code="cpg-batch-extraction-failed",
            message=f"Batch extraction failed: {type(error).__name__}: {error}",
            function=None,
            stage="extractor",
        )
        return cpg

    # Cross-file calls are resolved from actual call-site syntax after all
    # PDGs have been registered.  The former import-level CallGraph connected
    # every function in an importing file to every function in the imported
    # file, creating a quadratic, semantically spurious supergraph.
    return _build_cpg_from_program(compiler, program, deadline=deadline, **kwargs)


def _build_cpg_from_program(
    compiler: Any,
    prog: Any,
    *,
    run_ssa: bool = False,
    expand_phi: bool = False,
    include_control: bool = True,
    include_data: bool = True,
    deadline: float | None = None,
) -> CodePropertyGraph:
    """Lower one already-extracted program into function PDGs."""

    cpg = CodePropertyGraph()

    for code_obj in sorted(
        prog.liveCode,
        key=lambda code: getattr(code, "codeName", lambda: repr(code))(),
    ):
        if deadline is not None and monotonic() >= deadline:
            cpg.add_construction_diagnostic(
                code="cpg-construction-time-budget",
                message="CPG construction exceeded its time budget",
                function=None,
                stage="pdg",
                affects_completeness=True,
            )
            break
        func_name = getattr(code_obj, "codeName", lambda: "<unknown>")() or "<unknown>"
        try:
            # CPG construction consumes the simplified CFG directly and does
            # not use transformation remaps.  Skipping revision bookkeeping
            # avoids repeatedly indexing and rebuilding full IR semantics for
            # every function in a directory scan.
            cfg = cfg_transform.evaluate(
                compiler, code_obj, commit_revision=False
            )
        except Exception as error:
            cpg.add_construction_diagnostic(
                code="cpg-cfg-build-failed",
                message=(
                    f"CFG construction failed for {func_name!r}: "
                    f"{type(error).__name__}: {error}"
                ),
                function=func_name,
                stage="cfg",
            )
            continue
        try:
            pdg = construct_pdg(
                cfg,
                run_ssa=run_ssa,
                expand_phi=expand_phi,
                include_control=include_control,
                include_data=include_data,
            )
        except Exception as primary_error:
            try:
                pdg = construct_pdg(
                    cfg,
                    run_ssa=False,
                    expand_phi=False,
                    include_control=False,
                    include_data=False,
                )
            except Exception as fallback_error:
                cpg.add_construction_diagnostic(
                    code="cpg-pdg-build-failed",
                    message=(
                        f"PDG construction failed for {func_name!r}: "
                        f"{type(primary_error).__name__}: {primary_error}; "
                        f"fallback failed with {type(fallback_error).__name__}: "
                        f"{fallback_error}"
                    ),
                    function=func_name,
                    stage="pdg",
                )
                continue
            cpg.add_construction_diagnostic(
                code="cpg-pdg-structural-fallback",
                message=(
                    f"PDG construction for {func_name!r} required a structural "
                    f"fallback without control/data dependence: "
                    f"{type(primary_error).__name__}: {primary_error}"
                ),
                function=func_name,
                stage="pdg",
            )
        cpg.add_function(func_name, pdg)
    return cpg


def build_cpg(
    source: str,
    filename: str = "<unknown>",
    *,
    run_ssa: bool = False,
    expand_phi: bool = False,
    include_control: bool = True,
    include_data: bool = True,
    deadline: float | None = None,
) -> CodePropertyGraph:
    """Build a :class:`CodePropertyGraph` from Python source code.

    Handles the full pipeline: decompile → CFG → PDG → CPG.

    Parameters
    ----------
    source:
        Python source code string.
    filename:
        Logical filename (used for error messages and function naming).
    run_ssa:
        Enable SSA renaming during PDG construction.
    expand_phi:
        Expand phi nodes after SSA.
    include_control:
        Include control dependence edges.
    include_data:
        Include data dependence edges.

    Returns
    -------
    CodePropertyGraph
        A built CPG ready for querying.
    """
    compiler = context.CompilerContext(None)
    try:
        compiler.extractor = Extractor(compiler, verbose=False)
    except Exception as error:
        cpg = CodePropertyGraph()
        cpg.add_construction_diagnostic(
            code="cpg-extractor-initialization-failed",
            message=f"Extractor initialization failed: {type(error).__name__}: {error}",
            function=None,
            stage="extractor",
        )
        return cpg

    try:
        prog = compiler.extractor.extract_from_source(source, filename=filename)
    except Exception as error:
        cpg = CodePropertyGraph()
        cpg.add_construction_diagnostic(
            code="cpg-source-extraction-failed",
            message=f"Source extraction failed: {type(error).__name__}: {error}",
            function=None,
            stage="extractor",
        )
        return cpg
    if prog is None:
        cpg = CodePropertyGraph()
        cpg.add_construction_diagnostic(
            code="cpg-source-extraction-failed",
            message="Source extraction returned no program",
            function=None,
            stage="extractor",
        )
        return cpg

    return _build_cpg_from_program(
        compiler,
        prog,
        run_ssa=run_ssa,
        expand_phi=expand_phi,
        include_control=include_control,
        include_data=include_data,
        deadline=deadline,
    )


def build_cpg_with_callgraph(
    source: str,
    filename: str = "<unknown>",
    *,
    call_graph: Optional[CallGraph] = None,
    **kwargs,
) -> CodePropertyGraph:
    """Like :func:`build_cpg` but also attaches an optional call graph."""
    cpg = build_cpg(source, filename=filename, **kwargs)
    if call_graph is not None:
        cpg.add_call_graph(call_graph)
    return cpg
