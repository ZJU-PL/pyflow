"""
CPG construction convenience — one-call entry points.

Wraps the full pipeline: Python source → CFG → PDG → CPG.
Supports single-file and directory-level construction with import resolution.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from pyflow.application import context
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cfg import transform as cfg_transform
from pyflow.ir.pdg import construct_pdg
from pyflow.analysis.callgraph.callgraph import CallGraph
from pyflow.ir.cpg.graph import CodePropertyGraph

_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+(\S+)\s+import\s+\S+|import\s+(\S+))",
    re.MULTILINE,
)


def _resolve_imports(source: str) -> List[str]:
    """Extract imported module names from source code using simple regex."""
    imports: List[str] = []
    for m in _IMPORT_RE.finditer(source):
        name = m.group(1) or m.group(2) or ""
        name = name.split(".")[0]
        if name and not name.startswith("_"):
            imports.append(name)
    return imports


def _find_module_file(
    module_name: str, search_dir: Path, all_files: List[Path]
) -> Optional[Path]:
    for f in all_files:
        stem = f.stem
        if stem == module_name:
            return f
        if f.parent != search_dir:
            rel = str(f.relative_to(search_dir)).replace("/", ".").replace("\\", ".")
            if rel.endswith(".py"):
                rel = rel[:-3]
            if rel == module_name:
                return f
    init_file = search_dir / module_name / "__init__.py"
    if init_file in all_files:
        return init_file
    return None


def build_cpg_from_directory(
    directory: str,
    *,
    recursive: bool = True,
    resolve_imports: bool = True,
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
        Whether to detect import relationships and wire call edges.
    **kwargs:
        Passed through to :func:`build_cpg` for each file.

    Returns
    -------
    CodePropertyGraph
        A unified CPG spanning all discovered files.
    """
    root = Path(directory).resolve()
    pattern = "**/*.py" if recursive else "*.py"
    files = sorted(root.glob(pattern))
    if not files:
        return CodePropertyGraph()

    file_cpgs: Dict[str, CodePropertyGraph] = {}
    call_graph = CallGraph()
    module_to_file: Dict[str, str] = {}

    for f in files:
        try:
            source = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        cpg = build_cpg(source, filename=str(f), **kwargs)
        if len(cpg.functions) == 0:
            continue
        file_cpgs[str(f)] = cpg
        module_to_file[f.stem] = str(f)

    if resolve_imports and len(file_cpgs) > 1:
        for fpath, cpg in file_cpgs.items():
            try:
                source = Path(fpath).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            imported = _resolve_imports(source)
            for mod_name in imported:
                target_path = module_to_file.get(mod_name)
                if target_path is None:
                    target_path = _find_module_file(
                        mod_name, root, files
                    )
                    if target_path:
                        target_path = str(target_path)
                if target_path and target_path in file_cpgs:
                    for caller_fn in cpg.functions:
                        for callee_fn in file_cpgs[target_path].functions:
                            call_graph.add_edge(caller_fn, callee_fn)

    unified = CodePropertyGraph()
    for cpg in file_cpgs.values():
        for fname, pdg in cpg.pdgs.items():
            unified.add_function(fname, pdg)
    if resolve_imports:
        unified.add_call_graph(call_graph)
    return unified


def build_cpg(
    source: str,
    filename: str = "<unknown>",
    *,
    run_ssa: bool = False,
    expand_phi: bool = False,
    include_control: bool = True,
    include_data: bool = True,
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
        compiler.extractor = Extractor(compiler)
    except Exception:
        return CodePropertyGraph()

    prog = compiler.extractor.extract_from_source(source, filename=filename)
    if prog is None:
        return CodePropertyGraph()

    cpg = CodePropertyGraph()
    for code_obj in prog.liveCode:
        try:
            cfg = cfg_transform.evaluate(compiler, code_obj)
        except Exception:
            continue
        try:
            pdg = construct_pdg(
                cfg,
                run_ssa=run_ssa,
                expand_phi=expand_phi,
                include_control=include_control,
                include_data=include_data,
            )
        except Exception:
            # Fallback: build without SSA and data edges
            try:
                pdg = construct_pdg(
                    cfg,
                    run_ssa=False,
                    expand_phi=False,
                    include_control=False,
                    include_data=False,
                )
            except Exception:
                continue
        func_name = getattr(code_obj, "codeName", lambda: filename)() or filename
        cpg.add_function(func_name, pdg)
    return cpg


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
