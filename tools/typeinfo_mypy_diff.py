#!/usr/bin/env python3
"""Differential harness: PyFlow typeinfo vs mypy over a real-world corpus.

For every sampled module the harness

* runs :class:`ProjectTypeInferenceEngine` over the module (plus its project
  import closure) and records status, diagnostics and expression types;
* copies the module into a shadow project tree, wraps selected expressions in
  ``reveal_type(...)`` and asks mypy for the inferred type;
* normalises both type strings and classifies differences.

Only expressions where mypy reports a concrete (Any-free) type are compared,
because mypy deliberately types unannotated parameters as ``Any``.

``--diagnostics`` switches to the other half of the audit: PyFlow's diagnostics
are compared with mypy's error list for the same module.  A PyFlow diagnostic
without a mypy error is a C3 false positive; a mypy error without a PyFlow
diagnostic is a C4 false negative.  Mypy codes whose category PyFlow does not
model yet (``attr-defined``, ``union-attr``, ``misc``, ...) are tallied under
``unmodeled_categories`` so the coverage gap stays visible.

Usage::

    .venv/bin/python tools/typeinfo_mypy_diff.py --list-projects
    .venv/bin/python tools/typeinfo_mypy_diff.py --project Textualize--rich \
        --max-modules 5 --out /tmp/rich.jsonl
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = Path.home() / "Work/tools/data/py/top100"

SKIP_TOP_LEVEL = {
    "tests",
    "test",
    "docs",
    "doc",
    "examples",
    "example",
    "scripts",
    "tools",
    "benchmarks",
    "bench",
    "build",
    "dist",
    "node_modules",
    "site-packages",
}


@dataclass
class Candidate:
    index: int
    module: str
    path: str
    lineno: int
    col_offset: int
    end_lineno: int | None
    end_col_offset: int | None
    text: str
    kind: str


@dataclass
class ExprRecord:
    project: str
    module: str
    path: str
    index: int
    kind: str
    text: str
    lineno: int
    col_offset: int
    pyflow_type: str | None = None
    pyflow_complete: bool | None = None
    mypy_type: str | None = None
    mypy_status: str | None = None
    normalized_pyflow: str | None = None
    normalized_mypy: str | None = None
    verdict: str = "unknown"
    diagnostics: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Module discovery
# ---------------------------------------------------------------------------


def import_roots(project_root: Path) -> list[Path]:
    """Return directories that act as sys.path entries for *project_root*."""
    roots: list[Path] = []
    for name in ("src", "lib"):
        source_root = project_root / name
        if source_root.is_dir() and not (source_root / "__init__.py").is_file():
            roots.append(source_root)
    roots.append(project_root)
    return roots


def _looks_like_package_dir(path: Path) -> bool:
    if not path.is_dir() or path.name.startswith((".", "_")):
        return False
    if path.name in SKIP_TOP_LEVEL:
        return False
    return (path / "__init__.py").is_file()


def discover_packages(project_root: Path) -> list[tuple[str, Path]]:
    """Discover importable top-level packages/modules in a project."""
    found: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for root in import_roots(project_root):
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir()):
            if entry.name in seen or entry.name.startswith("."):
                continue
            if _looks_like_package_dir(entry):
                found.append((entry.name, entry))
                seen.add(entry.name)
            elif (
                entry.is_file()
                and entry.suffix == ".py"
                and entry.name
                not in {
                    "setup.py",
                    "conftest.py",
                }
            ):
                found.append((entry.stem, entry))
                seen.add(entry.stem)
    return found


def module_name_for(root: Path, path: Path) -> str:
    rel = path.relative_to(root)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def annotation_score(source: str) -> int:
    """Cheap proxy for how much annotated surface a module exposes."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0
    score = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            score += 2
            args = list(node.args.args) + list(node.args.kwonlyargs)
            score += sum(1 for arg in args if arg.annotation is not None)
            if node.returns is not None:
                score += 2
        elif isinstance(node, ast.AnnAssign):
            score += 2
        elif isinstance(node, ast.ClassDef):
            score += 1
    return score


def sample_modules(
    package_root: Path,
    *,
    limit: int,
    name_filter: str | None = None,
) -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    for path in sorted(package_root.rglob("*.py")):
        parts = set(path.relative_to(package_root).parts)
        if "__pycache__" in parts or "tests" in parts or "test" in parts:
            continue
        if name_filter and not re.search(name_filter, str(path)):
            continue
        files.append((module_name_for(package_root.parent, path), path))
    scored: list[tuple[int, str, Path]] = []
    for name, path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        scored.append((annotation_score(source), name, path))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [(name, path) for _, name, path in scored[:limit]]


# ---------------------------------------------------------------------------
# Candidate extraction / mypy rewriting
# ---------------------------------------------------------------------------

_SAFE_STATEMENTS = (
    ast.Assign,
    ast.AnnAssign,
    ast.AugAssign,
    ast.Return,
    ast.Expr,
    ast.Raise,
    ast.Assert,
    ast.Delete,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
)


class _CandidateCollector(ast.NodeVisitor):
    def __init__(self, module: str, path: str, source: str) -> None:
        self.module = module
        self.path = path
        self.source = source
        self.candidates: list[Candidate] = []
        self._stmt_stack: list[ast.stmt] = []
        self._in_comprehension = 0
        self._in_lambda = 0
        self._host: dict[int, ast.stmt] = {}

    # -- statement bookkeeping ------------------------------------------------
    def _visit_stmt(self, node: ast.stmt) -> None:
        self._stmt_stack.append(node)
        self.generic_visit(node)
        self._stmt_stack.pop()

    visit_Assign = _visit_stmt
    visit_AnnAssign = _visit_stmt
    visit_AugAssign = _visit_stmt
    visit_Return = _visit_stmt
    visit_Expr = _visit_stmt
    visit_Raise = _visit_stmt
    visit_Assert = _visit_stmt
    visit_Delete = _visit_stmt
    visit_For = _visit_stmt
    visit_AsyncFor = _visit_stmt
    visit_While = _visit_stmt
    visit_With = _visit_stmt
    visit_AsyncWith = _visit_stmt
    visit_Try = _visit_stmt
    visit_FunctionDef = _visit_stmt
    visit_AsyncFunctionDef = _visit_stmt
    visit_ClassDef = _visit_stmt
    visit_If = _visit_stmt

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._in_lambda += 1
        self.generic_visit(node)
        self._in_lambda -= 1

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._comprehension(node)

    def _comprehension(self, node: ast.AST) -> None:
        self._in_comprehension += 1
        self.generic_visit(node)
        self._in_comprehension -= 1

    # -- candidate collection ------------------------------------------------
    def _host_statement(self) -> ast.stmt | None:
        for stmt in reversed(self._stmt_stack):
            if isinstance(stmt, ast.If):
                continue  # ``elif``/``else`` branches make insertion unsafe.
            if isinstance(stmt, _SAFE_STATEMENTS):
                return stmt
        return None

    def add(self, node: ast.expr, kind: str) -> None:
        if self._in_comprehension or self._in_lambda:
            return
        if (
            isinstance(node, ast.Await)
            or isinstance(node, ast.Yield)
            or isinstance(node, ast.YieldFrom)
        ):
            return
        host = self._host_statement()
        if host is None:
            return
        text = ast.get_source_segment(self.source, node)
        if text is None or "#" in text:
            return
        index = len(self.candidates)
        candidate = Candidate(
            index=index,
            module=self.module,
            path=self.path,
            lineno=node.lineno,
            col_offset=node.col_offset,
            end_lineno=getattr(node, "end_lineno", None),
            end_col_offset=getattr(node, "end_col_offset", None),
            text=text,
            kind=kind,
        )
        self.candidates.append(candidate)
        self._host[id(candidate)] = host

    def visit_Assign(self, node: ast.Assign) -> None:
        self._stmt_stack.append(node)
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            self.add(node.value, "assign")
        self.generic_visit(node)
        self._stmt_stack.pop()

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._stmt_stack.append(node)
        if node.value is not None:
            self.add(node.value, "annassign")
        self.generic_visit(node)
        self._stmt_stack.pop()

    def visit_Return(self, node: ast.Return) -> None:
        self._stmt_stack.append(node)
        if node.value is not None:
            self.add(node.value, "return")
        self.generic_visit(node)
        self._stmt_stack.pop()

    def hosts(self) -> dict[int, ast.stmt]:
        return self._host


def extract_candidates(
    module: str, path: Path, source: str
) -> tuple[list[Candidate], dict[int, ast.stmt]]:
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return [], {}
    collector = _CandidateCollector(module, str(path), source)
    collector.visit(tree)
    return collector.candidates, collector.hosts()


def rewrite_for_reveal(
    source: str,
    candidates: list[Candidate],
    hosts: dict[int, ast.stmt],
) -> tuple[str, dict[int, int]]:
    """Insert one ``reveal_type(expr)`` line before each host statement."""
    lines = source.splitlines(keepends=True)
    inserts: dict[int, list[tuple[str, int]]] = {}
    for candidate in candidates:
        host = hosts.get(id(candidate))
        if host is None:
            continue
        indent = " " * host.col_offset
        anchor = host.lineno
        decorators = getattr(host, "decorator_list", None)
        if decorators:
            anchor = min(decorator.lineno for decorator in decorators)
        expr_text = candidate.text
        if "\n" in expr_text:
            # Keep the inserted statement readable but on one logical line.
            expr_text = " ".join(part.strip() for part in expr_text.splitlines())
        inserts.setdefault(anchor, []).append(
            (f"{indent}reveal_type({expr_text})\n", candidate.index)
        )
    out: list[str] = []
    line_map: dict[int, int] = {}
    for lineno, line in enumerate(lines, start=1):
        for text, index in inserts.get(lineno, ()):  # pragma: no branch
            line_map[len(out) + 1] = index
            out.append(text)
        out.append(line)
    return "".join(out), line_map


# ---------------------------------------------------------------------------
# Type normalisation
# ---------------------------------------------------------------------------

_PREFIXES = (
    "builtins.",
    "typing.",
    "typing_extensions.",
    "collections.abc.",
    "collections.",
    "types.",
    "_typeshed.",
    "abc.",
)
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")


def _matching(text: str, open_index: int) -> int:
    """Return the index of the bracket closing ``text[open_index]``."""
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] in "[(":
            depth += 1
        elif text[i] in ")]":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def _split_top_level(text: str, sep: str = ",") -> list[str]:
    depth = 0
    parts: list[str] = []
    current: list[str] = []
    for char in text:
        if char in "[(":
            depth += 1
        elif char in ")]":
            depth -= 1
        if char == sep and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _rewrite_applications(text: str, name: str, transform) -> str:
    """Rewrite every ``name[...]`` application using ``transform(args, raw)``."""
    out = text
    search = 0
    while True:
        pos = out.find(f"{name}[", search)
        if pos == -1:
            return out
        # Skip when the match is part of a longer qualified name.
        if pos > 0 and (out[pos - 1].isalnum() or out[pos - 1] in "._"):
            search = pos + len(name)
            continue
        open_index = pos + len(name)
        close = _matching(out, open_index)
        args = _split_top_level(out[open_index + 1 : close])
        replacement = transform(args)
        if replacement is None:
            search = close + 1
            continue
        out = out[:pos] + replacement + out[close + 1 :]
        search = pos + len(replacement)


def _strip_prefix(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        name = match.group(0)
        for prefix in _PREFIXES:
            if name.startswith(prefix):
                return name[len(prefix) :]
        return name

    return _TOKEN.sub(repl, text)


def _normalize_mypy_callables(text: str) -> str:
    """Convert mypy's ``def (a: int) -> str`` spelling into ``Callable``."""
    out = text
    while True:
        pos = out.find("def (")
        if pos == -1:
            break
        open_index = pos + 4
        close = _matching(out, open_index)
        params = out[open_index + 1 : close]
        rest = out[close + 1 :]
        if rest.startswith(" -> "):
            ret_start = close + len(" -> ")
            depth = 0
            ret_end = len(out)
            for j in range(ret_start, len(out)):
                if out[j] in "[(":
                    depth += 1
                elif out[j] in ")]":
                    if depth == 0:
                        ret_end = j
                        break
                    depth -= 1
                elif out[j] == "," and depth == 0:
                    ret_end = j
                    break
            ret = out[ret_start:ret_end]
            out = out[:pos] + f"Callable[[{params}], {ret}]" + out[ret_end:]
        else:
            out = out[:pos] + f"Callable[[{params}], Any]" + out[close + 1 :]
    return out


def _normalize_fallback_tuples(text: str) -> str:
    """``tuple[int, int, fallback=X]`` is mypy's spelling for ``X``."""

    def transform(args: list[str]) -> str | None:
        for arg in args:
            stripped = arg.strip()
            if stripped.startswith("fallback="):
                return stripped[len("fallback=") :].strip()
        return None

    return _rewrite_applications(text, "tuple", transform)


_LITERAL_BASE = {
    "True": "bool",
    "False": "bool",
    "None": "None",
}


def _normalize_literal_question(text: str) -> str:
    """mypy marks inferred literal types with ``?``; widen them to their base."""

    def transform(args: list[str]) -> str | None:
        return None

    out = text
    search = 0
    while True:
        pos = out.find("Literal[", search)
        if pos == -1:
            return out
        if pos > 0 and (out[pos - 1].isalnum() or out[pos - 1] in "._"):
            search = pos + 7
            continue
        open_index = pos + len("Literal")
        close = _matching(out, open_index)
        if close + 1 < len(out) and out[close + 1] == "?":
            args = _split_top_level(out[open_index + 1 : close])
            first = args[0].strip()
            if first in _LITERAL_BASE:
                replacement = _LITERAL_BASE[first]
            elif first.startswith(("'", '"')):
                replacement = "str"
            elif first.startswith(("b'", 'b"')):
                replacement = "bytes"
            elif re.fullmatch(r"-?\d+", first):
                replacement = "int"
            elif re.fullmatch(r"-?\d+\.\d*", first):
                replacement = "float"
            elif "." in first:
                replacement = first.rsplit(".", 1)[0]
            else:
                replacement = "int"
            out = out[:pos] + replacement + out[close + 2 :]
            search = pos + len(replacement)
            continue
        search = close + 1


def _normalize_optional_union(text: str) -> str:
    out = text

    def optional(args: list[str]) -> str | None:
        return f"{args[0]}|None" if args else None

    def union(args: list[str]) -> str | None:
        return "|".join(args)

    while True:
        new = _rewrite_applications(out, "Optional", optional)
        new = _rewrite_applications(new, "Union", union)
        if new == out:
            return out
        out = new


def _sort_unions(text: str) -> str:
    if "|" not in text:
        return text
    parts = _split_top_level(text, "|")
    if len(parts) == 1:
        return text
    return "|".join(sorted({part.strip() for part in parts if part.strip()}))


def _strip_parameter_names(text: str) -> str:
    """``Callable[[x: int, y: str], R]`` -> ``Callable[[int, str], R]``."""
    out: list[str] = []
    depth = 0
    i = 0
    while i < len(text):
        char = text[i]
        if char in "[(":
            depth += 1
        elif char in ")]":
            depth -= 1
        if depth == 2 and (char.isalpha() or char == "_") and (not out or out[-1] in "[, "):
            match = re.match(r"[A-Za-z_][A-Za-z0-9_]*\s*:", text[i:])
            if match:
                i += match.end()
                continue
        out.append(char)
        i += 1
    return "".join(out)


def normalize_type(text: str | None) -> str | None:
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    text = _normalize_mypy_callables(text)
    text = _normalize_fallback_tuples(text)
    text = _normalize_literal_question(text)
    text = _strip_prefix(text)
    text = _normalize_optional_union(text)
    text = text.replace("NoneType", "None")
    text = re.sub(r"\s+", " ", text)
    text = text.replace(" | ", "|")
    text = _sort_unions(text)
    text = _strip_parameter_names(text)
    text = re.sub(r"\[\s+", "[", text)
    text = re.sub(r"\s+,", ",", text)
    text = re.sub(r",\s+", ",", text)
    text = text.replace(",)", ")")
    return text


# ---------------------------------------------------------------------------
# PyFlow driver
# ---------------------------------------------------------------------------


def _query_expression(module_result, candidate: Candidate):
    """Query the unambiguous end position of an expression.

    ``expression_value`` prefers the narrowest expression that starts at a
    position (reasonable for token hover), but for differential testing we want
    the type of the complete expression.  Querying ``end - 1`` lands inside the
    outermost expression only.
    """
    from pyflow.analysis.typeinfo.inference.models import SourceSpan

    if candidate.end_lineno is not None and candidate.end_col_offset is not None:
        span = SourceSpan(
            candidate.lineno,
            candidate.col_offset,
            candidate.end_lineno,
            candidate.end_col_offset,
        )
        value = module_result.expressions.get(span)
        if value is not None:
            return value
        for existing, existing_value in module_result.expressions.items():
            if (
                existing.lineno == candidate.lineno
                and existing.col_offset == candidate.col_offset
                and (existing.end_col_offset or 0) >= candidate.end_col_offset
            ):
                value = existing_value
                break
        if value is not None:
            return value
    return module_result.expression_value(candidate.lineno, candidate.col_offset)


MEMBER_CHECKS = True


def run_pyflow(
    project_root: Path,
    modules: list[tuple[str, Path]],
    *,
    budget: float,
    max_iterations: int = 3,
) -> tuple[dict[str, object], dict[str, object]]:
    """Return (module -> result, module -> error/status info)."""
    from pyflow.analysis.typeinfo.inference.project import ProjectTypeInferenceEngine
    from pyflow.language.modules.project_resolution import ProjectContext

    # Pass the same import roots mypy receives: ``ProjectContext`` only adds
    # ``src/`` on its own, while some corpus projects (ansible) use ``lib/``.
    ctx = ProjectContext(
        project_root,
        added_sys_path=[str(root) for root in import_roots(project_root) if root != project_root],
    )
    results: dict[str, object] = {}
    errors: dict[str, object] = {}
    start = time.time()
    remaining = list(modules)
    batch_size = 4
    while remaining and time.time() - start < budget:
        if len(remaining) > batch_size and len(remaining) <= 2 * batch_size:
            batch = remaining
        else:
            batch = remaining[:batch_size]
        remaining = remaining[len(batch) :]
        entry = [name for name, _ in batch]
        try:
            from pyflow.analysis.typeinfo.inference.engine import InferenceOptions

            engine = ProjectTypeInferenceEngine(
                ctx,
                max_project_iterations=max_iterations,
                options=InferenceOptions(check_member_access=MEMBER_CHECKS),
            )
            result = engine.infer_project(entry)
        except Exception as exc:  # pragma: no cover - defensive
            for name, _ in batch:
                errors[name] = {"crash": True, "error": f"{type(exc).__name__}: {exc}"}
            continue
        for name, _ in batch:
            module_result = result.modules.get(name)
            if module_result is None:
                errors[name] = {"crash": True, "error": "module not analysed"}
                continue
            results[name] = module_result
            if not module_result.converged or any(
                item.severity == "error" for item in module_result.diagnostics
            ):
                errors[name] = {
                    "crash": False,
                    "status": module_result.status,
                    "diagnostics": [
                        {"code": d.code, "message": d.message, "severity": d.severity}
                        for d in module_result.diagnostics
                    ],
                }
    for name, _ in remaining:
        errors[name] = {"crash": False, "status": "skipped", "error": "project budget exhausted"}
    return results, errors


# ---------------------------------------------------------------------------
# mypy driver
# ---------------------------------------------------------------------------

_REVEAL_RE = re.compile(
    r'^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+): note: Revealed type is "(?P<type>.*)"$'
)


@dataclass
class MypyOutcome:
    types: dict[int, str]
    raw: str
    returncode: int
    errors: list[dict] = field(default_factory=list)


def run_mypy(
    project_root: Path,
    module_name: str,
    path: Path,
    source: str,
    candidates: list[Candidate],
    hosts: dict[int, ast.stmt],
    *,
    shadow_root: Path,
    cache_dir: Path,
    timeout: float,
) -> MypyOutcome:
    rewritten, line_map = rewrite_for_reveal(source, candidates, hosts)
    rel = path.relative_to(_shadow_base(project_root, path))
    target = shadow_root / rel
    original = target.read_text(encoding="utf-8") if target.exists() else None
    target.write_text(rewritten, encoding="utf-8")
    env = dict(os.environ)
    roots = [str(shadow_root)]
    for root in import_roots(project_root):
        roots.append(str(root))
    for entry in _project_sys_path(project_root):
        if "site-packages" in entry or "dist-packages" in entry:
            continue
        try:
            Path(entry).resolve().relative_to(project_root.resolve())
        except (ValueError, OSError):
            continue
        if entry not in roots:
            roots.append(entry)
    env["MYPYPATH"] = os.pathsep.join(roots)
    env.pop("PYTHONPATH", None)
    cmd = [
        sys.executable,
        "-m",
        "mypy",
        "--check-untyped-defs",
        "--show-error-codes",
        "--no-error-summary",
        "--no-pretty",
        "--show-column-numbers",
        "--ignore-missing-imports",
        "--follow-imports=normal",
        "--cache-dir",
        str(cache_dir),
        str(target),
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=shadow_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        if original is not None:
            target.write_text(original, encoding="utf-8")
        return MypyOutcome(types={}, raw="", returncode=-1, errors=[{"error": "timeout"}])
    output = proc.stdout + proc.stderr
    found: dict[int, str] = {}
    errors: list[dict] = []
    for line in output.splitlines():
        match = _REVEAL_RE.match(line)
        if match:
            line_no = int(match.group("line"))
            index = line_map.get(line_no)
            if index is not None:
                found[index] = match.group("type")
            continue
        if ": error:" in line or ": note:" in line:
            errors.append({"line": line[:300]})
    if original is not None:
        target.write_text(original, encoding="utf-8")
    return MypyOutcome(types=found, raw=output, returncode=proc.returncode, errors=errors)


def _project_sys_path(project_root: Path) -> list[str]:
    try:
        from pyflow.language.modules.project_resolution import ProjectContext

        return ProjectContext(project_root).get_sys_path()
    except Exception:
        return []


def _shadow_base(project_root: Path, path: Path) -> Path:
    for root in import_roots(project_root):
        try:
            path.relative_to(root)
        except ValueError:
            continue
        return root
    return project_root


def make_shadow(project_root: Path, shadow_root: Path) -> None:
    base = None
    for root in import_roots(project_root):
        if root.is_dir():
            base = root
            break
    if base is None:
        return
    for entry in base.iterdir():
        if entry.name in {"__pycache__", ".git"}:
            continue
        dest = shadow_root / entry.name
        if dest.exists():
            continue
        try:
            proc = subprocess.run(
                ["cp", "-Rc", str(entry), str(dest)],
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                raise OSError(proc.stderr)
        except OSError:
            if entry.is_dir():
                shutil.copytree(
                    entry, dest, symlinks=True, ignore=shutil.ignore_patterns("__pycache__")
                )
            else:
                shutil.copy2(entry, dest)


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def classify(pyflow: str | None, mypy: str | None, complete: bool | None) -> str:
    if pyflow is None:
        return "C5_missing"
    if mypy is None:
        return "uncomparable"
    if normalize_type(pyflow) == normalize_type(mypy):
        return "match"
    if not complete:
        return "C5_incomplete"
    if pyflow in {"Any", "object", "Unknown"}:
        return "C5_unknown"
    return "mismatch"


def resolve_project(name: str, corpus: Path) -> Path:
    direct = corpus / name
    if direct.is_dir():
        return direct
    matches = [candidate for candidate in corpus.iterdir() if candidate.name.startswith(name)]
    if len(matches) == 1:
        return matches[0]
    raise SystemExit(f"unknown project {name!r}")


_MYPY_ERROR_LINE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+)(?::(?P<col>\d+))?: error: (?P<message>.*?)"
    r"(?:\s+\[(?P<code>[a-z-]+)\])?$"
)

# PyFlow reports a small, deliberate set of diagnostics.  Anything else mypy
# rejects (``attr-defined``, ``name-defined``, ``misc``, ...) is outside what
# PyFlow currently checks and therefore a coverage gap, not a disagreement.
_PYFLOW_TYPE_CODES = {
    "annotation-mismatch": "type",
    "call-arity-mismatch": "arity",
    "typed-dict-key": "typed-dict",
    "format-string-mismatch": "format",
    "union-attr": "union-attr",
    "attr-defined": "attr-defined",
    "index": "index",
    "name-defined": "name-defined",
}
# Checks PyFlow performs that mypy has no equivalent for.  They are reported
# separately instead of counting as false positives.
_PYFLOW_ONLY_CODES = {"format-string-mismatch"}

_PYFLOW_COMPLETENESS_CODES = {
    "missing-external-type",
    "unresolved-annotation",
    "unsupported-expression",
    "unsupported-statement",
    "unmodeled-context-manager",
    "specialization-budget-exceeded",
    "loop-widened",
    "call-model-error",
    "module-inference-error",
    "project-inference-did-not-converge",
}


def mypy_error_category(code: str | None) -> str:
    if code in {
        "arg-type",
        "assignment",
        "return-value",
        "list-item",
        "dict-item",
        "typeddict-item",
        "index",
        "operator",
        "has-type",
        "valid-type",
        "union-attr",
        "attr-defined",
        "override",
        "var-annotated",
    }:
        return "type"
    if code in {"call-arg", "call-overload", "misc"}:
        return "arity"
    if code in {"import-not-found", "import-untyped"}:
        return "import"
    if code in {"str-format", "format"}:
        return "format"
    return "unmodeled"


def run_mypy_errors(
    project_root: Path,
    module_name: str,
    path: Path,
    *,
    shadow_root: Path,
    cache_dir: Path,
    timeout: float,
) -> list[dict]:
    rel = path.relative_to(_shadow_base(project_root, path))
    target = shadow_root / rel
    env = dict(os.environ)
    roots = [str(shadow_root)]
    for root in import_roots(project_root):
        roots.append(str(root))
    for entry in _project_sys_path(project_root):
        if "site-packages" in entry or "dist-packages" in entry:
            continue
        try:
            Path(entry).resolve().relative_to(project_root.resolve())
        except (ValueError, OSError):
            continue
        if entry not in roots:
            roots.append(entry)
    env["MYPYPATH"] = os.pathsep.join(roots)
    env.pop("PYTHONPATH", None)
    cmd = [
        sys.executable,
        "-m",
        "mypy",
        "--check-untyped-defs",
        "--show-error-codes",
        "--no-error-summary",
        "--no-pretty",
        "--show-column-numbers",
        "--ignore-missing-imports",
        "--follow-imports=normal",
        "--cache-dir",
        str(cache_dir),
        str(target),
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=shadow_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [{"error": "timeout"}]
    target_path = str(target)
    errors: list[dict] = []
    for line in (proc.stdout + proc.stderr).splitlines():
        match = _MYPY_ERROR_LINE.match(line)
        if match is None or match.group("file") != target_path:
            continue
        errors.append(
            {
                "line": int(match.group("line")),
                "col": int(match.group("col") or 0),
                "code": match.group("code"),
                "message": match.group("message")[:300],
            }
        )
    return errors


def diagnostics_project(
    project_root: Path,
    *,
    module_limit: int,
    module_filter: str | None,
    out_lines: list[dict],
    budget: float,
    mypy_timeout: float,
    per_package: int | None = None,
) -> dict[str, object]:
    project_name = project_root.name
    packages = discover_packages(project_root)
    chosen: list[tuple[str, Path]] = []
    remaining = module_limit
    for package_name, package_path in packages:
        if remaining <= 0:
            break
        if package_path.is_file():
            chosen.append((package_name, package_path))
            remaining -= 1
            continue
        take = remaining if per_package is None else min(remaining, per_package)
        modules = sample_modules(package_path, limit=take, name_filter=module_filter)
        chosen.extend(modules)
        remaining -= len(modules)

    started = time.time()
    # A single-module project run keeps diagnostics anchored to the module the
    # engine reports them for, which is what mypy does per file.
    results: dict[str, object] = {}
    errors: dict[str, object] = {}
    crashes: list[dict] = []
    for name, _ in chosen:
        one_results, one_errors = run_pyflow(project_root, [(name, _)], budget=budget)
        results.update(one_results)
        errors.update(one_errors)
        for failed_name, error in one_errors.items():
            if error.get("crash"):
                crashes.append({"module": failed_name, "error": error.get("error")})
    pyflow_elapsed = time.time() - started

    shadow_parent = Path(tempfile.mkdtemp(prefix=f"tmdiag-{project_name}-"))
    shadow_root = shadow_parent / "shadow"
    shadow_root.mkdir()
    cache_dir = shadow_parent / "mypy-cache"
    cache_dir.mkdir()
    make_shadow(project_root, shadow_root)

    stats: dict[str, object] = {
        "project": project_name,
        "mode": "diagnostics",
        "modules_requested": len(chosen),
        "modules_analysed": len(results),
        "pyflow_seconds": round(pyflow_elapsed, 2),
        "mypy_errors": 0,
        "crashes": crashes,
        "pyflow_diagnostics": 0,
        "matched": 0,
        "c3_false_positive": [],
        "c4_false_negative": [],
        "unmodeled_categories": {},
    }
    unmodeled: dict[str, int] = {}
    try:
        for name, path in chosen:
            module_result = results.get(name)
            if module_result is None:
                continue
            mypy_errors = run_mypy_errors(
                project_root,
                name,
                path,
                shadow_root=shadow_root,
                cache_dir=cache_dir,
                timeout=mypy_timeout,
            )
            if mypy_errors and mypy_errors[0].get("error") == "timeout":
                stats["mypy_errors"] = int(stats["mypy_errors"]) + 1
                continue
            stats["mypy_errors"] = int(stats["mypy_errors"]) + len(mypy_errors)
            pyflow_diags = [
                item
                for item in module_result.diagnostics
                if item.span is not None
                and item.code not in _PYFLOW_COMPLETENESS_CODES
                and item.code not in _PYFLOW_ONLY_CODES
            ]
            stats["pyflow_diagnostics"] = int(stats["pyflow_diagnostics"]) + len(pyflow_diags)
            mypy_by_line: dict[int, list[dict]] = {}
            for error in mypy_errors:
                mypy_by_line.setdefault(error["line"], []).append(error)
            matched_lines: set[int] = set()
            for diag in pyflow_diags:
                line = diag.span.lineno
                candidates = mypy_by_line.get(line) or mypy_by_line.get(line - 1) or []
                category = _PYFLOW_TYPE_CODES.get(diag.code, "completeness")
                compatible = [
                    error
                    for error in candidates
                    if error["code"] == diag.code
                    or mypy_error_category(error["code"]) in {category, "unmodeled"}
                ]
                if compatible:
                    stats["matched"] = int(stats["matched"]) + 1
                    matched_lines.add(line)
                    out_lines.append(
                        {
                            "project": project_name,
                            "module": name,
                            "line": line,
                            "verdict": "match",
                            "pyflow_code": diag.code,
                            "mypy_code": compatible[0]["code"],
                            "pyflow": diag.message[:200],
                            "mypy": compatible[0]["message"][:200],
                        }
                    )
                    continue
                stats["c3_false_positive"].append(
                    {
                        "module": name,
                        "line": line,
                        "code": diag.code,
                        "message": diag.message[:200],
                        "mypy_on_line": [error["code"] for error in candidates],
                    }
                )
                out_lines.append(
                    {
                        "project": project_name,
                        "module": name,
                        "line": line,
                        "verdict": "C3_false_positive",
                        "pyflow_code": diag.code,
                        "mypy_code": None,
                        "pyflow": diag.message[:200],
                        "mypy": None,
                    }
                )
            for error in mypy_errors:
                if error["line"] in matched_lines:
                    continue
                category = mypy_error_category(error["code"])
                if category == "unmodeled":
                    unmodeled[str(error["code"])] = unmodeled.get(str(error["code"]), 0) + 1
                stats["c4_false_negative"].append(
                    {
                        "module": name,
                        "line": error["line"],
                        "code": error["code"],
                        "category": category,
                        "message": error["message"][:200],
                    }
                )
                out_lines.append(
                    {
                        "project": project_name,
                        "module": name,
                        "line": error["line"],
                        "verdict": "C4_false_negative",
                        "pyflow_code": None,
                        "mypy_code": error["code"],
                        "pyflow": None,
                        "mypy": error["message"][:200],
                    }
                )
    finally:
        shutil.rmtree(shadow_parent, ignore_errors=True)
    stats["unmodeled_categories"] = unmodeled
    return stats


def diff_project(
    project_root: Path,
    *,
    module_limit: int,
    module_filter: str | None,
    out_lines: list[dict],
    budget: float,
    mypy_timeout: float,
    per_package: int | None = None,
) -> dict[str, object]:
    project_name = project_root.name
    packages = discover_packages(project_root)
    chosen: list[tuple[str, Path]] = []
    remaining = module_limit
    for package_name, package_path in packages:
        if remaining <= 0:
            break
        if package_path.is_file():
            if module_filter and not re.search(module_filter, str(package_path)):
                continue
            chosen.append((package_name, package_path))
            remaining -= 1
            continue
        take = remaining if per_package is None else min(remaining, per_package)
        modules = sample_modules(package_path, limit=take, name_filter=module_filter)
        chosen.extend(modules)
        remaining -= len(modules)

    started = time.time()
    results, errors = run_pyflow(project_root, chosen, budget=budget)
    pyflow_elapsed = time.time() - started

    shadow_parent = Path(tempfile.mkdtemp(prefix=f"tmdiff-{project_name}-"))
    shadow_root = shadow_parent / "shadow"
    shadow_root.mkdir()
    cache_dir = shadow_parent / "mypy-cache"
    cache_dir.mkdir()
    make_shadow(project_root, shadow_root)

    stats: dict[str, object] = {
        "project": project_name,
        "packages": len(packages),
        "modules_requested": len(chosen),
        "modules_analysed": len(results),
        "pyflow_seconds": round(pyflow_elapsed, 2),
        "crashes": [],
        "partial": [],
        "expressions": 0,
        "comparable": 0,
        "matches": 0,
        "mismatches": [],
        "c5_missing": 0,
        "c5_unknown": 0,
        "c5_incomplete": 0,
        "mypy_errors": 0,
    }
    try:
        for name, path in chosen:
            source = path.read_text(encoding="utf-8")
            candidates, hosts = extract_candidates(name, path, source)
            module_result = results.get(name)
            error = errors.get(name)
            if error and error.get("crash"):
                stats["crashes"].append({"module": name, "error": error.get("error")})
                continue
            if error and error.get("status") == "skipped":
                continue
            if module_result is not None and module_result.status != "complete":
                stats["partial"].append(
                    {
                        "module": name,
                        "status": module_result.status,
                        "diagnostics": [
                            {"code": d.code, "message": d.message}
                            for d in module_result.diagnostics[:5]
                        ],
                    }
                )
            if not candidates:
                continue
            try:
                mypy_outcome = run_mypy(
                    project_root,
                    name,
                    path,
                    source,
                    candidates,
                    hosts,
                    shadow_root=shadow_root,
                    cache_dir=cache_dir,
                    timeout=mypy_timeout,
                )
            except Exception as exc:  # pragma: no cover - defensive
                stats["mypy_errors"] += 1
                out_lines.append(
                    {"project": project_name, "module": name, "error": f"mypy-harness: {exc}"}
                )
                continue
            if not mypy_outcome.types:
                stats["mypy_errors"] += 1
            for candidate in candidates:
                if candidate.index not in mypy_outcome.types:
                    continue
                mypy_type = mypy_outcome.types[candidate.index]
                if "Any" in mypy_type or mypy_type in {"None", "Any"}:
                    continue
                stats["expressions"] = int(stats["expressions"]) + 1
                pyflow_type = None
                complete = None
                if module_result is not None:
                    value = _query_expression(module_result, candidate)
                    if value is not None:
                        typ = value.runtime_type()
                        pyflow_type = None if typ is None else str(typ)
                        complete = value.is_complete
                verdict = classify(pyflow_type, mypy_type, complete)
                record = ExprRecord(
                    project=project_name,
                    module=name,
                    path=str(path),
                    index=candidate.index,
                    kind=candidate.kind,
                    text=candidate.text[:200],
                    lineno=candidate.lineno,
                    col_offset=candidate.col_offset,
                    pyflow_type=pyflow_type,
                    pyflow_complete=complete,
                    mypy_type=mypy_type,
                    mypy_status="ok",
                )
                record.verdict = verdict
                normalized_pyflow = normalize_type(pyflow_type)
                normalized_mypy = normalize_type(mypy_type)
                record.normalized_pyflow = normalized_pyflow
                record.normalized_mypy = normalized_mypy
                if verdict == "match":
                    stats["matches"] = int(stats["matches"]) + 1
                elif verdict == "C5_missing":
                    stats["c5_missing"] = int(stats["c5_missing"]) + 1
                elif verdict == "C5_unknown":
                    stats["c5_unknown"] = int(stats["c5_unknown"]) + 1
                elif verdict == "C5_incomplete":
                    stats["c5_incomplete"] = int(stats["c5_incomplete"]) + 1
                elif verdict == "mismatch":
                    stats["mismatches"].append(
                        {
                            "module": name,
                            "line": candidate.lineno,
                            "col": candidate.col_offset,
                            "kind": candidate.kind,
                            "text": candidate.text[:120],
                            "pyflow": pyflow_type,
                            "mypy": mypy_type,
                        }
                    )
                if verdict not in {"uncomparable"}:
                    stats["comparable"] = int(stats["comparable"]) + 1
                out_lines.append(asdict(record))
    finally:
        shutil.rmtree(shadow_parent, ignore_errors=True)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--project", action="append", default=[])
    parser.add_argument("--list-projects", action="store_true")
    parser.add_argument("--max-modules", type=int, default=12)
    parser.add_argument("--per-package", type=int, default=None)
    parser.add_argument("--module-filter", default=None)
    parser.add_argument(
        "--no-member-checks",
        dest="member_checks",
        action="store_false",
        help="Disable PyFlow's union-attr/attr-defined checks",
    )
    parser.add_argument(
        "--diagnostics",
        action="store_true",
        help="Compare PyFlow diagnostics with mypy errors instead of revealed types",
    )
    parser.add_argument("--budget", type=float, default=120.0, help="PyFlow seconds per project")
    parser.add_argument("--mypy-timeout", type=float, default=180.0)
    parser.add_argument("--out", default=None, help="JSONL output path")
    parser.add_argument("--summary-out", default=None)
    args = parser.parse_args()

    global MEMBER_CHECKS
    MEMBER_CHECKS = bool(getattr(args, "member_checks", True))
    corpus = Path(args.corpus).expanduser()
    if args.list_projects:
        for entry in sorted(corpus.iterdir()):
            if entry.is_dir():
                print(entry.name)
        return

    projects = args.project or [
        "Textualize--rich",
        "pallets--flask",
        "django--django",
        "scikit-learn--scikit-learn",
    ]
    out_lines: list[dict] = []
    summaries = []
    runner = diagnostics_project if args.diagnostics else diff_project
    for project in projects:
        root = resolve_project(project, corpus)
        print(f"[diff] {root.name}", file=sys.stderr, flush=True)
        stats = runner(
            root,
            module_limit=args.max_modules,
            module_filter=args.module_filter,
            out_lines=out_lines,
            budget=args.budget,
            mypy_timeout=args.mypy_timeout,
            per_package=args.per_package,
        )
        summaries.append(stats)
        print(
            json.dumps(
                {key: value for key, value in stats.items() if key not in {"mismatches", "partial"}}
            ),
            file=sys.stderr,
            flush=True,
        )
    if args.out:
        Path(args.out).write_text(
            "\n".join(json.dumps(item) for item in out_lines) + "\n", encoding="utf-8"
        )
    if args.summary_out:
        Path(args.summary_out).write_text(
            json.dumps(summaries, indent=2, default=str) + "\n", encoding="utf-8"
        )
    print(json.dumps(summaries, indent=2, default=str))


if __name__ == "__main__":
    main()
