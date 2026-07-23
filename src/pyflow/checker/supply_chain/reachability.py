"""Conservative source-import evidence for dependency vulnerability triage."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Iterator, Mapping

from packaging.utils import canonicalize_name

from .input_safety import load_json_file
from .models import SupplyChainFinding, SupplyChainScan


def analyze_reachability(
    scan: SupplyChainScan,
    roots: Iterable[str | Path],
    *,
    import_map: Mapping[str, Iterable[str]] | None = None,
    max_files: int = 20_000,
    max_file_size: int = 5 * 1024 * 1024,
) -> tuple[frozenset[str], tuple[SupplyChainFinding, ...]]:
    """Return component refs with observed imports, closed over dependency edges.

    Absence from the returned set is only a lack of evidence.  Callers must not
    treat it as proof that vulnerable code is unreachable.
    """

    findings: list[SupplyChainFinding] = []
    imports: set[str] = set()
    files_seen = 0
    for source in _python_files(roots):
        files_seen += 1
        if files_seen > max_files:
            findings.append(
                SupplyChainFinding(
                    kind="reachability-file-limit",
                    message="Source reachability analysis exceeded its file limit",
                    location=str(source),
                    severity="MEDIUM",
                    details={"limit": max_files},
                )
            )
            break
        try:
            if source.stat().st_size > max_file_size:
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        except (OSError, UnicodeError, SyntaxError) as exc:
            findings.append(
                SupplyChainFinding(
                    kind="reachability-source-error",
                    message="Source file could not be inspected for imports",
                    location=str(source),
                    severity="LOW",
                    details={"error": str(exc)},
                )
            )
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".", 1)[0])

    modules_by_distribution: dict[str, set[str]] = {}
    for distribution, modules in (import_map or {}).items():
        modules_by_distribution[canonicalize_name(distribution)] = {
            str(module).split(".", 1)[0] for module in modules
        }
    reachable: set[str] = set()
    for component in scan.components:
        name = canonicalize_name(str(component.get("name", "")))
        declared_imports = {
            str(prop.get("value", "")).split(".", 1)[0]
            for prop in component.get("properties", ())
            if isinstance(prop, dict)
            and prop.get("name") == "pyflow:import-name"
            and prop.get("value")
        }
        candidates = modules_by_distribution.get(name) or declared_imports
        if not candidates:
            candidates = {name.replace("-", "_"), name.replace("-", "")}
        if candidates & imports:
            reachable.add(str(component.get("purl") or name))

    edges = {
        str(dependency.get("ref", "")): {
            str(target) for target in dependency.get("dependsOn", ()) or ()
        }
        for dependency in scan.dependencies
    }
    queue = list(reachable)
    while queue:
        current_ref = queue.pop()
        for target in edges.get(current_ref, ()):
            if target not in reachable:
                reachable.add(target)
                queue.append(target)
    return frozenset(reachable), tuple(findings)


def load_import_map(path: Path) -> dict[str, list[str]]:
    data = load_json_file(path)
    if not isinstance(data, dict) or not all(
        isinstance(value, list) for value in data.values()
    ):
        raise ValueError(
            "import map must be an object of distribution-to-module arrays"
        )
    return {str(key): [str(item) for item in value] for key, value in data.items()}


def _python_files(roots: Iterable[str | Path]) -> Iterator[Path]:
    ignored = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist"}
    for value in roots:
        path = Path(value)
        if path.is_symlink():
            continue
        if path.is_file() and path.suffix == ".py":
            yield path
        elif path.is_dir():
            for child in sorted(path.rglob("*.py")):
                try:
                    relative_parts = child.relative_to(path).parts
                except ValueError:
                    continue
                if (
                    not ignored.intersection(relative_parts)
                    and child.is_file()
                    and not child.is_symlink()
                ):
                    yield child
