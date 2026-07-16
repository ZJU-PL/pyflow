"""CLI entrypoint for alias analysis — flow-sensitive heap and k-CFA pointer."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from pyflow.analysis.alias.flow_sensitive import HeapAnalysis
from pyflow.analysis.alias.kcfa import PointerAnalysis


def add_alias_parser(subparsers):
    """Add the alias subcommand parser."""
    parser = subparsers.add_parser(
        "alias",
        help="Run alias analysis on Python files (flow-sensitive or k-CFA)",
        description=(
            "Parse one or more Python source files and run alias analysis. "
            "Supports two engines: flow-sensitive (heap alias/escape analysis) "
            "and kcfa (k-CFA pointer/call-graph analysis)."
        ),
    )
    parser.add_argument(
        "input_path",
        help="Python file or directory to analyze",
    )
    parser.add_argument(
        "--engine",
        choices=["flow-sensitive", "kcfa"],
        default="flow-sensitive",
        help="Analysis engine: flow-sensitive (default) or kcfa",
    )
    parser.add_argument(
        "--k",
        type=int,
        default=1,
        help="k-CFA context sensitivity depth (kcfa engine only, default: 1)",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Recursively analyze Python files in a directory",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON instead of human-friendly text",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Include per-entry details",
    )
    return parser


def _discover_python_files(input_path: Path, recursive: bool) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    if input_path.is_dir():
        pattern = "**/*.py" if recursive else "*.py"
        return sorted(p for p in input_path.glob(pattern) if p.is_file())
    raise FileNotFoundError(f"Path not found: {input_path}")


def _convert_functions(source: str, filename: str) -> dict[str, object]:
    from pyflow.frontend.ast_converter import ASTConverter

    tree = ast.parse(source, filename=filename)
    converter = ASTConverter(verbose=False)
    result: dict[str, object] = {}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        try:
            func_def = converter._convert_function_def(node)
        except Exception:
            continue
        if func_def is None:
            continue
        code = getattr(func_def, "code", None)
        if code is None:
            continue
        result[code.name] = code

    return result


# ---------------------------------------------------------------------------
# Flow-sensitive (heap) engine
# ---------------------------------------------------------------------------

def _format_entry(entry, verbose: bool) -> str:
    loc = entry.location
    sig = "S" if entry.is_singleton else " "
    esc = "E" if entry.is_escaped else " "
    label = entry.label

    if verbose:
        strong = "strong" if entry.is_strong else "weak"
        sel = getattr(loc, "selectors", ())
        sel_str = f"  selectors={list(sel)}" if sel else ""
        return (
            f"    [{sig}{esc}] refs={entry.ref_count} {label}  "
            f"[{strong}]{sel_str}"
        )
    return f"    [{sig}{esc}] refs={entry.ref_count} {label}"


def _build_alias_group_lines(all_entries, graph, verbose: bool) -> list[str]:
    lines: list[str] = []
    groups: dict[int, list] = {}
    group_ref_count: dict[int, int] = {}
    for entry in all_entries:
        key = id(entry.aliases)
        groups.setdefault(key, []).append(entry)
        group_ref_count[key] = entry.ref_count

    multi_member = {k: v for k, v in groups.items() if len(v) >= 2}
    if not multi_member and not verbose:
        return lines

    header = "    alias groups (must-alias):" if multi_member else ""
    if header:
        lines.append(header)
    for group_list in multi_member.values():
        labels = sorted(e.label for e in group_list)
        refs = group_ref_count[id(group_list[0].aliases)]
        status_flags = []
        if any(e.is_singleton for e in group_list):
            status_flags.append("S")
        if any(e.is_escaped for e in group_list):
            status_flags.append("E")
        flags = f" [{''.join(status_flags)}]" if status_flags else ""
        lines.append(f"      {{{', '.join(labels)}}}{flags}  refs={refs}")

    group_keys = list(groups.keys())
    may_pairs: list[tuple[str, str, str]] = []
    for i in range(len(group_keys)):
        for j in range(i + 1, len(group_keys)):
            a_entry = groups[group_keys[i]][0]
            b_entry = groups[group_keys[j]][0]
            if graph.may_alias(a_entry.location, b_entry.location):
                a_labels = ", ".join(sorted(e.label for e in groups[group_keys[i]]))
                b_labels = ", ".join(sorted(e.label for e in groups[group_keys[j]]))
                exact = (
                    "≡"
                    if graph.must_alias(a_entry.location, b_entry.location)
                    else "~"
                )
                may_pairs.append((f"{{{a_labels}}}", f"{{{b_labels}}}", exact))

    if may_pairs:
        if header:
            lines.append("    may-alias:")
        else:
            lines.append("    may-alias:")
        for a_lab, b_lab, exact in may_pairs:
            lines.append(f"      {exact} {a_lab}  ↔  {b_lab}")

    return lines


def _collect_param_names(code) -> list[str]:
    param_names: list[str] = []
    if hasattr(code, "codeparameters") and code.codeparameters is not None:
        cp = code.codeparameters
        for attr in ("selfparam", "posonlyparams", "params"):
            objs = getattr(cp, attr, None) or ()
            if not isinstance(objs, (list, tuple)):
                objs = (objs,)
            for p in objs:
                if hasattr(p, "name"):
                    param_names.append(p.name)
    return param_names


def _analyze_file_flow_sensitive(filepath: Path, verbose: bool) -> None:
    source = filepath.read_text()
    codes = _convert_functions(source, str(filepath))

    if not codes:
        print(f"  (no functions found to analyze)")
        return

    print(f"# {filepath}  [engine: flow-sensitive]")
    print()

    for func_name, code in codes.items():
        analysis = HeapAnalysis()
        try:
            graph = analysis.analyze(None, code)
        except Exception as exc:
            print(f"  {func_name}(): ERROR — {exc}", file=sys.stderr)
            continue

        param_names = _collect_param_names(code)
        all_entries = list(graph.iter_entries())
        singleton_count = sum(1 for e in all_entries if e.is_singleton)
        escaped_count = sum(1 for e in all_entries if e.is_escaped)

        seen_groups: set[int] = set()
        for e in all_entries:
            seen_groups.add(id(e.aliases))
        group_count = len(seen_groups)

        print(f"  {func_name}({', '.join(param_names)})")
        print(f"    entries={len(all_entries)}  "
              f"singletons={singleton_count}  "
              f"escaped={escaped_count}  "
              f"alias-groups={group_count}")

        for entry in all_entries:
            print(_format_entry(entry, verbose))

        group_lines = _build_alias_group_lines(all_entries, graph, verbose)
        if group_lines:
            for l in group_lines:
                print(l)

        print()


def _to_json_entry_flow_sensitive(entry, graph) -> dict:
    must_aliases = sorted(
        e.label for e in graph.iter_entries()
        if graph.must_alias(e.location, entry.location)
    )
    may_aliases = sorted(
        e.label for e in graph.iter_entries()
        if graph.may_alias(e.location, entry.location)
        and not graph.must_alias(e.location, entry.location)
    )
    return {
        "label": entry.label,
        "is_singleton": entry.is_singleton,
        "cardinality": entry.cardinality.value,
        "is_escaped": entry.is_escaped,
        "is_strong": entry.is_strong,
        "ref_count": entry.ref_count,
        "must_aliases": must_aliases,
        "may_aliases": may_aliases,
    }


def _analyze_file_flow_sensitive_json(filepath: Path) -> dict:
    source = filepath.read_text()
    codes = _convert_functions(source, str(filepath))
    functions: dict[str, object] = {}

    for func_name, code in codes.items():
        analysis = HeapAnalysis()
        try:
            graph = analysis.analyze(None, code)
        except Exception as exc:
            functions[func_name] = {"error": str(exc)}
            continue

        entries = [_to_json_entry_flow_sensitive(e, graph) for e in graph.iter_entries()]
        functions[func_name] = {
            "entry_count": len(entries),
            "singleton_count": sum(1 for e in entries if e["is_singleton"]),
            "escaped_count": sum(1 for e in entries if e["is_escaped"]),
            "entries": entries,
        }

    return {"file": str(filepath), "functions": functions}


# ---------------------------------------------------------------------------
# k-CFA pointer engine
# ---------------------------------------------------------------------------

def _analyze_file_kcfa(filepath: Path, k: int, verbose: bool) -> None:
    source = filepath.read_text()

    print(f"# {filepath}  [engine: kcfa, k={k}]")
    print()

    try:
        analysis = PointerAnalysis(source, k=k)
        result = analysis.run()
    except Exception as exc:
        print(f"  ERROR — {exc}", file=sys.stderr)
        return

    call_edges = result.call_edges()
    print(f"  call edges: {len(call_edges)}")
    if verbose:
        for caller, callee in call_edges:
            print(f"    {caller} → {callee}")

    seen_names: set[str] = set()
    all_bindings: dict[str, list[tuple[str, set[str]]]] = {}
    for name in _collect_variable_names(source):
        bindings = result.bindings_for_name(name)
        if bindings:
            all_bindings[name] = bindings
            seen_names.add(name)

    print(f"  tracked variables: {len(seen_names)}")
    for name in sorted(seen_names):
        pts = result.points_to(name)
        print(f"    {name} → {sorted(pts) if pts else '∅'}")
        if verbose:
            for ctx, ctx_pts in all_bindings.get(name, []):
                print(f"      [{ctx}] → {sorted(ctx_pts)}")

    print()


def _collect_variable_names(source: str) -> set[str]:
    """Collect variable names from a Python source for kcfa display."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Load)):
            names.add(node.id)
    return names


def _analyze_file_kcfa_json(filepath: Path, k: int) -> dict:
    source = filepath.read_text()
    result_data: dict = {"file": str(filepath), "engine": "kcfa", "k": k}

    try:
        analysis = PointerAnalysis(source, k=k)
        result = analysis.run()
    except Exception as exc:
        result_data["error"] = str(exc)
        return result_data

    call_edges = result.call_edges()
    result_data["call_edges"] = [
        {"caller": c, "callee": t} for c, t in call_edges
    ]

    variables: dict[str, object] = {}
    for name in sorted(_collect_variable_names(source)):
        pts = result.points_to(name)
        if pts:
            variables[name] = {
                "points_to": sorted(pts),
                "bindings": [
                    {"context": ctx, "points_to": sorted(ctx_pts)}
                    for ctx, ctx_pts in result.bindings_for_name(name)
                ],
            }
    result_data["variables"] = variables

    return result_data


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------

def run_alias_analysis(input_path: str, args) -> int:
    engine: str = getattr(args, "engine", "flow-sensitive")
    k: int = getattr(args, "k", 1)

    try:
        files = _discover_python_files(Path(input_path), getattr(args, "recursive", False))
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 1

    if not files:
        print("No Python files found to analyze", file=sys.stderr)
        return 1

    verbose = getattr(args, "verbose", False)
    json_mode = getattr(args, "json", False)

    if engine == "kcfa":
        if json_mode:
            import json
            all_results: list[dict] = []
            for filepath in files:
                all_results.append(_analyze_file_kcfa_json(filepath, k))
            print(json.dumps(all_results, indent=2))
        else:
            for filepath in files:
                _analyze_file_kcfa(filepath, k, verbose)
    else:
        if json_mode:
            import json
            all_results: list[dict] = []
            for filepath in files:
                all_results.append(_analyze_file_flow_sensitive_json(filepath))
            print(json.dumps(all_results, indent=2))
        else:
            for filepath in files:
                _analyze_file_flow_sensitive(filepath, verbose)

    return 0
