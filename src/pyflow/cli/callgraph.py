"""
CLI functionality for call graph analysis.
"""

import ast
import json
import sys
from pathlib import Path
from typing import Optional

from pyflow.analysis.callgraph.ast_based import analyze_file as analyze_file_ast
from pyflow.analysis.callgraph.constraint_based import (
    analyze_file_constraint,
    extract_value_flow_graph_constraint,
)
from pyflow.analysis.callgraph.pycg_based import analyze_file_pycg


_KNOWN_ENTRY_NAMES = ["main.py", "app.py", "cli.py", "run.py", "launch.py"]


def _module_to_path(module: str, repo: Path) -> Optional[str]:
    parts = module.split(".")
    for base in (repo, repo / "src"):
        py_file = base / f"{'/'.join(parts)}.py"
        if py_file.exists():
            return str(py_file.relative_to(repo))
        pkg_init = base / f"{'/'.join(parts)}" / "__init__.py"
        if pkg_init.exists():
            return str(pkg_init.relative_to(repo))
    return None


def _entry_from_pyproject(repo: Path) -> Optional[str]:
    pyproject = repo / "pyproject.toml"
    if not pyproject.exists():
        return None

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return None

    try:
        with open(pyproject, "rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return None

    scripts = data.get("project", {}).get("scripts", {})
    if not scripts:
        scripts = data.get("tool", {}).get("poetry", {}).get("scripts", {})

    for ref in scripts.values():
        module = ref.split(":")[0].strip()
        entry = _module_to_path(module, repo)
        if entry:
            return entry
    return None


def _entry_from_setup_py(repo: Path) -> Optional[str]:
    setup = repo / "setup.py"
    if not setup.exists():
        return None

    try:
        with open(setup) as fh:
            tree = ast.parse(fh.read())
    except SyntaxError:
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or getattr(node.func, "id", None) != "setup":
            continue
        for kw in node.keywords:
            if kw.arg != "entry_points" or not isinstance(kw.value, ast.Dict):
                continue
            for key, val in zip(kw.value.keys, kw.value.values):
                if not (
                    isinstance(key, ast.Constant)
                    and key.value == "console_scripts"
                    and isinstance(val, ast.List)
                ):
                    continue
                for elt in val.elts:
                    if not (isinstance(elt, ast.Constant) and isinstance(elt.value, str)):
                        continue
                    module = elt.value.split(":")[0].strip()
                    module = module.split("=")[-1].strip()
                    entry = _module_to_path(module, repo)
                    if entry:
                        return entry
    return None


def _detect_entry(repo: Path) -> Optional[str]:
    # Priority: pyproject.toml → setup.py → __main__.py → known filenames
    entry = _entry_from_pyproject(repo)
    if entry:
        return entry

    entry = _entry_from_setup_py(repo)
    if entry:
        return entry

    for child in sorted(repo.iterdir()):
        if not child.is_dir() or child.name.startswith(".") or child.name == "tests":
            continue
        main_py = child / "__main__.py"
        if main_py.exists():
            return str(main_py.relative_to(repo))

    for name in _KNOWN_ENTRY_NAMES:
        entry = repo / name
        if entry.is_file():
            return name

    return None


def _validate_algorithm_options(args) -> bool:
    if args.algorithm == "constraint":
        return True

    incompatible_flags = []
    if getattr(args, "context_sensitive", False):
        incompatible_flags.append("--context-sensitive")
    if getattr(args, "context_depth", 1) != 1:
        incompatible_flags.append("--context-depth")
    if getattr(args, "fixpoint_max_iterations", None) is not None:
        incompatible_flags.append("--fixpoint-max-iterations")
    if getattr(args, "no_fixpoint_warning", False):
        incompatible_flags.append("--no-fixpoint-warning")
    if getattr(args, "allocation_site_sensitive_instances", False):
        incompatible_flags.append("--allocation-site-sensitive-instances")
    if getattr(args, "as_graph_output", None):
        incompatible_flags.append("--as-graph-output")

    if incompatible_flags:
        joined = ", ".join(incompatible_flags)
        print(
            "Error: "
            f"{joined} are only supported with --algorithm constraint",
            file=sys.stderr,
        )
        return False
    return True


def _analyze_file(file_path: Path, args) -> int:
    if file_path.suffix != ".py":
        print(f"Error: '{file_path}' is not a valid Python file", file=sys.stderr)
        return 1

    if not _validate_algorithm_options(args):
        return 1

    if args.algorithm == "simple":
        output = analyze_file_ast(str(file_path))
    elif args.algorithm == "constraint":
        output = analyze_file_constraint(
            str(file_path),
            verbose=args.verbose,
            context_sensitive=args.context_sensitive,
            context_depth=args.context_depth,
            fixpoint_max_iterations=args.fixpoint_max_iterations,
            warn_on_fixpoint_truncation=not args.no_fixpoint_warning,
            allocation_site_sensitive_instances=args.allocation_site_sensitive_instances,
            skip_stdlib_modules=args.skip_stdlib,
        )
    elif args.algorithm == "pycg":
        try:
            output = analyze_file_pycg(str(file_path), args.verbose)
        except ImportError:
            print(
                "Error: PyCG algorithm not available. Install pycg package.",
                file=sys.stderr,
            )
            return 1
    else:
        print(f"Error: Unknown algorithm '{args.algorithm}'", file=sys.stderr)
        return 1

    if args.as_graph_output:
        if args.algorithm != "constraint":
            print(
                "Error: --as-graph-output is currently supported only with --algorithm constraint",
                file=sys.stderr,
            )
            return 1
        with open(file_path, "r", encoding="utf-8") as handle:
            source = handle.read()
        as_graph = extract_value_flow_graph_constraint(
            source_code=source,
            source_path=str(file_path),
            verbose=args.verbose,
            context_sensitive=args.context_sensitive,
            context_depth=args.context_depth,
            fixpoint_max_iterations=args.fixpoint_max_iterations,
            warn_on_fixpoint_truncation=not args.no_fixpoint_warning,
            allocation_site_sensitive_instances=args.allocation_site_sensitive_instances,
            skip_stdlib_modules=args.skip_stdlib,
        )
        with open(args.as_graph_output, "w", encoding="utf-8") as handle:
            json.dump(as_graph, handle, indent=2, sort_keys=True)
        if args.verbose:
            print(f"Value-flow graph written to {args.as_graph_output}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        if args.verbose:
            print(f"Call graph written to {args.output}")
    else:
        print(output)

    return 0


def _run_callgraph_on_dir(repo_path: Path, args) -> int:
    entry = getattr(args, "entry", None)
    if entry:
        entry_rel = entry
        source_desc = "user-specified"
    else:
        detected = _detect_entry(repo_path)
        if not detected:
            print(
                f"Error: No entry point detected in '{repo_path}'.\n"
                "Use --entry to specify one relative to the project root.",
                file=sys.stderr,
            )
            return 1
        entry_rel = detected
        source_desc = "auto-detected"

    if args.verbose:
        print(f"Repository: {repo_path}")
        print(f"Entry point: {entry_rel} ({source_desc})")

    if getattr(args, "dry_run", False):
        print(entry_rel)
        return 0

    full_path = (repo_path / entry_rel).resolve()
    if not full_path.exists():
        print(
            f"Error: Entry point '{entry_rel}' not found in '{repo_path}'",
            file=sys.stderr,
        )
        return 1

    return _analyze_file(full_path, args)


def run_callgraph(input_path, args):
    try:
        if not input_path.exists():
            print(f"Error: Path '{input_path}' not found", file=sys.stderr)
            return 1

        if input_path.is_dir():
            return _run_callgraph_on_dir(input_path, args)

        if getattr(args, "dry_run", False):
            print(str(input_path))
            return 0

        if getattr(args, "entry", None):
            print(
                "Warning: --entry is ignored when input is a file, not a directory.",
                file=sys.stderr,
            )

        return _analyze_file(input_path, args)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def add_callgraph_parser(subparsers):
    parser = subparsers.add_parser(
        "callgraph", help="Extract call graphs from Python code"
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Python file or project directory to analyze",
    )

    parser.add_argument(
        "--entry",
        type=str,
        default=None,
        help=(
            "Entry point file relative to the project root "
            "(requires directory input; auto-detected when omitted)"
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print detected entry point without running analysis",
    )

    parser.add_argument(
        "--algorithm",
        "-a",
        choices=["simple", "constraint", "pycg"],
        default="simple",
        help="Call graph algorithm to use (default: simple)",
    )

    parser.add_argument(
        "--output", "-o", type=Path, help="Output file (default: stdout)"
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.add_argument(
        "--context-sensitive",
        action="store_true",
        help="Enable call-site context sensitivity (constraint algorithm only)",
    )
    parser.add_argument(
        "--context-depth",
        type=int,
        default=1,
        help="Call-string depth when --context-sensitive is enabled",
    )
    parser.add_argument(
        "--fixpoint-max-iterations",
        type=int,
        default=None,
        help="Cap fixpoint iterations (constraint algorithm only)",
    )
    parser.add_argument(
        "--no-fixpoint-warning",
        action="store_true",
        help="Disable warning when fixpoint cap is hit (constraint algorithm only)",
    )
    parser.add_argument(
        "--allocation-site-sensitive-instances",
        action="store_true",
        help="Track per-allocation instance identities (constraint algorithm only)",
    )
    parser.add_argument(
        "--skip-stdlib",
        action="store_true",
        default=True,
        dest="skip_stdlib",
        help="Skip loading standard library modules (default: on)",
    )
    parser.add_argument(
        "--no-skip-stdlib",
        action="store_false",
        dest="skip_stdlib",
        help="Include standard library modules in the call graph",
    )
    parser.add_argument(
        "--as-graph-output",
        type=Path,
        default=None,
        help="Write constraint value-flow assignment graph JSON (debug output)",
    )

    parser.set_defaults(func=run_callgraph)
