"""
CLI functionality for call graph analysis.
"""

import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

from pyflow.analysis.callgraph.ast_based import analyze_file as analyze_file_ast
from pyflow.analysis.callgraph.constraint_based import (
    analyze_file_constraint,
    extract_value_flow_graph_constraint,
    extract_call_graph_constraint,
)
from pyflow.analysis.callgraph.pycg_based import analyze_file_pycg
from pyflow.analysis.callgraph.pycg_mir import analyze_file_pycg_mir
from pyflow.frontend.entry_discovery import (
    detect_entry_file,
    discover_entry_files,
    resolve_entry_file,
)


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
    if getattr(args, "all_scopes", False):
        incompatible_flags.append("--all-scopes")
    if getattr(args, "as_graph_output", None):
        incompatible_flags.append("--as-graph-output")

    if incompatible_flags:
        joined = ", ".join(incompatible_flags)
        print(
            "Error: " f"{joined} are only supported with --algorithm constraint",
            file=sys.stderr,
        )
        return False
    return True


def _run_analyzer(analyzer, *args, **kwargs):
    """Reserve stdout for the requested graph, including verbose JSON runs."""
    with redirect_stdout(sys.stderr):
        return analyzer(*args, **kwargs)


def _analyze_file(
    file_path: Path, args, *, project_entry: bool = False, project_root: Path | None = None
) -> int:
    if file_path.suffix != ".py":
        print(f"Error: '{file_path}' is not a valid Python file", file=sys.stderr)
        return 1

    if not _validate_algorithm_options(args):
        return 1
    format_kwargs = {"format": "json"} if getattr(args, "format", "text") == "json" else {}

    if args.algorithm == "simple":
        output = _run_analyzer(analyze_file_ast, str(file_path), **format_kwargs)
    elif args.algorithm == "constraint":
        analyze_reachable_only = project_entry and not getattr(args, "all_scopes", False)
        output = _run_analyzer(
            analyze_file_constraint,
            str(file_path),
            verbose=args.verbose,
            context_sensitive=args.context_sensitive,
            context_depth=args.context_depth,
            fixpoint_max_iterations=args.fixpoint_max_iterations,
            warn_on_fixpoint_truncation=not args.no_fixpoint_warning,
            allocation_site_sensitive_instances=(args.allocation_site_sensitive_instances),
            skip_stdlib_modules=args.skip_stdlib,
            analyze_reachable_only=analyze_reachable_only,
            seed_entry_file_scopes=analyze_reachable_only,
            skip_external_modules=not getattr(args, "include_external", False),
            canonical_entry_names=True,
            **format_kwargs,
        )
    elif args.algorithm == "pycg":
        try:
            output = _run_analyzer(analyze_file_pycg, str(file_path), args.verbose, **format_kwargs)
        except ImportError:
            print(
                "Error: PyCG algorithm not available. Install pycg package.",
                file=sys.stderr,
            )
            return 1
    elif args.algorithm == "pycg-mir":
        output = _run_analyzer(
            analyze_file_pycg_mir,
            str(file_path),
            verbose=args.verbose,
            project_root=str(project_root) if project_root is not None else None,
            **format_kwargs,
        )
    else:
        print(f"Error: Unknown algorithm '{args.algorithm}'", file=sys.stderr)
        return 1
    if output.startswith("Error analyzing "):
        print(output, file=sys.stderr)
        return 2

    if args.as_graph_output:
        if args.algorithm != "constraint":
            print(
                "Error: --as-graph-output is currently supported only with "
                "--algorithm constraint",
                file=sys.stderr,
            )
            return 1
        with open(file_path, "r", encoding="utf-8") as handle:
            source = handle.read()
        as_graph = _run_analyzer(
            extract_value_flow_graph_constraint,
            source_code=source,
            source_path=str(file_path),
            verbose=args.verbose,
            context_sensitive=args.context_sensitive,
            context_depth=args.context_depth,
            fixpoint_max_iterations=args.fixpoint_max_iterations,
            warn_on_fixpoint_truncation=not args.no_fixpoint_warning,
            allocation_site_sensitive_instances=(args.allocation_site_sensitive_instances),
            skip_stdlib_modules=args.skip_stdlib,
            analyze_reachable_only=analyze_reachable_only,
            seed_entry_file_scopes=analyze_reachable_only,
        )
        with open(args.as_graph_output, "w", encoding="utf-8") as handle:
            json.dump(as_graph, handle, indent=2, sort_keys=True)
        if args.verbose:
            print(f"Value-flow graph written to {args.as_graph_output}", file=sys.stderr)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        if args.verbose:
            print(f"Call graph written to {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0


def _run_callgraph_on_dir(repo_path: Path, args) -> int:
    entry = getattr(args, "entry", None)
    if entry:
        entry_rel = entry
        source_desc = "user-specified"
    else:
        detected = detect_entry_file(repo_path)
        if not detected:
            candidates = discover_entry_files(repo_path)
            if candidates:
                print(
                    f"Error: Multiple entry points detected in '{repo_path}':",
                    file=sys.stderr,
                )
                for candidate in candidates:
                    command = (
                        f" (command: {candidate.command})" if candidate.command is not None else ""
                    )
                    print(
                        f"  {candidate.path} [{candidate.source}]{command}",
                        file=sys.stderr,
                    )
                print(
                    "Use --entry to select one relative to the project root.",
                    file=sys.stderr,
                )
            else:
                print(
                    f"Error: No entry point detected in '{repo_path}'.\n"
                    "This may be a library project; use --entry to specify an "
                    "analysis root.",
                    file=sys.stderr,
                )
            return 1
        entry_rel = str(detected)
        source_desc = "auto-detected"

    if args.verbose:
        print(f"Repository: {repo_path}", file=sys.stderr)
        print(f"Entry point: {entry_rel} ({source_desc})", file=sys.stderr)

    if getattr(args, "dry_run", False):
        print(entry_rel)
        return 0

    try:
        full_path = resolve_entry_file(repo_path, entry_rel)
    except ValueError as error:
        print(
            f"Error: {error}",
            file=sys.stderr,
        )
        return 1
    assert full_path is not None
    return _analyze_file(full_path, args, project_entry=True, project_root=repo_path)


def run_callgraph(input_path, args):
    try:
        if not input_path.exists():
            print(f"Error: Path '{input_path}' not found", file=sys.stderr)
            return 1

        if input_path.is_dir() and getattr(args, "recursive", False):
            return _analyze_project_sources(input_path, args)
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

    except BrokenPipeError:
        raise
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def add_callgraph_parser(subparsers):
    parser = subparsers.add_parser("callgraph", help="Extract call graphs from Python code")

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
        choices=["simple", "constraint", "pycg", "pycg-mir"],
        default="constraint",
        help=(
            "Call graph algorithm (default: constraint; pycg-mir uses native MIR "
            "analysis without the optional pycg package)"
        ),
    )

    parser.add_argument("--output", "-o", type=Path, help="Output file (default: stdout)")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format; JSON maps caller names to sorted callee lists",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Analyze all project source files (constraint algorithm), including libraries without an entry point",
    )
    parser.add_argument(
        "--include-external",
        action="store_true",
        help="Load third-party dependency source in constraint analysis (default: project sources only)",
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
        "--all-scopes",
        action="store_true",
        help=(
            "Analyze every loaded top-level scope instead of entry-reachable "
            "scopes when the input is a project directory"
        ),
    )
    parser.add_argument(
        "--skip-stdlib",
        action="store_true",
        default=True,
        dest="skip_stdlib",
        help="Skip standard library modules (constraint algorithm only; default: on)",
    )
    parser.add_argument(
        "--no-skip-stdlib",
        action="store_false",
        dest="skip_stdlib",
        help="Include standard library modules (constraint algorithm only)",
    )
    parser.add_argument(
        "--as-graph-output",
        type=Path,
        default=None,
        help="Write constraint value-flow assignment graph JSON (debug output)",
    )

    parser.set_defaults(func=run_callgraph)


def _analyze_project_sources(root, args):
    from pyflow.frontend.file_selection import discover_python_files, SECURITY_DEFAULT_EXCLUDES
    from pyflow.analysis.callgraph.formats import generate_text_output, generate_adjacency_json

    if args.algorithm != "constraint":
        print("Error: recursive project scans require --algorithm constraint", file=sys.stderr)
        return 2
    files = discover_python_files(root, recursive=True, exclude=SECURITY_DEFAULT_EXCLUDES)
    if not files:
        print("Error: no project Python files found", file=sys.stderr)
        return 2
    if args.dry_run:
        print("\n".join(str(path.relative_to(root)) for path in files))
        return 0
    if args.as_graph_output:
        print(
            "Error: --as-graph-output requires a single entry scan; omit --recursive",
            file=sys.stderr,
        )
        return 2
    entry = resolve_entry_file(root, args.entry) if args.entry else files[0]
    sources = {str(path.resolve()): path.read_text(encoding="utf-8-sig") for path in files}
    with redirect_stdout(sys.stderr):
        graph = extract_call_graph_constraint(
            sources[str(entry.resolve())],
            source_path=str(entry),
            additional_sources=sources,
            skip_stdlib_modules=args.skip_stdlib,
            skip_external_modules=not args.include_external,
            canonical_entry_names=True,
            context_sensitive=args.context_sensitive,
            context_depth=args.context_depth,
            fixpoint_max_iterations=args.fixpoint_max_iterations,
            warn_on_fixpoint_truncation=not args.no_fixpoint_warning,
            allocation_site_sensitive_instances=args.allocation_site_sensitive_instances,
        )
    output = (
        generate_adjacency_json(graph)
        if getattr(args, "format", "text") == "json"
        else generate_text_output(graph, args)
    )
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0
