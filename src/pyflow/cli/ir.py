"""
IR dumping command for PyFlow CLI.

This module provides functionality to dump MIR programs and AST, CFG, SSA,
CDG, DDG, and GIR forms for specific functions in Python code.
"""

import sys
import os
import argparse
import fnmatch
import json
from contextlib import redirect_stdout
from copy import copy
from tempfile import TemporaryDirectory
from pathlib import Path

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.application.pipeline import Pipeline
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import (
    InterfaceBuildOptions,
    build_interface_from_paths,
)
from pyflow.util.application.console import Console
from pyflow.ir.cfg import transform, dump as cfg_dump, ssa
from pyflow.ir.cfg.dump import generate_clang_style_cfg, generate_json_cfg
from pyflow.ir.cdg import construct_cdg, dump_cdg
from pyflow.ir.ddg import construction, dump as ddg_dump
from pyflow.ir.dataflow import convert
from pyflow.ir.gir import build_function_gir
from pyflow.ir.gir.dump import dump_gir_content
from pyflow.analysis.programculler import findLiveCode
import pyflow.util.pydot as pydot


def add_ir_parser(subparsers):
    """Add IR dumping command parser to the main CLI."""
    parser = subparsers.add_parser(
        "ir", help="Dump MIR programs or AST, CFG, SSA, CDG, DDG, and GIR functions"
    )

    # Input arguments
    parser.add_argument("input_path", help="Python file or directory to analyze")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Recursively analyze subdirectories",
    )
    parser.add_argument(
        "--exclude", nargs="*", default=[], help="Patterns to exclude from analysis"
    )
    parser.add_argument(
        "--include",
        nargs="*",
        default=["*.py"],
        help="File patterns to include in analysis",
    )

    # Dependency resolution
    parser.add_argument(
        "--dependency-strategy",
        choices=["auto", "stubs", "noop", "strict", "ast_only"],
        default="auto",
        help="How to handle import dependencies (default: auto)",
    )

    # Dump arguments
    parser.add_argument(
        "--dump-mir",
        nargs="?",
        const="*",
        metavar="SCOPE",
        help=(
            "Dump the seven-instruction MIR program; optionally select a "
            "qualified scope or an unambiguous function name"
        ),
    )
    parser.add_argument(
        "--mir-view",
        choices=("source", "full"),
        help=(
            "MIR view: source hides runtime CFGs; full includes them. "
            "Default: source for text/dot, full for JSON compatibility"
        ),
    )
    parser.add_argument(
        "--dump-ast",
        metavar="FUNCTION",
        help="Dump AST for the specified function name",
    )
    parser.add_argument(
        "--mir-import-policy",
        choices=("strict", "opaque"),
        help="Reject unmodeled imports, or retain opaque boundaries for inspection (default: opaque)",
    )
    parser.add_argument(
        "--mir-follow-imports",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Whether to follow imports when dumping MIR (default: false unless explicitly requested)",
    )
    parser.add_argument(
        "--dump-cfg",
        metavar="FUNCTION",
        help="Dump CFG for a qualified function or an unambiguous short name (e.g. Class.method)",
    )
    parser.add_argument(
        "--dump-ssa",
        metavar="FUNCTION",
        help="Dump SSA form for the specified function name",
    )
    parser.add_argument(
        "--dump-cdg",
        metavar="FUNCTION",
        help="Dump Control Dependence Graph for the specified function name",
    )
    parser.add_argument(
        "--dump-ddg",
        metavar="FUNCTION",
        help="Dump Data Dependence Graph for the specified function name",
    )
    parser.add_argument(
        "--dump-gir",
        metavar="FUNCTION",
        help="Dump Lian-compatible GIR for the specified function name",
    )
    parser.add_argument(
        "--dump-format",
        choices=["text", "dot", "json"],
        default="text",
        help="Format for IR dumps",
    )
    parser.add_argument("--dump-output", help="Write IR dumps to this directory (default: stdout)")

    return parser


def find_function_in_live_code(liveCode, function_name: str, program=None):
    """Use the public query resolver for all function IR views."""
    from types import SimpleNamespace
    from pyflow.api.queries.context import QueryContext

    view = SimpleNamespace(
        liveCode=liveCode,
        interface=getattr(program, "interface", None),
        ir=getattr(program, "ir", None),
    )
    try:
        return QueryContext(None, view).resolve_function(function_name)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return None


def write_ir_file(output_file: str, function_name: str, ir_type: str, content: str):
    """Write IR content to file with standard header."""
    with open(output_file, "w") as f:
        f.write(f"{ir_type} for function: {function_name}\n")
        f.write("=" * 50 + "\n\n")
        f.write(content)
    print(f"{ir_type} dumped to: {output_file}")


def _get_ast_content(func, function_name: str):
    """Extract AST content from function object."""
    if hasattr(func, "ast") and func.ast:
        return str(func.ast)
    elif hasattr(func, "code") and hasattr(func.code, "ast") and func.code.ast:
        return str(func.code.ast)
    else:
        raise ValueError(f"No AST available for function '{function_name}'")


def _get_ast_node(func):
    """Return the AST node for *func*, or ``None`` when unavailable."""
    if hasattr(func, "ast") and func.ast:
        return func.ast
    code = getattr(func, "code", None)
    if code is not None and getattr(code, "ast", None):
        return code.ast
    return None


def _ast_node_to_json(node, depth: int = 0):
    """Serialize a Python AST node into JSON-friendly structures."""
    from pyflow.language.python import ast as py_ast

    if depth > 200:
        return "<max-depth>"
    if node is None or isinstance(node, (str, int, float, bool)):
        return node
    if isinstance(node, (list, tuple)):
        return [_ast_node_to_json(item, depth + 1) for item in node]
    if isinstance(node, py_ast.PythonASTNode):
        return {
            "type": type(node).__name__,
            "fields": {name: _ast_node_to_json(value, depth + 1) for name, value in node.fields()},
        }
    missing = object()
    pyobj = getattr(node, "pyobj", missing)
    if pyobj is not missing:
        try:
            json.dumps(pyobj)
        except (TypeError, ValueError):
            return repr(pyobj)
        return pyobj
    return repr(node)


def _write_json_ir_file(output_file: str, label: str, payload) -> None:
    """Write a JSON IR artifact without the text header used by text dumps."""
    with open(output_file, "w", encoding="utf-8") as output:
        json.dump(payload, output, indent=2)
        output.write("\n")
    print(f"{label} dumped to: {output_file}")


def dump_ir(
    compiler,
    liveCode,
    function_name: str,
    output_dir: str,
    ir_type: str,
    format: str = "text",
    program=None,
):
    """Generic IR dumping function for AST, CFG, and SSA."""
    func = find_function_in_live_code(liveCode, function_name, program)
    if not func:
        return False

    def _dump_impl():
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"{function_name}_{ir_type.lower()}.{format}")

        if ir_type == "AST":
            if format == "json":
                ast_node = _get_ast_node(func)
                if ast_node is None:
                    raise ValueError(f"No AST available for function '{function_name}'")
                _write_json_ir_file(
                    output_file,
                    "AST",
                    {"function": function_name, "ast": _ast_node_to_json(ast_node)},
                )
            elif format == "text":
                content = _get_ast_content(func, function_name)
                write_ir_file(output_file, function_name, "AST", content)
            else:
                raise ValueError("AST dumps support only text and json formats")
        elif ir_type == "CFG":
            cfg = transform.evaluate(compiler, func)
            if format == "dot":
                try:
                    g = pydot.Dot(graph_type="digraph")
                    ctd = cfg_dump.CFGToDot(g)
                    ctd.process(cfg)
                    with open(output_file, "w") as f:
                        f.write(f"// CFG for function: {function_name}\n")
                        f.write(g.to_string())
                    print(f"CFG dumped to: {output_file}")
                except Exception as e:
                    print(f"Warning: DOT generation failed, falling back to text format: {e}")
                    write_ir_file(output_file, function_name, "CFG", str(cfg))
            elif format == "json":
                _write_json_ir_file(
                    output_file,
                    "CFG",
                    {"function": function_name, "cfg": generate_json_cfg(cfg)},
                )
            elif format == "text":
                content = generate_clang_style_cfg(cfg)
                write_ir_file(output_file, function_name, "CFG", content)
            else:
                raise ValueError("CFG dumps support only text, dot, and json formats")
        elif ir_type == "SSA":
            cfg = transform.evaluate(compiler, func)
            ssa.evaluate(compiler, cfg)
            if format == "dot":
                graph = pydot.Dot(graph_type="digraph")
                cfg_dump.CFGToDot(graph).process(cfg)
                with open(output_file, "w", encoding="utf-8") as output:
                    output.write(graph.to_string())
                print(f"SSA form dumped to: {output_file}")
            elif format == "json":
                _write_json_ir_file(
                    output_file,
                    "SSA form",
                    {"function": function_name, "ssa": generate_json_cfg(cfg)},
                )
            elif format == "text":
                content = generate_clang_style_cfg(cfg)
                write_ir_file(output_file, function_name, "SSA form", content)
            else:
                raise ValueError("SSA dumps support only text, dot, and json formats")
        return True

    return _dump_with_error_handling(ir_type, _dump_impl)


def _dump_with_error_handling(func_name: str, dump_func, *args, **kwargs):
    """Helper to handle common error patterns in dump functions."""
    try:
        return dump_func(*args, **kwargs)
    except BrokenPipeError:
        raise
    except Exception as e:
        print(f"Error dumping {func_name}: {e}", file=sys.stderr)
        return False


def dump_ast(
    compiler,
    liveCode,
    function_name: str,
    output_dir: str,
    format: str = "text",
    program=None,
):
    """Dump the AST for a specific function."""
    return dump_ir(compiler, liveCode, function_name, output_dir, "AST", format, program)


def dump_cfg(
    compiler,
    liveCode,
    function_name: str,
    output_dir: str,
    format: str = "text",
    program=None,
):
    """Dump the CFG for a specific function."""
    return dump_ir(compiler, liveCode, function_name, output_dir, "CFG", format, program)


def dump_ssa(
    compiler,
    liveCode,
    function_name: str,
    output_dir: str,
    format: str = "text",
    program=None,
):
    """Dump the SSA form for a specific function."""
    return dump_ir(compiler, liveCode, function_name, output_dir, "SSA", format, program)


def dump_gir(
    compiler,
    liveCode,
    function_name: str,
    output_dir: str,
    format: str = "text",
    program=None,
):
    """Dump the Lian-compatible GIR for a specific function."""
    func = find_function_in_live_code(liveCode, function_name, program)
    if not func:
        return False

    def _dump_impl():
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"{function_name}_gir.{format}")
        rows = build_function_gir(func, function_name)
        if format == "json":
            with open(output_file, "w") as output:
                json.dump(rows, output, indent=2)
            print(f"GIR dumped to: {output_file}")
        elif format == "text":
            content = dump_gir_content(rows)
            write_ir_file(output_file, function_name, "GIR", content)
        else:
            raise ValueError("GIR dumps support only text and json formats")
        return True

    return _dump_with_error_handling("GIR", _dump_impl)


def _dump_graph_ir(
    compiler,
    liveCode,
    function_name: str,
    output_dir: str,
    format: str,
    builder_func,
    dump_func,
    ir_name: str,
    program=None,
):
    """Generic function to dump graph-based IRs (CDG, DDG)."""
    func = find_function_in_live_code(liveCode, function_name, program)
    if not func:
        return False

    try:
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"{function_name}_{ir_name.lower()}.{format}")

        # Build base structure (CFG for CDG, Dataflow for DDG)
        base_structure = builder_func(compiler, func)

        # Construct and dump the graph IR
        graph_ir = (
            construct_cdg(base_structure)
            if ir_name == "CDG"
            else construction.construct_ddg(base_structure)
        )
        dump_func(graph_ir, output_file, format, function_name)
        print(f"{ir_name} dumped to: {output_file}")
        return True

    except BrokenPipeError:
        raise
    except Exception as e:
        print(f"Error dumping {ir_name}: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return False


def dump_cdg_func(
    compiler,
    liveCode,
    function_name: str,
    output_dir: str,
    format: str = "text",
    program=None,
):
    """Dump the Control Dependence Graph for a specific function."""
    return _dump_graph_ir(
        compiler,
        liveCode,
        function_name,
        output_dir,
        format,
        lambda c, f: transform.evaluate(c, f),
        dump_cdg,
        "CDG",
        program,
    )


def dump_ddg(
    compiler,
    liveCode,
    function_name: str,
    output_dir: str,
    format: str = "text",
    program=None,
):
    """Dump the Data Dependence Graph for a specific function."""
    return _dump_graph_ir(
        compiler,
        liveCode,
        function_name,
        output_dir,
        format,
        convert.evaluateCode,
        ddg_dump.dump_ddg,
        "DDG",
        program,
    )


def find_python_files(directory, args):
    """Find Python files in a directory based on include/exclude patterns."""

    def should_include(file_path):
        if file_path.suffix != ".py":
            return False
        filename = file_path.name
        include_match = any(fnmatch.fnmatch(filename, pattern) for pattern in args.include)
        exclude_match = any(fnmatch.fnmatch(filename, pattern) for pattern in args.exclude)
        return include_match and not exclude_match

    if args.recursive:
        files = []
        for root, dirs, filenames in os.walk(directory):
            dirs[:] = [
                d for d in dirs if not any(fnmatch.fnmatch(d, pattern) for pattern in args.exclude)
            ]
            files.extend(Path(root) / f for f in filenames if should_include(Path(root) / f))
        return sorted(files)
    else:
        return sorted(
            item for item in directory.iterdir() if item.is_file() and should_include(item)
        )


def _select_mir_programs(compiled, scope):
    """Resolve scopes across files, deduplicating shared imported definitions."""
    if scope in (None, "*"):
        return [(source, program, None) for source, program in compiled]
    exact, suffix, source_suffix = {}, {}, {}
    for source, program in compiled:
        for name, cfg in program.cfgs.items():
            identity = (name, cfg.filename or str(source.resolve()))
            if name == scope:
                exact.setdefault(identity, (source, program, name))
            elif name.endswith(f".{scope}"):
                suffix.setdefault(identity, (source, program, name))
                if cfg.filename and not cfg.is_synthetic:
                    source_suffix.setdefault(identity, (source, program, name))
    matches = exact or source_suffix or suffix
    if len(matches) == 1:
        return list(matches.values())
    if not matches:
        candidates = sorted(
            {
                name
                for _, program in compiled
                for name, cfg in program.cfgs.items()
                if cfg.filename and not cfg.is_synthetic
            }
        )
        hint = f" Available candidates: {', '.join(candidates[:5])}" if candidates else ""
        raise ValueError(f"MIR scope '{scope}' was not found.{hint}")
    choices = ", ".join(f"{name} ({filename})" for name, filename in sorted(matches))
    raise ValueError(f"MIR scope '{scope}' is ambiguous; choose one of: {choices}")


def _format_mir_view(program, args, scope, diagnostics=()):
    """Keep human inspection compact while preserving default JSON exports."""
    from dataclasses import replace
    from pyflow.ir.mir import format_program

    view = getattr(args, "mir_view", None) or ("full" if args.dump_format == "json" else "source")
    if scope is not None or view == "full":
        content = format_program(program, format=args.dump_format, scope=scope)
        if diagnostics and args.dump_format == "json":
            data = json.loads(content)
            data.update(status="partial", inspection_only=True, diagnostics=list(diagnostics))
            return json.dumps(data, indent=2) + "\n"
        if diagnostics and args.dump_format == "text":
            return "MIR partial inspection (opaque imports/literals; see diagnostics)\n" + content
        return content
    cfgs = {
        name: cfg for name, cfg in program.cfgs.items() if cfg.filename and not cfg.is_synthetic
    }
    source_program = replace(program, cfgs=cfgs)
    if args.dump_format == "json":
        # Explicit source views are inspection artifacts; only the full JSON
        # export is a standalone, executable MIR program.
        data = source_program.to_dict()
        data.update(view="source", omitted_runtime_cfgs=len(program.cfgs) - len(cfgs))
        if diagnostics:
            data.update(status="partial", inspection_only=True, diagnostics=list(diagnostics))
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    content = format_program(source_program, format=args.dump_format)
    if args.dump_format == "text":
        return "MIR source view (runtime CFGs omitted; use --mir-view full)\n" + content
    return content


def _dump_mir_files(python_files, input_path: Path, args):
    """Lower source directly, so MIR inspection never imports target modules."""
    from pyflow.ir.mir import lower_file
    from pyflow.ir.mir.lowering import _default_root

    output_dir = Path(args.dump_output or ".")
    project_root = (
        str(_default_root(input_path.resolve() / "__init__.py")) if input_path.is_dir() else None
    )
    view = getattr(args, "mir_view", None) or ("full" if args.dump_format == "json" else "source")
    import_policy = getattr(args, "mir_import_policy", None) or "opaque"
    # Default dumps inspect the requested files. Following a project's
    # entire dependency graph requires explicit follow-imports or strict verification.
    explicit_follow = getattr(args, "mir_follow_imports", None)
    if explicit_follow is not None:
        follow_imports = explicit_follow
    else:
        follow_imports = (
            getattr(args, "mir_view", None) == "full" and import_policy == "strict"
        ) or (import_policy == "strict")
    compiled, diagnostics_by_source = [], {}
    for source in python_files:
        diagnostics = []
        program = lower_file(
            str(source),
            project_root=project_root,
            import_policy=import_policy,
            diagnostics=diagnostics,
            follow_imports=follow_imports,
        )
        compiled.append((source, program))
        diagnostics_by_source[source] = diagnostics
        if diagnostics:
            modules = sorted({item["module"] for item in diagnostics if "module" in item})
            print(
                f"MIR inspection is partial: {len(diagnostics)} unmodeled semantic site(s). Opaque imports: {', '.join(modules) or '<none>'}. Use --mir-import-policy strict to require complete semantics.",
                file=sys.stderr,
            )
    prepared = []
    for source_path, program, scope in _select_mir_programs(compiled, args.dump_mir):
        content = _format_mir_view(program, args, scope, diagnostics_by_source[source_path])
        if input_path.is_dir():
            relative = source_path.relative_to(input_path).with_suffix("")
            relative_dir = relative.parent
        else:
            relative_dir = Path()
        stem = source_path.stem
        if scope is not None:
            # Qualified names may contain compiler-generated markers; keep
            # emitted filenames portable and confined to the output directory.
            safe_scope = "".join(char if char.isalnum() or char in "._-" else "_" for char in scope)
            stem = f"{stem}.{safe_scope}"
        prepared.append((output_dir / relative_dir / f"{stem}_mir.{args.dump_format}", content))

    for output_file, content in prepared:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(content, encoding="utf-8")
        print(f"MIR dumped to: {output_file}")


def run_ir_dump(input_path: Path, args):
    """Print inspection artifacts by default; persist only to an explicit path."""
    if not any(
        getattr(args, name, None)
        for name in (
            "dump_mir",
            "dump_ast",
            "dump_cfg",
            "dump_ssa",
            "dump_cdg",
            "dump_ddg",
            "dump_gir",
        )
    ):
        print(
            "Error: no IR dump target specified; use --dump-mir, --dump-cfg, or --help",
            file=sys.stderr,
        )
        sys.exit(2)

    if getattr(args, "dump_output", None):
        return _run_ir_dump(input_path, args)
    with TemporaryDirectory(prefix="pyflow-ir-") as directory:
        effective_args = copy(args)
        effective_args.dump_output = directory
        with redirect_stdout(sys.stderr):
            _run_ir_dump(input_path, effective_args)
        artifacts = sorted(path for path in Path(directory).rglob("*") if path.is_file())
        if args.dump_format == "json" and len(artifacts) > 1:
            contents = {}
            for path in artifacts:
                content = path.read_text(encoding="utf-8")
                try:
                    content = json.loads(content)
                except ValueError:
                    pass
                contents[str(path.relative_to(directory))] = content
            print(json.dumps(contents, indent=2))
        else:
            for path in artifacts:
                print(path.read_text(encoding="utf-8"), end="")


def _run_ir_dump(input_path: Path, args):
    """Run IR dumping for the specified function."""
    try:
        if input_path.is_file():
            python_files = [input_path]
        elif input_path.is_dir():
            python_files = find_python_files(input_path, args)
            if not python_files:
                print("No Python files found to analyze")
                return
        else:
            print(
                f"Error: '{input_path}' is neither a file nor a directory",
                file=sys.stderr,
            )
            sys.exit(1)

        if getattr(args, "dump_mir", None):
            _dump_mir_files(python_files, input_path, args)
            if not any(
                getattr(args, name, None)
                for name in ("dump_ast", "dump_cfg", "dump_ssa", "dump_cdg", "dump_ddg", "dump_gir")
            ):
                print("IR dumping complete!")
                return

        console = Console(verbose=args.verbose)
        compiler = CompilerContext(console)
        program = Program()
        program.interface, all_source_code = build_interface_from_paths(
            python_files, InterfaceBuildOptions.from_namespace(args)
        )
        # Keep source syntax retention enabled by default so that GIR emission
        # and AST provenance remain intact regardless of dump combinations.
        compiler.extractor = Extractor(
            compiler,
            verbose=args.verbose,
            source_code=all_source_code,
            retain_source_syntax=True,
        )

        with console.scope("extraction"):
            extract_program(compiler, program)

        parse_failures = [
            diagnostic
            for diagnostic in getattr(program, "frontend_diagnostics", ())
            if getattr(diagnostic, "stage", None) == "parse"
        ]
        failed_paths = {os.path.realpath(str(diagnostic.filename)) for diagnostic in parse_failures}
        if parse_failures and all(
            os.path.realpath(str(path)) in failed_paths for path in python_files
        ):
            for diagnostic in parse_failures:
                print(
                    f"Error: Could not parse {diagnostic.filename}: "
                    f"{diagnostic.exception_type}: {diagnostic.message}",
                    file=sys.stderr,
                )
            sys.exit(1)

        if program.liveCode:
            print(
                f"Created {len(program.liveCode)} entry points from {len(program.liveCode)} functions"
            )
        elif program.interface.func:
            print(
                f"Created {len(program.interface.entryPoint)} entry points from {len(program.interface.func)} functions"
            )

        # Skip analysis pipeline for AST/CFG/CDG/DDG dumping since it clears AST blocks
        if not (
            args.dump_ast
            or args.dump_cfg
            or args.dump_ssa
            or args.dump_cdg
            or args.dump_ddg
            or args.dump_gir
        ):
            with console.scope("analysis"):
                Pipeline().run(program, compiler=compiler, name=str(input_path))

        liveCode = program.liveCode if program.liveCode else findLiveCode(program)[0]
        output_dir = args.dump_output or "."

        success = True
        dump_functions = {
            "dump_ast": dump_ast,
            "dump_cfg": dump_cfg,
            "dump_ssa": dump_ssa,
            "dump_cdg": dump_cdg_func,
            "dump_ddg": dump_ddg,
            "dump_gir": dump_gir,
        }

        for dump_arg, dump_func in dump_functions.items():
            if hasattr(args, dump_arg) and getattr(args, dump_arg):
                if not dump_func(
                    compiler,
                    liveCode,
                    getattr(args, dump_arg),
                    output_dir,
                    args.dump_format,
                    program,
                ):
                    success = False

        if success:
            print("IR dumping complete!")
        else:
            print("IR dumping completed with errors")
            sys.exit(1)

    except BrokenPipeError:
        raise
    except Exception as e:
        print(f"Error during IR dumping: {e}", file=sys.stderr)
        import traceback

        if args.verbose:
            traceback.print_exc()
        sys.exit(1)
