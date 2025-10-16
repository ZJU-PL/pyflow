"""
IR dumping command for PyFlow CLI.

This module provides functionality to dump AST, CFG, SSA, CDG, and DDG forms
for specific functions in Python code.
"""

import sys
import os
import fnmatch
from pathlib import Path
import argparse

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.application.pipeline import evaluate
from pyflow.frontend.programextractor import extractProgram, Extractor
from pyflow.util.application.console import Console
from pyflow.analysis.cfg import transform, dump as cfg_dump, ssa
from pyflow.analysis.cfg.dump import generate_clang_style_cfg
from pyflow.analysis.cdg import construct_cdg, dump_cdg
from pyflow.analysis.ddg import construction, dump as ddg_dump
from pyflow.analysis.dataflowIR import convert
from pyflow.analysis.programculler import findLiveCode
import pyflow.util.pydot as pydot


def add_ir_parser(subparsers):
    """Add IR dumping command parser to the main CLI."""
    parser = subparsers.add_parser("ir", help="Dump AST, CFG, SSA, CDG, and DDG forms for specific functions")

    # Input arguments
    parser.add_argument("input_path", help="Python file or directory to analyze")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--recursive", "-r", action="store_true", help="Recursively analyze subdirectories")
    parser.add_argument("--exclude", nargs="*", default=[], help="Patterns to exclude from analysis")
    parser.add_argument("--include", nargs="*", default=["*.py"], help="File patterns to include in analysis")

    # Dependency resolution
    parser.add_argument("--dependency-strategy",
                       choices=["auto", "stubs", "noop", "strict", "ast_only"],
                       default="auto",
                       help="How to handle import dependencies (default: auto)")

    # Dump arguments
    parser.add_argument("--dump-ast", metavar="FUNCTION", help="Dump AST for the specified function name")
    parser.add_argument("--dump-cfg", metavar="FUNCTION", help="Dump CFG for the specified function name")
    parser.add_argument("--dump-ssa", metavar="FUNCTION", help="Dump SSA form for the specified function name")
    parser.add_argument("--dump-cdg", metavar="FUNCTION", help="Dump Control Dependence Graph for the specified function name")
    parser.add_argument("--dump-ddg", metavar="FUNCTION", help="Dump Data Dependence Graph for the specified function name")
    parser.add_argument("--dump-format", choices=["text", "dot", "json"], default="text", help="Format for IR dumps")
    parser.add_argument("--dump-output", help="Output directory for IR dumps")

    return parser


def find_function_in_live_code(liveCode, function_name: str, program=None):
    """Find a function by name in live code."""
    for code in liveCode:
        if hasattr(code, 'codeName') and code.codeName() == function_name:
            return code

    # Check entry points if not found in live code
    if program and hasattr(program, 'interface') and hasattr(program.interface, 'entryPoint'):
        for ep in program.interface.entryPoint:
            if hasattr(ep.code, 'codeName') and ep.code.codeName() == function_name:
                return ep.code

    return None


def write_ir_file(output_file: str, function_name: str, ir_type: str, content: str):
    """Write IR content to file with standard header."""
    with open(output_file, 'w') as f:
        f.write(f"{ir_type} for function: {function_name}\n")
        f.write("=" * 50 + "\n\n")
        f.write(content)
    print(f"{ir_type} dumped to: {output_file}")


def _get_ast_content(func, function_name: str):
    """Extract AST content from function object."""
    if hasattr(func, 'ast') and func.ast:
        return str(func.ast)
    elif hasattr(func, 'code') and hasattr(func.code, 'ast') and func.code.ast:
        return str(func.code.ast)
    else:
        raise ValueError(f"No AST available for function '{function_name}'")


def dump_ir(compiler, liveCode, function_name: str, output_dir: str, ir_type: str, format: str = "text", program=None):
    """Generic IR dumping function for AST, CFG, and SSA."""
    func = find_function_in_live_code(liveCode, function_name, program)
    if not func:
        print(f"Error: Function '{function_name}' not found in live code", file=sys.stderr)
        return False

    def _dump_impl():
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"{function_name}_{ir_type.lower()}.{format}")

        if ir_type == "AST":
            content = _get_ast_content(func, function_name)
            write_ir_file(output_file, function_name, "AST", content)
        elif ir_type == "CFG":
            cfg = transform.evaluate(compiler, func)
            if format == "dot":
                try:
                    g = pydot.Dot(graph_type="digraph")
                    ctd = cfg_dump.CFGToDot(g)
                    ctd.process(cfg)
                    with open(output_file, 'w') as f:
                        f.write(f"// CFG for function: {function_name}\n")
                        f.write(g.to_string())
                    print(f"CFG dumped to: {output_file}")
                except Exception as e:
                    print(f"Warning: DOT generation failed, falling back to text format: {e}")
                    write_ir_file(output_file, function_name, "CFG", str(cfg))
            else:
                content = generate_clang_style_cfg(cfg)
                write_ir_file(output_file, function_name, "CFG", content)
        elif ir_type == "SSA":
            cfg = transform.evaluate(compiler, func)
            ssa.evaluate(compiler, cfg)
            if format == "dot":
                cfg_dump.evaluate(compiler, cfg)
                print(f"SSA form dumped to: {output_file}")
            else:
                content = generate_clang_style_cfg(cfg)
                write_ir_file(output_file, function_name, "SSA form", content)
        return True

    return _dump_with_error_handling(ir_type, _dump_impl)


def _dump_with_error_handling(func_name: str, dump_func, *args, **kwargs):
    """Helper to handle common error patterns in dump functions."""
    try:
        return dump_func(*args, **kwargs)
    except Exception as e:
        print(f"Error dumping {func_name}: {e}", file=sys.stderr)
        return False


def dump_ast(compiler, liveCode, function_name: str, output_dir: str, format: str = "text", program=None):
    """Dump the AST for a specific function."""
    return dump_ir(compiler, liveCode, function_name, output_dir, "AST", format, program)

def dump_cfg(compiler, liveCode, function_name: str, output_dir: str, format: str = "text", program=None):
    """Dump the CFG for a specific function."""
    return dump_ir(compiler, liveCode, function_name, output_dir, "CFG", format, program)

def dump_ssa(compiler, liveCode, function_name: str, output_dir: str, format: str = "text", program=None):
    """Dump the SSA form for a specific function."""
    return dump_ir(compiler, liveCode, function_name, output_dir, "SSA", format, program)


def _dump_graph_ir(compiler, liveCode, function_name: str, output_dir: str, format: str,
                   builder_func, dump_func, ir_name: str, program=None):
    """Generic function to dump graph-based IRs (CDG, DDG)."""
    func = find_function_in_live_code(liveCode, function_name, program)
    if not func:
        print(f"Error: Function '{function_name}' not found in live code", file=sys.stderr)
        return False

    try:
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"{function_name}_{ir_name.lower()}.{format}")

        # Build base structure (CFG for CDG, Dataflow for DDG)
        base_structure = builder_func(compiler, func)

        # Construct and dump the graph IR
        graph_ir = construct_cdg(base_structure) if ir_name == "CDG" else construction.construct_ddg(base_structure)
        dump_func(graph_ir, output_file, format, function_name)
        print(f"{ir_name} dumped to: {output_file}")
        return True

    except Exception as e:
        print(f"Error dumping {ir_name}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False


def dump_cdg_func(compiler, liveCode, function_name: str, output_dir: str, format: str = "text", program=None):
    """Dump the Control Dependence Graph for a specific function."""
    return _dump_graph_ir(compiler, liveCode, function_name, output_dir, format,
                         lambda c, f: transform.evaluate(c, f), dump_cdg, "CDG", program)


def dump_ddg(compiler, liveCode, function_name: str, output_dir: str, format: str = "text", program=None):
    """Dump the Data Dependence Graph for a specific function."""
    return _dump_graph_ir(compiler, liveCode, function_name, output_dir, format,
                         convert.evaluateCode, ddg_dump.dump_ddg, "DDG", program)


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
            dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, pattern) for pattern in args.exclude)]
            files.extend(Path(root) / f for f in filenames if should_include(Path(root) / f))
        return sorted(files)
    else:
        return sorted(item for item in directory.iterdir() if item.is_file() and should_include(item))


def create_interface_from_paths(python_files, args):
    """Create a basic interface from multiple Python files using dependency resolver."""
    from pyflow.application import interface
    from pyflow.frontend.dependency_resolver import DependencyResolver

    interface_decl = interface.InterfaceDeclaration()
    all_source_code = {}

    resolver = DependencyResolver(
        strategy=getattr(args, 'dependency_strategy', 'auto'),
        verbose=args.verbose,
        safe_modules=['math', 'os', 'sys', 're', 'json', 'datetime', 'collections']
    )

    for file_path in python_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
            all_source_code[str(file_path)] = source

            functions = resolver.extract_functions(source, str(file_path))

            for func_name, func_obj in functions.items():
                interface_decl.func.append((func_obj, []))
                if args.verbose:
                    print(f"Added function '{func_name}' from {file_path}")

        except Exception as e:
            if args.verbose:
                print(f"Warning: Could not parse file {file_path}: {e}")

    return interface_decl, all_source_code


def run_ir_dump(input_path: Path, args):
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
            print(f"Error: '{input_path}' is neither a file nor a directory", file=sys.stderr)
            sys.exit(1)

        console = Console(verbose=args.verbose)
        compiler = CompilerContext(console)
        program = Program()
        program.interface, all_source_code = create_interface_from_paths(python_files, args)
        compiler.extractor = Extractor(compiler, verbose=args.verbose, source_code=all_source_code)

        with console.scope("extraction"):
            extractProgram(compiler, program)

        if program.liveCode:
            print(f"Created {len(program.liveCode)} entry points from {len(program.liveCode)} functions")
        elif program.interface.func:
            print(f"Created {len(program.interface.entryPoint)} entry points from {len(program.interface.func)} functions")

        # Skip analysis pipeline for AST/CFG/CDG/DDG dumping since it clears AST blocks
        if not (args.dump_ast or args.dump_cfg or args.dump_cdg or args.dump_ddg):
            with console.scope("analysis"):
                evaluate(compiler, program, str(input_path))

        liveCode = program.liveCode if program.liveCode else findLiveCode(program)[0]
        output_dir = args.dump_output or "."

        success = True
        dump_functions = {'dump_ast': dump_ast, 'dump_cfg': dump_cfg, 'dump_ssa': dump_ssa, 'dump_cdg': dump_cdg_func, 'dump_ddg': dump_ddg}

        for dump_arg, dump_func in dump_functions.items():
            if hasattr(args, dump_arg) and getattr(args, dump_arg):
                if not dump_func(compiler, liveCode, getattr(args, dump_arg), output_dir, args.dump_format, program):
                    success = False

        if success:
            print("IR dumping complete!")
        else:
            print("IR dumping completed with errors")
            sys.exit(1)

    except Exception as e:
        print(f"Error during IR dumping: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)