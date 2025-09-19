"""Analysis CLI tool for PyFlow."""

import sys
import os
import fnmatch
import argparse
from pathlib import Path

from pyflow.application.context import CompilerContext, Context
from pyflow.application.program import Program
from pyflow.application.pipeline import evaluate
from pyflow.analysis.programextractor import extractProgram
from pyflow.util.application.console import Console


def run_analysis(input_path, args):
    """Run PyFlow analysis on the input path (file or directory)."""
    try:
        # Get Python files to analyze
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

        # Setup
        console = Console(verbose=args.verbose)
        compiler = CompilerContext(console)
        program = Program()
        program.interface, all_source_code = create_interface_from_paths(
            python_files, args
        )

        # Initialize extractor
        from pyflow.analysis.programextractor import Extractor

        compiler.extractor = Extractor(
            compiler, verbose=args.verbose, source_code=all_source_code
        )

        # Extract and analyze
        with console.scope("extraction"):
            extractProgram(compiler, program)

        program.interface.translate(compiler.extractor)
        if program.interface.func:
            print(
                f"Created {len(program.interface.entryPoint)} entry points from {len(program.interface.func)} functions"
            )

        # Handle dumping before analysis
        if hasattr(args, "dump_ast") and args.dump_ast:
            dump_for_function(compiler, program, args.dump_ast, "ast", args)
        if hasattr(args, "dump_cfg") and args.dump_cfg:
            dump_for_function(compiler, program, args.dump_cfg, "cfg", args)

        # Run analysis
        with console.scope("analysis"):
            if args.analysis == "all":
                if getattr(args, "no_passes", False):
                    run_analysis_only(compiler, program)
                elif getattr(args, "passes", None):
                    run_specific_passes(compiler, program, args.passes)
                else:
                    evaluate(compiler, program, str(input_path))
            else:
                run_specific_analysis(compiler, program, args.analysis)

        # Dump results if requested
        if args.dump:
            dump_results(compiler, program, input_path, args.output)

        print("Analysis complete!")

    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


def find_python_files(directory, args):
    """Find Python files in a directory based on include/exclude patterns."""
    python_files = []

    def should_include(file_path):
        if file_path.suffix != ".py":
            return False
        filename = file_path.name
        include_match = any(
            fnmatch.fnmatch(filename, pattern) for pattern in args.include
        )
        exclude_match = any(
            fnmatch.fnmatch(filename, pattern) for pattern in args.exclude
        )
        return include_match and not exclude_match

    if args.recursive:
        for root, dirs, files in os.walk(directory):
            dirs[:] = [
                d
                for d in dirs
                if not any(fnmatch.fnmatch(d, pattern) for pattern in args.exclude)
            ]
            for file in files:
                file_path = Path(root) / file
                if should_include(file_path):
                    python_files.append(file_path)
    else:
        for item in directory.iterdir():
            if item.is_file() and should_include(item):
                python_files.append(item)

    return sorted(python_files)


def create_interface_from_paths(python_files, args):
    """Create a basic interface from multiple Python files."""
    from pyflow.application import interface

    # Create interface declaration
    interface_decl = interface.InterfaceDeclaration()
    all_source_code = {}

    for file_path in python_files:
        try:
            # Read the file
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()

            all_source_code[str(file_path)] = source

            # Create a module namespace
            module_globals = {}
            exec(source, module_globals)

            # Find all function objects
            for name, obj in module_globals.items():
                if callable(obj) and not name.startswith("_"):
                    # Add function to interface with empty argument list for now
                    # In a real implementation, you'd want to specify actual arguments
                    interface_decl.func.append((obj, []))
                    if args.verbose:
                        print(f"Added function '{name}' from {file_path}")

        except Exception as e:
            if args.verbose:
                print(f"Warning: Could not parse file {file_path}: {e}")

    return interface_decl, all_source_code


def run_specific_analysis(compiler, program, analysis_type):
    """Run a specific type of analysis."""
    analysis_modules = {
        "cpa": ("pyflow.analysis.cpa", "evaluate"),
        "ipa": ("pyflow.analysis.ipa", "evaluate"),
        "shape": ("pyflow.analysis.shape", "evaluate"),
        "lifetime": ("pyflow.analysis.lifetimeanalysis", "evaluate"),
    }

    if analysis_type in analysis_modules:
        module_name, func_name = analysis_modules[analysis_type]
        module = __import__(module_name, fromlist=[func_name])
        getattr(module, func_name)(compiler, program)
    else:
        print(f"Unknown analysis type: {analysis_type}")


def dump_results(compiler, program, input_path, output_file):
    """Dump analysis results to files."""
    try:
        from pyflow.analysis.dump import dumpreport

        if output_file:
            output_path = Path(output_file)
        else:
            if input_path.is_file():
                output_path = input_path.with_suffix(".analysis")
            else:
                output_path = input_path / "analysis_results"

        # Create output directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Dump the report
        dumpreport.evaluate(compiler, program, str(output_path))
        print(f"Results dumped to: {output_path}")

    except Exception as e:
        print(f"Warning: Could not dump results: {e}")


def dump_for_function(compiler, program, function_name, dump_type, args):
    """Dump AST or CFG for a specific function."""
    try:
        # Find the function in the program
        target_func = next(
            (
                func[0]
                for func in program.interface.func
                if hasattr(func[0], "__name__") and func[0].__name__ == function_name
            ),
            None,
        )

        if not target_func:
            print(f"Warning: Function '{function_name}' not found")
            return

        # Get output directory
        dump_output = getattr(args, "dump_output", None)
        output_dir = Path(dump_output) if dump_output else Path.cwd()
        output_dir.mkdir(parents=True, exist_ok=True)

        # Get the data based on dump type
        if dump_type == "ast":
            # Get AST data
            data = get_ast_for_function(target_func, compiler)
        elif dump_type == "cfg":
            # Get CFG data using existing CFG infrastructure
            data = get_cfg_for_function(target_func, compiler)
        else:
            print(f"Warning: Unknown dump type '{dump_type}'")
            return

        if data:
            dump_format = getattr(args, "dump_format", "text")
            output_file = output_dir / f"{function_name}_{dump_type}.{dump_format}"

            dump_functions = {
                "ast": {
                    "text": dump_ast_text,
                    "dot": dump_ast_dot,
                    "json": dump_ast_json,
                },
                "cfg": {
                    "text": dump_cfg_text,
                    "dot": dump_cfg_dot,
                    "json": dump_cfg_json,
                },
            }

            if dump_format in dump_functions[dump_type]:
                dump_functions[dump_type][dump_format](data, output_file)
                print(
                    f"{dump_type.upper()} dumped for function '{function_name}' to: {output_file}"
                )
            else:
                print(f"Warning: Unknown dump format '{dump_format}'")
        else:
            print(
                f"Warning: Could not find {dump_type.upper()} for function '{function_name}'"
            )

    except Exception as e:
        print(f"Error dumping {dump_type.upper()} for function '{function_name}': {e}")


def run_analysis_only(compiler, program):
    """Run only analysis passes, no optimization."""
    from pyflow.analysis import cpa, ipa, lifetimeanalysis

    with compiler.console.scope("analysis-only"):
        # Run core analysis passes
        cpa.evaluate(compiler, program)
        lifetimeanalysis.evaluate(compiler, program)

        compiler.console.output("Analysis-only mode completed")


def run_specific_passes(compiler, program, passes):
    """Run specific optimization passes."""
    from pyflow.analysis import cpa, lifetimeanalysis
    from pyflow.optimization import (
        methodcall,
        simplify,
        clone,
        argumentnormalization,
        codeinlining,
        cullprogram,
        loadelimination,
        storeelimination,
    )

    with compiler.console.scope("specific-passes"):
        # Always run CPA and lifetime analysis first
        cpa.evaluate(compiler, program)
        lifetimeanalysis.evaluate(compiler, program)

        # Map pass names to functions
        pass_map = {
            "methodcall": methodcall.evaluate,
            "lifetime": lambda c, p: None,  # Already run above
            "simplify": simplify.evaluate,
            "clone": clone.evaluate,
            "argumentnormalization": argumentnormalization.evaluate,
            "inlining": codeinlining.evaluate,
            "cullprogram": cullprogram.evaluate,
            "loadelimination": loadelimination.evaluate,
            "storeelimination": storeelimination.evaluate,
            "dce": lambda c, p: None,  # DCE is integrated into simplify
        }

        # Run requested passes
        for pass_name in passes:
            if pass_name in pass_map:
                with compiler.console.scope(pass_name):
                    pass_map[pass_name](compiler, program)
            else:
                print(f"Warning: Unknown pass '{pass_name}'")

        compiler.console.output(f"Completed {len(passes)} optimization passes")


# Dumping helper functions
def dump_ast_text(code, output_file):
    """Dump AST in text format."""
    import ast

    with open(output_file, "w") as f:
        f.write("Abstract Syntax Tree\n")
        f.write("===================\n\n")
        f.write(ast.dump(code, indent=2))


def dump_ast_dot(code, output_file):
    """Dump AST in DOT format (fallback to text)."""
    dump_ast_text(code, output_file.with_suffix(".txt"))


def dump_ast_json(code, output_file):
    """Dump AST in JSON format (fallback to text)."""
    dump_ast_text(code, output_file.with_suffix(".txt"))


def dump_cfg_text(cfg, output_file):
    """Dump CFG in text format."""
    with open(output_file, "w") as f:
        f.write("Control Flow Graph\n==================\n\n")
        f.write(str(cfg))


def dump_cfg_dot(cfg, output_file):
    """Dump CFG in DOT format."""
    try:
        from pyflow.analysis.cfg.dump import CFGToDot

        dumper = CFGToDot()
        dumper.process(cfg)
        with open(output_file, "w") as f:
            f.write(dumper.g.to_string())
    except Exception as e:
        print(f"Warning: Could not generate DOT format: {e}")
        dump_cfg_text(cfg, output_file.with_suffix(".txt"))


def dump_cfg_json(cfg, output_file):
    """Dump CFG in JSON format (fallback to text)."""
    dump_cfg_text(cfg, output_file.with_suffix(".txt"))


def get_ast_for_function(func, compiler):
    """Get AST data for a specific function."""
    try:
        import ast

        if hasattr(func, "__name__"):
            # Try to get source from the extractor's source_code first
            if hasattr(compiler, "extractor") and hasattr(
                compiler.extractor, "source_code"
            ):
                source_code = compiler.extractor.source_code
                if isinstance(source_code, dict):
                    # Multiple files - find the right one
                    for file_path, source in source_code.items():
                        tree = ast.parse(source)
                        for node in ast.walk(tree):
                            if (
                                isinstance(node, ast.FunctionDef)
                                and node.name == func.__name__
                            ):
                                return node
                elif isinstance(source_code, str):
                    # Single file
                    tree = ast.parse(source_code)
                    for node in ast.walk(tree):
                        if (
                            isinstance(node, ast.FunctionDef)
                            and node.name == func.__name__
                        ):
                            return node

            # Fallback to inspect if source_code not available
            import inspect

            try:
                source = inspect.getsource(func)
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name == func.__name__:
                        return node
            except OSError:
                pass  # inspect.getsource failed

        return None
    except Exception as e:
        print(f"Error getting AST for function {func}: {e}")
        return None


def get_cfg_for_function(func, compiler):
    """Get CFG data for a specific function - simplified approach."""
    try:
        import ast

        if hasattr(func, "__name__"):
            func_ast = None

            # Try to get source from the extractor's source_code first
            if hasattr(compiler, "extractor") and hasattr(
                compiler.extractor, "source_code"
            ):
                source_code = compiler.extractor.source_code
                if isinstance(source_code, dict):
                    # Multiple files - find the right one
                    for file_path, source in source_code.items():
                        tree = ast.parse(source)
                        for node in ast.walk(tree):
                            if (
                                isinstance(node, ast.FunctionDef)
                                and node.name == func.__name__
                            ):
                                func_ast = node
                                break
                        if func_ast:
                            break
                elif isinstance(source_code, str):
                    # Single file
                    tree = ast.parse(source_code)
                    for node in ast.walk(tree):
                        if (
                            isinstance(node, ast.FunctionDef)
                            and node.name == func.__name__
                        ):
                            func_ast = node
                            break

            # Fallback to inspect if source_code not available
            if func_ast is None:
                import inspect

                try:
                    source = inspect.getsource(func)
                    tree = ast.parse(source)
                    for node in ast.walk(tree):
                        if (
                            isinstance(node, ast.FunctionDef)
                            and node.name == func.__name__
                        ):
                            func_ast = node
                            break
                except OSError:
                    pass  # inspect.getsource failed

            if func_ast is None:
                return None

            # Create a simple CFG representation from the AST
            class SimpleCFG:
                def __init__(self, ast_node, func_name):
                    self.ast = ast_node
                    self.name = func_name
                    self.blocks = self._extract_blocks()

                def _extract_blocks(self):
                    """Extract basic blocks from the function AST."""
                    blocks = []
                    current_block = []

                    for node in ast.walk(self.ast):
                        if isinstance(node, ast.Return):
                            if current_block:
                                blocks.append(current_block)
                                current_block = []
                            blocks.append([node])
                        elif isinstance(node, (ast.If, ast.While, ast.For)):
                            if current_block:
                                blocks.append(current_block)
                                current_block = []
                            blocks.append([node])
                        elif isinstance(node, ast.Expr) and not isinstance(
                            node.value, (ast.If, ast.While, ast.For, ast.Return)
                        ):
                            current_block.append(node)

                    if current_block:
                        blocks.append(current_block)

                    return blocks

                def __str__(self):
                    """String representation of the CFG."""
                    result = f"Control Flow Graph for function '{self.name}'\n"
                    result += "=" * 50 + "\n\n"

                    for i, block in enumerate(self.blocks):
                        result += f"Block {i}:\n"
                        for node in block:
                            result += f"  {ast.dump(node, indent=2)}\n"
                        result += "\n"

                    return result

            cfg = SimpleCFG(func_ast, func.__name__)
            return cfg

        return None
    except Exception as e:
        print(f"Error getting CFG for function {func}: {e}")
        return None
