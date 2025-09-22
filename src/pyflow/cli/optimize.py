"""
Running optimization passes on Python code.
"""

import sys
import os
import fnmatch
import argparse
from pathlib import Path

from pyflow.application.context import CompilerContext, Context
from pyflow.application.program import Program
from pyflow.application.pipeline import evaluate
from pyflow.frontend.programextractor import extractProgram
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
        from pyflow.frontend.programextractor import Extractor

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

        # Dumping functionality has been removed to keep this file concise

        # Run analysis
        with console.scope("analysis"):
            if args.analysis == "all":
                if getattr(args, "no_passes", False):
                    run_analysis_only(compiler, program)
                elif getattr(args, "passes", None):
                    run_optimization_passes(compiler, program, args.passes)
                else:
                    evaluate(compiler, program, str(input_path))
            else:
                run_analysis_passes(compiler, program, args.analysis)

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


def run_analysis_passes(compiler, program, analysis_type):
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
        func = getattr(module, func_name)
        # Shape analysis needs full pipeline to be run first
        if analysis_type == "shape":
            # Run the full analysis pipeline first
            from pyflow.application.pipeline import evaluate as pipeline_evaluate
            pipeline_evaluate(compiler, program, "shape_analysis")
            print("Shape analysis completed as part of full pipeline")
        else:
            func(compiler, program)
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


def run_analysis_only(compiler, program):
    """Run only analysis passes, no optimization."""
    from pyflow.analysis import cpa, ipa, lifetimeanalysis

    with compiler.console.scope("analysis-only"):
        # Run core analysis passes
        cpa.evaluate(compiler, program)
        lifetimeanalysis.evaluate(compiler, program)

        compiler.console.output("Analysis-only mode completed")


def run_optimization_passes(compiler, program, passes):
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
