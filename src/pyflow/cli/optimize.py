"""CLI module for running optimization passes on Python code."""

import sys
import os
import fnmatch
from pathlib import Path

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.application.pipeline import evaluate
from pyflow.frontend.programextractor import extractProgram
from pyflow.util.application.console import Console

# Constants
OPTIMIZATION_PASSES = {
    "methodcall": "Fuse method calls and optimize method dispatch",
    "lifetime": "Lifetime analysis for variables and objects",
    "simplify": "Constant folding and dead code elimination",
    "clone": "Separate different invocations of the same code",
    "argumentnormalization": "Normalize function arguments (eliminate *args, **kwargs)",
    "inlining": "Inline function calls where beneficial",
    "cullprogram": "Remove dead functions and contexts",
    "loadelimination": "Eliminate redundant load operations",
    "storeelimination": "Eliminate redundant store operations",
    "dce": "Dead code elimination",
}

ANALYSIS_MODULES = {
    "cpa": ("pyflow.analysis.cpa", "evaluate"),
    "ipa": ("pyflow.analysis.ipa", "evaluate"),
    "shape": ("pyflow.analysis.shape", "evaluate"),
    "lifetime": ("pyflow.analysis.lifetimeanalysis", "evaluate"),
}


def add_optimize_parser(subparsers):
    """Add optimization subcommand parser."""
    parser = subparsers.add_parser("optimize", help="Run static analysis and optimization")

    # Input/Output options
    parser.add_argument("input_path", nargs="?", help="Python file, directory, or library to optimize")
    parser.add_argument("--output", "-o", help="Output file for results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--dump", "-d", action="store_true", help="Dump analysis results")
    parser.add_argument("--dump-ipa", action="store_true", help="Dump IPA analysis results")
    parser.add_argument("--dump-shape", action="store_true", help="Dump Shape analysis results")

    # Analysis options
    parser.add_argument("--analysis", "-a", choices=["all", "cpa", "ipa", "shape", "lifetime"],
                       default="all", help="Analysis type (default: all)")
    parser.add_argument("--dependency-strategy",
                       choices=["auto", "stubs", "noop", "strict", "ast_only"],
                       default="auto", help="Dependency handling strategy")

    # File discovery options
    parser.add_argument("--recursive", "-r", action="store_true", help="Recursively analyze subdirectories")
    parser.add_argument("--exclude", nargs="*", default=[], help="Exclude patterns")
    parser.add_argument("--include", nargs="*", default=["*.py"], help="Include patterns")

    # Optimization options
    parser.add_argument("--opt-passes", nargs="*", help="Specific optimization passes")
    parser.add_argument("--list-opt-passes", action="store_true", help="List available passes")
    parser.add_argument("--no-opt-passes", action="store_true", help="Analysis only")

    return parser


def list_optimization_passes():
    """List all available optimization passes."""
    print("Available optimization passes:")
    for name, desc in OPTIMIZATION_PASSES.items():
        print(f"  {name:<25} - {desc}")

    
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
            print(f"Error: '{input_path}' is neither a file nor a directory", file=sys.stderr)
            sys.exit(1)

        # Setup compiler and program
        console = Console(verbose=args.verbose)
        compiler = CompilerContext(console)
        program = Program()

        # Extract program
        from pyflow.frontend.programextractor import create_interface_from_paths, Extractor
        program.interface, all_source_code = create_interface_from_paths(python_files, args)
        compiler.extractor = Extractor(compiler, verbose=args.verbose, source_code=all_source_code)

        with console.scope("extraction"):
            extractProgram(compiler, program)

        if not program.interface.func:
            print("Warning: No functions found in interface")
            return

        # Run analysis based on type
        with console.scope("analysis"):
            if args.analysis == "all":
                if getattr(args, "no_opt_passes", False):
                    run_analysis_only(compiler, program)
                elif getattr(args, "opt_passes", None):
                    run_optimization_passes(compiler, program, args.opt_passes)
                else:
                    evaluate(compiler, program, str(input_path))
            elif args.analysis == "ipa":
                # Run only IPA analysis (skip CPA and later passes)
                from pyflow.analysis import ipa as ipa_module
                with console.scope("ipa-only"):
                    result = ipa_module.evaluate(compiler, program)
                    if result:
                        program.ipa_analysis = result
            else:
                run_analysis_passes(compiler, program, args.analysis)

        # Handle result dumping
        if args.dump_ipa:
            dump_ipa_results(compiler, program, input_path, args.output)
        elif args.dump_shape:
            dump_shape_results(compiler, program, input_path, args.output)
        elif args.dump:
            dump_results(compiler, program, input_path, args.output)

        print("Analysis complete!")

    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def find_python_files(directory, args):
    """Find Python files based on include/exclude patterns."""
    def should_include(file_path):
        if file_path.suffix != ".py":
            return False
        name = file_path.name
        include_match = any(fnmatch.fnmatch(name, p) for p in args.include)
        exclude_match = any(fnmatch.fnmatch(name, p) for p in args.exclude)
        return include_match and not exclude_match

    if args.recursive:
        files = []
        for root, dirs, filenames in os.walk(directory):
            dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, p) for p in args.exclude)]
            files.extend(Path(root) / f for f in filenames if should_include(Path(root) / f))
        return sorted(files)
    else:
        return sorted(f for f in directory.iterdir() if f.is_file() and should_include(f))





def run_analysis_passes(compiler, program, analysis_type):
    """Run a specific type of analysis."""
    if analysis_type not in ANALYSIS_MODULES:
        print(f"Unknown analysis type: {analysis_type}")
        return

    # For IPA and Shape analysis, run the full pipeline to ensure proper setup
    if analysis_type in ["ipa", "shape"]:
        from pyflow.application.pipeline import evaluate as pipeline_evaluate
        pipeline_evaluate(compiler, program, f"dummy_{analysis_type}")
        print(f"{analysis_type.upper()} analysis completed as part of full pipeline")

        if analysis_type == "ipa" and not (hasattr(program, 'ipa_analysis') and program.ipa_analysis):
            print("Warning: IPA analysis results not available from pipeline run")
    else:
        module_name, func_name = ANALYSIS_MODULES[analysis_type]
        module = __import__(module_name, fromlist=[func_name])
        func = getattr(module, func_name)

        if analysis_type == "shape":
            from pyflow.application.pipeline import evaluate as pipeline_evaluate
            pipeline_evaluate(compiler, program, "shape_analysis")
        else:
            # Store analysis result in program for later dumping
            analysis_result = func(compiler, program)
            if analysis_result and hasattr(analysis_result, 'contexts'):
                setattr(program, f'{analysis_type}_analysis', analysis_result)


def dump_specific_results(compiler, program, input_path, args):
    """Dump specific analysis results (IPA, Shape) to files."""
    try:
        if args.dump_ipa:
            dump_ipa_results(compiler, program, input_path, args.output)
        if args.dump_shape:
            dump_shape_results(compiler, program, input_path, args.output)
    except Exception as e:
        print(f"Warning: Could not dump specific results: {e}")


def dump_ipa_results(compiler, program, input_path, output_file):
    """Dump IPA analysis results."""
    try:
        from pyflow.analysis.ipa.dump import Dumper

        if not (hasattr(program, 'ipa_analysis') and program.ipa_analysis):
            print("IPA analysis results not available for dumping")
            return

        output_path = get_output_path(output_file, input_path, "ipa_results")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        dumper = Dumper(str(output_path))
        dumper.index(program.ipa_analysis.contexts.values(), program.ipa_analysis.root)

        for context in program.ipa_analysis.contexts.values():
            dumper.dumpContext(context)

        print(f"IPA analysis results dumped to: {output_path}")
    except Exception as e:
        print(f"Warning: Could not dump IPA results: {e}")


def dump_shape_results(compiler, program, input_path, output_file):
    """Dump Shape analysis results."""
    try:
        if not (hasattr(program, 'shape_analysis') and program.shape_analysis):
            print("Shape analysis results not available for dumping")
            return

        output_path = get_output_path(output_file, input_path, "shape_results")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Capture statistics output to file
        import io
        from contextlib import redirect_stdout

        with redirect_stdout(io.StringIO()) as output_buffer:
            program.shape_analysis.dumpStatistics()

        with open(output_path, 'w') as f:
            f.write(output_buffer.getvalue())

        print(f"Shape analysis results dumped to: {output_path}")
    except Exception as e:
        print(f"Warning: Could not dump shape results: {e}")


def get_output_path(output_file, input_path, default_suffix):
    """Get output path for dumping results."""
    if output_file:
        return Path(output_file)
    return input_path.with_suffix(f".{default_suffix}") if input_path.is_file() else input_path / default_suffix


def dump_results(compiler, program, input_path, output_file):
    """Dump analysis results to files."""
    try:
        from pyflow.analysis.dump import dumpreport

        output_path = Path(output_file) if output_file else (
            input_path.with_suffix(".analysis") if input_path.is_file()
            else input_path / "analysis_results"
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        dumpreport.evaluate(compiler, program, str(output_path))
        print(f"Results dumped to: {output_path}")
    except Exception as e:
        print(f"Warning: Could not dump results: {e}")


def run_analysis_only(compiler, program):
    """Run only analysis passes, no optimization."""
    from pyflow.analysis import cpa, lifetimeanalysis

    with compiler.console.scope("analysis-only"):
        cpa.evaluate(compiler, program)
        lifetimeanalysis.evaluate(compiler, program)
        compiler.console.output("Analysis-only mode completed")


def run_optimization_passes(compiler, program, passes):
    """Run specific optimization passes."""
    from pyflow.analysis import cpa, lifetimeanalysis
    from pyflow.optimization import (
        methodcall, simplify, clone, argumentnormalization,
        codeinlining, cullprogram, loadelimination, storeelimination
    )

    with compiler.console.scope("specific-passes"):
        cpa.evaluate(compiler, program)
        lifetimeanalysis.evaluate(compiler, program)

        pass_map = {
            "methodcall": methodcall.evaluate,
            "lifetime": lambda c, p: None,
            "simplify": simplify.evaluate,
            "clone": clone.evaluate,
            "argumentnormalization": argumentnormalization.evaluate,
            "inlining": codeinlining.evaluate,
            "cullprogram": cullprogram.evaluate,
            "loadelimination": loadelimination.evaluate,
            "storeelimination": storeelimination.evaluate,
            "dce": lambda c, p: None,
        }

        for pass_name in passes:
            if pass_name in pass_map:
                with compiler.console.scope(pass_name):
                    pass_map[pass_name](compiler, program)
            else:
                print(f"Warning: Unknown pass '{pass_name}'")

        compiler.console.output(f"Completed {len(passes)} optimization passes")
