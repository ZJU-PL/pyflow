"""CLI module for running optimization passes on Python code."""

import sys
import os
import fnmatch
from pathlib import Path

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.application.pipeline import Pipeline
from pyflow.frontend.programextractor import extractProgram
from pyflow.util.application.console import Console

# Constants
OPTIMIZATION_PASSES = {
    "methodcall": "Fuse method calls and optimize method dispatch",
    "lifetime": "Lifetime analysis for variables and objects",
    "simplify": "Constant folding and dead code elimination",
    "clone": "Separate different invocations of the same code",
    "argumentnormalization": "Specialize eligible *args when existing callers are positional-compatible",
    "inlining": "Inline function calls where beneficial (experimental)",
    "cullprogram": "Remove dead functions and contexts",
    "loadelimination": "Eliminate redundant load operations",
    "storeelimination": "Eliminate redundant store operations",
    "dce": "Dead code elimination",
}

OPT_PASS_ALIASES = {
    "argument_normalization": "argumentnormalization",
    "cull_program": "cullprogram",
    "load_elimination": "loadelimination",
    "store_elimination": "storeelimination",
}

ANALYSIS_MODULES = {
    "cpa": ("pyflow.analysis.cpa", "evaluate"),
    "ipa": ("pyflow.analysis.ipa", "evaluate"),
    "shape": ("pyflow.analysis.shape", "evaluate"),
    "lifetime": ("pyflow.analysis.lifetimeanalysis", "evaluate"),
}


def add_optimize_parser(subparsers):
    """Add optimization subcommand parser."""
    parser = subparsers.add_parser(
        "optimize", help="Run static analysis and optimization"
    )

    # Input/Output options
    parser.add_argument(
        "input_path", nargs="?", help="Python file, directory, or library to optimize"
    )
    parser.add_argument(
        "--output", "-o", help="Output file for dumped analysis results"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--dump", "-d", action="store_true", help="Dump analysis results"
    )
    parser.add_argument(
        "--dump-ipa", action="store_true", help="Dump IPA analysis results"
    )
    parser.add_argument(
        "--dump-shape", action="store_true", help="Dump Shape analysis results"
    )

    # Analysis options
    parser.add_argument(
        "--analysis",
        "-a",
        choices=["all", "cpa", "ipa", "shape", "lifetime"],
        default="all",
        help="Analysis type (default: all)",
    )
    parser.add_argument(
        "--dependency-strategy",
        choices=["auto", "stubs", "noop", "strict", "ast_only"],
        default="auto",
        help="Dependency handling strategy",
    )

    # File discovery options
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Recursively analyze subdirectories",
    )
    parser.add_argument("--exclude", nargs="*", default=[], help="Exclude patterns")
    parser.add_argument(
        "--include", nargs="*", default=["*.py"], help="Include patterns"
    )

    # Optimization options
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--suggest-only",
        action="store_true",
        help="Generate optimization suggestions without running transforming passes",
    )
    mode_group.add_argument(
        "--apply-optimizations",
        action="store_true",
        help="Explicitly run optimization passes (also the default behavior)",
    )
    parser.add_argument(
        "--experimental-inlining",
        action="store_true",
        help="Enable the experimental and potentially unsafe inlining pass",
    )
    parser.add_argument("--opt-passes", nargs="*", help="Specific optimization passes")
    parser.add_argument(
        "--list-opt-passes", action="store_true", help="List available passes"
    )
    parser.add_argument("--no-opt-passes", action="store_true", help="Analysis only")

    return parser


def list_optimization_passes():
    """List all available optimization passes."""
    print("Available optimization passes:")
    for name, desc in OPTIMIZATION_PASSES.items():
        print(f"  {name:<25} - {desc}")
    print("  all".ljust(27) + "- Run the full default optimization pipeline")


def _build_analysis_state(python_files, args):
    """Create compiler/program state for one analysis run."""
    console = Console(verbose=args.verbose)
    compiler = CompilerContext(console)
    program = Program()

    from pyflow.frontend.programextractor import create_interface_from_paths, Extractor

    program.interface, all_source_code = create_interface_from_paths(python_files, args)
    compiler.extractor = Extractor(
        compiler, verbose=args.verbose, source_code=all_source_code
    )

    with console.scope("extraction"):
        extractProgram(compiler, program)

    return compiler, program


def _run_default_pipeline(
    compiler, program, name, *, include_experimental_inlining: bool = False
):
    """Run the default optimization pipeline through the pass manager."""
    return Pipeline(use_pass_manager=True).run(
        program,
        compiler=compiler,
        name=name,
        include_experimental_inlining=include_experimental_inlining,
    )


def _normalize_opt_pass_name(pass_name):
    """Normalize CLI pass names to the pass-manager registry."""
    return OPT_PASS_ALIASES.get(pass_name, pass_name)


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

        compiler, program = _build_analysis_state(python_files, args)
        console = compiler.console

        if not program.interface.func:
            print("Warning: No functions found in interface")
            return

        # Run analysis based on mode
        with console.scope("analysis"):
            if args.analysis == "all":
                apply_mode = getattr(args, "apply_optimizations", False)
                if getattr(args, "no_opt_passes", False):
                    run_analysis_only(compiler, program)
                elif getattr(args, "suggest_only", False):
                    suggestion_compiler, suggestion_program = _build_analysis_state(
                        python_files, args
                    )
                    run_suggestions(suggestion_compiler, suggestion_program)
                    if args.dump or args.dump_ipa or args.dump_shape:
                        run_analysis_only(compiler, program)
                elif getattr(args, "opt_passes", None):
                    run_optimization_passes(compiler, program, args.opt_passes, args)
                else:
                    # Optimization is the default mode, and --apply-optimizations
                    # is an explicit spelling of the same behavior.
                    _run_default_pipeline(
                        compiler,
                        program,
                        str(input_path),
                        include_experimental_inlining=getattr(
                            args, "experimental_inlining", False
                        ),
                    )
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
            dirs[:] = [
                d for d in dirs if not any(fnmatch.fnmatch(d, p) for p in args.exclude)
            ]
            files.extend(
                Path(root) / f for f in filenames if should_include(Path(root) / f)
            )
        return sorted(files)
    else:
        return sorted(
            f for f in directory.iterdir() if f.is_file() and should_include(f)
        )


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

        if analysis_type == "ipa" and not (
            hasattr(program, "ipa_analysis") and program.ipa_analysis
        ):
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
            if analysis_result and hasattr(analysis_result, "contexts"):
                setattr(program, f"{analysis_type}_analysis", analysis_result)


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
        from pyflow.analysis import ipa as ipa_module

        if not (hasattr(program, "ipa_analysis") and program.ipa_analysis):
            result = ipa_module.evaluate(compiler, program)
            if result:
                program.ipa_analysis = result

        if not (hasattr(program, "ipa_analysis") and program.ipa_analysis):
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
        if not (hasattr(program, "shape_analysis") and program.shape_analysis):
            print("Shape analysis results not available for dumping")
            return

        output_path = get_output_path(output_file, input_path, "shape_results")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Capture statistics output to file
        import io
        from contextlib import redirect_stdout

        with redirect_stdout(io.StringIO()) as output_buffer:
            program.shape_analysis.dumpStatistics()

        with open(output_path, "w") as f:
            f.write(output_buffer.getvalue())

        print(f"Shape analysis results dumped to: {output_path}")
    except Exception as e:
        print(f"Warning: Could not dump shape results: {e}")


def get_output_path(output_file, input_path, default_suffix):
    """Get output path for dumping results."""
    if output_file:
        return Path(output_file)
    return (
        input_path.with_suffix(f".{default_suffix}")
        if input_path.is_file()
        else input_path / default_suffix
    )


def dump_results(compiler, program, input_path, output_file):
    """Dump analysis results to files."""
    try:
        from pyflow.analysis.dump import dumpreport

        output_path = (
            Path(output_file)
            if output_file
            else (
                input_path.with_suffix(".analysis")
                if input_path.is_file()
                else input_path / "analysis_results"
            )
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        dumpreport.evaluate(compiler, program, str(output_path))
        print(f"Results dumped to: {output_path}")
    except Exception as e:
        print(f"Warning: Could not dump results: {e}")


def run_analysis_only(compiler, program):
    """Run only analysis passes, no optimization."""
    with compiler.console.scope("analysis-only"):
        Pipeline(use_pass_manager=True).run_custom_pipeline(
            compiler, program, ["ipa", "cpa", "lifetime"]
        )
        compiler.console.output("Analysis-only mode completed")


def run_suggestions(compiler, program):
    """Run analysis and optimization passes, report what optimizations were found."""
    from pyflow.analysis import cpa, lifetimeanalysis, ipa
    from pyflow.optimization import (
        methodcall,
        simplify,
        clone,
        argumentnormalization,
        cullprogram,
        storeelimination,
    )

    suggestions = {
        "Dead Functions Removed": [],
        "Constant Folding": [],
        "Code Cloning/Specialization": [],
        "Argument Normalization": [],
        "Type Analysis": [],
        "Method Call Optimizations": [],
    }

    with compiler.console.scope("suggestions"):
        # Run full IPA analysis first
        ipa_result = ipa.evaluate(compiler, program)
        if ipa_result:
            program.ipa_analysis = ipa_result

        # Capture initial metrics
        initial_code_count = len(getattr(program, "liveCode", []))
        initial_contexts = (
            len(program.ipa_analysis.contexts)
            if hasattr(program, "ipa_analysis") and program.ipa_analysis
            else 0
        )
        initial_funcs = set()
        for code in getattr(program, "liveCode", []):
            if code and hasattr(code, "name") and code.name:
                initial_funcs.add(code.name)

        # Run CPA analysis
        cpa_result = cpa.evaluate(compiler, program)
        program.cpa_analysis = cpa_result

        # Run lifetime analysis
        lifetime_analysis = lifetimeanalysis.evaluate(compiler, program)
        program.lifetime_analysis = lifetime_analysis

        # Analyze functions for *args/**kwargs BEFORE normalization
        funcs_with_varargs = []
        funcs_with_kwargs = []
        for code in getattr(program, "liveCode", []):
            if code and hasattr(code, "ast") and code.ast:
                ast = code.ast
                func_name = getattr(code, "name", None)
                if hasattr(ast, "args") and ast.args:
                    if getattr(ast.args, "vararg", None):
                        funcs_with_varargs.append(func_name)
                    if getattr(ast.args, "kwarg", None):
                        funcs_with_kwargs.append(func_name)

        # Capture initial context count for clone analysis
        contexts_before_clone = (
            len(program.ipa_analysis.contexts)
            if hasattr(program, "ipa_analysis") and program.ipa_analysis
            else 0
        )

        # Run optimization passes one by one
        with compiler.console.scope("analyzing"):
            # Method call optimization
            methodcall.evaluate(compiler, program)

            # Simplification (constant folding, dead code elimination)
            simplify.evaluate(compiler, program)

            # Code cloning (specialization)
            clone.evaluate(compiler, program)

            # Argument normalization
            argumentnormalization.evaluate(compiler, program)

            # Program culling (dead function elimination)
            cullprogram.evaluate(compiler, program)

            # Store elimination
            storeelimination.evaluate(compiler, program)

        refreshed_ipa = ipa.evaluate(compiler, program)
        if refreshed_ipa:
            program.ipa_analysis = refreshed_ipa

        # Capture final metrics
        final_code_count = len(getattr(program, "liveCode", []))
        final_funcs = set()
        for code in getattr(program, "liveCode", []):
            if code and hasattr(code, "name") and code.name:
                final_funcs.add(code.name)

        contexts_after_clone = (
            len(program.ipa_analysis.contexts)
            if hasattr(program, "ipa_analysis") and program.ipa_analysis
            else 0
        )

        # Find removed functions
        removed_funcs = initial_funcs - final_funcs

        # Report findings
        if removed_funcs:
            for func in sorted(removed_funcs):
                suggestions["Dead Functions Removed"].append(f"  - {func}")

        # Clone pass: creates specialized contexts (code units)
        if final_code_count > initial_code_count:
            added = final_code_count - initial_code_count
            suggestions["Code Cloning/Specialization"].append(
                f"  Clone pass created {added} specialized context(s)"
            )

        # Argument issues
        if funcs_with_varargs:
            suggestions["Argument Normalization"].append(
                f"  Functions with *args: {', '.join(funcs_with_varargs)}"
            )
        if funcs_with_kwargs:
            suggestions["Argument Normalization"].append(
                f"  Functions with **kwargs: {', '.join(funcs_with_kwargs)}"
            )

        # Check for unresolved calls (type hints needed)
        if hasattr(program, "cpa_analysis") and program.cpa_analysis:
            if hasattr(program.cpa_analysis, "unresolved"):
                unresolved = getattr(program.cpa_analysis, "unresolved", [])
                unresolved_count = (
                    len(unresolved) if isinstance(unresolved, list) else 0
                )
                if unresolved_count > 0:
                    suggestions["Type Analysis"].append(
                        f"  {unresolved_count} unresolved calls - add type hints for better precision"
                    )

        # Method call optimizations
        if hasattr(program, "liveCode") and len(program.liveCode) > 0:
            has_method_calls = False
            for code in program.liveCode:
                if code and hasattr(code, "ast") and code.ast:
                    # Check for method calls in AST
                    pass
            if has_method_calls:
                suggestions["Method Call Optimizations"].append(
                    "  Method call patterns detected - methodcall optimization available"
                )

        # Print results
        print("\n" + "=" * 60)
        print("OPTIMIZATION ANALYSIS RESULTS")
        print("=" * 60)
        print(
            f"\nInitial: {initial_code_count} functions, {contexts_before_clone} contexts"
        )
        print(f"After:   {final_code_count} functions, {contexts_after_clone} contexts")

        has_suggestions = False
        for category, items in suggestions.items():
            if items:
                has_suggestions = True
                print(f"\n{category}:")
                for item in items:
                    print(item)

        if not has_suggestions:
            print("\nNo optimization opportunities found.")

        contexts_added = max(0, final_code_count - initial_code_count)
        print(
            f"\n✓ Summary: {len(removed_funcs)} dead functions removed, {contexts_added} contexts added"
        )
        print("=" * 60)
        compiler.console.output("Suggestion mode completed")


def run_optimization_passes(compiler, program, passes, args=None):
    """Run specific optimization passes."""
    with compiler.console.scope("specific-passes"):
        normalized = [_normalize_opt_pass_name(pass_name) for pass_name in passes]

        if "all" in normalized:
            _run_default_pipeline(
                compiler,
                program,
                "cli_optimize_all",
                include_experimental_inlining=(
                    args is not None and getattr(args, "experimental_inlining", False)
                ),
            )
            compiler.console.output("Completed full optimization pipeline")
            return

        if "inlining" in normalized and not (
            args is not None and getattr(args, "experimental_inlining", False)
        ):
            print(
                "Warning: Skipping 'inlining' pass. "
                "Use --experimental-inlining to enable it."
            )
            normalized = [pass_name for pass_name in normalized if pass_name != "inlining"]

        if not normalized:
            compiler.console.output("No optimization passes selected")
            return

        Pipeline(use_pass_manager=True).run_custom_pipeline(
            compiler, program, normalized
        )
        compiler.console.output(f"Completed {len(normalized)} optimization passes")
