#!/usr/bin/env python3
"""
Pass Manager Demo for PyFlow

This example demonstrates how to use PyFlow's new LLVM-inspired pass manager system
for flexible composition and execution of analysis and optimization passes.

The pass manager provides:
- Pass registration with dependencies
- Automatic dependency resolution
- Caching and invalidation
- Pipeline construction and execution
- Standardized pass interfaces
"""

from pyflow.application.pipeline import Pipeline
from pyflow.application.passes.manager import PassManager
from pyflow.application.passes.base import AnalysisPass, OptimizationPass, PassResult, PassKind
from pyflow.application.passes.registry import register_standard_passes


def demo_basic_usage():
    """Demonstrate basic pass manager usage."""
    print("=== Basic Pass Manager Usage ===")

    # Create a pass manager
    pm = PassManager()

    # Register standard PyFlow passes
    register_standard_passes(pm)

    # List available passes
    print(f"Available passes: {pm.list_passes()}")

    # Get pass information
    cpa_info = pm.get_pass_info("cpa")
    print(f"CPA pass info: {cpa_info}")

    # Build a custom pipeline
    pipeline = pm.build_pipeline([
        "ipa",      # Inter-procedural analysis
        "cpa",      # Constraint propagation
        "simplify", # Simplification
    ])

    print(f"Custom pipeline: {[p for p in pipeline.passes]}")

    return pm


def demo_custom_pass():
    """Demonstrate creating and registering a custom pass."""
    print("\n=== Custom Pass Registration ===")

    class CustomAnalysisPass(AnalysisPass):
        def __init__(self):
            super().__init__(
                "custom_analysis",
                "A custom analysis pass for demonstration"
            )

        def run(self, compiler, program) -> PassResult:
            print("Running custom analysis pass...")
            # Here you would implement your custom analysis logic
            return PassResult(success=True, changed=False, data={"custom_data": "example"})

    # Create and register the custom pass
    custom_pass = CustomAnalysisPass()

    pm = PassManager()
    pm.register_pass(custom_pass)

    print(f"Registered custom pass: {custom_pass.name}")
    print(f"Pass dependencies: {custom_pass.info.dependencies}")

    return pm


def demo_pass_dependencies():
    """Demonstrate pass dependency resolution."""
    print("\n=== Pass Dependency Resolution ===")

    pm = PassManager()
    register_standard_passes(pm)

    # Show how dependencies are resolved
    print("Pass execution order (dependency resolved):")
    for i, pass_name in enumerate(pm.pass_order):
        pass_info = pm.get_pass_info(pass_name)
        deps = ", ".join(pass_info.dependencies) if pass_info.dependencies else "none"
        print(f"  {i+1}. {pass_name} (depends on: {deps})")


def demo_pipeline_execution():
    """Demonstrate pipeline execution (would need actual compiler/program)."""
    print("\n=== Pipeline Execution Demo ===")

    # Create pipeline with pass manager
    pipeline = Pipeline()

    print(f"Default passes: {pipeline.default_pass_names()}")

    # In a real scenario, you would:
    # 1. Create a compiler and program
    # 2. Run the pipeline: results = pipeline.run(program, compiler=compiler)

    print("To run the pipeline:")
    print("  compiler = create_compiler()")
    print("  program = create_program()")
    print("  results = pipeline.run(program, compiler=compiler)")
    print("  # results contains PassResult objects for each pass")


def demo_caching():
    """Demonstrate pass caching capabilities."""
    print("\n=== Pass Caching ===")

    pm = PassManager(enable_caching=True)

    # Cache is enabled by default
    print(f"Caching enabled: {pm.cache is not None}")

    # You can clear cache when needed
    pm.clear_cache()
    print("Cache cleared")

    # Cache automatically invalidates when passes change the program
    print("Cache will automatically invalidate dependent passes when program changes")


def main():
    """Run all demonstrations."""
    print("PyFlow Pass Manager Demonstration")
    print("=" * 50)

    demo_basic_usage()
    demo_custom_pass()
    demo_pass_dependencies()
    demo_pipeline_execution()
    demo_caching()

    print("\n" + "=" * 50)
    print("Pass Manager Demo Complete!")
    print("\nKey Benefits of the Pass Manager:")
    print("• Modular pass composition")
    print("• Automatic dependency resolution")
    print("• Caching for performance")
    print("• Easy addition of new passes")
    print("• LLVM-inspired design for familiarity")


if __name__ == "__main__":
    main()
