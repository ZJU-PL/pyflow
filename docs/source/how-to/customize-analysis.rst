.. _how-to-customize-analysis:

========================================
How to Customize Analysis
========================================

This guide explains how to configure and customize PyFlow's analysis behavior
for your specific needs.

Custom Analysis Passes
======================

Create custom analysis passes by extending PyFlow's base classes:

.. code-block:: python

   from pyflow.ir.cfg.graph import CFGBlock

   class MyCustomAnalysis:
       """Custom analysis pass for specific needs."""

       def __init__(self):
           super().__init__()
           self.results = {}

       def analyze(self, program):
           """Run the analysis on a program."""
           for function in program.functions:
               self.analyze_function(function)
           return self.results

       def analyze_function(self, function):
           """Analyze a single function."""
           cfg = function.cfg
           # Custom analysis logic here
           self.results[function.name] = {
               "num_blocks": len(cfg.blocks),
               "num_edges": len(cfg.edges),
           }

   # Register the pass via the pass manager pipeline
   # See pyflow.application.passes for the standard pass registration pattern

Running Custom Analysis
-----------------------

.. code-block:: bash

   pyflow optimize input.py --analysis cpa

Custom Optimization Passes
===========================

Create custom optimization passes:

.. code-block:: python

   from pyflow.application.passes.base import OptimizationPass, PassResult

   class MyCustomOptimization(OptimizationPass):
       """Custom optimization pass."""

       def __init__(self):
           super().__init__("my_optimization", "Custom optimization example")

       def run(self, compiler, program):
           # Custom optimization logic here
           changed = False
           for function in program.liveCode:
               changed = self.optimize_function(function) or changed
           return PassResult(success=True, changed=changed)

       def optimize_function(self, function):
           return False

   # Register the pass
   from pyflow.application.passes.manager import PassManager

   manager = PassManager()
   manager.register_pass(MyCustomOptimization())

Running Custom Optimization
----------------------------

.. code-block:: bash

   pyflow optimize input.py --opt-passes my_custom

Custom Output Formatters
========================

Create custom output formatters:

.. code-block:: python

    from pyflow.analysis.callgraph.formats import generate_text_output

    def my_custom_formatter(call_graph, args):
        """Custom output formatter."""
        # Custom formatting logic
        return f"Custom: {len(call_graph.get())} functions"

    # Use the formatter with your call graph
    output = my_custom_formatter(call_graph, args)

Using Custom Formatter
----------------------

.. code-block:: python

   # Use your custom formatter directly
   output = my_custom_formatter(call_graph, args)
   print(output)

Advanced Configuration
======================

Analysis Options
----------------

Configure analysis parameters programmatically via ``AnalysisOptions`` on the program session:

.. code-block:: python

   from pyflow.application.session import AnalysisOptions

   # Configure CPA path sensitivity, caching, and report options
   options = AnalysisOptions(
       cpa_path_length=3,
       enable_caching=True,
       dump_reports=False,
   )
   program.session.configure(options)

Security & IFDS Configuration
------------------------------

For IFDS security analysis, reusable project defaults can be supplied via ``pyflow.json``:

.. code-block:: json

   {
     "analysis": "taint",
     "entry": ["app.py"],
     "frameworks": ["stdlib", "flask"],
     "unknown_call_policy": "preserve",
     "solver_options": {
       "max_seconds": 30,
       "max_path_edges": 100000
     }
   }

Command-Line Overrides
======================

Override configuration from the command line:

.. code-block:: bash

   # Run with specific analysis
   pyflow optimize input.py --analysis cpa

   # Disable optimizations
   pyflow optimize input.py --no-opt-passes

   # Set output format
   pyflow callgraph input.py --output result.txt

Programmatic Usage
==================

Use PyFlow programmatically for fine-grained control:

.. code-block:: python

   from pyflow.application.context import CompilerContext
   from pyflow.application.pipeline import Pipeline
   from pyflow.application.session import AnalysisOptions
   from pyflow.frontend.extractor import Extractor
   from pyflow.analysis.callgraph.constraint_based.api import extract_call_graph_constraint

   compiler = CompilerContext()
   compiler.extractor = Extractor(compiler)
   program = compiler.extractor.extract_from_file("input.py")
   program.session.configure(AnalysisOptions(cpa_path_length=5))

   results = Pipeline().run_custom_pipeline(compiler, program, ["ipa", "cpa"])
   cpa = program.session.get_result("cpa")
   graph = extract_call_graph_constraint(open("input.py").read())

   combined_results = {"cpa": cpa, "callgraph": graph}

Troubleshooting
===============

Issue: Configuration not applied
---------------------------------

- Verify CLI flags are correct with ``pyflow optimize --help``
- Ensure pass names match available passes with ``pyflow optimize --list-opt-passes``
- Check that the analysis engine is supported by the requested pass

Issue: Custom pass not found
----------------------------

- Ensure the pass is registered before use
- Check import paths
- Verify class inheritance

Issue: Performance issues with custom configuration
----------------------------------------------------

- Reduce context depth for large codebases
- Disable flow sensitivity for faster analysis
- Use incremental analysis for repeated runs
