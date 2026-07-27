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

   from pyflow.application.passmanager import OptimizationPass, PassResult

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
   from pyflow.application.passmanager import PassManager

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

Context-Sensitive Analysis
--------------------------

Configure context-sensitive analysis:

.. code-block:: toml

   [analysis.cpa]
   context_sensitive = true
   # Context depth limit (0 = unlimited)
   max_context_depth = 5
   # Context representation: "k-limiting", "-object-sensitive", "call-string"
   context_representation = "k-limiting"
   k_value = 3

Field Sensitivity
-----------------

Configure field-sensitive analysis:

.. code-block:: toml

   [analysis.cpa]
   field_sensitive = true
   # Track individual fields separately
   track_individual_fields = true
   # Maximum fields to track per object
   max_tracked_fields = 20

Flow Sensitivity
----------------

Configure flow-sensitive analysis:

.. code-block:: toml

   [analysis.cpa]
   flow_sensitive = true
   # Statement-level vs block-level analysis
   granularity = "statement"  # or "block"

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

   from pyflow import Context
   from pyflow.frontend.extractor import Extractor
   from pyflow.analysis.cpa import InterproceduralDataflow
   from pyflow.analysis.callgraph.constraint_based.api import extract_call_graph_constraint

   # Set up compiler and extractor
   context = Context()
   extractor = Extractor(context)
   extractor.process(["input.py"])
   program = context.program

   # Create analysis context
   context = Context()
   context.slots["context_sensitive"] = True
   context.slots["flow_sensitive"] = True

   # Run specific analyses
   cpa = InterproceduralDataflow()
   cpa.run(program)

   graph = extract_call_graph_constraint(open("input.py").read())

   # Combine results
   combined_results = {
       "cpa": cpa,
       "callgraph": graph,
   }

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
