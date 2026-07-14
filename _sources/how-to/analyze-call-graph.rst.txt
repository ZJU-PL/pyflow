.. _how-to-analyze-call-graph:

=========================
How to Analyze Call Graphs
=========================

This guide explains how to use PyFlow's call graph analysis to understand the
function call structure of your Python programs.

When to Use Call Graph Analysis
================================

Use call graph analysis when you need to:

- Understand how functions interact in your codebase
- Find circular dependencies or mutual recursion
- Identify unused functions or dead code
- Analyze the impact of changing a function
- Find hot paths for performance optimization

Basic Call Graph Analysis
==========================

Generate a call graph for a single file:

.. code-block:: bash

   pyflow callgraph input.py

This outputs a text representation of the call graph.

Output Formats
--------------

Choose the appropriate format for your needs:

Text (default)
^^^^^^^^^^^^^^

For quick inspection:

.. code-block:: bash

   pyflow callgraph input.py

JSON (programmatic processing)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For scripts and automation:

.. code-block:: bash

   pyflow callgraph input.py --output callgraph.txt

Text output
^^^^^^^^^^^

For quick inspection:

.. code-block:: bash

   pyflow callgraph input.py --output callgraph.txt

Analyzing Large Codebases
==========================

For large projects, analyze entire directories:

Recursive analysis
------------------

.. code-block:: bash

   pyflow callgraph src/ --recursive

Filter by patterns
------------------

Include only specific files:

.. code-block:: bash

   pyflow callgraph src/ --include "*.py" --exclude "test_*"

Constrain solver resources
--------------------------

For large projects, cap fixpoint iterations for the constraint algorithm:

.. code-block:: bash

   pyflow callgraph input.py --algorithm constraint --fixpoint-max-iterations 1000

Finding Specific Patterns
==========================

Detect recursive functions
--------------------------

Recursive calls appear as self-loops in the call graph output:

Find functions called by a specific function
--------------------------------------------

Use the constraint algorithm output and filter programmatically from the JSON
value-flow graph.

Programmatic Call Graph Analysis
=================================

Use the JSON output for programmatic analysis:

.. code-block:: python

   import json

   def analyze_call_graph(json_path):
       """Analyze call graph for potential issues."""
       with open(json_path) as f:
           graph = json.load(f)

       # Build reverse mapping (who calls whom)
       callers = {}
       for edge in graph.get("edges", []):
           callee = edge["to"]
           caller = edge["from"]
           callers.setdefault(callee, []).append(caller)

       # Find functions with no callers (potentially dead code)
       all_functions = {node["name"] for node in graph.get("nodes", [])}
       dead_code = all_functions - set(callers.keys())

       # Find recursive functions
       recursive = []
       for node in graph.get("nodes", []):
           if node["name"] in callers.get(node["name"], []):
               recursive.append(node["name"])

       return {
           "dead_code": dead_code,
           "recursive": recursive,
           "call_counts": {k: len(v) for k, v in callers.items()}
       }

   # Usage
   results = analyze_call_graph("callgraph.json")
   print("Potentially dead code:", results["dead_code"])
   print("Recursive functions:", results["recursive"])

Visualizing Call Graphs
========================

Create professional visualizations using DOT format:

Basic visualization
------------------

.. code-block:: bash

   pyflow callgraph input.py --output callgraph.txt
   # Re-run with constraint algorithm for JSON output
   pyflow callgraph input.py --algorithm constraint --as-graph-output callgraph.json

Customized visualization
------------------------

Create a custom layout script:

.. code-block:: python

   # custom_layout.gv
   graph [rankdir=TB, nodesep=0.5, ranksep=0.5]
   node [shape=box, style="rounded,filled", fontname="Arial"]
   edge [fontname="Arial", fontsize=10]

   # Color recursive functions
   "fibonacci" [fillcolor=yellow]
   "factorial" [fillcolor=yellow]

   # Highlight main entry point
   "main" [fillcolor=lightblue, penwidth=2]

Then apply it:

.. code-block:: bash

   dot -Tpng callgraph.dot -o callgraph.png -Gstylesheet=custom_layout.gv

Common Analysis Tasks
=====================

Task 1: Find unused functions
------------------------------

.. code-block:: python

   import json

   with open("callgraph.json") as f:
       graph = json.load(f)

   # Functions with no incoming edges are potentially unused
   all_functions = {node["name"] for node in graph["nodes"]}
   called_functions = {edge["to"] for edge in graph["edges"]}
   unused = all_functions - called_functions

   if unused:
       print("Potentially unused functions:")
       for func in sorted(unused):
           print(f"  - {func}")
   else:
       print("All functions are called at least once.")

Task 2: Find critical functions
--------------------------------

Functions called from many places are critical and should be tested carefully:

.. code-block:: python

   with open("callgraph.json") as f:
       graph = json.load(f)

   caller_counts = {}
   for edge in graph["edges"]:
       callee = edge["to"]
       caller_counts[callee] = caller_counts.get(callee, 0) + 1

   # Sort by number of callers
   critical = sorted(caller_counts.items(), key=lambda x: -x[1])

   print("Most called functions:")
   for func, count in critical[:10]:
       print(f"  {func}: called from {count} places")

Task 3: Find deep call chains
------------------------------

Find functions that are deeply nested in the call hierarchy:

.. code-block:: bash

   pyflow callgraph input.py --algorithm constraint --as-graph-output callgraph.json

Then analyze the maximum depth programmatically.

Troubleshooting
===============

Issue: Call graph is too large
-------------------------------

- Use ``--exclude`` to filter out test files
- Analyze specific modules instead of the whole project
- Limit fixpoint iterations with ``--fixpoint-max-iterations`` (constraint algorithm)

Issue: Missing functions in call graph
---------------------------------------

- Ensure the file is valid Python
- Check for syntax errors that prevent full parsing
- Use ``--recursive`` for multi-file projects

Issue: Recursive calls not detected
------------------------------------

- Recursive calls appear as self-loops in the call graph output
- Use the constraint algorithm for more precise call resolution
