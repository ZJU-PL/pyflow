.. _how-to-analyze-control-flow:

===========================
How to Analyze Control Flow
===========================

This guide explains how to use PyFlow's control flow analysis to understand
the structure and flow of control within your Python functions.

When to Use Control Flow Analysis
==================================

Use control flow analysis when you need to:

- Understand complex conditional logic
- Identify unreachable code or infinite loops
- Optimize control flow structures
- Prepare for data flow analysis
- Visualize program structure

Basic Control Flow Analysis
============================

Dump the CFG for a specific function:

.. code-block:: bash

   pyflow ir input.py --dump-cfg function_name --dump-format text

For the fibonacci function:

.. code-block:: bash

   pyflow ir input.py --dump-cfg fibonacci --dump-format text

Output shows the basic blocks and their connections:

.. code-block:: text

   CFG for fibonacci:
   ───────────────────────────────────────

   Block 0 (Entry):
     n: Parameter
     if n <= 1

   Block 1 (True - Return):
     return n

   Block 2 (False - Recursive):
     temp1 = fibonacci(n - 1)
     temp2 = fibonacci(n - 2)
     return temp1 + temp2

   Edges:
     Block 0 → Block 1 (n <= 1 is True)
     Block 0 → Block 2 (n <= 1 is False)

Understanding Basic Blocks
===========================

A basic block is a sequence of instructions where:

- Control can only enter at the beginning
- Control can only exit at the end
- No branches occur within the block (except at the end)

Block Types
-----------

Entry Block
^^^^^^^^^^^

The first block of the function, where control enters:

.. code-block:: text

   Block 0 (Entry):
     n: Parameter
     if n > 0

Regular Block
^^^^^^^^^^^^^

A standard block with instructions and an exit:

.. code-block:: text

   Block 3:
     x = x + 1
     if x < 10

Exit Block
^^^^^^^^^^

A block containing a return statement:

.. code-block:: text

   Block 5 (Exit):
     return result

Exception Block
^^^^^^^^^^^^^^^

A block handling exceptions:

.. code-block:: text

   Block 4 (Exception):
     print("Error occurred")
     return None

Control Flow Edges
===================

Edges represent possible transfers of control between blocks.

Conditional Edges
-----------------

From if statements:

.. code-block:: text

   Block 0 → Block 1 (condition is True)
   Block 0 → Block 2 (condition is False)

Loop Edges
----------

From loop headers:

.. code-block:: text

   Block 2 → Block 1 (loop back edge)
   Block 2 → Block 3 (loop exit edge)

Exception Edges
---------------

From try-except blocks:

.. code-block:: text

   Block 0 → Block 4 (exception caught)

Visualizing Control Flow
========================

Create visual representations of control flow:

Text diagram
------------

.. code-block:: bash

   pyflow ir input.py --dump-cfg function_name --dump-format text

DOT visualization
-----------------

.. code-block:: bash

   pyflow ir input.py --dump-cfg function_name --dump-format dot --output cfg.dot
   dot -Tpng cfg.dot -o cfg.png

Advanced CFG Options
====================

Multiple formats
----------------

Choose the output format that best fits your needs:

JSON for programmatic access:

.. code-block:: bash

   pyflow ir input.py --dump-cfg function_name --dump-format json --output cfg.json

All CFGs for a file
-------------------

Dump all CFGs in a file:

.. code-block:: bash

   pyflow ir input.py --dump-cfg all --output all_cfg.dot

Common Analysis Tasks
=====================

Task 1: Identify unreachable code
----------------------------------

Unreachable code appears in blocks that have no incoming edges (except from
themselves):

.. code-block:: python

   def analyze_reachability(json_path):
       """Identify potentially unreachable code."""
       with open(json_path) as f:
           cfg = json.load(f)

       blocks = cfg["blocks"]
       edges = cfg["edges"]

       # Build set of blocks with incoming edges
       reachable = set()
       for edge in edges:
           reachable.add(edge["from"])

       # Entry block is always reachable
       reachable.add(cfg.get("entry_block"))

       # Find unreachable blocks
       all_blocks = {block["id"] for block in blocks}
       unreachable = all_blocks - reachable

       return unreachable

Task 2: Find loop complexity
-----------------------------

Analyze loop nesting depth:

.. code-block:: python

   def analyze_loop_depth(json_path):
       """Analyze loop nesting depth."""
       with open(json_path) as f:
           cfg = json.load(f)

       # Back edges indicate loops
       # Count edges from higher blocks to lower blocks
       back_edges = [
           e for e in cfg["edges"]
           if e["from"] > e.get("to", 0) and "loop" in e.get("type", "")
       ]

       return {
           "num_loops": len(back_edges),
           "back_edges": back_edges
       }

Task 3: Simplify complex conditionals
---------------------------------------

Identify functions with complex control flow:

.. code-block:: python

   def analyze_complexity(json_path):
       """Calculate control flow complexity metrics."""
       with open(json_path) as f:
           cfg = json.load(f)

       edges = cfg["edges"]
       blocks = cfg["blocks"]

       # Cyclomatic complexity = edges - nodes + 2
       n_edges = len(edges)
       n_nodes = len(blocks)

       complexity = n_edges - n_nodes + 2

       return {
           "cyclomatic_complexity": complexity,
           "num_blocks": n_nodes,
           "num_edges": n_edges
       }

Interpreting Results
====================

Simple Control Flow
-------------------

Functions with simple control flow (low complexity) are easier to understand
and maintain:

- **Complexity 1-10**: Simple, low risk
- **Complexity 11-20**: Moderate complexity
- **Complexity 21+**: High complexity, consider refactoring

Example: Low Complexity
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   def simple(x):
       if x > 0:
           return "positive"
       return "non-positive"

Complexity: 2 (very simple)

Example: High Complexity
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   def complex(x):
       if x > 100:
           if x > 200:
               if x > 300:
                   return "very high"
               return "high"
           elif x < 150:
               return "medium-high"
           else:
               return "medium"
       elif x > 50:
           return "medium-low"
       elif x > 0:
           return "low"
       return "non-positive"

Complexity: 8+ (high complexity, consider refactoring)

Troubleshooting
===============

Issue: CFG shows unexpected structure
--------------------------------------

- Check for syntax errors in the source code
- Ensure the function name is correct
- Try with ``--dump-ast`` first to verify parsing

Issue: Missing blocks
---------------------

- The function may have been inlined or optimized
- Check if the function exists in the source
- Use ``--no-opt-passes`` to skip optimizations

Issue: Circular edges in visualization
---------------------------------------

- Recursive functions naturally have circular edges
- This is expected behavior, not an error
