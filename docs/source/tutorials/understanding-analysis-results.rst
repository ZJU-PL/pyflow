.. _tutorial-understanding-analysis-results:

==============================
Understanding Analysis Results
==============================

This tutorial explains how to interpret and use the results from PyFlow's
various analyses.

What You'll Learn
=================

- Understanding output formats (text, JSON, DOT)
- Interpreting analysis results and annotations
- Using results for further analysis or optimization
- Common patterns and how to identify them

Output Formats
==============

PyFlow supports multiple output formats for analysis results:

1. **text**: Human-readable text format (default)
2. **dot**: Graphviz DOT format for visualization
3. **json**: JSON format for programmatic processing

Text Format
-----------

Text format is designed for human readability:

.. code-block:: bash

   pyflow callgraph example.py

Output:

.. code-block:: text

   Call Graph for example.py:
   ───────────────────────────────────────

   Nodes:
     fibonacci: fibonacci(n)
     factorial: factorial(n)
     main: main()

   Edges:
     main → fibonacci (line 21)
     main → factorial (line 22)

JSON Format
-----------

The callgraph command outputs text by default, suitable for inspection:

.. code-block:: bash

   pyflow callgraph example.py

The constraint algorithm can also produce a JSON value-flow graph:

.. code-block:: bash

   pyflow callgraph example.py --algorithm constraint --as-graph-output callgraph.json

DOT Format
----------

DOT format is available for IR dumps via ``pyflow ir``:

.. code-block:: bash

   pyflow ir example.py --dump-cfg main --dump-format dot --dump-output cfg.dot

Then render to an image:

.. code-block:: bash

   dot -Tpng cfg.dot -o cfg.png

Interpreting Call Graph Results
===============================

Call graphs show function call relationships. Key elements:

Nodes
-----

Each node represents a function:

- **name**: The function name
- **signature**: The function signature (parameters)
- **line**: The line number where the function is defined

Edges
-----

Each edge represents a function call:

- **from**: The calling function
- **to**: The called function
- **line**: The line number of the call
- **type**: The type of call (direct, indirect, recursive)

Common Patterns
---------------

1. **Direct call**: One function directly calls another
2. **Indirect call**: Call through function pointer or callback
3. **Recursive call**: Function calls itself
4. **Mutual recursion**: Two or more functions call each other

Example: Recursive Function
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   def factorial(n):
       if n <= 1:
           return 1
       return n * factorial(n - 1)

Call graph shows:

.. code-block:: text

   factorial → factorial (line 5, recursive)

Example: Mutual Recursion
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   def is_even(n):
       if n == 0:
           return True
       return is_odd(n - 1)

   def is_odd(n):
       if n == 0:
           return False
       return is_even(n - 1)

Call graph shows:

.. code-block:: text

   is_even → is_odd (line 4)
   is_odd → is_even (line 4)

Interpreting CFG Results
========================

Control Flow Graphs show the structure of control within a function.

Basic Blocks
------------

Each block contains:

- **Label**: Block identifier
- **Instructions**: Statements in the block
- **Type**: Entry, exit, or regular block

Edges
-----

Edges show possible control flow transfers:

- **Conditional**: From if/else branches
- **Unconditional**: From fall-through or jumps
- **Exceptional**: From exception handling

Example: CFG for a Simple Function
-----------------------------------

.. code-block:: python

   def example(x):
       if x > 0:
           return "positive"
       elif x < 0:
           return "negative"
       else:
           return "zero"

CFG output:

.. code-block:: text

   Block 0 (Entry):
     x: Parameter
     if x > 0

   Block 1 (True):
     return "positive"

   Block 2 (elif x < 0):
     if x < 0

   Block 3 (True):
     return "negative"

   Block 4 (else):
     return "zero"

   Edges:
     Block 0 → Block 1 (x > 0)
     Block 0 → Block 2 (x > 0 is False)
     Block 2 → Block 3 (x < 0)
     Block 2 → Block 4 (x < 0 is False)

Interpreting Data Flow Results
==============================

Data flow analysis results show how values propagate through the program.

Reaching Definitions
--------------------

A "reaching definition" is an assignment that can reach a program point without
being overwritten.

Example:

.. code-block:: python

   x = 1      # Definition of x
   y = x + 1  # Uses x
   x = 2      # Redefinition of x
   z = x + 1  # Uses x (reaches from line 3)

Analysis output:

.. code-block:: text

   Line 2 (y = x + 1):
     x reaches from: {x = 1 (line 1)}

   Line 4 (z = x + 1):
     x reaches from: {x = 2 (line 3)}

Live Variables
--------------

A variable is "live" at a point if its value may be used before being
reassigned.

Example:

.. code-block:: python

   x = 1
   y = x + 1  # x is live here
   z = 2      # x is dead here

Analysis output:

.. code-block:: text

   Line 1: {x} (x becomes defined)
   Line 2: {y} (x used, y defined)
   Line 3: {z} (y used, z defined)

Interpreting CPA Results
========================

Constraint-based analysis results show object relationships and type information.

Points-to Sets
--------------

Points-to sets show which objects a variable may reference:

.. code-block:: python

   a = []
   b = []
   c = a

Analysis output:

.. code-block:: text

   a: {[empty list]}
   b: {[empty list]}
   c: {a}  # c points to same object as a

Type Information
----------------

CPA also infers types:

.. code-block:: python

   def process(x):
       return x.upper()

   result = process("hello")

Analysis output:

.. code-block:: text

   process: str -> str
   result: str

Interpreting Shape Analysis Results
===================================

Shape analysis identifies the structure of data objects.

List Shapes
-----------

.. code-block:: python

   empty_list = []
   non_empty = [1, 2, 3]
   mixed = [1, "two", 3.0]

Analysis output:

.. code-block:: text

   empty_list: List[Empty]
   non_empty: List[Fixed(length=3, elements={int})]
   mixed: List[Variable(length, elements={int, str, float})]

Dictionary Shapes
-----------------

.. code-block:: python

   empty_dict = {}
   config = {"key": "value", "count": 5}

Analysis output:

.. code-block:: text

   empty_dict: Dict[Empty]
   config: Dict[Fixed(keys={str}, values={str, int})]

Using Results Programmatically
===============================

JSON output can be processed programmatically:

.. code-block:: python

   import json

   # Load call graph
   with open("callgraph.json") as f:
       graph = json.load(f)

   # Find all functions that call a given function
   def find_callers(graph, target):
       callers = []
       for edge in graph["edges"]:
           if edge["to"] == target:
               callers.append(edge["from"])
       return callers

   # Usage
   callers = find_callers(graph, "fibonacci")
   print("Functions that call fibonacci:", callers)

Exporting for Visualization
============================

Use DOT format with Graphviz for professional visualizations:

.. code-block:: bash

   pyflow callgraph example.py --output callgraph.txt

Customize the visualization:

.. code-block:: bash

   dot -Tpng callgraph.dot -o callgraph.png -Gdpi=300

Or create an HTML visualization:

.. code-block:: python

   # Use pygraphviz for more control
   import pygraphviz as pgv

   G = pgv.AGraph("callgraph.dot")
   G.layout(prog="dot")
   G.draw("callgraph.png")

Best Practices
==============

1. **Use appropriate format**: Text for quick inspection, JSON for scripts
2. **Visualize complex graphs**: DOT format for large graphs
3. **Combine analyses**: Use multiple analyses for complete understanding
4. **Automate processing**: Use JSON output for automated analysis pipelines

Next Steps
==========

- Explore :doc:`/how-to/index` for task-specific guides
- Learn about the :doc:`/explanation/algorithms` behind the analyses
- Check out the :doc:`/api` for complete API documentation
