.. _tutorial-analyzing-python-code:

======================
Analyzing Python Code
======================

This tutorial covers the various analysis capabilities of PyFlow and how to
use them effectively to understand Python programs.

What You'll Learn
=================

- How to run different types of static analysis
- Understanding control flow graphs and data flow analysis
- Using call graph analysis to understand program structure
- Interpreting analysis results

Analysis Overview
=================

PyFlow provides several types of static analysis:

1. **Control Flow Analysis**: Understand the control flow structure of your code
2. **Data Flow Analysis**: Track how data flows through the program
3. **Inter-procedural Analysis**: Analyze behavior across function boundaries
4. **Constraint-based Analysis**: Understand object relationships and types
5. **Shape Analysis**: Analyze data structure shapes and properties
6. **Call Graph Analysis**: Understand function call relationships

Control Flow Analysis
=====================

Control Flow Graph (CFG) construction is the foundation of many analyses.
The CFG shows the basic blocks of your program and how control flows between them.

Running CFG Analysis
--------------------

Dump the CFG for a specific function:

.. code-block:: bash

   pyflow ir example.py --dump-cfg function_name --dump-format text

For our example file:

.. code-block:: bash

   pyflow ir example.py --dump-cfg fibonacci --dump-format text

Output:

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
---------------------------

A **basic block** is a sequence of instructions with a single entry and exit
point. Control flow can only enter at the beginning and exit at the end.

Key CFG concepts:

- **Entry Block**: The first block in the function
- **Exit Block**: The block(s) containing return statements
- **Edges**: Show possible control flow transfers
- **Dominators**: Blocks that must be executed before reaching other blocks

Data Flow Analysis
==================

Data flow analysis tracks how values propagate through the program. PyFlow
provides several data flow analyses.

Running Data Flow Analysis
--------------------------

.. code-block:: bash

   pyflow optimize example.py --analysis cpa,ipa

This runs forward and backward data flow analysis, computing:

- **Reaching Definitions**: Which assignments can reach a given program point
- **Live Variables**: Which variables are live (will be used) at each point
- **Available Expressions**: Which expressions have been computed and available

Example output for reaching definitions:

.. code-block:: text

   Data Flow Analysis Results:
   ───────────────────────────────────────

   Block 0:
     n: {n := @parameter}
     result: {}

   Block 1:
     n: {n := @parameter}
     result: {result := n}

Inter-procedural Analysis
=========================

Inter-procedural analysis (IPA) analyzes behavior across function boundaries,
providing more precise results than purely intra-procedural analysis.

Running IPA
-----------

.. code-block:: bash

   pyflow optimize example.py --analysis ipa

IPA provides:

- **Context Sensitivity**: Distinguishes between different calling contexts
- **Field Sensitivity**: Tracks individual object fields separately
- **Flow Sensitivity**: Respects the order of statements

Context-Sensitive Analysis
---------------------------

PyFlow uses context-sensitive analysis to distinguish between different
invocations of the same function. For example:

.. code-block:: python

   def double(x):
       return x * 2

   a = double(5)    # Context 1: x = 5
   b = double(10)   # Context 2: x = 10

In context-sensitive analysis, these are analyzed separately, providing more
precise results than merging them together.

Constraint-Based Analysis (CPA)
===============================

CPA uses constraint solving to perform precise analysis of Python objects,
types, and their relationships.

Running CPA
-----------

.. code-block:: bash

   pyflow optimize example.py --analysis cpa

CPA produces results such as:

- **Points-to sets**: Which objects a variable may point to
- **Type information**: Known types of variables and expressions
- **Object relationships**: How objects are related through fields and aliases

Example CPA output:

.. code-block:: text

   CPA Results for example.py:
   ───────────────────────────────────────

   fibonacci(10):
     n: {10} (constant)
     return: PointsTo{Integer}

   fibonacci(n - 1):
     n: PointsTo{Integer}
     return: PointsTo{Integer}

Shape Analysis
==============

Shape analysis determines the shape (structure) of data objects such as lists,
dictionaries, and custom objects.

Running Shape Analysis
----------------------

.. code-block:: bash

   pyflow optimize example.py --analysis shape

Shape analysis identifies:

- **List shapes**: Empty, non-empty, length, element types
- **Dictionary shapes**: Key-value patterns, empty vs non-empty
- **Object shapes**: Class types, field structures

Call Graph Analysis
===================

Call graph analysis builds a graph showing which functions call which other
functions.

Building Call Graphs
--------------------

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
     main → print (line 20)
     fibonacci → fibonacci (line 16, recursive)
     factorial → factorial (line 10, recursive)

Call Graph Formats
------------------

You can output call graphs in different formats:

- **text** (default): Human-readable text format
- **dot**: Graphviz DOT format for visualization
- **json**: JSON format for programmatic processing

.. code-block:: bash

   pyflow callgraph example.py --format dot --output callgraph.dot

Analyzing Multiple Files
========================

PyFlow can analyze entire projects:

.. code-block:: bash

   # Analyze a directory recursively
   pyflow callgraph src/ --recursive

   # Include specific patterns
   pyflow callgraph src/ --include "*.py" --exclude "test_*"

Advanced Analysis Options
==========================

Combine multiple analyses:

.. code-block:: bash

   pyflow optimize example.py --analysis all

Or run specific combinations:

.. code-block:: bash

   pyflow optimize example.py --analysis cpa,ipa,shape

Dump intermediate representations:

.. code-block:: bash

   pyflow ir example.py --dump-ast fibonacci --dump-format json --output ast.json

Next Steps
==========

Now that you understand the basic analysis capabilities, you can:

- Learn about :ref:`optimizing-python-programs`
- Explore :ref:`understanding-analysis-results`
- Dive into :doc:`../explanation/architecture` for detailed architecture information
