.. _explanation-analysis-comparison:

====================
Analysis Comparison
====================

This document compares PyFlow's analysis capabilities with other static
analysis tools and explains the trade-offs.

Comparison with Other Tools
===========================

PyFlow vs. Type Checkers
-------------------------

+----------------------+----------------------+----------------------+
| Feature              | PyFlow               | Type Checkers        |
+======================+======================+======================+
| Type inference       | Yes                  | Yes                  |
| Runtime behavior     | Static only          | Mostly static        |
| Call graph           | Built-in             | Limited              |
| Optimization         | Built-in             | None                 |
| Precision            | Context-sensitive    | Mostly insensitive   |
+----------------------+----------------------+----------------------+

**When to use PyFlow**:

- Need call graph analysis
- Need combined analysis and optimization
- Analyzing dynamically typed code

**When to use type checkers**:

- Primary need is type checking
- Already using mypy/pyright
- Need IDE integration

PyFlow vs. Linters
------------------

+----------------------+----------------------+----------------------+
| Feature              | PyFlow               | Linters (pylint)     |
+======================+======================+======================+
| Bug detection        | Yes                  | Yes                  |
| Style checking       | Limited              | Yes                  |
| Security analysis    | Yes                  | Some                 |
| Performance analysis | Yes                  | Limited              |
| Call graph           | Built-in             | Plugin               |
+----------------------+----------------------+----------------------+

**When to use PyFlow**:

- Need security vulnerability detection
- Need performance optimization
- Need call graph analysis

**When to use linters**:

- Primary need is code quality
- Need style enforcement
- Need quick feedback during development

PyFlow vs. SAST Tools
---------------------

+----------------------+----------------------+----------------------+
| Feature              | PyFlow               | Commercial SAST      |
+======================+======================+======================+
| Language support     | Python only          | Multiple languages   |
| Integration          | CLI, API             | CI/CD, IDE           |
| Custom rules         | Via Python API       | DSL or GUI           |
| Accuracy             | High for Python      | Varies               |
| Open source          | Yes                  | Usually no           |
+----------------------+----------------------+----------------------+

**When to use PyFlow**:

- Python-only codebase
- Need open source solution
- Need customization via Python

**When to use commercial SAST**:

- Multi-language codebase
- Need enterprise support
- Need compliance reporting

Analysis Depth Comparison
=========================

+----------------------+-------------+------------+------------+
| Analysis Type        | PyFlow      | pyright    | mypy       |
+======================+=============+============+============+
| Intra-procedural     | Yes         | Yes        | Yes        |
+----------------------+-------------+------------+------------+
| Inter-procedural     | Yes         | Limited    | Limited    |
+----------------------+-------------+------------+------------+
| Context-sensitive    | Configurable| No         | No         |
+----------------------+-------------+------------+------------+
| Field-sensitive      | Configurable| Partial    | Partial    |
+----------------------+-------------+------------+------------+
| Flow-sensitive       | Configurable| No         | No         |
+----------------------+-------------+------------+------------+

Precision Comparison
====================

+----------------------+----------------------+
| Analysis Scenario    | PyFlow Precision     |
+======================+======================+
| Simple assignments   | Very high            |
+----------------------+----------------------+
| Function calls       | High (context-sens)  |
+----------------------+----------------------+
| Dynamic features     | Medium               |
+----------------------+----------------------+
| Reflection usage     | Low                  |
+----------------------+----------------------+

Performance Comparison
======================

+----------------------+----------------------+----------------------+
| Tool                 | Analysis Speed       | Scale                |
+======================+======================+======================+
| PyFlow (basic)       | ~1000 LOC/second     | Up to 100K LOC       |
+----------------------+----------------------+----------------------+
| PyFlow (deep)        | ~100 LOC/second      | Up to 50K LOC        |
+----------------------+----------------------+----------------------+
| pyright              | ~5000 LOC/second     | Unlimited            |
+----------------------+----------------------+----------------------+
| mypy                 | ~500 LOC/second      | Up to 1M LOC         |
+----------------------+----------------------+----------------------+

Complementary Use
=================

PyFlow works well with other tools:

Use with Type Checkers
----------------------

.. code-block:: bash

   # Run type checking first
   pyright input.py

   # Then run PyFlow for deeper analysis
   pyflow optimize input.py

Use with Linters
----------------

.. code-block:: bash

   # Run linter for style
   pylint input.py

   # Then run PyFlow for analysis
   pyflow optimize input.py

Use in CI/CD
------------

.. code-block:: yaml
   :caption: .github/workflows/analysis.yml

   name: Code Analysis

   jobs:
     lint:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - name: Run linter
           run: pip install pylint && pylint input.py

     typecheck:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - name: Run type checker
           run: pip install pyright && pyright input.py

     pyflow:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - name: Run PyFlow
           run: pip install pyflow && pyflow optimize input.py

Recommendation Matrix
=====================

+---------------------------+----------------------------------+
| Use Case                  | Recommended Tool                 |
+===========================+==================================+
| Type checking             | pyright or mypy                  |
+---------------------------+----------------------------------+
| Code style                | pylint or ruff                   |
+---------------------------+----------------------------------+
| Security analysis         | PyFlow or Bandit                 |
+---------------------------+----------------------------------+
| Call graph generation     | PyFlow                           |
+---------------------------+----------------------------------+
| Code optimization         | PyFlow                           |
+---------------------------+----------------------------------+
| General quality           | Combination of above             |
+---------------------------+----------------------------------+
