Concolic Execution
==================

PyFlow includes an AST-level dynamic symbolic execution (concolic testing) engine inspired by Py-Conbyte and CrossHair.
It generates branch-covering test inputs, searches for contract counterexamples, refines library behaviors from real executions, and synthesizes replay-validated pytest suites.

Overview
--------

The concolic engine pairs concrete Python execution with symbolic execution over an AST interpreter, tracking path constraints and employing Z3 to flip branches toward unexplored code paths.

Features
--------

- **Type & Expression Modeling**: Integers, floats, strings, byte-strings, lists, dictionaries, sets, tuples, f-strings, comprehensions, and pattern matching.
- **Python Semantics**: Classes, inheritance, properties, descriptors, decorators, generators with suspension (``send``, ``throw``, ``close``), coroutines, and async scheduling.
- **Search Strategies**: Coverage-guided search (default), breadth-first, and FIFO queue exploration.
- **Contract Checking**: Verification of PEP 316-style precondition and postcondition contracts (``--check-contracts``) with automatic counterexample generation.
- **Observation-Refined Library Calls**: Safe standard library calls are executed concretely to observe input/output relations and guide symbolic reasoning (``--refine-opaque-calls``).
- **Test Generation**: Generates minimized, CPython-replay-validated test suites directly in ``pytest`` format (``--emit-pytest``).
- **Project Scanning**: Static discovery of eligible functions across entire codebases with side-effect hazard filtering and automated input generation (``--scan-project``).

CLI Usage
---------

Explore a single target function:

.. code-block:: bash

   # Generate branch-covering inputs for a function
   pyflow concolic target.py --entry parse --inputs '[0, 0]' --json

   # Check contracts and seek counterexamples
   pyflow concolic target.py --entry process --check-contracts

   # Emit replay-validated pytest test suite
   pyflow concolic target.py --entry parse --emit-pytest tests/test_generated.py

Scan an entire project:

.. code-block:: bash

   pyflow concolic ./src --scan-project --json --json-output report.json

Python API
----------

Use ``explore_file`` or ``explore_function`` for programmatic exploration:

.. code-block:: python

   from pyflow.concolic import explore_file

   result = explore_file(
       "target.py",
       entry="parse",
       initial_inputs=[0, 0],
       max_iterations=50,
   )

   for run in result.runs:
       print("Input:", run.inputs, "Coverage:", len(run.coverage.nodes))
