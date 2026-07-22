.. _tutorial-optimizing-python-programs:

=======================
Optimizing Python Programs
=======================

This tutorial covers how to use PyFlow's optimization passes to improve the
performance of your Python programs.

What You'll Learn
=================

- Understanding PyFlow's optimization passes
- How to apply optimizations via CLI and programmatically
- Combining passes for maximum effect
- Analyzing optimization results

Optimization Overview
=====================

PyFlow provides a comprehensive suite of optimization passes organized into
categories:

1. **Constant Folding and Propagation**: Evaluate constants at compile time
2. **Dead Code Elimination**: Remove unreachable and unused code
3. **Control Flow Simplification**: Simplify basic blocks and control flow
4. **Function Inlining**: Inline small functions to reduce call overhead
5. **Data Flow Optimizations**: Eliminate redundant memory operations
6. **Method Call Optimization**: Optimize method dispatch and calls

Running Optimizations
=====================

Basic Optimization
------------------

Run all default optimizations:

.. code-block:: bash

   pyflow optimize input.py

This runs PyFlow's default optimization pipeline, including whole-program
analysis, simplification, specialization, and a final path-sensitive cleanup pass.

Selective Optimization
----------------------

Run specific optimization passes:

.. code-block:: bash

   pyflow optimize input.py --opt-passes simplify methodcall

Available optimization passes:

- ``simplify``: Constant folding and dead code elimination
- ``methodcall``: Method call optimization
- ``lifetime``: Lifetime analysis for variables
- ``clone``: Separate different invocations of the same code
- ``argumentnormalization``: Normalize function arguments
- ``inlining``: Inline function calls (experimental)
- ``cullprogram``: Remove dead functions and contexts
- ``loadelimination``: Eliminate redundant load operations
- ``storeelimination``: Eliminate redundant store operations
- ``dce``: Dead code elimination without constant folding

List available passes:

.. code-block:: bash

   pyflow optimize --list-opt-passes

If you want a report on the analyzed program, combine optimization with a dump:

.. code-block:: bash

   pyflow optimize input.py --dump --output analysis.txt

Constant Folding
================

Constant folding evaluates constant expressions at compile time, replacing them
with their computed values.

Example transformation:

.. code-block:: python
   :caption: Before optimization

   # Original code
   PI = 3.14159
   radius = 5
   area = PI * radius * radius

.. code-block:: python
   :caption: After constant folding

   # Optimized code
   PI = 3.14159
   radius = 5
   area = 78.53975  # Computed at compile time

Running Constant Folding
------------------------

.. code-block:: bash

   pyflow optimize input.py --opt-passes simplify

The ``simplify`` pass includes constant folding along with dead code elimination.

What Gets Folded
----------------

- Arithmetic operations on constants: ``2 + 3`` → ``5``
- String concatenations: ``"Hello" + "World"`` → ``"HelloWorld"``
- Boolean operations: ``True and x`` → ``x``
- Function calls on constants (when the function is pure)

Dead Code Elimination
=====================

Dead code elimination removes code that does not affect program results.

Types of Dead Code
------------------

1. **Unreachable code**: Code after unconditional return/break/continue
2. **Unused variables**: Variables that are assigned but never read
3. **Dead branches**: Code in if-else that can never be executed

Example transformation:

.. code-block:: python
   :caption: Before optimization

   def example():
       x = 10  # Unused variable
       return 5
       print("This is unreachable")  # After return

.. code-block:: python
   :caption: After optimization

   def example():
       return 5

Running Dead Code Elimination
------------------------------

Dead code elimination is included in the ``simplify`` pass:

.. code-block:: bash

   pyflow optimize input.py --opt-passes simplify

Control Flow Simplification
============================

Control flow simplification optimizes the structure of control flow graphs.

Transformations include:

- **Basic block merging**: Combining consecutive blocks when possible
- **Jump threading**: Simplifying consecutive jumps
- **Branch folding**: Eliminating redundant branches

Example transformation:

.. code-block:: python
   :caption: Before optimization

   def example(x):
       if x > 0:
           if x > 0:
               return True
           else:
               return False
       else:
           return False

.. code-block:: python
   :caption: After optimization

   def example(x):
       return x > 0

Function Inlining
=================

Function inlining replaces function calls with the function body, eliminating
call overhead.

When to Inline
--------------

PyFlow uses heuristics to determine when inlining is beneficial:

- Small functions (few instructions)
- Functions called infrequently
- Functions with simple control flow and tail returns

Example transformation:

.. code-block:: python
   :caption: Before optimization

   def add(a, b):
       return a + b

   result = add(5, 10)

.. code-block:: python
   :caption: After inlining

   result = 5 + 10  # Can further simplify to 15

Running Inlining
----------------

.. code-block:: bash

   pyflow optimize input.py --opt-passes inlining --experimental-inlining

Method Call Optimization
========================

Method call optimization improves the performance of method calls by:

- Eliminating indirect calls where possible
- Devirtualizing calls when the type is known
- Bypassing unnecessary lookups

Running Method Call Optimization
---------------------------------

.. code-block:: bash

   pyflow optimize input.py --opt-passes methodcall

Argument Normalization
======================

Argument normalization currently targets ``*args`` when the argument length is
statically known and incoming call sites are monomorphic, positional, and
already compatible with the specialized arity.

Example transformation:

.. code-block:: python
   :caption: Before normalization

   def func(a, b, *args, **kwargs):
       return a + b

.. code-block:: python
   :caption: After normalization

   def func(a, b, arg0, arg1):
       return a + b

Running Argument Normalization
------------------------------

.. code-block:: bash

   pyflow optimize input.py --opt-passes argumentnormalization

Optimization Pipeline
=====================

PyFlow applies optimizations in a carefully ordered pipeline:

1. **Analysis Phase**: Run IPA and CPA
2. **Dispatch/Lifetime Phase**: Optimize method calls, then refresh lifetime information
3. **Simplification Phase**: Constant folding, dead code elimination
4. **Advanced Phase**: Code cloning, argument normalization, program culling
5. **Finalization Phase**: Path-sensitive re-analysis, final simplification, and dead store elimination

Custom Pipelines
----------------

Build custom optimization pipelines:

.. code-block:: python

   from pyflow.application.passmanager import PassManager
   from pyflow.application.passes import register_standard_passes

   pass_manager = PassManager()
   register_standard_passes(pass_manager)
   pipeline = pass_manager.build_pipeline([
       "ipa",           # Inter-procedural analysis first
       "cpa",           # Constraint-based analysis
       "simplify",      # Basic simplifications
       "methodcall",    # Method call optimization
       "cullprogram",   # Remove dead code
   ])
   results = pass_manager.run_pipeline(compiler, program, pipeline)

Analyzing Optimization Results
==============================

After optimization, you can analyze the results:

1. **Compare file sizes**: Check if the optimized code is smaller
2. **Run benchmarks**: Measure performance improvements
3. **Check correctness**: Ensure the program still produces correct results

Generating Optimization Reports
--------------------------------

.. code-block:: bash

   pyflow optimize input.py --opt-passes all --verbose

This outputs detailed information about each optimization pass.

Best Practices
==============

1. **Start with correct code**: Ensure the program works before optimizing
2. **Profile first**: Use profiling to identify actual bottlenecks
3. **Apply selectively**: Not all optimizations help every program
4. **Verify results**: Always test optimized code for correctness

Common Optimization Patterns
-----------------------------

Pattern 1: Precompute Constants
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python
   :caption: Before

   # Configuration loaded at runtime
   TAX_RATE = 0.08
   subtotal = 100
   tax = subtotal * TAX_RATE

.. code-block:: python
   :caption: After (when TAX_RATE is constant)

   tax = 8.0

Pattern 2: Inline Simple Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python
   :caption: Before

   def is_even(n):
       return n % 2 == 0

   if is_even(x):
       pass

.. code-block:: python
   :caption: After

   if x % 2 == 0:
       pass

Pattern 3: Eliminate Dead Branches
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python
   :caption: Before

   if DEBUG:  # DEBUG = False in production
       log_detailed_info()
   process_data()

.. code-block:: python
   :caption: After

   process_data()

Next Steps
==========

- Learn more about :ref:`tutorial-understanding-analysis-results`
- Explore detailed :doc:`../optimization/index` documentation
- Understand the :doc:`../explanation/architecture` behind optimizations
