Optimizing Python Programs
===========================

PyFlow provides a comprehensive suite of optimization passes that transform Python code for better performance, smaller size, and improved efficiency. These optimizations leverage static analysis to make safe, semantics-preserving transformations.

Overview
========

PyFlow's optimization system operates on an intermediate representation (IR) of Python code, allowing for sophisticated transformations. The optimizations are organized into categories:

- :doc:`constant-folding` - Compile-time evaluation and constant propagation
- :doc:`dataflow` - Data flow analysis and memory optimizations
- :doc:`control-flow` - Control flow simplification and dead code removal
- :doc:`function-optimizations` - Inlining, method call optimization, and specialization
- :doc:`advanced` - Advanced transformations and code rewriting

Optimization Categories
========================

**Constant Folding and Propagation** (fold.py, dce.py, simplify.py)
  Compile-time evaluation of constant expressions, dead code elimination, and iterative simplification.

**Data Flow Optimizations** (dataflow/*.py, loadelimination.py, storeelimination.py)
  Forward/backward data flow analysis for reaching definitions, live variables, redundant load elimination, and dead store elimination.

**Control Flow Optimizations** (simplify.py, cullprogram.py)
  Basic block merging, jump optimization, unreachable code removal, and unused function/class elimination.

**Function and Method Optimizations** (codeinlining.py, methodcall.py, argumentnormalization.py, clone.py)
  Function inlining, virtual method call elimination, argument normalization, and context-specific code cloning.

**Advanced Optimizations** (callconverter.py, convertboolelimination.py, rewrite.py, termrewrite.py)
  Call conversion, boolean elimination, algebraic simplifications, and pattern-based code rewriting.

Optimization Pipeline
=====================

PyFlow applies optimizations in phases:

1. **Analysis Phase**: IPA, CPA, lifetime analysis, shape analysis
2. **Simplification Phase**: Constant folding, dead code elimination, control flow simplification
3. **Advanced Phase**: Method optimization, code cloning, argument normalization, function inlining
4. **Finalization Phase**: Dead store elimination, redundant load elimination, program culling

Pass Dependencies
-----------------

Key dependencies ensure correct ordering:
- IPA → CPA → most optimizations
- Simplify → clone, argument normalization, cull program
- Lifetime analysis runs early

Usage
=====

CLI Usage
---------

.. code-block:: bash

   # Run all optimizations
   pyflow optimize input.py

   # Run specific passes
   pyflow optimize input.py --opt-passes simplify methodcall clone

   # List available passes
   pyflow optimize --list-opt-passes

Programmatic Usage
------------------

.. code-block:: python

   from pyflow.optimization import simplify, methodcall, clone

   # Run individual passes
   simplify.evaluate(compiler, program)
   methodcall.evaluate(compiler, program)
   clone.evaluate(compiler, program)

Pass Manager
------------

For complex pipelines:

.. code-block:: python

   from pyflow.application.passmanager import PassManager

   pass_manager = PassManager()
   pipeline = pass_manager.build_pipeline([
       "ipa", "cpa", "simplify", "methodcall", "clone"
   ])
   results = pass_manager.run_pipeline(compiler, program, pipeline)

.. toctree::
   :maxdepth: 2
   :caption: Detailed Documentation

   constant-folding
   dataflow
   control-flow
   function-optimizations
   advanced