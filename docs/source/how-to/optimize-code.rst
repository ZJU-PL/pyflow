.. _how-to-optimize-code:

==================
How to Optimize Code
==================

This guide explains how to use PyFlow's optimization passes to improve the
performance of your Python programs.

When to Use Optimization
=========================

Use PyFlow optimization when you need to:

- Reduce execution time of Python code
- Decrease code size
- Eliminate redundant operations
- Prepare code for further optimization
- Improve performance of compute-intensive functions

Optimization Levels
===================

PyFlow supports different optimization levels:

Basic (simplify)
----------------

Constant folding and dead code elimination:

.. code-block:: bash

   pyflow optimize input.py --opt-passes simplify

Moderate (methodcall)
---------------------

Method call optimization and data flow improvements:

.. code-block:: bash

   pyflow optimize input.py --opt-passes simplify methodcall

Aggressive (all)
----------------

All available optimizations:

.. code-block:: bash

   pyflow optimize input.py

Inlining remains experimental and must be enabled explicitly when requested.

Applying Optimizations
======================

Via Command Line
----------------

The simplest way to apply optimizations:

.. code-block:: bash

   pyflow optimize input.py

Apply specific passes:

.. code-block:: bash

   pyflow optimize input.py \
       --opt-passes simplify methodcall inlining \
       --experimental-inlining

Write a report to disk:

.. code-block:: bash

   pyflow optimize input.py --dump --output optimization-analysis.txt

Via Python API
--------------

For programmatic optimization:

.. code-block:: python

   from pyflow.application.passmanager import PassManager
   from pyflow.application.passes import register_standard_passes

   pass_manager = PassManager()
   register_standard_passes(pass_manager)

   pass_manager.run_passes(
       compiler,
       program,
       ["simplify", "methodcall", "inlining"],
   )

Via Pass Manager
----------------

For complex optimization pipelines:

.. code-block:: python

   from pyflow.application.passmanager import PassManager
   from pyflow.application.passes import register_standard_passes

   pass_manager = PassManager()
   register_standard_passes(pass_manager)
   pipeline = pass_manager.build_pipeline([
       "simplify",          # Basic simplifications
       "methodcall",        # Method call optimization
       "argumentnormalization",  # Normalize arguments
       "inlining",          # Function inlining
       "cullprogram",       # Remove dead code
   ])

   results = pass_manager.run_pipeline(compiler, program, pipeline)

Common Optimizations
====================

Constant Folding
----------------

Evaluate constant expressions at compile time:

.. code-block:: python
   :caption: Before

   def calculate():
       result = 3.14159 * 5 * 5  # 78.53975
       return result

.. code-block:: python
   :caption: After

   def calculate():
       result = 78.53975
       return result

Dead Code Elimination
---------------------

Remove unreachable and unused code:

.. code-block:: python
   :caption: Before

   DEBUG = False

   def process():
       if DEBUG:
           log_detailed_information()
       return core_logic()

.. code-block:: python
   :caption: After

   def process():
       return core_logic()

Function Inlining
-----------------

Replace function calls with function body:

.. code-block:: python
   :caption: Before

   def square(x):
       return x * x

   result = square(5)

.. code-block:: python
   :caption: After

   result = 25

Method Call Optimization
------------------------

Optimize method dispatch:

.. code-block:: python
   :caption: Before

   class Math:
       def double(self, x):
           return x * 2

   m = Math()
   result = m.double(5)

.. code-block:: python
   :caption: After

   # Direct call without lookup overhead
   result = 5 * 2

Argument Normalization
----------------------

Eliminate ``*args`` when possible:

.. code-block:: python
   :caption: Before

   def process(a, b, *args, **kwargs):
       return a + b

.. code-block:: python
   :caption: After

   def process(a, b, arg0, arg1):
       return a + b

Optimization Best Practices
===========================

1. Profile Before Optimizing
----------------------------

Use profiling to identify actual bottlenecks:

.. code-block:: python

   import cProfile
   import pstats

   # Profile your code
   cProfile.run("your_function()", "profile.prof")

   # Analyze results
   stats = pstats.Stats("profile.prof")
   stats.sort_stats("cumulative").print_stats(20)

2. Verify Correctness
---------------------

Always test optimized code:

.. code-block:: python

   import pytest

   def test_optimization_preserves_behavior():
       original_result = original_function(input_data)
       optimized_result = optimized_function(input_data)
       assert original_result == optimized_result

3. Measure Performance
----------------------

Benchmark before and after:

.. code-block:: python

   import timeit

   original_time = timeit.timeit(original_function, number=1000)
   optimized_time = timeit.timeit(optimized_function, number=1000)

   speedup = original_time / optimized_time
   print(f"Speedup: {speedup:.2f}x")

4. Apply Selectively
--------------------

Not all optimizations help every program. Test different combinations:

.. code-block:: bash

   # Try different pass combinations
   pyflow optimize input.py --opt-passes simplify
   pyflow optimize input.py --opt-passes simplify methodcall
   pyflow optimize input.py --opt-passes simplify methodcall inlining --experimental-inlining

Troubleshooting
===============

Issue: Optimization changes behavior
-------------------------------------

- Some optimizations may change behavior in edge cases
- Use ``--no-opt-passes`` to disable optimizations
- Report bugs at https://github.com/ZJU-PL/pyflow/issues

Issue: No visible improvement
------------------------------

- The code may already be optimized
- Profile to find actual bottlenecks
- Manual optimization may be needed for hot paths

Issue: Large code size increase
--------------------------------

- Inlining can increase code size
- Use selective inlining with size limits
- Consider trade-offs between speed and size
