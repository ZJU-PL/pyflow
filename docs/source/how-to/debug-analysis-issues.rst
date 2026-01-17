.. _how-to-debug-analysis-issues:

===========================
How to Debug Analysis Issues
===========================

This guide explains how to diagnose and resolve issues with PyFlow's analysis.

Common Issues
=============

PyFlow analysis may encounter various issues. This guide helps you identify
and resolve them.

Syntax Errors
=============

Symptom
-------

Analysis fails with syntax error messages.

Solution
--------

1. Verify the Python file is syntactically correct:

   .. code-block:: bash

      python -m py_compile input.py

2. Check for Python version compatibility:

   .. code-block:: bash

      python --version

3. Run PyFlow with verbose output:

   .. code-block:: bash

      pyflow analyze input.py --verbose

Example error and fix:

.. code-block:: text

   SyntaxError: invalid syntax (line 15)
   x = )  # Missing operand

Fix:

.. code-block:: python

   x = 5  # Added operand

Import Errors
=============

Symptom
-------

Analysis fails due to missing modules or import errors.

Solution
--------

1. Install required dependencies:

   .. code-block:: bash

      pip install -r requirements.txt

2. Use virtual environment:

   .. code-block:: bash

      source venv/bin/activate

3. Check for version mismatches:

   .. code-block:: bash

      pip list | grep pyflow

4. Exclude problematic files:

   .. code-block:: bash

      pyflow analyze input.py --exclude "test_*"

Incomplete Analysis
===================

Symptom
-------

Analysis completes but misses some functions or produces incomplete results.

Solution
--------

1. Increase analysis depth:

   .. code-block:: bash

      pyflow callgraph input.py --max-depth 20

2. Enable all analyses:

   .. code-block:: bash

      pyflow analyze input.py --analysis all

3. Check for unhandled language features:

   .. code-block:: bash

      pyflow ir input.py --dump-ast function_name

4. Use context-sensitive analysis:

   .. code-block:: bash

      pyflow analyze input.py --analysis cpa --cpa-config context_sensitive=true

Incorrect Results
=================

Symptom
-------

Analysis produces incorrect or unexpected results.

Solution
--------

1. Verify with multiple analysis passes:

   .. code-block:: bash

      pyflow analyze input.py --analysis cpa,ipa,shape

2. Compare with expected behavior:

   .. code-block:: python

      # Expected: function returns positive numbers
      # Check actual behavior
      assert result > 0

3. Use more precise analysis:

   .. code-block:: bash

      pyflow analyze input.py \
          --analysis cpa \
          --cpa-config flow_sensitive=true,field_sensitive=true

4. Report false positives/negatives:

   .. code-block:: bash

      pyflow security input.py --report-false-positive --details "..."

Performance Issues
==================

Symptom
-------

Analysis takes too long or runs out of memory.

Solution
--------

1. Limit analysis scope:

   .. code-block:: bash

      pyflow analyze input.py --exclude "test_*","*_test.py"

2. Reduce context depth:

   .. code-block:: bash

      pyflow analyze input.py --cpa-config max_context_depth=2

3. Use faster analysis algorithms:

   .. code-block:: bash

      pyflow callgraph input.py --algorithm cha

4. Process files incrementally:

   .. code-block:: bash

      pyflow analyze file1.py --output results1.json
      pyflow analyze file2.py --output results2.json
      # Combine results programmatically

5. Use streaming mode for large files:

   .. code-block:: bash

      pyflow analyze large_file.py --streaming

Debugging Techniques
====================

Enable Verbose Output
---------------------

Get detailed information about analysis progress:

.. code-block:: bash

   pyflow analyze input.py --verbose --log-level debug

Log to File
-----------

Capture detailed logs for later analysis:

.. code-block:: bash

   pyflow analyze input.py --log-file analysis.log

Dump Intermediate Representations
---------------------------------

Inspect intermediate representations:

.. code-block:: bash

   pyflow ir input.py \
       --dump-ast function_name \
       --dump-format json \
       --output ast.json

   pyflow ir input.py \
       --dump-cfg function_name \
       --dump-format json \
       --output cfg.json

Debug Mode
----------

Run analysis in debug mode for maximum information:

.. code-block:: bash

   pyflow analyze input.py --debug --verbose

Common Error Messages
======================

Error: "Module not found"
-------------------------

The required module is not installed or not in the Python path.

Solution:

.. code-block:: bash

   pip install missing_module
   # or
   PYTHONPATH=/path/to/module pyflow analyze input.py

Error: "Function not found"
---------------------------

The specified function does not exist in the source file.

Solution:

.. code-block:: bash

   # List all functions in file
   pyflow ir input.py --dump-ast all --format json | grep '"name"'

Error: "Analysis timeout"
-------------------------

The analysis took too long and was aborted.

Solution:

.. code-block:: bash

   pyflow analyze input.py --timeout 300  # 5 minute timeout

Error: "Memory exhausted"
-------------------------

The analysis ran out of memory.

Solution:

.. code-block:: bash

   pyflow analyze input.py --memory-limit 4G
   # or analyze smaller subsets

Getting Help
============

If you cannot resolve an issue:

1. Check the documentation at: https://github.com/ZJU-PL/pyflow/docs
2. Search existing issues: https://github.com/ZJU-PL/pyflow/issues
3. Create a new issue with:

   - Full error message
   - Minimal reproduction case
   - Environment details (Python version, OS, PyFlow version)
