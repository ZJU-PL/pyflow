.. _explanation-best-practices:

========================================
Best Practices
========================================

This page outlines best practices for using PyFlow effectively. Following these
guidelines will help you get the most out of PyFlow's static analysis and
optimization capabilities.

This guide is organized into sections for different use cases and experience levels.

Beginner Best Practices
========================

Start with Simple Analysis
--------------------------

**Do**: Begin with basic analysis before diving into complex configurations.

**Don't**: Jump straight to deep, context-sensitive analysis without understanding
the basics.

**Why**: Simple analysis is faster and often sufficient for initial understanding.
Complex analysis takes longer and may be harder to interpret.

**Example**:

.. code-block:: bash

   # Good: Start simple
   pyflow callgraph input.py

    # Then pass specific options as needed
   pyflow callgraph input.py --algorithm constraint

Choose the right tools for your task.

- Use ``pyflow callgraph`` for textual call graph analysis
- Use ``pyflow ir --dump-format dot`` for IR visualization
- Use ``pyflow security --format sarif`` for CI/CD security integration

**Example**:

.. code-block:: bash

   # For quick check
   pyflow callgraph input.py

   # For constraint-based analysis
   pyflow callgraph input.py --algorithm constraint

   # For visualization, use ir dump with DOT format
   pyflow ir input.py --dump-cfg main --dump-format dot --dump-output ./out

Check Configuration
-------------------

**Do**: Verify your configuration is applied correctly.

**Why**: Misconfiguration can lead to incorrect or missing results.

**Example**:

.. code-block:: bash

   # Verify configuration
   pyflow optimize input.py --verbose

Intermediate Best Practices
============================

Combine Multiple Analyses
--------------------------

**Do**: Use multiple analyses together for comprehensive understanding.

**Why**: Different analyses provide different insights. Combining them gives a
complete picture.

**Example**:

.. code-block:: bash

   # Run analysis with CPA
   pyflow optimize input.py --analysis cpa

   # Or run all analyses
   pyflow optimize input.py --analysis all

Profile Before Optimizing
--------------------------

**Do**: Profile your code to identify actual bottlenecks before optimizing.

**Why**: Optimizing the wrong code wastes time and may not improve performance.

**Example**:

.. code-block:: python

   import cProfile

   # Profile before optimizing
   cProfile.run("your_function()", "profile.prof")

   # Analyze results
   import pstats
   stats = pstats.Stats("profile.prof")
   stats.sort_stats("cumulative").print_stats(20)

   # Then optimize based on results
   pyflow optimize hot_path.py --opt-passes all

Verify Optimized Code
---------------------

**Do**: Always test optimized code for correctness.

**Why**: Optimizations should not change program behavior.

**Example**:

.. code-block:: python

   def test_optimization():
       # Test with same inputs
       original_result = original_function(input_data)
       optimized_result = optimized_function(input_data)

       # Should produce same results
       assert original_result == optimized_result

       # Performance should improve
       import timeit
       original_time = timeit.timeit(original_function, number=1000)
       optimized_time = timeit.timeit(optimized_function, number=1000)

       assert optimized_time < original_time

Use Incremental Analysis
-------------------------

**Do**: Use incremental analysis for large projects.

**Why**: Analyzing only changed files is much faster than full analysis.

**Example**:

.. code-block:: python

   # Use Python API for incremental analysis
   from pyflow.analysis.cache.incremental import IncrementalCache

   cache = IncrementalCache()
   cache.store(program, results)
   # Later: re-analyze only changed files

Advanced Best Practices
========================

Configure Context Sensitivity
------------------------------

**Do**: Tune context sensitivity based on your precision and performance needs.

**Why**: More context sensitivity means more precise results but slower analysis.

**Example**:

.. code-block:: python

   # Fast, context-insensitive
   context.set_config("cpa.context_sensitive", False)

   # Balanced, k-limiting
   context.set_config("cpa.context_sensitive", True)
   context.set_config("cpa.k_value", 3)

   # Precise, full context
   context.set_config("cpa.context_sensitive", True)
   context.set_config("cpa.max_context_depth", 10)

Customize for Your Codebase
----------------------------

**Do**: Create custom configurations for your specific codebase.

**Why**: Default settings may not be optimal for your code patterns.

**Example**:

.. code-block:: python

   from pyflow import Context

   context = Context()
   context.slots["cpa.field_sensitive"] = True
   context.slots["cpa.max_context_depth"] = 5

   [optimization]
   # Custom optimization settings
   max_inline_size = 15
   enable_dce = true

Integrate with Development Workflow
------------------------------------

**Do**: Integrate PyFlow into your development and CI/CD workflows.

**Why**: Early detection of issues is cheaper than late detection.

**Example**:

.. code-block:: yaml
   :caption: .github/workflows/pyflow.yml

   name: PyFlow Analysis

   on: [push, pull_request]

   jobs:
     analyze:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - name: Set up Python
           uses: actions/setup-python@v4
           with:
             python-version: '3.10'
         - name: Install PyFlow
           run: pip install pyflow
          - name: Run Analysis
            run: |
              pyflow callgraph . --output callgraph.txt
              pyflow security . --format sarif --output security.sarif
          - name: Upload SARIF
            uses: github/codeql-action/upload-sarif@v2
            with:
              sarif_file: security.sarif

Security Analysis Best Practices
=================================

Scan Early and Often
--------------------

**Do**: Run security analysis regularly, not just before releases.

**Why**: Catching vulnerabilities early is cheaper and safer.

**Example**:

.. code-block:: bash

   # In pre-commit hook
   pyflow security input.py

   # In CI/CD
   pyflow security . --format sarif --output security.sarif

Understand Findings
-------------------

**Do**: Take time to understand security findings.

**Why**: False positives may occur. Understanding helps you assess real risk.

**Example**:

.. code-block:: bash

   # Get detailed output
   pyflow security input.py --verbose

   # Check context of finding
   pyflow ir input.py --dump-ast function_name --verbose

Prioritize Remediation
-----------------------

**Do**: Prioritize findings by severity and exploitability.

**Why**: Not all findings are equally important. Focus on high-risk issues first.

**Example**:

.. code-block:: bash

   # Focus on specific checks
   pyflow security input.py --verbose

   # Get detailed output
   pyflow security input.py --debug

Performance Best Practices
===========================

Choose Appropriate Analysis Depth
----------------------------------

**Do**: Match analysis depth to your needs.

- Shallow: Quick overview, initial understanding
- Medium: Balanced analysis, most use cases
- Deep: Maximum precision, security-critical code

**Why**: Deep analysis is slower. Use depth appropriate for your use case.

**Example**:

.. code-block:: bash

   # Quick check — use simple callgraph
   pyflow callgraph input.py --algorithm simple

   # Standard analysis — default optimization
   pyflow optimize input.py

   # Security analysis — use IFDS engine
   pyflow security input.py --engine ifds

Use Caching
----------------------------------------

**Do**: Use PyFlow's internal caching capabilities for repeated analysis.

**Why**: Caching avoids re-analyzing unchanged code.

**Example**:

.. code-block:: python

   from pyflow.analysis.cache.incremental import IncrementalCache

   cache = IncrementalCache()
   cache.store(program, results)
   # Later: re-analyze only changed files

Parallel Analysis
-----------------

**Do**: Use parallel analysis for large projects.

**Why**: Parallel analysis utilizes multiple CPU cores.

**Example**:

.. code-block:: bash

   # Use recursive mode for large projects
   pyflow optimize project/ --recursive

Documentation Best Practices
=============================

Document Analysis Configurations
---------------------------------

**Do**: Document your PyFlow configuration and the rationale behind it.

**Why**: Helps team members understand and reproduce analyses.

**Example**:

.. code-block:: markdown
   :caption: ANALYSIS.md

   # PyFlow Analysis Configuration

   ## Purpose
   This document describes our PyFlow analysis configuration and rationale.

   ## Configuration

   ```toml
   [analysis]
   context_sensitive = true
   max_context_depth = 5

   [optimization]
   enable_dce = true
   max_inline_size = 20
   ```

   ## Rationale

   - Context depth of 5 balances precision and performance for our codebase
   - DCE is enabled to remove obvious dead code before optimization

Include Analysis Results in Documentation
------------------------------------------

**Do**: Include relevant analysis results in project documentation.

**Why**: Documents current state and helps track improvements.

**Example**:

.. code-block:: markdown
   :caption: ARCHITECTURE.md

   ## Call Graph

   ![Call Graph](docs/callgraph.png)

   Generated: 2024-01-15
   Command: `pyflow callgraph src/ --output docs/callgraph.png`

Troubleshooting Best Practices
===============================

Start with Verbose Output
--------------------------

**Do**: Use verbose mode when troubleshooting.

**Why**: Verbose output provides detailed information about what's happening.

**Example**:

.. code-block:: bash

   pyflow optimize input.py --verbose --debug

Reproduce with Minimal Example
-------------------------------

**Do**: Create minimal examples when reporting issues.

**Why**: Minimal examples are easier to debug and faster to fix.

**Example**:

.. code-block:: python
   :caption: minimal_example.py

   # Minimal example demonstrating the issue
   def problematic_function():
       # Only include code related to the issue
       pass

Check Existing Issues
---------------------

**Do**: Check existing issues before reporting new ones.

**Why**: Your issue may already be known or have a workaround.

**Example**:

.. code-block:: bash

   # Search existing issues
   gh issue list --repo ZJU-PL/pyflow --search "context"

   # Check documentation
   pyflow optimize --help
