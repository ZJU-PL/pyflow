Statistics Collection and Reporting
===================================

The ``pyflow.stats`` module collects metrics during analysis and generates
LaTeX reports.  It is designed for research-oriented workflows where
quantitative comparison of analysis configurations is needed.

.. contents::
   :local:
   :depth: 2

Overview
--------

The stats subsystem tracks per-function and per-operation statistics across
all analyzed code, categorizing functions by their origin (user, interpreter,
runtime, or primitive).  It produces LaTeX tables and figures suitable for
inclusion in research papers.

The module is activated by the ``dumpStats`` configuration flag and runs after
the optimization pipeline via ``contextStats()``.

Key Capabilities
----------------

- **Code classification**: Categorizes functions by annotation type (user
  code, interpreter code, runtime code, primitive stubs)
- **Context counting**: Tracks how many contexts (call sites) each function
  is analyzed under
- **Operation statistics**: Counts AST operation types per code category
- **Ratio analysis**: Compares code vs. context-weighted operation counts
- **Optimization comparison**: Compares operation counts between two analysis
  runs to measure optimization effectiveness
- **Visualization**: Generates pie charts of operation distributions

API Reference
-------------

.. py:class:: StatCollector

   Collects and aggregates statistics during analysis.  Tracks code counts,
   context counts, operation frequencies, and variable access patterns.

   .. py:method:: code(cls: str, code)

      Record a function code object for classification counting.

   .. py:method:: op(cls: str, code, op)

      Record an individual AST operation for frequency counting.

   .. py:method:: copies(cls: str, code, count: int)

      Record synthetic copy-local operations introduced by optimization.

   .. py:method:: digest()

      Finalize and process collected statistics.

   .. py:method:: contextOps() -> dict

      Return context-weighted operation counts indexed by operation type name.

.. py:function:: contextStats(compiler, prgm, name: str, classOK: bool = False) -> StatCollector

   Run the full statistics pipeline for a program.  Requires
   ``config.dumpStats`` to be ``True``.  Generates LaTeX tables and an index
   file in ``outputDirectory/stats/{name}/``.

   :param compiler: The compiler context.
   :param prgm: The analyzed program.
   :param name: A label used for output file naming.
   :param classOK: If ``True``, include per-class breakdown rows in ratio
                   tables.
   :returns: The populated ``StatCollector`` instance.

.. py:function:: classifyCode(code)

   Categorize a code object by its annotation type.  Returns one of:
   ``"user"``, ``"interp"``, ``"runtime"``, or ``"primitive"``.

   :param code: A ``Code`` AST node with annotations.
   :returns: The classification string.

.. py:function:: opRatios(collect: StatCollector, classOK: bool)

   Generate ``op-ratios.tex`` — a LaTeX table comparing raw operation
   counts against context-weighted counts.

.. py:function:: functionRatios(collect: StatCollector, classOK: bool)

   Generate ``context-ratios.tex`` — a LaTeX table comparing function
   counts against context-weighted function counts.

.. py:function:: opsRemoved(current: StatCollector, old: StatCollector)

   Generate ``ops-removed.tex`` — a LaTeX table comparing operation counts
   between two analysis runs (e.g., before and after optimization).

.. py:function:: opPieChart(collect: StatCollector)

   Generate a Ploticus pie chart script (``op-piechart.pl``) for operation
   distribution visualization.  Requires the ``pl`` executable for rendering.

Output Files
------------

All output is written to ``config.outputDirectory/stats/{name}/``:

- ``index.tex`` — Master file including all sub-tables
- ``op-ratios.tex`` — Operation type breakdown by code class
- ``context-ratios.tex`` — Context-weighted function counts by code class
- ``ops-removed.tex`` — Before/after optimization comparison
- ``op-piechart.pl`` — Ploticus script for pie chart generation

Usage
-----

Enable statistics collection in your analysis configuration and call
``contextStats()`` after the pass pipeline has completed:

.. code-block:: python

   from pyflow import config
   from pyflow.stats import contextStats

   config.dumpStats = True

   # ... run analysis and optimization pipeline ...

   stats = contextStats(compiler, program, "my_experiment")

The generated LaTeX files can be compiled with any LaTeX distribution that
includes ``\includegraphics`` and ``\subfloat`` support (e.g., standard
``pdflatex`` with the ``subfig`` package).

See Also
--------

- :doc:`cfg` — CFG construction (statistics draw on CFG-level metrics)
- :doc:`../optimization/index` — Optimization passes whose effects are measured
