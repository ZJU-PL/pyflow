.. _explanation-design-decisions:

================
Design Decisions
================

This document explains the key design decisions made in PyFlow's development,
including the rationale behind them and alternatives considered.

Overview
========

PyFlow makes several important design decisions that affect its capabilities,
performance, and usability. This document explains these decisions and their
implications.

Analysis Precision vs. Performance
===================================

Decision: Default to Sound, Possibly Imprecise Analysis
--------------------------------------------------------

**Decision**: PyFlow prioritizes soundness over precision by default.

**Rationale**:

- Static analysis for security-critical code must not miss real issues
- Users can opt into more precise (but slower) analyses when needed
- False positives are better than false negatives in most use cases

**Trade-offs**:

+----------------------+----------------------+
| Sound Analysis       | Precise Analysis     |
+======================+======================+
| Catches all issues   | May miss some issues |
| May have false pos   | Fewer false positives|
| Slower (more checks) | Faster               |
| Conservative         | Aggressive           |
+----------------------+----------------------+

**Configuration Options**:

.. code-block:: bash

   # Sound but potentially slow
   pyflow optimize input.py --analysis all

   # Faster but may miss issues
   pyflow optimize input.py --analysis cpa

Context Sensitivity
===================

Decision: Support Multiple Context Sensitivity Strategies
----------------------------------------------------------

**Decision**: PyFlow supports different context sensitivity levels rather than
forcing a single approach.

**Available Strategies**:

1. **Insensitive**: Ignore calling context
2. **k-limiting**: Limit context depth
3. **Call-string**: Full call stack
4. **Object-sensitive**: Based on allocation site

**Rationale**:

- Different codebases have different precision needs
- Large codebases may need faster (less precise) analysis
- Security analysis may need maximum precision

**Example**:

.. code-block:: bash

   # Fast but insensitive
   pyflow callgraph input.py --algorithm simple

   # Slower but context-sensitive
   pyflow callgraph input.py --algorithm constraint --context-sensitive

IR Design
=========

Decision: Use Multiple IR Forms
--------------------------------

**Decision**: PyFlow uses multiple intermediate representations for different
purposes.

**IR Forms**:

1. **AST**: Preserves source structure, used for parsing
2. **CFG**: Control flow representation, used for flow analysis
3. **SSA**: Single Static Assignment form, used for optimizations
4. **Store Graph**: Heap abstraction, used for pointer analysis

**Rationale**:

- Each IR is optimized for specific analyses
- No single IR works well for all purposes
- Allows mixing analysis techniques

**Trade-offs**:

+----------------------+----------------------+
| AST                  | SSA                  |
+======================+======================+
| Close to source      | Optimized for opt    |
| Easy to understand   | Complex to build     |
| Good for analysis    | Good for transform   |
+----------------------+----------------------+

Optimization Pipeline
=====================

Decision: Ordered, Composable Passes
-------------------------------------

**Decision**: PyFlow's optimization pipeline applies passes in a specific
order, with each pass building on previous results.

**Default Order**:

1. IPA (Inter-procedural Analysis)
2. CPA (Constraint-based Analysis)
3. Shape Analysis
4. Lifetime Analysis
5. Simplification (constant folding, DCE)
6. Method Call Optimization
7. Function Inlining
8. Argument Normalization
9. Code Cloning
10. Dead Store Elimination
11. Program Culling

**Rationale**:

- Analysis passes must run before optimizations
- Simple optimizations before complex ones
- Inlining requires prior analysis
- DCE after inlining catches new dead code

**Customization**:

.. code-block:: python

   from pyflow.application.passmanager import PassManager
   from pyflow.application.passes import register_standard_passes

   pm = PassManager()
   register_standard_passes(pm)
   pipeline = pm.build_pipeline([
       "ipa",           # Analysis first
       "cpa",
       "simplify",      # Then basic optimizations
       "inlining",      # Then advanced
       "cullprogram",   # Cleanup last
   ])

Language Support
================

Decision: Python-First Design
------------------------------

**Decision**: PyFlow is designed specifically for Python, rather than as a
generic framework adapted for Python.

**Rationale**:

- Python has unique features (dynamic typing, decorators, metaclasses)
- Python-specific optimizations are more effective
- Better integration with Python ecosystem

**Trade-offs**:

+----------------------+----------------------+
| Python-Specific      | Generic              |
+======================+======================+
| Better precision     | Works for any lang   |
| Faster for Python    | Shared development   |
| Limited scope        | Broader impact       |
+----------------------+----------------------+

Extensibility
=============

Decision: Plugin Architecture for Extensions
---------------------------------------------

**Decision**: PyFlow provides a plugin architecture for adding custom
analyses and optimizations.

**Extension Points**:

1. **Analysis Passes**: Add new static analyses
2. **Optimization Passes**: Add custom transformations
3. **Output Formatters**: Add new output formats
4. **Constraint Types**: Add domain-specific constraints

**Example**:

.. code-block:: python

   from pyflow.application.passes import register_standard_passes

   class MyCustomPass:
       """Custom pass example. Passes are registered through the pass manager."""
       pass

   # Register the pass through the pass manager pipeline
   # See pyflow.application.passes for the standard pass registration pattern

CLI Design
==========

Decision: Subcommand-Based CLI
-------------------------------

**Decision**: PyFlow uses a subcommand-based CLI similar to git and docker.

**Subcommands**:

- ``pyflow optimize``: Run analysis and optimization pipeline
- ``pyflow callgraph``: Build call graphs
- ``pyflow ir``: Dump intermediate representations
- ``pyflow alias``: Run alias analysis (flow-sensitive heap or k-CFA pointer)
- ``pyflow security``: Run security analysis
- ``pyflow supply-chain``: Generate SBOMs and audit distribution metadata

**Rationale**:

- Familiar interface for developers
- Clear separation of concerns
- Easy to extend with new commands

Output Format Design
====================

Decision: Multiple Output Formats
----------------------------------

**Decision**: PyFlow supports multiple output formats for different use cases.

**Formats**:

1. **text**: Human-readable, for terminal
2. **json**: Machine-readable, for scripts
3. **dot**: Graphviz format, for visualization
4. **sarif**: Standard format, for CI/CD

**Rationale**:

- Different use cases need different formats
- JSON enables programmatic access
- DOT enables visualization
- SARIF enables CI/CD integration

Error Handling
==============

Decision: Graceful Degradation
-------------------------------

**Decision**: PyFlow continues analysis when possible, rather than failing
completely on errors.

**Strategies**:

1. Skip unparseable files with warnings
2. Use conservative assumptions for ambiguous code
3. Report partial results when analysis is incomplete

**Rationale**:

- Large codebases may have some problematic files
- Users want results for the rest of the code
- Warnings help identify issues without blocking analysis

Performance Trade-offs
======================

Decision: Configurable Analysis Depth
--------------------------------------

**Decision**: PyFlow allows users to configure analysis depth based on their
needs.

**Options**:

- Shallow analysis: Fast, less precise
- Medium analysis: Balanced
- Deep analysis: Slow, more precise

**Example**:

.. code-block:: bash

   # Fast analysis
   pyflow callgraph input.py --algorithm simple

   # Comprehensive analysis
   pyflow security input.py --engine ifds --function main
