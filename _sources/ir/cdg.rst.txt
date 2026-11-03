Control Dependence Graph (CDG)
==============================

The ``pyflow.ir.cdg`` package represents control dependencies between program
statements and provides construction helpers for program slicing and control
flow reasoning.

Overview
--------

CDG construction uses dominance frontiers to determine which statements control the execution of others. This is essential for:

- **Program Slicing**: Identifying statements that affect a particular point of interest
- **Debugging**: Understanding control flow dependencies
- **Optimization**: Safe code motion and elimination

Construction Process
--------------------

1. **CFG Analysis**: Builds on control flow graph analysis
2. **Dominance Frontiers**: Computes control dependence using dominance frontiers
3. **Edge Creation**: Creates edges from controlling to controlled statements
4. **Graph Refinement**: Handles complex control structures and exceptions

The default CDG projects structured control flow: implicit ``fail``/``error``
edges alongside a normal continuation are excluded from post-dominance and
dependence construction. An ordinary potentially raising suite therefore
does not become a controller of the entire remaining function. Explicit
unconditional exceptional transfers remain in the projection. A return after
both arms of an ``if`` is not controlled by either arm merely because an
operation in that arm might raise.

Use ``construct_cdg(cfg, include_exceptional=True)`` or
``CDGConstructor(cfg, include_exceptional=True)`` to include implicit
exceptional flow. In that mode, later statements can correctly depend on
earlier operations completing normally; dense control edges are possible.
The CFG itself is unchanged in either mode. Text and JSON exports identify
the selected mode.

Applications
------------

- Program slicing for debugging and analysis
- Control flow-aware optimization
- Dependency analysis for refactoring
- Security analysis of control flow patterns
