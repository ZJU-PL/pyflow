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

Applications
------------

- Program slicing for debugging and analysis
- Control flow-aware optimization
- Dependency analysis for refactoring
- Security analysis of control flow patterns
