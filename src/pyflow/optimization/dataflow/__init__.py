"""
Data flow analysis framework for optimizations.

This package provides forward and backward data flow analysis infrastructure
used by various optimizations. The framework supports:

- Forward data flow: Information flows from entry to exit (e.g., constant propagation)
- Backward data flow: Information flows from exit to entry (e.g., liveness analysis)
- Control flow handling: Loops, conditionals, exceptions
- Meet operations: Combining information from multiple paths

The data flow framework is used by:
- Constant folding (forward: constant propagation)
- Dead code elimination (backward: liveness analysis)
- Method call optimization (forward: method binding)
- Load/store elimination (forward/backward: reaching definitions/liveness)
"""

