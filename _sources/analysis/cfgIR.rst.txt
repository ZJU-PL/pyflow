Control Flow Graph Intermediate Representation (CFG-IR)
=========================================================

CFG-IR provides an intermediate representation specifically designed for control flow analysis, bridging AST and lower-level analysis representations.

Purpose
-------

CFG-IR serves as a bridge between Python AST and analysis-specific representations:

- **Unified Representation**: Standardizes control flow constructs for analysis
- **Optimization Ready**: Prepares CFGs for optimization passes
- **Analysis Integration**: Provides common interface for various analysis modules
- **Structural Analysis**: Enables deep analysis of control flow patterns

Key Components
--------------

Data Flow Synthesis
~~~~~~~~~~~~~~~~~~~

- Converts AST operations to data flow operations
- Handles variable assignments and expressions
- Manages control flow dependencies
- Prepares for inter-procedural analysis

Structural Analysis
~~~~~~~~~~~~~~~~~~~

- Analyzes loop structures and nesting
- Identifies conditional patterns
- Detects unreachable code
- Provides structural metrics for optimization

CFG-IR Operations
~~~~~~~~~~~~~~~~~

- **Basic Blocks**: Group operations into atomic units
- **Control Edges**: Represent control flow transfers
- **Data Dependencies**: Track value flow between operations
- **Optimization Hooks**: Enable analysis-driven transformations
