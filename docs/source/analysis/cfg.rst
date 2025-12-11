Control Flow Graph (CFG) Analysis
==================================

PyFlow's Control Flow Graph (CFG) module constructs and analyzes control flow graphs from Python AST, providing the foundation for data flow analysis and optimization.

Key Features
------------

- **Precise CFG Construction**: Builds CFGs from Python AST handling loops, conditionals, exceptions, and complex control structures
- **Dominance Analysis**: Computes dominance relationships and frontiers for advanced analysis
- **Loop Detection**: Identifies and analyzes loop structures
- **CFG Optimization**: Applies control flow optimizations including dead code elimination and simplification
- **SSA Transformation**: Converts CFGs to Static Single Assignment form for data flow analysis

Core Components
---------------

CFG Construction
~~~~~~~~~~~~~~~~

The CFG construction process:

1. Parses Python AST into basic blocks
2. Handles control flow constructs (if/else, loops, try/except)
3. Manages exceptional control flow (exceptions, returns, breaks)
4. Builds edge relationships between blocks

Dominance Analysis
~~~~~~~~~~~~~~~~~~

Provides dominance information for:

- Dominator trees
- Dominance frontiers
- Post-dominance relationships
- Control dependence analysis

SSA Transformation
~~~~~~~~~~~~~~~~~~

Converts CFGs to SSA form for:

- Precise def-use analysis
- Efficient data flow computation
- Optimization opportunities
- Phi node insertion and elimination
