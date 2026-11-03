Control Flow Graph (CFG)
========================

The ``pyflow.ir.cfg`` package constructs and represents control flow graphs
from Python AST nodes. It also provides the graph algorithms and
transformations used by analyses and optimization passes.

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

Exception flow
~~~~~~~~~~~~~~

``try/except/else/finally`` is lowered into separate protected, handler,
else, and cleanup blocks. Potentially raising operations have explicit
``fail``/``error`` successors. Typed handlers are tested in source order;
unmatched exceptions propagate outwards. Errors in a handler or ``else``
suite bypass that try's handlers.

Assignments in protected suites evaluate their right-hand side before
committing local bindings on the normal edge. SSA therefore merges the
values available at each exceptional predecessor, including assignments
completed before a later operation raises. Cleanup executes on normal,
return, break, continue, and exceptional paths; abrupt completion in
``finally`` replaces a pending transfer.

Source-level ``with`` and ``async with`` use these same exception regions,
including cleanup when their bodies return or leave a loop. Handler type
matching is conservative: both match and non-match paths may remain in the
graph without exception type facts. Exception-group partitioning for
``except*`` is not modeled precisely. Reconstruction of exception-aware CFGs
back into structured AST by ``structuralanalysis`` is not yet supported;
CFG and SSA inspection are available directly.

IFDS and CPG consume the lowered graph directly. ``ExceptionMatch`` blocks
identify ordered handler dispatch separately from application calls.
Exceptional cleanup paths capture the pending exception and end in an explicit
rethrow, preserving value flow into enclosing handlers. Both consumers track
anonymous local temporaries by symbol identity; built-in exception types and
tuple handlers support first-match refinement, while dynamic types retain
conservative branches.

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

Expression renaming, verification, and CFG/SSA dump rendering use explicit
stacks, so deeply nested operator chains do not consume a Python frame per
AST level. This does not make every AST transformation iterative.

``verify_ssa(cfg)`` checks value availability, dominance, and phi consistency.
SSA dumps, ``get_ssa`` queries, and PDG construction with ``run_ssa=True``
verify before returning results or expanding phis. Invalid SSA raises
``SSAVerificationError``; query results are cached only after verification.

SSA versions describe local values. Globals, closure cells, attributes, and
subscripts remain storage operations handled by the memory model. Local copy
assignments can disappear through reach-through optimization, so SSA does not
preserve a value for every source binding. Walrus definitions remain inside
``NamedExpr`` expressions, including switch conditions; consumers must inspect
those expressions rather than only scanning ``Suite.ops`` for assignments.
Unbound reads are legal values marked ``Value.undefined=True``. Verification
accepts these values; consumers must check that flag explicitly.
