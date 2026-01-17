.. _explanation-algorithms:

=============
Algorithms
=============

This document provides detailed explanations of the algorithms used in PyFlow's
static analysis and optimization passes.

Control Flow Analysis
=====================

CFG Construction Algorithm
--------------------------

PyFlow constructs control flow graphs using the following algorithm:

1. **Parse to AST**: Convert source code to Python's AST
2. **Build Basic Blocks**: Group statements into basic blocks
3. **Handle Control Structures**: Process if/else, loops, try/except
4. **Add Edges**: Connect blocks based on control flow
5. **Post-Process**: Add dominance information and optimize

Block Creation
^^^^^^^^^^^^^^

A basic block is created for:

- Function/method entry
- After unconditional branches
- After conditional branches (both paths)
- Exception handlers
- Loop headers
- Return statements

Dominance Analysis
^^^^^^^^^^^^^^^^^^

PyFlow uses the Lengauer-Tarjan algorithm for dominance computation:

.. code-block:: text

   Algorithm: Lengauer-Tarjan Dominance Algorithm
   Input: CFG with entry node
   Output: Dominator tree

   1. Perform DFS from entry, numbering nodes
   2. Calculate semi-dominators
   3. Build dominator tree using union-find
   4. Optimize with path compression

The algorithm runs in near-linear time: O((V+E) * α(V,E))

Data Flow Analysis
==================

Framework
---------

PyFlow implements data flow analysis using the classic framework:

.. code-block:: python

   class DataFlowAnalysis:
       def __init__(self, direction, lattice, transfer):
           self.direction = direction  # forward or backward
           self.lattice = lattice      # abstract domain
           self.transfer = transfer    # transfer functions

Worklist Algorithm
^^^^^^^^^^^^^^^^^^

.. code-block:: text

   Algorithm: Worklist Data Flow Analysis
   Input: CFG, initial lattice values
   Output: Fixed point (stable lattice values)

   1. Initialize worklist with all nodes
   2. While worklist not empty:
       a. Pop node from worklist
       b. Apply transfer function
       c. If output changed:
           i. Update lattice
           ii. Add successors/predecessors to worklist
   3. Return fixed point

Reaching Definitions
--------------------

Tracks which assignments can reach each program point:

**Lattice**: Powerset of definition sites (bottom = empty, top = all)

**Meet Operation**: Union of definition sets

**Transfer Function**:

.. code-block:: text

   D_in(n) = U { D_out(p) for p in predecessors(n) }
   D_out(n) = (D_in(n) - kill(n)) U gen(n)

Where:
- kill(n): Definitions overwritten in n
- gen(n): New definitions created in n

Live Variables
--------------

Tracks which variables are live at each point:

**Lattice**: Powerset of variables

**Meet Operation**: Union of variable sets

**Transfer Function** (backward analysis):

.. code-block:: text

   L_out(n) = U { L_in(s) for s in successors(n) }
   L_in(n) = use(n) U (L_out(n) - def(n))

Where:
- use(n): Variables used before definition in n
- def(n): Variables defined in n

Constraint-Based Analysis (CPA)
===============================

CPA uses constraint solving to perform precise analysis.

Constraint Generation
---------------------

Constraints are generated for each statement type:

**Assignment**:

.. code-block:: text

   x = y
   Constraint: x ⊇ y

**Field Load**:

.. code-block:: text

   z = x.f
   Constraint: z ⊇ field(x, "f")

**Field Store**:

.. code-block:: text

   x.f = y
   Constraint: field(x, "f") ⊇ y

**Allocation**:

.. code-block:: text

   x = C()
   Constraint: x ⊇ alloc(C)

Worklist Algorithm
------------------

.. code-block:: text

   Algorithm: CPA Worklist Solver
   Input: Set of constraints C
   Output: Satisfying assignment

   1. Initialize all variables to ⊤ (may-be)
   2. worklist = C
   3. while worklist not empty:
       a. Remove constraint c from worklist
       b. Evaluate c with current assignment
       c. If constraint not satisfied:
           i. Strengthen assignment
           ii. Add related constraints to worklist
   4. Return final assignment

Fixed Point
-----------

The algorithm terminates when:

- All constraints are satisfied (stable state)
- Lattice values can only increase (monotonicity)
- Lattice is finite height (guaranteed termination)

Context Sensitivity
-------------------

CPA supports k-limiting context sensitivity:

.. code-block:: text

   Context = (call_stack[0:k])

   For a call at depth d:
   - If d < k: use full call stack
   - If d >= k: merge with similar calls

Shape Analysis
==============

Shape analysis uses region-based abstraction.

Shape Graphs
------------

Abstract representation of heap objects:

.. code-block:: text

   Nodes:
   - Abstract heap objects
   - Variables (pointer nodes)
   - Field nodes

   Edges:
   - Points-to edges (variable → heap)
   - Field edges (heap → field → heap/value)

Region Analysis
---------------

Groups related nodes into regions:

.. code-block:: text

   Region types:
   - L: List-like structures
   - T: Tree-like structures
   - D: DAG structures
   - G: General graphs

Transfer Functions
------------------

Handle each statement type:

**Allocation**:

.. code-block:: text

   x = new()
   Create new abstract node N
   Add points-to edge x → N

**Assignment**:

.. code-block:: text

   x = y
   If y points to {N1, N2, ...}:
       Add points-to edges x → {N1, N2, ...}

**Field Load**:

.. code-block:: text

   z = x.f
   For each N in points-to(x):
       If N has f → M:
           Add points-to edge z → M

**Field Store**:

.. code-block:: text

   x.f = y
   For each N in points-to(x):
       For each M in points-to(y):
           Add/modify field edge N.f → M

Optimization Algorithms
=======================

Constant Folding
----------------

Evaluates constant expressions at compile time:

.. code-block:: python

   def fold_constant(expr):
       if isinstance(expr, BinaryOp):
           left = fold_constant(expr.left)
           right = fold_constant(expr.right)
           if is_constant(left) and is_constant(right):
               return evaluate_binary_op(expr.op, left, right)
       return expr

Dead Code Elimination
---------------------

Removes unreachable and unused code:

.. code-block:: text

   Algorithm: Dead Code Elimination
   Input: CFG
   Output: CFG with dead code removed

   1. Mark entry block as reachable
   2. Traverse reachable blocks via edges
   3. Mark all reachable blocks
   4. Remove unreachable blocks
   5. For each block:
       a. Remove unused variable assignments
       b. Remove code after unconditional return

Function Inlining
-----------------

Replaces function calls with function body:

.. code-block:: text

   Algorithm: Function Inlining
   Input: Call site, callee function
   Output: Inlined code

   1. Check inlining criteria:
       a. Function size < threshold
       b. Call frequency > threshold
       c. No recursion (or limited depth)
   2. Create parameter mapping
   3. Replace call with function body
   4. Update parameter uses
   5. Add return value handling

Complexity Analysis
==================

Time Complexity
---------------

+----------------------+------------------+
| Analysis             | Complexity       |
+======================+==================+
| CFG Construction     | O(n)             |
+----------------------+------------------+
| Dominance Analysis   | O(n log n)       |
+----------------------+------------------+
| Data Flow (worklist) | O(n²) worst case |
+----------------------+------------------+
| CPA                  | O(n²) worst case |
+----------------------+------------------+
| Shape Analysis       | O(n³) worst case |
+----------------------+------------------+

Space Complexity
----------------

+----------------------+------------------+
| Analysis             | Space            |
+======================+==================+
| CFG                  | O(n + e)         |
+----------------------+------------------+
| Data Flow Results    | O(n × d)         |
+----------------------+------------------+
| CPA                  | O(n × c)         |
+----------------------+------------------+
| Store Graph          | O(n × f)         |
+----------------------+------------------+

Where:
- n = number of program points
- e = number of edges
- d = data flow domain size
- c = context depth
- f = number of fields
