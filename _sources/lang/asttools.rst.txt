AST Tools
==========

The ``asttools`` package (``pyflow.language.asttools``) provides utilities for
inspecting and measuring Python ASTs.  Each module focuses on a single
responsibility and works with the standard library ``ast`` module.

.. contents::
   :local:
   :depth: 2

Cyclomatic Complexity
---------------------

``pyflow.language.asttools.complexity``

Computes `McCabe cyclomatic complexity <https://en.wikipedia.org/wiki/Cyclomatic_complexity>`_
for Python source code.  The implementation is adapted from the ``mccabe``
library by Florent Xicluna, Tarek Ziade, and Ned Batchelder.

.. code-block:: python

   from pyflow.language.asttools import mccabe_complexity
   import ast

   tree = ast.parse(source_code)
   score = mccabe_complexity(tree)
   print(f"Total complexity: {score}")

API Reference
~~~~~~~~~~~~~

.. py:function:: mccabe_complexity(tree: ast.AST) -> int

   Compute the total McCabe cyclomatic complexity for an AST.

   Sums the complexity of every function, method, and top-level control-flow
   construct found in the tree.  A function with no branches has complexity
   1; each ``if``, ``while``, ``for``, ``except``, ``with``, and boolean
   operator (``and`` / ``or``) adds 1.

   :param tree: The parsed AST (e.g., from ``ast.parse``).
   :returns: The total cyclomatic complexity.

How It Works
~~~~~~~~~~~~

The algorithm walks the AST and builds a **path graph** for each function
and method scope.  Each control-flow decision point (``if``, ``while``,
``for``, ``except``, ``with``, ``and``, ``or``) adds a node and edge to the
graph.  Cyclomatic complexity is then computed as:

.. math::

   M = E - N + 2P

where *E* is the number of edges, *N* is the number of nodes, and *P* is the
number of connected components (always 1 for a single function).

Complexity Interpretation
~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1

   * - Score
     - Risk Level
     - Guidance
   * - 1–10
     - Low
     - Simple, well-structured code
   * - 11–20
     - Moderate
     - More complex; consider simplifying
   * - 21–50
     - High
     - High risk; refactoring recommended
   * - 51+
     - Very High
     - Untestable; needs decomposition

Decorator Utilities
-------------------

``pyflow.language.asttools.decorators``

Helpers for inspecting function decorators at the AST level without needing
runtime imports.

.. py:function:: has_decorator(func: ASTFunctionDef, decorators: str | Iterable[str]) -> bool

   Check whether a function node has one or more specific decorators.
   Performs a name-based match against ``decorator_list``.

   :param func: The function or async function AST node.
   :param decorators: A single decorator name or a collection of names.
   :returns: ``True`` if at least one of the requested decorators is present.

.. code-block:: python

   from pyflow.language.asttools import has_decorator

   tree = ast.parse("@login_required\ndef foo(): pass")
   func = tree.body[0]
   has_decorator(func, "login_required")  # True
   has_decorator(func, ("cache", "memoize"))  # False

.. py:function:: extract_decorator_name(expr: ast.expr) -> str | None

   Extract a canonical name from a decorator expression node.
   Handles ``ast.Name`` (``@login_required`` → ``"login_required"``),
   ``ast.Attribute`` (``@auth.login_required`` → ``"auth.login_required"``),
   and returns ``None`` for complex expressions like calls.

   :param expr: The decorator expression AST node.
   :returns: The extracted name string, or ``None``.

AST Visitor Utilities
---------------------

``pyflow.language.asttools.visitors``

Focused, single-responsibility visitors that answer specific questions about
an AST subtree without pulling in heavy analysis logic.  All visitors
**do not recurse into nested functions or classes**, ensuring results are
scoped to the function being analyzed.

Yield Detection
~~~~~~~~~~~~~~~

.. py:function:: contains_yield(node: ast.AST) -> bool

   Check whether *node* (typically a function def) contains ``yield`` or
   ``yield from``.  Determines whether the outer function is a generator.

   :param node: The AST node to inspect (e.g., ``ast.FunctionDef``).
   :returns: ``True`` if a ``yield`` or ``yield from`` is found in the top-level body.

.. py:class:: YieldVisitor

   Visitor that detects ``yield`` and ``yield from``.  Exposes
   ``found_yield`` and ``found_yield_from`` boolean attributes.

Return Analysis
~~~~~~~~~~~~~~~

.. py:function:: get_return_info(node: ast.AST) -> tuple[bool, bool]

   Return ``(has_return, has_empty_return)`` for *node*.  A bare return
   (``return`` without a value) counts as an empty return.

   :param node: The AST node to inspect.
   :returns: A 2-tuple ``(has_return, has_empty_return)``.

.. py:class:: ReturnVisitor

   Visitor that detects ``return`` statements.  Exposes ``has_return`` and
   ``has_empty_return`` boolean attributes.

Assert Detection
~~~~~~~~~~~~~~~~

.. py:function:: contains_assert(node: ast.AST) -> bool

   Check whether *node* contains ``assert`` statements.

   :param node: The AST node to inspect.
   :returns: ``True`` if an ``assert`` is found.

.. py:class:: AssertVisitor

   Visitor that collects ``assert`` statements.  Exposes an ``asserts`` list.

See Also
--------

- :doc:`ast` — PyFlow's AST node types
- :doc:`frontend` — How Python source is parsed into ASTs
