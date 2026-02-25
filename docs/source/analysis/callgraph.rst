Call Graph Analysis
===================

PyFlow provides multiple algorithms for call graph construction.



Analysis Approaches
-------------------

Constraint-Based Analysis (Default)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Abstract Value Propagation**: Propagates abstract values (functions, classes, instances, bound methods, modules) through assignments, calls, and returns
- **Context Sensitivity**: Optional call-site context sensitivity with configurable depth for improved precision
- **Full MRO Support**: Complete C3 MRO linearization for class method lookup
- **Rich Semantics**: Handles descriptors, closures, comprehensions, and container tracking
- **Dynamic Summaries**: Generates explicit summary nodes for unresolved call targets

.. code-block:: python

   from pyflow.analysis.callgraph import extract_call_graph_constraint

   # Context-insensitive (default)
   cg = extract_call_graph_constraint(source_code)

   # Context-sensitive with call-string depth of 2
   cg = extract_call_graph_constraint(
       source_code,
       context_sensitive=True,
       context_depth=2,
   )

AST-Based Analysis
~~~~~~~~~~~~~~~~~~

- **Static Analysis**: Analyzes source code AST to identify function calls
- **Precise Resolution**: Handles direct function calls and simple indirection
- **Fast Construction**: Quick analysis suitable for large codebases
- **Conservative**: May include spurious edges

PyCG-Based Analysis
~~~~~~~~~~~~~~~~~~~

- **Framework Support**: Better handling of popular Python frameworks
- **Comprehensive**: Captures more call relationships than pure AST analysis



Applications
------------

- **Dependency Analysis**: Understand module and function dependencies
- **Optimization**: Identify inlining and specialization opportunities
- **Security Analysis**: Detect potentially dangerous call patterns
- **Code Understanding**: Visualize complex codebases
