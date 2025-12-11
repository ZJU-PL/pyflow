Call Graph Analysis
===================

PyFlow provides multiple algorithms for call graph construction.



Analysis Approaches
-------------------

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
