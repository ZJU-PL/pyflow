Overview
========

===============
What is PyFlow?
===============

PyFlow is a comprehensive static analysis and compilation framework for Python code. It provides a rich set of analysis capabilities that enable deep understanding and optimization of Python programs without requiring their execution.

PyFlow is built around a modular architecture that separates concerns into distinct analysis domains, making it both powerful and extensible for research and practical applications.

===============
Key Features
===============

Static Analysis Capabilities
----------------------------

**Control Flow Analysis**
  - Constructs precise Control Flow Graphs (CFGs) from Python AST
  - Handles complex control structures including loops, conditionals, and exception handling
  - Provides dominance analysis and loop detection

**Data Flow Analysis**
  - Forward and backward data flow analysis with configurable meet functions
  - Support for various analysis domains (constants, types, shapes)
  - Flow-sensitive analysis with precise modeling of Python semantics

**Inter-procedural Analysis (IPA)**
  - Context-sensitive analysis across function boundaries
  - Precise modeling of function calls and returns
  - Support for complex calling patterns including closures and generators

**Constraint-based Analysis (CPA)**
  - Constraint-based analysis using constraint solving for Python objects
  - Precise modeling of object aliasing and sharing through constraint propagation
  - Support for complex object relationships and inheritance via constraint relationships

**Shape Analysis**
  - Analysis of data structure shapes and properties
  - Region-based shape analysis for complex data structures
  - Support for list, dictionary, and custom object shapes

**Call Graph Analysis**
  - Multiple algorithms for call graph construction
  - AST-based and PyCG-based approaches
  - Support for dynamic dispatch and complex calling patterns

Optimization Capabilities
-------------------------

**Constant Folding**
  - Compile-time evaluation of constant expressions
  - Elimination of redundant computations
  - Support for complex constant propagation

**Dead Code Elimination**
  - Removal of unreachable code
  - Elimination of unused variables and assignments
  - Support for complex control flow patterns

**Function Inlining**
  - Inlining of small functions to reduce call overhead
  - Context-sensitive inlining decisions
  - Support for complex inlining scenarios

**Load/Store Elimination**
  - Elimination of redundant memory operations
  - Optimization of object attribute access
  - Support for complex data flow patterns

**Method Call Optimization**
  - Optimization of method dispatch
  - Elimination of indirect calls where possible
  - Support for complex inheritance hierarchies


===============
Architecture
===============

PyFlow is built around a modular architecture with clear separation of concerns:

**Analysis Layer** (`src/pyflow/analysis/`)
  - Core analysis algorithms and data structures
  - Modular design allowing easy extension
  - Support for various analysis domains

**Optimization Layer** (`src/pyflow/optimization/`)
  - Compiler optimization passes
  - Data flow-based optimizations
  - Integration with analysis results

**Decompiler Layer** (`src/pyflow/decompiler/`)
  - Bytecode analysis and decompilation
  - AST reconstruction from bytecode
  - Integration with analysis pipeline

**Application Layer** (`src/pyflow/application/`)
  - High-level program representation
  - Analysis pipeline orchestration
  - Context management

**Language Layer** (`src/pyflow/language/`)
  - Python-specific language constructs
  - AST representation and manipulation
  - Language-specific analysis support

**CLI Layer** (`src/pyflow/cli/`)
  - Command-line interface
  - Integration with analysis and optimization
  - Support for various output formats