Language Module
================

The Language module provides language-specific implementations for representing and processing Python code in PyFlow. This module defines the core intermediate representation (IR) used throughout the analysis pipeline.

===============
Overview
===============

The Language module (`src/pyflow/language/`) contains Python language support:

- :doc:`ast` - Abstract Syntax Tree node definitions for PyFlow's IR
- Program representation - Object model and type system
- AST transformations - Collapsing, folding, and def-use analysis
- Code generation - Output and simple code generation

The language module provides:
- **AST Representation**: Rich intermediate representation capturing Python semantics
- **Object Model**: Representation of Python objects, types, and relationships
- **Type System**: Support for abstract and concrete types, type information
- **Annotations**: Context-sensitive metadata attached to AST nodes

===============
Key Components
===============

AST Node System
---------------

The AST system (`pyflow.language.python.ast`) provides node types:

**Reference Nodes**: ``Existing`` (constants), ``Local`` (variables), ``DoNotCare`` (wildcards)

**Expression Nodes**: ``Call``, ``DirectCall``, ``MethodCall``, ``BinaryOp``, ``UnaryPrefixOp``, ``GetAttr``, ``SetAttr``, ``GetSubscript``, ``SetSubscript``, ``BuildTuple``, ``BuildList``, ``BuildMap``

**Statement Nodes**: ``Assign``, ``Return``, ``Discard``, ``Delete``

**Control Flow Nodes**: ``Switch``, ``While``, ``For``, ``TryExceptFinally``, ``Break``, ``Continue``

**Code Nodes**: ``Code``, ``FunctionDef``, ``ClassDef``

Program Representation
----------------------

The program module (`pyflow.language.python.program`) provides:

- **Object Model**: ``Object`` (concrete), ``ImaginaryObject`` (abstract), ``AbstractObject`` (base), ``TypeInfo``
- **Program Description**: ``ProgramDescription`` for metadata, object clustering, call binding

Annotations
-----------

The annotations module (`pyflow.language.python.annotations`) provides:

- **CodeAnnotation**: Context-sensitive analysis results, live variables, read/modify/allocate sets
- **OpAnnotation**: Operation-level analysis results, invocation information
- **SlotAnnotation**: Variable reference tracking

AST Transformations
-------------------

- **Collapser**: Collapses single-use variables into definitions
- **Fold**: Constant folding for compile-time evaluation
- **DefUse**: Def-use analysis for variables, tracks locals/globals/cells

===============
Usage
===============

The Language module is primarily used internally by PyFlow's analysis pipeline. Example:

.. code-block:: python

   from pyflow.language.python import ast
   from pyflow.language.python.program import Object
   
   const = ast.Existing(Object(42))
   local = ast.Local("x")
   assign = ast.Assign(const, [local])

===============
Module Structure
===============

.. toctree::
   :maxdepth: 2

   ast
   frontend

===============
See Also
===============

- :doc:`../analysis/index` - Analysis modules using the language IR
- :doc:`../optimization/index` - Optimization passes transforming the AST
- :doc:`../overview` - Overall PyFlow architecture
