"""Python language support for PyFlow.

This package provides Python language-specific implementations for representing
and processing Python code in PyFlow. It defines the core intermediate representation
(IR) used throughout the analysis pipeline.

Key components:
- AST: Abstract Syntax Tree node definitions for PyFlow's IR
- Program: Object model and type system for Python objects
- Annotations: Context-sensitive metadata attached to AST nodes
- Transformations: Collapsing, folding, and def-use analysis
- Code generation: Output and simple code generation

The language module provides:
- **AST Representation**: Rich intermediate representation capturing Python semantics
- **Object Model**: Representation of Python objects, types, and relationships
- **Type System**: Support for abstract and concrete types, type information
- **Annotations**: Context-sensitive metadata attached to AST nodes
- **Transformations**: AST transformations for optimization and analysis
- **Code Generation**: Converting AST back to Python code
"""
