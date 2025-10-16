"""
Core machinery module for PyFlow static analysis framework.

This module provides the fundamental data structures and managers that form the
backbone of PyFlow's static analysis capabilities. It includes:

- CallGraph: Represents function call relationships
- DefinitionManager: Manages variable and function definitions with points-to analysis
- ImportManager: Handles module imports and dependency tracking
- ScopeManager: Manages lexical scoping information
- ClassManager: Tracks class hierarchies and method resolution orders
- ModuleManager: Manages internal and external module information
- Various pointer types for tracking data flow

These components work together to build comprehensive program representations
that enable sophisticated static analysis passes.
"""
