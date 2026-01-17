"""
PyFlow Frontend Processing Module.

This module provides the frontend processing pipeline for PyFlow, handling
the initial parsing and preparation of Python code for static analysis.

Submodules:
    ast_converter: Converts Python AST to PyFlow's intermediate representation.
    programextractor: Extracts program structure from source code.
    dependency_resolver: Resolves import dependencies between modules.
    function_extractor: Extracts function definitions and their metadata.
    object_manager: Manages objects and their properties during analysis.
    stub_manager: Handles type stubs for builtins and standard library.

The frontend module is responsible for transforming raw Python source code
into a form suitable for the analysis pipeline, including AST conversion,
dependency resolution, and program structure extraction.
"""
