Frontend Module
================

The Frontend module extracts Python source code and converts it into PyFlow's internal AST representation. It handles parsing, dependency resolution, and conversion for static analysis.

===============
Overview
===============

The Frontend module (`src/pyflow/frontend/`) bridges Python source code and PyFlow's analysis pipeline:

- **Parsing**: Converting Python source to AST
- **Dependency Resolution**: Handling imports and missing dependencies
- **AST Conversion**: Transforming Python AST to PyFlow AST
- **Function Extraction**: Extracting functions and classes
- **Object Management**: Managing Python objects and representations
- **Stub Management**: Providing stubs for built-in operations

===============
Key Components
===============

AST Converter
-------------

The ``ASTConverter`` class converts Python's standard AST to PyFlow's internal AST.

**Features:**
  - Handles all major Python constructs (functions, classes, control flow, expressions)
  - Preserves semantic information and creates proper annotations
  - Supports Python 3.x syntax

**Example:**

.. code-block:: python

   from pyflow.frontend.ast_converter import ASTConverter
   import ast as python_ast
   
   source = "def add(x, y): return x + y"
   tree = python_ast.parse(source)
   converter = ASTConverter()
   pyflow_ast = converter.convert_python_ast_to_pyflow([tree])

Program Extractor
-----------------

The ``Extractor`` class orchestrates program extraction from Python source.

**Usage:**

.. code-block:: python

   from pyflow.frontend.programextractor import Extractor
   from pyflow.application.context import CompilerContext
   
   compiler = CompilerContext()
   extractor = Extractor(compiler, verbose=True)
   
   # Extract from source, file, or multiple files
   program = extractor.extract_from_source(source_code, "example.py")
   program = extractor.extract_from_file("example.py")
   program = extractor.extract_from_multiple_files({"file1.py": source1})

**Key Methods:**
  - ``extract_from_source()``, ``extract_from_file()``, ``extract_from_multiple_files()``
  - ``convertFunction()`` - Convert Python function to PyFlow AST
  - ``getObject()`` - Get or create object representation

Function Extractor
------------------

The ``FunctionExtractor`` class extracts and converts individual Python functions.

**Usage:**

.. code-block:: python

   from pyflow.frontend.function_extractor import FunctionExtractor
   
   extractor = FunctionExtractor(verbose=True)
   pyflow_code = extractor.convert_function(
       my_function,
       source_code="def my_function(x, y): return x + y"
   )

Dependency Resolver
-------------------

The ``DependencyResolver`` class handles import dependencies with multiple strategies:

**AUTO** (default): Tries runtime execution, falls back to AST parsing
**STUBS**: Creates stub modules for missing dependencies
**AST_ONLY**: Only uses AST parsing (safe for untrusted code)
**STRICT**: Fails if dependencies can't be resolved
**NOOP**: Treats external dependencies as no-ops

**Usage:**

.. code-block:: python

   from pyflow.frontend.dependency_resolver import DependencyResolver
   
   resolver = DependencyResolver(strategy="auto", verbose=True)
   functions = resolver.extract_functions(source_code, "example.py")

Object Manager
---------------

The ``ObjectManager`` class manages Python objects and their PyFlow representations.

**Usage:**

.. code-block:: python

   from pyflow.frontend.object_manager import ObjectManager
   
   manager = ObjectManager(verbose=True)
   obj = manager.get_object(some_python_object)
   func_obj, code_obj = manager.get_object_call(my_function)
   manager.ensure_loaded(obj)

**Key Methods:**
  - ``get_object()``, ``get_object_call()``, ``make_imaginary()``, ``ensure_loaded()``

Stub Manager
------------

The ``StubManager`` class manages stub functions for built-in Python operations (arithmetic, comparison, attribute access, function calls).

**Usage:**

.. code-block:: python

   from pyflow.frontend.stub_manager import StubManager
   
   manager = StubManager(compiler)
   add_stub = manager.stubs.exports["interpreter__add__"]

===============
Workflow
===============

Typical workflow:

1. Create Extractor with compiler context
2. Provide source (single file, multiple files, or source strings)
3. Extract program (functions and classes)
4. Convert functions to PyFlow AST as needed
5. Pass to analysis pipeline

**Example:**

.. code-block:: python

   from pyflow.frontend.programextractor import Extractor
   from pyflow.application.context import CompilerContext
   
   compiler = CompilerContext()
   extractor = Extractor(compiler, verbose=True)
   
   source = """
   def add(x, y):
       return x + y
   """
   
   program = extractor.extract_from_source(source, "example.py")
   code = extractor.convertFunction(add_func)

===============
Integration with Analysis
===============

The frontend integrates with PyFlow's analysis pipeline:

- **Program Object**: Extracted functions added to ``program.liveCode``
- **AST Conversion**: Functions converted to PyFlow AST on demand with annotations
- **Dependency Handling**: Missing dependencies handled via stubs or AST fallback

===============
Error Handling
===============

The frontend handles:
- **Syntax Errors**: Caught during parsing, reported with file location
- **Import Errors**: Handled by dependency resolver based on strategy
- **Missing Source**: Minimal code stubs created, signatures preserved
- **Type Errors**: Object creation errors caught, fallback objects provided

===============
See Also
===============

- :doc:`ast` - PyFlow AST node definitions
- :doc:`index` - Language module overview
- :doc:`../analysis/index` - Analysis modules
- :doc:`../overview` - PyFlow architecture
