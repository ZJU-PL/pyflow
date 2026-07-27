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
- **Intrinsic Models**: Providing IR models for built-in interpreter operations

The implementation is grouped by responsibility:

- ``pyflow.frontend.conversion`` converts source AST into PyFlow IR.
- ``pyflow.frontend.resolution`` coordinates dependency and hierarchy resolution.
- ``pyflow.frontend.runtime`` manages object representations and intrinsic models.
- ``pyflow.frontend.interface_builder`` discovers analysis entry points from paths.

New code should import supported classes from ``pyflow.frontend``. Historical
The package does not retain forwarding modules for its previous flat layout;
imports should use the canonical locations shown below.

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

   from pyflow.frontend.conversion.ast import ASTConverter
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

   from pyflow.frontend.extractor import Extractor
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

   from pyflow.frontend.conversion.functions import FunctionExtractor
   
   extractor = FunctionExtractor(verbose=True)
   pyflow_code = extractor.convert_function(
       my_function,
       source_code="def my_function(x, y): return x + y"
   )

Dependency Resolver
-------------------

The ``DependencyResolver`` class handles import dependencies with multiple strategies:

**AUTO** (default): AST-only extraction (side-effect free)
**STUBS**: Creates stub modules for missing dependencies
**AST_ONLY**: Only uses AST parsing (safe for untrusted code)
**STRICT**: Fails if dependencies can't be resolved
**NOOP**: Treats external dependencies as no-ops

Runtime extraction (``STRICT``, ``STUBS``, ``NOOP`` with
``allow_runtime_execution=True``) executes in an isolated subprocess to avoid
polluting analyzer process state (for example, ``sys.modules`` mutations).

For CI and production hardening, the dependency resolver also supports quality
gates:

- ``fail_on_diagnostics``: fail when any resolver diagnostic is recorded
- ``max_diagnostics``: fail when diagnostic count exceeds a threshold
- ``max_runtime_fallback_ratio``: fail when runtime-to-AST fallback ratio exceeds a threshold

**Usage:**

.. code-block:: python

   from pyflow.frontend.resolution.dependencies import DependencyResolver
   
   resolver = DependencyResolver(strategy="auto", verbose=True)
   functions = resolver.extract_functions(source_code, "example.py")

Object Manager
---------------

The ``ObjectManager`` class manages Python objects and their PyFlow representations.

**Usage:**

.. code-block:: python

   from pyflow.frontend.runtime.objects import ObjectManager
   
   manager = ObjectManager(verbose=True)
   obj = manager.get_object(some_python_object)
   func_obj, code_obj = manager.get_object_call(my_function)
   manager.ensure_loaded(obj)

**Key Methods:**
  - ``get_object()``, ``get_object_call()``, ``make_imaginary()``, ``ensure_loaded()``

Intrinsic Manager
-----------------

The ``IntrinsicManager`` class manages IR models for built-in Python operations
such as arithmetic, comparison, attribute access, and function calls.

**Usage:**

.. code-block:: python

   from pyflow.frontend.runtime.intrinsics import IntrinsicManager
   
   manager = IntrinsicManager(compiler)
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

   from pyflow.frontend.extractor import Extractor
   from pyflow.application.context import CompilerContext
   
   compiler = CompilerContext()
   extractor = Extractor(compiler, verbose=True)
   
   source = """
   def add(x, y):
       return x + y
   """
   
   program = extractor.extract_from_source(source, "example.py")
   code = extractor.convertFunction(add_func)

========================================
Integration with Analysis
========================================

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
