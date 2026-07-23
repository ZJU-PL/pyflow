PyFlow API
==========

The PyFlow API provides programmatic access to PyFlow's analysis capabilities.
The API is organized into two main packages:

- **Entry Points** (``pyflow.api.entrypoints``): Define what code to analyze
- **Query Service** (``pyflow.api.queries``): Query analysis results

Quick Start
-----------

.. code-block:: python

   from pyflow.api import (
       InterfaceDeclaration,
       ClassDeclaration,
       SemanticQueryService,
   )
   from pyflow.frontend.extractor import Extractor
   from pyflow.application.context import CompilerContext

   # Set up the compiler and extractor
   compiler = CompilerContext()
   extractor = Extractor(compiler)

   # Declare entry points
   interface = InterfaceDeclaration()
   
   # Add a class to analyze
   class_decl = ClassDeclaration(MyClass)
   class_decl.init(arg1, arg2)
   class_decl.attr("field1", "field2")
   class_decl.method("method_name", param1, param2)
   interface.cls.append(class_decl)

   # Extract and analyze
   interface.translate(extractor)
   program = extractor.extract_from_file("my_file.py")

   # Query analysis results
   service = SemanticQueryService(compiler, program)
   callgraph = service.get_callgraph()
   cfg = service.get_cfg("function_name")

Entry Points
------------

The entry points module (``pyflow.api.entrypoints``) provides classes for
declaring what code should be analyzed.

InterfaceDeclaration
~~~~~~~~~~~~~~~~~~~~

The main entry point for declaring analysis targets.

.. code-block:: python

   from pyflow.api import InterfaceDeclaration

   interface = InterfaceDeclaration()
   
   # Add function entry points
   interface.func.append((my_function, (arg1, arg2)))
   
   # Add class entry points
   cls_decl = ClassDeclaration(MyClass)
   interface.cls.append(cls_decl)

**Key Methods:**

- ``translate(extractor)``: Translates declarations into entry points for analysis
- ``createEntryPoint(...)``: Creates an entry point for a specific function call

ClassDeclaration
~~~~~~~~~~~~~~~~~

Declares a class with its initialization, attributes, and methods.

.. code-block:: python

   from pyflow.api import ClassDeclaration

   class_decl = ClassDeclaration(MyClass)
   class_decl.init(arg1, arg2)  # Constructor arguments
   class_decl.attr("field1", "field2")  # Attributes
   class_decl.method("method_name", param1, param2)  # Methods

**Key Methods:**

- ``init(*args)``: Declare constructor arguments
- ``attr(*args)``: Declare class attributes
- ``method(name, *args)``: Declare method signatures

Argument Wrappers
~~~~~~~~~~~~~~~~~

The ``wrappers`` module provides wrappers for different argument types:

- ``ExistingWrapper``: Wrap an existing object/value
- ``InstanceWrapper``: Wrap an instance creation
- ``NullWrapper``: Represent null/no argument

Query Service
-------------

The query service module (``pyflow.api.queries``) provides access to
analysis results.

SemanticQueryService
~~~~~~~~~~~~~~~~~~~~

The main facade for querying analysis results.

.. code-block:: python

   from pyflow.api import SemanticQueryService

   service = SemanticQueryService(compiler, program)

   # Get various analysis results
   cfg = service.get_cfg("function_name")
   callgraph = service.get_callgraph()
   data_flow = service.get_dataflow("function_name")
   callers = service.get_callers("function_name")
   callees = service.get_callees("function_name")

**Control Flow Queries:**

- ``get_cfg(function)``: Get Control Flow Graph
- ``get_cfg_structure(function)``: Get CFG as dictionary
- ``get_ssa(function)``: Get SSA form
- ``get_cdg(function)``: Get Control Dependence Graph
- ``get_pdg(function)``: Get Program Dependence Graph

**Call Graph Queries:**

- ``get_callgraph()``: Get complete call graph
- ``get_callers(function)``: Get functions that call the given function
- ``get_callees(function)``: Get functions called by the given function
- ``get_method_resolution_order(class)``: Get class MRO

**Data Flow Queries:**

- ``get_dataflow(function)``: Get data flow analysis results
- ``get_aliases(variable)``: Get alias information
- ``get_points_to(variable)``: Get points-to information
- ``get_reaching_defs(variable)``: Get reaching definitions

Query Context
~~~~~~~~~~~~~

The ``QueryContext`` class maintains the analysis context.

.. code-block:: python

   from pyflow.api.queries import QueryContext

   context = QueryContext(compiler, program)
   # Access underlying analysis data

Graph Query Engine
~~~~~~~~~~~~~~~~~~

The ``GraphQueryEngine`` provides graph-based querying capabilities.

.. code-block:: python

   from pyflow.api.queries import GraphQueryEngine

   engine = GraphQueryEngine(context)
   
   # Query graph structures
   nodes = engine.get_nodes(function_name)
   edges = engine.get_edges(function_name)

Query Helper Classes
~~~~~~~~~~~~~~~~~~~~

PyFlow provides dedicated query classes for each analysis domain:

.. code-block:: python

   from pyflow.api.queries import (
       CallGraphQueries,
       ControlFlowQueries,
       DataFlowQueries,
   )

   call_queries = CallGraphQueries(context, engine)
   callers = call_queries.get_callers("function_name")

   ctrl_queries = ControlFlowQueries(context, engine)
   cfg = ctrl_queries.get_cfg("function_name")

   data_queries = DataFlowQueries(context, engine)
   reaching_defs = data_queries.get_reaching_defs("function_name")

Analysis Result Models
~~~~~~~~~~~~~~~~~~~~~~

The API exposes typed result models for programmatic consumption:

.. code-block:: python

   from pyflow.api.queries import (
       ReachingDef,
       AliasInfo,
       PointsToInfo,
       TaintFlowReport,
       IpaFunctionSummary,
   )

   # ReachingDef: captures a reaching definition with source location
   # AliasInfo: alias relationship with confidence and evidence
   # PointsToInfo: points-to set with allocation sites
   # TaintFlowReport: taint flow from source to sink with code flow
   # IpaFunctionSummary: inter-procedural function summary

Server Modes
~~~~~~~~~~~~

PyFlow supports different server modes for different use cases:

- ``DEFAULT_MODE``: Standard analysis
- ``MCPServerMode``: Mode optimized for MCP tooling (supports ``BASIC``, ``FULL``, ``ADVANCED`` levels)

.. code-block:: python

   from pyflow.api.queries import MCPServerMode, DEFAULT_MODE
   from pyflow.api.queries.capabilities import (
       get_server_mode_description,
       resolve_capabilities,
   )

   # Set server mode
   service = SemanticQueryService(compiler, program, server_mode=DEFAULT_MODE)
   
   # Check capabilities
   caps = service.capabilities()

   # Resolve and describe server mode capabilities
   resolved = resolve_capabilities(MCPServerMode)
   description = get_server_mode_description(MCPServerMode)

Localization Queries
~~~~~~~~~~~~~~~~~~~

Query for code localization (finding where variables are defined/used).

.. code-block:: python

   from pyflow.api.queries import LocalizationQueries

   loc_queries = LocalizationQueries(context, engine)
   definitions = loc_queries.get_definitions(variable)
   uses = loc_queries.get_uses(variable)

Test Generation Queries
~~~~~~~~~~~~~~~~~~~~~~~

Query for test generation support.

.. code-block:: python

   from pyflow.api.queries import TestGenerationQueries

   test_queries = TestGenerationQueries(context)
   scenarios = test_queries.get_test_scenarios(function)

MCP Server Integration
----------------------

PyFlow can be used as an MCP (Model Context Protocol) server for AI tooling.

.. code-block:: python

   from pyflow.api.queries import MCPServerMode

   service = SemanticQueryService(compiler, program, server_mode=MCPServerMode)
   
   # MCP-compatible methods
   capabilities = service.capabilities()
   # Returns available query capabilities

See Also
--------

- :doc:`lang/index` - Language module and AST definitions
- :doc:`analysis/index` - Analysis modules
- :doc:`cli` - Command-line interface
