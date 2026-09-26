PyFlow API
==========

The PyFlow API provides programmatic access to PyFlow's analysis capabilities.
The API is organized into two main packages:

- **Entry Points** (``pyflow.api.entrypoints``): Define what code to analyze
- **Query Components** (``pyflow.api.queries``): Query analysis results

Quick Start
-----------

.. code-block:: python

   from pyflow.api import (
       InterfaceDeclaration,
       ClassDeclaration,
       create_query_components,
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

   # Query analysis results via composable query components
   queries = create_query_components(compiler, program)
   callgraph = queries.call_graph.get_callgraph()
   cfg = queries.control_flow.get_cfg("function_name")

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

Query Components
----------------

The query module (``pyflow.api.queries``) provides composable, protocol-neutral
semantic query components for analysis results.

QueryComponents and create_query_components
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Query components are created for an analyzed program snapshot via
``create_query_components``:

.. code-block:: python

   from pyflow.api import create_query_components

   queries = create_query_components(compiler, program)

   # Access domain-specific queries
   cfg = queries.control_flow.get_cfg("function_name")
   callgraph = queries.call_graph.get_callgraph()
   callers = queries.call_graph.get_callers("function_name")
   callees = queries.call_graph.get_callees("function_name")
   reaching_defs = queries.data_flow.get_reaching_definitions("function_name")
   aliases = queries.data_flow.get_aliases("function_name", "variable_name")

**Control Flow Queries (``queries.control_flow``):**

- ``get_cfg(function)``: Get Control Flow Graph
- ``get_cfg_structure(function)``: Get CFG as dictionary
- ``get_ssa(function)``: Get SSA form
- ``get_cdg(function)``: Get Control Dependence Graph
- ``get_pdg(function)``: Get Program Dependence Graph

**Call Graph Queries (``queries.call_graph``):**

- ``get_callgraph()``: Get complete call graph
- ``get_callers(function)``: Get functions that call the given function
- ``get_callees(function)``: Get functions called by the given function

**Data Flow Queries (``queries.data_flow``):**

- ``get_reaching_definitions(function)``: Get reaching definitions
- ``get_aliases(function, variable)``: Get alias and points-to information
- ``compute_backward_slice(target)``: Compute backward program slice
- ``compute_forward_slice(target)``: Compute forward program slice

**Type Information Queries (``queries.type_info``):**

- ``get_type(module, line, column)``: Query inferred type at a source position

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

Server Modes and Snapshots
~~~~~~~~~~~~~~~~~~~~~~~~~~

PyFlow provides immutable analysis snapshots (``AnalysisSnapshot``) and protocol modes
defined in ``pyflow.lsp.mcp_config``:

- ``MCPServerMode.BASIC``: Lightweight graph and CFG facts
- ``MCPServerMode.FULL``: Default mode, includes CPA and lifetime analysis
- ``MCPServerMode.ADVANCED``: Includes heap analysis for alias and points-to queries

.. code-block:: python

   from pyflow.lsp.mcp_config import MCPServerMode
   from pyflow.application.analysis_snapshot import AnalysisSnapshot

   # Create a snapshot from compiler context and program
   snapshot = AnalysisSnapshot.from_program(compiler, program)

   # Query snapshot properties and query components
   queries = snapshot.queries
   callgraph = queries.call_graph.get_callgraph()

Localization Queries
~~~~~~~~~~~~~~~~~~~~

Query for code localization (finding where variables are defined/used):

.. code-block:: python

   loc_queries = queries.localization
   definitions = loc_queries.get_definitions("variable_name")

Test Generation Queries
~~~~~~~~~~~~~~~~~~~~~~~

Query for test generation support:

.. code-block:: python

   test_queries = queries.test_generation

Editor & Agent Protocol Integration
-----------------------------------

PyFlow provides ready-to-use LSP and MCP servers for integration with editors and agents.
See :doc:`lsp` for detailed instructions on configuring the LSP and MCP servers or using the ``pyflow query`` CLI.

See Also
--------

- :doc:`lang/index` - Language module and AST definitions
- :doc:`analysis/index` - Analysis modules
- :doc:`cli` - Command-line interface
