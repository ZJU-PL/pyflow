.. _explanation-architecture:

=============
Architecture
=============

This document provides a detailed overview of PyFlow's architecture, including
its modular design, key components, and how they interact.

System Overview
===============

PyFlow is built around a modular architecture that separates concerns into
distinct layers:

.. image:: architecture-diagram.png
   :alt: PyFlow Architecture Overview
   :align: center

The architecture consists of five main layers:

1. **Frontend Layer**: Parses and preprocesses Python code
2. **IR Layer**: Creates and manages intermediate representations
3. **Analysis Layer**: Implements various static analyses
4. **Optimization Layer**: Applies code transformations
5. **Application Layer**: Orchestrates the analysis pipeline

Frontend Layer
==============

The frontend layer is responsible for parsing and preprocessing Python code.

Components
----------

AST Converter
^^^^^^^^^^^^^

Converts Python's AST into PyFlow's internal representation:

.. code-block:: python

   from pyflow.frontend.conversion.ast import ASTConverter

   converter = ASTConverter()
   pyflow_ir = converter.convert(python_ast)

Key responsibilities:

- Extract function definitions and classes
- Handle Python-specific constructs (decorators, comprehensions)
- Convert to a canonical form for analysis

Program Extractor
^^^^^^^^^^^^^^^^^

Extracts the complete program structure from source files:

.. code-block:: python

   from pyflow.frontend.extractor import Extractor

   extractor = Extractor()
   program = extractor.process(["input.py"])

Key responsibilities:

- Parse multiple files recursively
- Resolve imports
- Build program dependency graph

Dependency Resolver
^^^^^^^^^^^^^^^^^^^

Resolves module and import dependencies:

.. code-block:: python

   from pyflow.frontend.resolution.dependencies import DependencyResolver

   resolver = DependencyResolver()
   dependencies = resolver.resolve(program)

Key responsibilities:

- Find module locations
- Handle circular imports
- Build import graph

Type Stub Resolution
^^^^^^^^^^^^^^^^^^^^

Resolves project, PEP 561, and typeshed ``.pyi`` files:

.. code-block:: python

   from pyflow.language.modules.type_stubs import StubResolver

   resolver = StubResolver()
   os_stub = resolver.resolve("os")

Key responsibilities:

- Locate and parse type stubs without executing analyzed modules
- Provide analysis information for library code
- Handle stub versioning

IR Layer
========

The IR (Intermediate Representation) layer provides data structures for
representing program structure and analysis results.

Control Flow Graph (CFG)
------------------------

The CFG represents the control flow structure of a function:

.. code-block:: python

   from pyflow.analysis.cfg.graph import CFGBlock

   entry = CFGBlock("entry")
   loop_body = CFGBlock("loop_body")
   entry.add_successor(loop_body)

Key components:

- **BasicBlock**: A sequence of instructions with single entry/exit
- **Edge**: Control flow transfer between blocks
- **DominanceInfo**: Dominator tree and dominance frontiers

Data Flow IR
------------

Represents data flow information for analysis:

.. code-block:: python

   from pyflow.analysis.dataflowIR.convert import CodeToDataflow

   converter = CodeToDataflow()
   df_graph = converter.convert(cfg_block)

Key components:

- **Lattice**: Abstract domain for values
- **TransferFunction**: How values flow through instructions
- **WorklistAlgorithm**: Iterative fixed-point computation

Store Graph
-----------

Represents object allocation and field access:

.. code-block:: python

   from pyflow.analysis.storegraph.storegraph import StoreGraph, ObjectNode

   graph = StoreGraph()
   node = ObjectNode("obj", "Object()")

Key components:

- **AllocationSite**: Where an object is created
- **FieldAccess**: Object field read/write
- **PointsToSet**: Set of objects a reference may point to

Analysis Layer
==============

The analysis layer implements various static analysis algorithms.

Constraint-Based Analysis (CPA)
-------------------------------

CPA uses constraint solving for precise analysis:

.. code-block:: python

   from pyflow.analysis.cpa import InterproceduralDataflow

   cpa = InterproceduralDataflow()
   cpa.run(program)

Key concepts:

- **Constraints**: Relationships between program elements
- **Worklist**: Set of constraints to solve
- **Fixed Point**: Stable state where all constraints are satisfied

Constraint types:

- **AssignmentConstraint**: Variable assignment
- **LoadConstraint**: Field read operation
- **StoreConstraint**: Field write operation
- **CallConstraint**: Function call

Inter-Procedural Analysis (IPA)
-------------------------------

Extends analysis across function boundaries:

.. code-block:: python

   from pyflow.analysis.ipa import IPAnalysis

   ipa = IPAnalysis()
   ipa.analyze(program)

Key concepts:

- **Calling Context**: Information about how a function is called
- **Summary**: Analysis result for a function
- **Context Sensitive**: Distinguishes different calling contexts

Shape Analysis
--------------

Analyzes data structure shapes:

.. code-block:: python

   from pyflow.analysis.shape import RegionBasedShapeAnalysis

   shape = RegionBasedShapeAnalysis()
   shape.analyze(program)

Key concepts:

- **Shape Graph**: Abstract representation of data structures
- **Region**: Set of memory locations with similar properties
- **Heap Abstraction**: How heap objects are represented

Call Graph Analysis
-------------------

Builds function call relationships:

.. code-block:: python

   from pyflow.analysis.callgraph.constraint_based.api import extract_call_graph_constraint

   graph = extract_call_graph_constraint(source_code)

Optimization Layer
==================

The optimization layer applies code transformations.

Optimization Passes
-------------------

PyFlow implements various optimization passes:

Constant Folding
^^^^^^^^^^^^^^^^

Evaluates constant expressions at analysis time:

.. code-block:: python

   from pyflow.optimization.fold import evaluateCode
   from pyflow.optimization.simplify import evaluate

Dead Code Elimination
^^^^^^^^^^^^^^^^^^^^^

Removes unreachable and unused code:

.. code-block:: python

   from pyflow.optimization.dce import evaluate

Function Inlining
^^^^^^^^^^^^^^^^^

Replaces function calls with function body:

.. code-block:: python

   from pyflow.optimization.codeinlining import evaluate

Pass Manager
------------

Orchestrates optimization passes:

.. code-block:: python

   from pyflow.application.passmanager import PassManager
   from pyflow.application.passes import register_standard_passes

   pm = PassManager()
   register_standard_passes(pm)
   pipeline = pm.build_pipeline([
       "simplify",
       "methodcall",
       "inlining",
       "cullprogram"
   ])
   results = pm.run_pipeline(compiler, program, pipeline)

Application Layer
=================

The application layer provides high-level interfaces and orchestration.

Analysis Pipeline
-----------------

Coordinates the overall analysis process:

.. code-block:: python

   from pyflow.application.pipeline import Pipeline

   pipeline = Pipeline()
   results = pipeline.run(program)

Analysis Context
----------------

Manages analysis configuration and state:

.. code-block:: python

   from pyflow import Context

   context = Context()
   context.slots["cpa.context_sensitive"] = True
   context.slots["callgraph.algorithm"] = "constraint"

Data Flow
=========

This section describes how data flows through PyFlow's architecture:

1. **Input**: Python source files
2. **Frontend**: Parse and extract program structure
3. **IR**: Build intermediate representations
4. **Analysis**: Run static analyses
5. **Optimization**: Apply transformations
6. **Output**: Analysis results or optimized code

Key Design Principles
======================

1. **Modularity**: Each component has a single, well-defined responsibility
2. **Extensibility**: New analyses can be added without modifying core
3. **Reusability**: IR structures can be shared across analyses
4. **Performance**: Efficient algorithms for large codebases
5. **Precision**: Context-sensitive, flow-sensitive analysis options

Trade-offs
==========

- **Precision vs. Performance**: More precise analyses are slower
- **Soundness vs. Completeness**: PyFlow favors soundness
- **Generality vs. Specificity**: General-purpose but can be configured
