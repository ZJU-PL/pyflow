"""
PyFlow API - Entry point declarations and query services.

This module provides the public API for:
- Declaring program entry points for analysis (entrypoints package)
- Querying analysis results (queries package)

Example usage:

    from pyflow.api import (
        InterfaceDeclaration,
        ClassDeclaration,
        SemanticQueryService,
    )

    # Declare entry points
    interface = InterfaceDeclaration()
    cls_decl = ClassDeclaration(MyClass)
    cls_decl.init(arg1, arg2)
    interface.cls.append(cls_decl)

    # Query analysis results
    service = SemanticQueryService(compiler, program)
    callers = service.get_callers("my_function")
"""

from .entrypoints import (
    ArgumentWrapper,
    ClassDeclaration,
    EntryPoint,
    ExistingWrapper,
    InstanceWrapper,
    InterfaceDeclaration,
    NullWrapper,
    nullWrapper,
)
from .queries import (
    DEFAULT_MODE,
    MCPServerMode,
    AliasInfo,
    CallGraphQueries,
    ControlFlowQueries,
    DataFlowQueries,
    FunctionTestProfile,
    GraphQueryEngine,
    IpaFunctionSummary,
    LocalizationCandidate,
    LocalizationQueries,
    PointsToInfo,
    ProgramSlice,
    QueryContext,
    ReachingDef,
    SemanticQueryService,
    TestGenerationQueries,
    TestScenario,
    get_server_mode_description,
    resolve_capabilities,
)

__all__ = [
    # Entrypoints
    "ClassDeclaration",
    "EntryPoint",
    "InterfaceDeclaration",
    "ArgumentWrapper",
    "InstanceWrapper",
    "ExistingWrapper",
    "NullWrapper",
    "nullWrapper",
    # Queries - core
    "QueryContext",
    "GraphQueryEngine",
    "MCPServerMode",
    "DEFAULT_MODE",
    "get_server_mode_description",
    "resolve_capabilities",
    # Queries - service
    "SemanticQueryService",
    # Queries - graph
    "CallGraphQueries",
    "ControlFlowQueries",
    "DataFlowQueries",
    "IpaFunctionSummary",
    "AliasInfo",
    "PointsToInfo",
    "ReachingDef",
    # Queries - tasks
    "LocalizationQueries",
    "LocalizationCandidate",
    "ProgramSlice",
    "TestGenerationQueries",
    "FunctionTestProfile",
    "TestScenario",
]
