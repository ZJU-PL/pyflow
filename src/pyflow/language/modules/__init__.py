"""Module handling and utilities for PyFlow.

This package provides utilities for working with Python modules, including:
- Workspace & SourceStore: Shared file discovery, encoding-aware source loading,
  bounded read-only AST caching, and monorepo import-root discovery
- ModuleGraph & ModuleExportTable: IR-independent static import graph, Tarjan
  SCC ordering, relative import / re-export resolution, and Merkle dependency hashes
- ProjectContext & StubResolver: Module and ``.pyi`` stub resolution
- Module definitions, AST transformations, scope graphs, and helpers
"""

from .module_graph import (
    ExportBinding,
    ImportEdge,
    ModuleExportTable,
    ModuleGraph,
    extract_module_export_table,
    resolve_relative_module,
)
from .workspace import (
    DEFAULT_IGNORED_DIRS,
    SourceRecord,
    SourceStore,
    Workspace,
    discover_source_roots,
    parse_source_cached,
    read_python_source,
)

__all__ = [
    "DEFAULT_IGNORED_DIRS",
    "ExportBinding",
    "ImportEdge",
    "ModuleExportTable",
    "ModuleGraph",
    "SourceRecord",
    "SourceStore",
    "Workspace",
    "discover_source_roots",
    "extract_module_export_table",
    "parse_source_cached",
    "read_python_source",
    "resolve_relative_module",
]
