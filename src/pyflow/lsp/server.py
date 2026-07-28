"""
Pyflow analysis server — wraps SemanticQueryService behind JSON-RPC.

This module provides the bridge between pyflow's internal analysis API
and the JSON-RPC transport layer, so external tools can query analysis
results without importing pyflow as a library.
"""

import os
import logging
import threading
from pathlib import Path
from typing import Any, Optional

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.application.pipeline import Pipeline
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import (
    InterfaceBuildOptions,
    build_interface_from_paths,
)
from pyflow.analysis.typeinfo import TypeInfoService
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.util.application.console import Console
from pyflow.api.queries import (
    SemanticQueryService,
    MCPServerMode,
    DEFAULT_MODE,
    resolve_capabilities,
)

from .workspace import SourceIndex, WorkspaceDocuments, uri_to_path

LOG = logging.getLogger(__name__)


class PyflowAnalysisServer:
    """Wraps pyflow's analysis pipeline behind a queryable interface.

    Typical workflow::

        server = PyflowAnalysisServer()
        server.load("path/to/project/")   # or load_files([...])
        result = server.get_callers("my_function")
    """

    def __init__(
        self, server_mode: MCPServerMode = DEFAULT_MODE, verbose: bool = False
    ):
        self._compiler: Optional[CompilerContext] = None
        self._program: Optional[Program] = None
        self._service: Optional[SemanticQueryService] = None
        self._mode = server_mode
        self._verbose = verbose
        self._loaded = False
        self._root_path: Optional[str] = None
        self._python_files: list[Path] = []
        self._source_files: dict[str, str] = {}
        self._source_index = SourceIndex({})
        self._documents = WorkspaceDocuments()
        self._state_lock = threading.RLock()
        self._analysis_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self, root_path: str, *, run_pipeline: bool = True) -> None:
        """Load a project directory for analysis.

        Discovers Python files, extracts an interface, runs the default
        analysis pipeline, and makes the ``SemanticQueryService`` ready.
        """
        root_path = os.path.abspath(root_path)
        root = Path(root_path)
        if not root.is_dir():
            raise ValueError(f"Project root is not a directory: {root_path}")

        # Find Python files
        python_files = sorted(
            p
            for p in root.rglob("*.py")
            if not any(part.startswith(".") for part in p.relative_to(root).parts)
            and not set(p.parts).intersection(
                {
                    "site-packages",
                    "node_modules",
                    "build",
                    "dist",
                    "__pycache__",
                    "venv",
                }
            )
        )

        if not python_files:
            raise ValueError(f"No Python files found in {root_path}")

        self._root_path = root_path
        self.load_files(python_files, run_pipeline=run_pipeline, root_path=root_path)

    def load_files(
        self,
        python_files: list[Path],
        *,
        run_pipeline: bool = True,
        root_path: Optional[str] = None,
    ) -> None:
        """Load a specific set of Python files for analysis.

        Builds the interface, extracts the program, runs the default
        analysis pipeline, and initializes the query service.
        """
        normalized_files = [Path(path).absolute() for path in python_files]
        if not normalized_files:
            raise ValueError("At least one Python file is required")
        effective_root = os.path.abspath(
            root_path
            or self._root_path
            or os.path.commonpath([str(p.parent) for p in normalized_files])
        )
        # Only one compiler pipeline is built at a time.  The completed state is
        # swapped atomically so queries can continue using the previous snapshot.
        with self._analysis_lock:
            # Read overlays after acquiring the analysis lock. Concurrent reload
            # requests therefore analyze the latest revision and cannot commit an
            # older snapshot after a newer one.
            source_overrides = self._documents.source_overrides()
            console = Console(verbose=self._verbose)
            compiler = CompilerContext(console)
            program = Program()

            opts = InterfaceBuildOptions(
                dependency_strategy="auto",
                verbose=self._verbose,
            )
            program.interface, all_source_code = build_interface_from_paths(
                normalized_files,
                opts,
                source_overrides=source_overrides,
            )
            compiler.extractor = Extractor(
                compiler,
                verbose=self._verbose,
                source_code=all_source_code,
                analysis_root=effective_root,
            )

            with console.scope("extraction"):
                extract_program(compiler, program)

            if run_pipeline:
                with console.scope("analysis"):
                    pipeline = Pipeline(use_pass_manager=True)
                    pipeline.run_custom_pipeline(
                        compiler,
                        program,
                        self._analysis_passes(),
                    )

            project_context = ProjectContext(
                effective_root,
                source_files=all_source_code,
            )
            type_info = TypeInfoService(project_context)
            service = program.get_semantic_queries(
                compiler,
                server_mode=self._mode,
                type_info_service=type_info,
            )
            service.set_server_mode(self._mode)
            source_index = SourceIndex(all_source_code, effective_root)

            with self._state_lock:
                self._compiler = compiler
                self._program = program
                self._service = service
                self._root_path = effective_root
                self._python_files = normalized_files
                self._source_files = dict(all_source_code)
                self._source_index = source_index
                self._loaded = True

    def _analysis_passes(self) -> list[str]:
        if self._mode is MCPServerMode.BASIC:
            return ["ipa"]
        if self._mode is MCPServerMode.ADVANCED:
            return ["ipa", "cpa", "lifetime", "heap"]
        return ["ipa", "cpa", "lifetime"]

    def reload(self) -> None:
        """Rebuild analysis from the current disk files plus open overlays."""
        with self._state_lock:
            files = list(self._python_files)
            root = self._root_path
        if not files:
            if root:
                self.load(root)
                return
            raise RuntimeError("No project has been loaded")
        self.load_files(files, root_path=root)

    def open_document(self, uri: str, text: str, version: Optional[int] = None) -> None:
        self._documents.open(uri_to_path(uri), text, version)

    def change_document(
        self, uri: str, text: str, version: Optional[int] = None
    ) -> None:
        self._documents.change(uri_to_path(uri), text, version)

    def close_document(self, uri: str) -> None:
        self._documents.close(uri_to_path(uri))

    def close(self) -> None:
        """Release resources held by the server."""
        with self._state_lock:
            self._compiler = None
            self._program = None
            self._service = None
            self._source_files = {}
            self._source_index = SourceIndex({})
            self._loaded = False

    @property
    def service(self) -> SemanticQueryService:
        """Return the underlying query service (raises if not loaded)."""
        if not self._loaded or self._service is None:
            raise RuntimeError("Server not loaded. Call load() first.")
        return self._service

    @property
    def compiler(self) -> CompilerContext:
        if not self._loaded or self._compiler is None:
            raise RuntimeError("Server not loaded. Call load() first.")
        return self._compiler

    @property
    def program(self) -> Program:
        if not self._loaded or self._program is None:
            raise RuntimeError("Server not loaded. Call load() first.")
        return self._program

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def source_index(self) -> SourceIndex:
        return self._source_index

    @property
    def server_mode(self) -> MCPServerMode:
        return self._mode

    @property
    def root_path(self) -> Optional[str]:
        return self._root_path

    def supports(self, capability: str) -> bool:
        info = resolve_capabilities(self._mode).get(capability)
        if capability == "type_info":
            return self.is_loaded and self.service.type_info_service is not None
        return bool(info and info["available"])

    def _require_capability(self, capability: str) -> None:
        if not self.supports(capability):
            raise RuntimeError(
                f"Capability '{capability}' is unavailable in {self._mode.value} mode"
            )

    # ------------------------------------------------------------------
    # Query methods — thin facades over SemanticQueryService
    # ------------------------------------------------------------------

    def get_capabilities(self) -> dict[str, Any]:
        return self.service.capabilities()

    # -- Call graph ----------------------------------------------------

    def get_callgraph_data(self) -> dict[str, Any]:
        self._require_capability("callgraph")
        return self.service.get_callgraph_data()

    def get_callers(self, function: str) -> list[str]:
        self._require_capability("callers")
        return self.service.get_callers(function)

    def get_callees(self, function: str) -> list[str]:
        self._require_capability("callees")
        return self.service.get_callees(function)

    def get_downstream_functions(
        self, function: str, max_depth: Optional[int] = None
    ) -> list[str]:
        self._require_capability("callgraph")
        return self.service.get_downstream_functions(function, max_depth)

    def get_upstream_functions(
        self, function: str, max_depth: Optional[int] = None
    ) -> list[str]:
        self._require_capability("callgraph")
        return self.service.get_upstream_functions(function, max_depth)

    def get_shortest_path(self, source: str, target: str) -> Optional[list[str]]:
        self._require_capability("callgraph")
        return self.service.get_shortest_path(source, target)

    # -- Control flow --------------------------------------------------

    def get_cfg_structure(self, function: str) -> dict[str, Any]:
        self._require_capability("cfg")
        return self.service.get_cfg_structure(function)

    # -- Data flow -----------------------------------------------------

    def get_reaching_defs(self, function: str) -> dict[str, Any]:
        self._require_capability("reaching_defs")
        result = self.service.get_reaching_defs(function)
        return self._serialize_reaching_defs(result)

    def get_ipa_function_summaries(self, function: Optional[str] = None) -> list[Any]:
        self._require_capability("function_summaries")
        return self.service.get_ipa_function_summaries(function)

    # -- Type information ----------------------------------------------

    def get_expression_type(
        self, module_name: str, lineno: int, col_offset: int
    ) -> Optional[dict[str, Any]]:
        self._require_capability("type_info")
        result = self.service.get_expression_type(module_name, lineno, col_offset)
        if result is None:
            return None
        return {"type": str(result)}

    # -- Heap / alias --------------------------------------------------

    def get_aliases_for_variable(self, variable: str) -> dict[str, Any]:
        self._require_capability("aliases")
        info = self.service.get_aliases_for_variable(variable)
        return {
            "variable": info.variable,
            "aliases": list(info.aliases),
            "is_aliased": info.is_aliased,
            "ref_count": info.ref_count,
            "is_escaped": info.is_escaped,
        }

    def get_points_to_for_variable(self, variable: str) -> dict[str, Any]:
        self._require_capability("points_to")
        info = self.service.get_points_to_for_variable(variable)
        return {
            "variable": info.variable,
            "points_to": list(info.points_to),
            "may_be_null": info.may_be_null,
            "ref_count": info.ref_count,
            "is_escaped": info.is_escaped,
        }

    # -- Test generation / localization --------------------------------

    def get_function_test_profile(self, function: str) -> dict[str, Any]:
        profile = self.service.get_function_test_profile(function)
        return {
            "name": profile.name,
            "signature": profile.signature,
            "parameters": profile.parameters,
            "return_type": profile.return_type,
            "calls": profile.calls,
            "called_by": profile.called_by,
            "has_branches": profile.has_branches,
            "has_loops": profile.has_loops,
            "complexity": profile.complexity,
            "external_dependencies": profile.external_dependencies,
        }

    # -- Utility -------------------------------------------------------

    @staticmethod
    def _serialize_reaching_defs(defs: Any) -> dict[str, Any]:
        """Convert reaching-def result objects to plain dicts."""
        result = {}
        for var, reaching_list in defs.items():
            result[var] = [
                {
                    "variable": rd.variable,
                    "def_location": str(rd.def_location) if rd.def_location else None,
                    "def_value": rd.def_value,
                    "is_call": rd.is_call,
                }
                for rd in reaching_list
            ]
        return result
