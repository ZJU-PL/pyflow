"""
Pyflow analysis server — wraps SemanticQueryService behind JSON-RPC.

This module provides the bridge between pyflow's internal analysis API
and the JSON-RPC transport layer, so external tools can query analysis
results without importing pyflow as a library.
"""

import os
import logging
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
from pyflow.util.application.console import Console
from pyflow.api.queries import (
    SemanticQueryService,
    MCPServerMode,
    DEFAULT_MODE,
)

LOG = logging.getLogger(__name__)


class PyflowAnalysisServer:
    """Wraps pyflow's analysis pipeline behind a queryable interface.

    Typical workflow::

        server = PyflowAnalysisServer()
        server.load("path/to/project/")   # or load_files([...])
        result = server.get_callers("my_function")
    """

    def __init__(self, server_mode: MCPServerMode = DEFAULT_MODE,
                 verbose: bool = False):
        self._compiler: Optional[CompilerContext] = None
        self._program: Optional[Program] = None
        self._service: Optional[SemanticQueryService] = None
        self._mode = server_mode
        self._verbose = verbose
        self._loaded = False
        self._root_path: Optional[str] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self, root_path: str, *, run_pipeline: bool = True) -> None:
        """Load a project directory for analysis.

        Discovers Python files, extracts an interface, runs the default
        analysis pipeline, and makes the ``SemanticQueryService`` ready.
        """
        self._root_path = os.path.abspath(root_path)
        root = Path(self._root_path)

        # Find Python files
        python_files = sorted(
            p for p in root.rglob("*.py")
            if not p.name.startswith(".")
            and "site-packages" not in p.parts
        )

        if not python_files:
            raise ValueError(f"No Python files found in {root_path}")

        self.load_files(python_files, run_pipeline=run_pipeline)

    def load_files(self, python_files: list[Path],
                   *, run_pipeline: bool = True) -> None:
        """Load a specific set of Python files for analysis.

        Builds the interface, extracts the program, runs the default
        analysis pipeline, and initializes the query service.
        """
        console = Console(verbose=self._verbose)
        compiler = CompilerContext(console)
        program = Program()

        opts = InterfaceBuildOptions(
            dependency_strategy="auto",
            verbose=self._verbose,
        )
        program.interface, all_source_code = build_interface_from_paths(
            python_files, opts
        )
        compiler.extractor = Extractor(  # type: ignore[assignment]
            compiler, verbose=True, source_code=all_source_code  # type: ignore[arg-type]
        )

        with console.scope("extraction"):
            extract_program(compiler, program)

        if run_pipeline:
            with console.scope("analysis"):
                Pipeline(use_pass_manager=True).run(
                    program, compiler=compiler, name="lsp-server"
                )

        self._compiler = compiler
        self._program = program
        self._service = program.get_semantic_queries(compiler, server_mode=self._mode)
        self._service.set_server_mode(self._mode)
        self._loaded = True

    def close(self) -> None:
        """Release resources held by the server."""
        self._compiler = None
        self._program = None
        self._service = None
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

    # ------------------------------------------------------------------
    # Query methods — thin facades over SemanticQueryService
    # ------------------------------------------------------------------

    def get_capabilities(self) -> dict[str, Any]:
        return self.service.capabilities()

    # -- Call graph ----------------------------------------------------

    def get_callgraph_data(self) -> dict[str, Any]:
        return self.service.get_callgraph_data()

    def get_callers(self, function: str) -> list[str]:
        return self.service.get_callers(function)

    def get_callees(self, function: str) -> list[str]:
        return self.service.get_callees(function)

    def get_downstream_functions(self, function: str,
                                  max_depth: Optional[int] = None) -> list[str]:
        return self.service.get_downstream_functions(function, max_depth)

    def get_upstream_functions(self, function: str,
                                max_depth: Optional[int] = None) -> list[str]:
        return self.service.get_upstream_functions(function, max_depth)

    def get_shortest_path(self, source: str,
                          target: str) -> Optional[list[str]]:
        return self.service.get_shortest_path(source, target)

    # -- Control flow --------------------------------------------------

    def get_cfg_structure(self, function: str) -> dict[str, Any]:
        return self.service.get_cfg_structure(function)

    # -- Data flow -----------------------------------------------------

    def get_reaching_defs(self, function: str) -> dict[str, Any]:
        result = self.service.get_reaching_defs(function)
        return self._serialize_reaching_defs(result)

    def get_ipa_function_summaries(self,
                                   function: Optional[str] = None) -> list[Any]:
        return self.service.get_ipa_function_summaries(function)

    # -- Type information ----------------------------------------------

    def get_expression_type(self, module_name: str,
                            lineno: int,
                            col_offset: int) -> Optional[dict[str, Any]]:
        result = self.service.get_expression_type(module_name, lineno, col_offset)
        if result is None:
            return None
        return {"type": str(result)}

    # -- Heap / alias --------------------------------------------------

    def get_aliases_for_variable(self, variable: str) -> dict[str, Any]:
        info = self.service.get_aliases_for_variable(variable)
        return {
            "variable": info.variable,
            "aliases": list(info.aliases),
            "is_aliased": info.is_aliased,
            "ref_count": info.ref_count,
            "is_escaped": info.is_escaped,
        }

    def get_points_to_for_variable(self, variable: str) -> dict[str, Any]:
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
