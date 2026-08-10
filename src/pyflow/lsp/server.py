"""Workspace analysis lifecycle and atomic snapshot publication."""

import os
import logging
import threading
from pathlib import Path
from typing import Optional

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.application.analysis_snapshot import AnalysisConfig, AnalysisSnapshot
from pyflow.application.pipeline import Pipeline
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import (
    InterfaceBuildOptions,
    build_interface_from_paths,
)
from pyflow.analysis.typeinfo import TypeInfoService
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.util.application.console import Console
from .workspace import SourceIndex, WorkspaceDocuments, uri_to_path

LOG = logging.getLogger(__name__)


def _read_source(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


class AnalysisManager:
    """Own workspace analysis state and atomically publish snapshots.

    Typical workflow::

        analysis = AnalysisManager()
        server.load("path/to/project/")   # or load_files([...])
        result = analysis.current_snapshot().queries.call_graph.get_callers("my_function")
    """

    def __init__(
        self,
        verbose: bool = False,
        analysis_config: Optional[AnalysisConfig] = None,
    ):
        self._snapshot: Optional[AnalysisSnapshot] = None
        self._analysis_config = analysis_config or AnalysisConfig()
        self._verbose = verbose
        self._loaded = False
        self._root_path: Optional[str] = None
        self._workspace_roots: tuple[str, ...] = ()
        self._python_files: list[Path] = []
        self._source_files: dict[str, str] = {}
        self._source_index = SourceIndex({})
        self._documents = WorkspaceDocuments()
        self._next_revision = 0
        self._state_lock = threading.RLock()
        self._analysis_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(
        self,
        root_path: str,
        *,
        run_pipeline: bool = True,
        passes: Optional[list[str]] = None,
    ) -> None:
        """Load a project directory for analysis.

        Discovers Python files, extracts an interface, runs the default
        analysis pipeline (or the specific *passes* if given), and makes
        a new analysis snapshot ready.
        """
        root_path = os.path.abspath(root_path)
        root = Path(root_path)
        if not root.is_dir():
            raise ValueError(f"Project root is not a directory: {root_path}")

        python_files = self._discover_python_files(root)

        if not python_files:
            raise ValueError(f"No Python files found in {root_path}")

        self._root_path = root_path
        self._workspace_roots = (root_path,)
        self.load_files(
            python_files,
            run_pipeline=run_pipeline,
            root_path=root_path,
            passes=passes,
        )

    @staticmethod
    def _discover_python_files(root: Path) -> list[Path]:
        """Discover the current workspace file set for every reload."""
        return sorted(
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

    def load_workspaces(
        self,
        root_paths: list[str],
        *,
        run_pipeline: bool = True,
        passes: Optional[list[str]] = None,
    ) -> None:
        """Load all supplied workspace folders into one published snapshot."""
        roots = tuple(os.path.abspath(path) for path in root_paths)
        if not roots:
            raise ValueError("At least one workspace folder is required")
        invalid = [path for path in roots if not Path(path).is_dir()]
        if invalid:
            raise ValueError(f"Workspace root is not a directory: {invalid[0]}")
        files = [
            file
            for root in roots
            for file in self._discover_python_files(Path(root))
        ]
        if not files:
            raise ValueError("No Python files found in workspace folders")
        self._workspace_roots = roots
        try:
            effective_root = os.path.commonpath(roots)
        except ValueError:
            # Roots on different drives have no common path. The compiler needs
            # one analysis root, while SourceIndex retains the actual roots.
            effective_root = roots[0]
        self.load_files(
            files,
            run_pipeline=run_pipeline,
            root_path=effective_root,
            passes=passes,
        )

    def load_files(
        self,
        python_files: list[Path],
        *,
        run_pipeline: bool = True,
        root_path: Optional[str] = None,
        passes: Optional[list[str]] = None,
    ) -> None:
        """Load a specific set of Python files for analysis.

        Builds the interface, extracts the program, runs the default
        analysis pipeline (or the specific *passes* if given),
        and initializes the query service.
        """
        normalized_files = [Path(path).absolute() for path in python_files]
        if not normalized_files:
            raise ValueError("At least one Python file is required")
        effective_root = os.path.abspath(
            root_path
            or self._root_path
            or os.path.commonpath([str(p.parent) for p in normalized_files])
        )
        if not self._workspace_roots:
            self._workspace_roots = (effective_root,)
        # Only one compiler pipeline is built at a time.  The completed state is
        # swapped atomically so queries can continue using the previous snapshot.
        with self._analysis_lock:
            # Read overlays after acquiring the analysis lock. Concurrent reload
            # requests therefore analyze the latest revision and cannot commit an
            # older snapshot after a newer one.
            source_overrides = self._documents.source_overrides()
            source_revision = self._documents.revision
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
                        passes if passes is not None else self._analysis_passes(),
                    )

            type_info = None
            if self._analysis_config.type_info:
                project_context = ProjectContext(
                    effective_root,
                    source_files=all_source_code,
                )
                type_info = TypeInfoService(project_context)
            source_index = SourceIndex(all_source_code, self._workspace_roots)

            with self._state_lock:
                self._next_revision += 1
                revision = self._next_revision
                self._snapshot = AnalysisSnapshot.create(
                    program=program,
                    compiler=compiler,
                    source_index=source_index,
                    source_files=dict(all_source_code),
                    revision=revision,
                    source_revision=source_revision,
                    type_info_service=type_info,
                )
                self._root_path = effective_root
                self._python_files = normalized_files
                self._source_files = dict(all_source_code)
                self._source_index = source_index
                self._loaded = True
            if self._documents.revision != source_revision:
                self._publish_syntax_snapshot()

    def _analysis_passes(self) -> list[str]:
        return self._analysis_config.passes()

    def reload(self) -> None:
        """Rebuild analysis from the current disk files plus open overlays."""
        with self._state_lock:
            files = list(self._python_files)
            root = self._root_path
        if root:
            roots = self._workspace_roots or (root,)
            discovered = [
                file
                for workspace_root in roots
                for file in self._discover_python_files(Path(workspace_root))
            ]
            if discovered:
                self.load_files(discovered, root_path=root)
                return
        if not files:
            raise RuntimeError("No project has been loaded")
        self.load_files(files, root_path=root)

    def open_document(self, uri: str, text: str, version: Optional[int] = None) -> bool:
        changed = self._documents.open(uri_to_path(uri), text, version)
        if changed and self._loaded:
            self._publish_syntax_snapshot()
        return changed

    def change_document(
        self,
        uri: str,
        changes: list[dict[str, object]],
        version: Optional[int] = None,
    ) -> bool:
        changed = self._documents.change(uri_to_path(uri), changes, version)
        if changed and self._loaded:
            self._publish_syntax_snapshot()
        return changed

    def close_document(self, uri: str) -> bool:
        changed = self._documents.close(uri_to_path(uri))
        if changed and self._loaded:
            self._publish_syntax_snapshot()
        return changed

    def _publish_syntax_snapshot(self) -> None:
        """Immediately publish current syntax while retaining semantic facts.

        The inherited query components remain pinned to the last completed
        semantic analysis and the resulting snapshot says so explicitly.
        """
        with self._state_lock:
            current = self._snapshot
            if current is None:
                return
            source_files = self._current_source_files()
            source_index = SourceIndex(source_files, self._workspace_roots)
            self._next_revision += 1
            self._snapshot = AnalysisSnapshot.create(
                program=current.program,
                compiler=current.compiler,
                source_index=source_index,
                source_files=source_files,
                revision=self._next_revision,
                semantic_revision=current.semantic_revision,
                source_revision=self._documents.revision,
                semantic_stale=True,
                type_info_service=current.type_info_service,
            )
            self._source_files = dict(source_files)
            self._source_index = source_index

    def _current_source_files(self) -> dict[str, str]:
        source_files: dict[str, str] = {}
        for path in self._python_files:
            normalized = str(path.absolute())
            source_files[normalized] = self._documents.text(normalized) or _read_source(
                path
            )
        for path, text in self._documents.source_overrides().items():
            if path.endswith(".py"):
                source_files[path] = text
        return source_files

    def close(self) -> None:
        """Release resources held by the server."""
        with self._state_lock:
            self._snapshot = None
            self._source_files = {}
            self._source_index = SourceIndex({})
            self._loaded = False

    def current_snapshot(self) -> AnalysisSnapshot:
        """Return one stable published snapshot for a complete request."""
        with self._state_lock:
            if not self._loaded or self._snapshot is None:
                raise RuntimeError("Server not loaded. Call load() first.")
            return self._snapshot

    @property
    def snapshot(self) -> AnalysisSnapshot:
        return self.current_snapshot()

    @property
    def queries(self):
        return self.current_snapshot().queries

    @property
    def compiler(self) -> CompilerContext:
        return self.current_snapshot().compiler

    @property
    def program(self) -> Program:
        return self.current_snapshot().program

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def source_index(self) -> SourceIndex:
        return self.current_snapshot().source_index

    @property
    def root_path(self) -> Optional[str]:
        return self._root_path

    @property
    def workspace_roots(self) -> tuple[str, ...]:
        return self._workspace_roots

    def supports(self, capability: str) -> bool:
        return self.is_loaded and self.current_snapshot().features.supports(capability)
