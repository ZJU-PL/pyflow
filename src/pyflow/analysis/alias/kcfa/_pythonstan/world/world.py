"""Shared registry of project-wide services and analysis state."""

from contextvars import ContextVar
from typing import List, Dict, Optional, Tuple, TYPE_CHECKING
from pyflow.analysis.alias.kcfa._pythonstan.ir import IRModule, IRScope, IRImport

if TYPE_CHECKING:
    from .namespace import Namespace, NamespaceManager
    from .scope_manager import ScopeManager
    from .config import Config
    from .class_hierarchy import ClassHierarchy
    from .import_manager import ImportManager


class World:
    """Hold the managers and entry module used by a pipeline run.

    Legacy backend code accesses this registry through ``World()``.  The
    current instance is context-local, so concurrent pipelines do not share
    mutable module/scope managers.
    """

    namespace_manager: 'NamespaceManager'
    entry_module: IRModule
    class_hierarchy: 'ClassHierarchy'
    import_manager: 'ImportManager'
    module2ns: Dict[IRModule, 'Namespace']
    truncated_imports: List[Tuple[IRModule, IRImport, int]]

    _current: ContextVar[Optional['World']] = ContextVar(
        "pyflow_kcfa_world", default=None
    )

    def __new__(cls):
        current = cls._current.get()
        if current is not None:
            return current
        instance = super().__new__(cls)
        cls._current.set(instance)
        return instance

    @classmethod
    def fresh(cls) -> 'World':
        """Create and activate a new isolated pipeline world."""
        instance = super().__new__(cls)
        cls._current.set(instance)
        return instance

    @classmethod
    def set_current(cls, world: 'World') -> None:
        cls._current.set(world)

    def setup(self):
        """Create fresh scope, namespace, hierarchy, and import managers."""
        from .scope_manager import ScopeManager
        from .class_hierarchy import ClassHierarchy
        from .import_manager import ImportManager
        from .namespace import NamespaceManager
        
        self.scope_manager = ScopeManager()
        self.namespace_manager = NamespaceManager()
        self.class_hierarchy = ClassHierarchy()
        self.import_manager = ImportManager()

        self.module2ns = {}
        self.truncated_imports = []

    def build(self, config: 'Config'):
        """Reset managers and configure module search paths from ``config``."""
        self.config = config
        self.scope_manager.build()
        self.import_manager.build()
        self.namespace_manager.build(
            config.project_path,
            config.library_paths,
            mock_libs=config.mock_libs,
            prefer_mock_libs=config.prefer_mock_libs,
        )

    def set_entry_module(self, module: IRModule):
        """Set the root module for subsequent interprocedural analyses."""
        self.entry_module = module

    def get_entry_module(self) -> IRModule:
        """Return the configured interprocedural entry module."""
        return self.entry_module
