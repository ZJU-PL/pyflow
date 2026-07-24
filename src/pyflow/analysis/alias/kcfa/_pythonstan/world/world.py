"""Shared registry of project-wide services and analysis state."""

from typing import List, Dict, Optional, Tuple, TYPE_CHECKING

from pyflow.analysis.alias.kcfa._pythonstan.utils.common import Singleton
from pyflow.analysis.alias.kcfa._pythonstan.ir import IRModule, IRScope, IRImport

if TYPE_CHECKING:
    from .namespace import Namespace, NamespaceManager
    from .scope_manager import ScopeManager
    from .config import Config
    from .class_hierarchy import ClassHierarchy
    from .import_manager import ImportManager


class World(Singleton):
    """Hold the managers and entry module used by a pipeline run.

    The migrated backend accesses this registry as a singleton. :meth:`setup`
    creates manager instances and :meth:`build` configures them for a project.
    """

    namespace_manager: 'NamespaceManager'
    entry_module: IRModule
    class_hierarchy: 'ClassHierarchy'
    import_manager: 'ImportManager'
    module2ns: Dict[IRModule, 'Namespace']

    @classmethod
    def setup(cls):
        """Create fresh scope, namespace, hierarchy, and import managers."""
        from .scope_manager import ScopeManager
        from .class_hierarchy import ClassHierarchy
        from .import_manager import ImportManager
        from .namespace import NamespaceManager
        
        cls.scope_manager = ScopeManager()
        cls.namespace_manager = NamespaceManager()
        cls.class_hierarchy = ClassHierarchy()
        cls.import_manager = ImportManager()

        cls.module2ns = {}

    def build(self, config: 'Config'):
        """Reset managers and configure module search paths from ``config``."""
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
