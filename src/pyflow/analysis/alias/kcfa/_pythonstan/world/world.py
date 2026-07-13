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
    namespace_manager: 'NamespaceManager'
    entry_module: IRModule
    class_hierarchy: 'ClassHierarchy'
    import_manager: 'ImportManager'
    module2ns: Dict[IRModule, 'Namespace']

    @classmethod
    def setup(cls):
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
        self.scope_manager.build()
        self.import_manager.build()
        self.namespace_manager.build(
            config.project_path,
            config.library_paths,
            mock_libs=config.mock_libs,
            prefer_mock_libs=config.prefer_mock_libs,
        )

    def set_entry_module(self, module: IRModule):
        self.entry_module = module

    def get_entry_module(self) -> IRModule:
        return self.entry_module
