"""Map lowered import statements to their resolved module objects."""

from typing import Tuple, Dict
from pyflow.analysis.alias.kcfa._pythonstan.ir import IRImport, IRModule


class ImportManager:
    """Store import resolution results for later analysis passes."""

    mod_import_submod: Dict[Tuple[IRModule, IRImport], IRModule] = {}

    def build(self):
        """Clear all recorded import resolutions."""
        self.mod_import_submod = {}

    def set_import(self, mod: IRModule, imp: IRImport, submod: IRModule):
        """Record the target module for an import in ``mod``."""
        self.mod_import_submod[(mod, imp)] = submod

    def get_import(self, mod: IRModule, imp: IRImport) -> IRModule:
        """Return the resolved target for ``imp`` in ``mod``."""
        return self.mod_import_submod[(mod, imp)]
