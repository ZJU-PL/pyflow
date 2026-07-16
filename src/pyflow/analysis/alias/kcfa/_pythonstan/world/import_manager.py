from typing import Tuple, Dict
from pyflow.analysis.alias.kcfa._pythonstan.ir import IRImport, IRModule


class ImportManager:
    mod_import_submod: Dict[Tuple[IRModule, IRImport], IRModule] = {}

    def build(self):
        self.mod_import_submod = {}

    def set_import(self, mod: IRModule, imp: IRImport, submod: IRModule):
        self.mod_import_submod[(mod, imp)] = submod

    def get_import(self, mod: IRModule, imp: IRImport) -> IRModule:
        return self.mod_import_submod[(mod, imp)]

