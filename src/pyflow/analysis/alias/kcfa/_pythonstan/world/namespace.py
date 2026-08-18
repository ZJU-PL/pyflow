"""Represent module namespaces and resolve imports to source or stub files."""

import ast
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pyflow.analysis.alias.kcfa._pythonstan.ir import IRImport
from pyflow.analysis.alias.kcfa._pythonstan.utils.common import (
    builtin_module_names,
    is_src_file,
)


def get_root(path: str, names: List[str]) -> str:
    """Remove a module namespace suffix from ``path`` to recover its root."""
    prev_num = len(names)
    path_obj = Path(path)
    if path_obj.name == "__init__.py":
        module_path = path_obj.parent
    elif path_obj.suffix == ".py":
        module_path = path_obj.with_suffix("")
    else:
        module_path = path_obj
    parts = module_path.parts
    root_parts = parts[: -prev_num] if prev_num <= len(parts) else parts
    if not root_parts:
        return path_obj.anchor if path_obj.is_absolute() else ""
    return str(Path(*root_parts))


class Namespace:
    """Interned dotted module name represented as path-like components."""

    names: List[str]
    empty_ns = None

    ns_dict: Dict[str, 'Namespace'] = {}

    def __init__(self, names):
        assert len(names) > 0, "Cannot  construct empty namespace"
        self.names = names
        self.ns_dict['.'.join(names)] = self

    def __str__(self):
        return '.'.join(self.names)

    @classmethod
    def build(cls, names: List[str]) -> 'Namespace':
        name_str = '.'.join(names)
        if name_str in cls.ns_dict:
            return cls.ns_dict[name_str]
        else:
            return cls(names)

    @classmethod
    def from_str(cls, name_str: str) -> 'Namespace':
        return cls.build(name_str.split('.'))

    @classmethod
    def from_path(cls, filename: str) -> 'Namespace':
        path_obj = Path(filename)
        if path_obj.name == "__init__.py":
            module_path = path_obj.parent
        elif path_obj.suffix == ".py":
            module_path = path_obj.with_suffix("")
        else:
            module_path = path_obj
        parts = list(module_path.parts)
        if parts and parts[0] == os.sep:
            parts = parts[1:]
        return cls(parts)

    def to_str(self):
        return '.'.join(self.names)
    
    def __str__(self):
        return self.to_str()
    
    def __repr__(self) -> str:
        return self.to_str()

    def to_filepath(self, rootpath: Optional[str] = None) -> str:
        path = f'{"/".join(self.names)}.py'
        if rootpath is not None:
            path = os.path.join(rootpath, path)
        return path

    def to_dirpath(self, rootpath: Optional[str] = None) -> str:
        path =  f'{"/".join(self.names)}/__init__.py'
        if rootpath is not None:
            path = os.path.join(rootpath, path)
        return path

    def base(self):
        return self.names[0]

    def relative_ns(self, names: List[str], level: int) -> 'Namespace':
        assert level >= 0
        assert len(self.names) >= level
        
        # TODO names=[''] is a special case, need to be clarified in the future
        if len(names) == 1 and names[0] == '':
            return self
        
        if level > 0:
            return self.build(self.names[: -level] + names)
        else:
            return self.build(self.names + names)

    def next_ns(self, names: List[str]) -> 'Namespace':
        return self.build(self.names + names)

    def subns(self, name):
        assert len(name) > 0
        return Namespace(self.names + [name])

    def prev_ns(self) -> 'Namespace':
        assert len(self.names) > 0
        return Namespace(self.names[:-1])

    def get_name(self) -> str:
        assert len(self.names) > 0
        return self.names[-1]


class NamespaceManager:
    """Resolve absolute and relative imports across project and stub paths.

    Results are cached in namespace-to-path and dotted-name indexes. Standard
    library models can be preferred or used only when real modules are absent.
    """

    homepath: str
    paths: List[str]
    names2path: Dict[str, str]
    ns2path: Dict[Namespace, str]
    resolved_paths: Dict[str, Optional[str]]
    mock_root: Path
    mock_libs: bool
    prefer_mock_libs: bool

    def build(
        self,
        homepath: str,
        paths: Optional[List[str]],
        mock_libs: bool = True,
        prefer_mock_libs: bool = False,
    ):
        """Initialize search roots, caches, and standard-library stub policy."""
        self.homepath = homepath
        self.paths = [homepath] + (paths or [])
        self.names2path = {}
        self.ns2path = {}
        self.resolved_paths = {}
        self.mock_libs = mock_libs
        self.prefer_mock_libs = prefer_mock_libs
        self.mock_root = (
            Path(__file__).resolve().parents[1]
            / "stubs"
            / "stdlib"
        )

    # path to namespace
    def get_module(self, filepath: str) -> Namespace:
        full_path = filepath
        if not os.path.isabs(filepath):
            for path in self.paths:
                cur_path = os.path.join(path, filepath)
                if (is_src_file(cur_path) and os.path.isfile(cur_path)) \
                        or os.path.isdir(cur_path):
                    full_path = cur_path
                    break
        ns = Namespace.from_str(full_path)
        return ns

    def get_ns2path(self, ns: Namespace) -> str:
        return self.names2path[ns.to_str()]
    
    def set_entry_module(self, module_path: str, root_path: str) -> Namespace:
        """Register and return the namespace of the analysis entry module."""
        if root_path.endswith("/"):
            root_path = root_path[:-1]
        if module_path.startswith(root_path):
            rel_module_path = module_path[len(root_path) + 1:]
        else:
            rel_module_path = module_path
        ns = Namespace.from_path(rel_module_path)
        self.ns2path[ns] = module_path
        self.names2path[ns.to_str()] = module_path
        return ns

    def names_from_import(self, ir: IRImport) -> List[str]:
        ...

    def _cache_ns_path(self, ns: Namespace, path: str) -> str:
        self.ns2path[ns] = path
        self.names2path[ns.to_str()] = path
        self.resolved_paths[ns.to_str()] = path
        return path

    def find_ns_in_path(self, paths: List[str], ns: Namespace) -> Optional[str]:
        for path in paths:
            if os.path.isfile(ns.to_filepath(rootpath=path)):
                mod_path = ns.to_filepath(path)
                return self._cache_ns_path(ns, mod_path)
            elif os.path.isfile(ns.to_dirpath(rootpath=path)):
                mod_path = ns.to_dirpath(path)
                return self._cache_ns_path(ns, mod_path)
        if ns.base() in builtin_module_names():
            return self._cache_ns_path(ns, f"__builtin__.{ns.base()}")
        return None

    def _find_mock_path(self, ns: Namespace) -> Optional[str]:
        if not self.mock_libs:
            return None
        if not self.mock_root.exists():
            return None
        file_path = ns.to_filepath(rootpath=str(self.mock_root))
        if os.path.isfile(file_path):
            return file_path
        dir_path = ns.to_dirpath(rootpath=str(self.mock_root))
        if os.path.isfile(dir_path):
            return dir_path
        return None

    def _resolve_import_path(self, ns: Namespace) -> Optional[str]:
        name = ns.to_str()
        if name in self.resolved_paths:
            return self.resolved_paths[name]

        if not self.mock_libs:
            result = self.find_ns_in_path(self.paths, ns)
        elif self.prefer_mock_libs:
            mock_path = self._find_mock_path(ns)
            if mock_path is not None:
                result = self._cache_ns_path(ns, mock_path)
            else:
                result = self.find_ns_in_path(self.paths, ns)
        else:
            result = self.find_ns_in_path(self.paths, ns)
            if result is None:
                mock_path = self._find_mock_path(ns)
                result = (
                    self._cache_ns_path(ns, mock_path)
                    if mock_path is not None
                    else None
                )

        # Negative results are stable because a manager's search roots and
        # stub policy do not change during a pipeline run.
        self.resolved_paths[name] = result
        return result

    def resolve_import(self, name: str) -> Optional[Tuple[Namespace, str]]:
        """
        Resolve import from name to namespace and path.
        
        Args:
            name: Name of the module to import
        
        Returns:
            Tuple[Namespace, str]: Namespace and path of the imported module
        """
        ns = Namespace.from_str(name)
        path = self._resolve_import_path(ns)
        if path is not None:
            return ns, path
        return None

    def resolve_importfrom(self, module: str, name: str) -> Optional[Tuple[Namespace, str]]:
        """
        Resolve import from module.name to name.
        
        Args:
            module: Module name
            name: Name of the item to import
        
        Returns:
            Tuple[Namespace, str]: Namespace and path of the imported module
        """
        mod_ns = Namespace.from_str(module)
        succ_mod_ns = mod_ns.next_ns([name])
        succ_mod_path = self._resolve_import_path(succ_mod_ns)
        mod_path = self._resolve_import_path(mod_ns)
        if succ_mod_path is not None:
            return succ_mod_ns, succ_mod_path
        elif mod_path is not None:
            return mod_ns, mod_path
        return None

    def resolve_rel_importfrom(self, cur_ns: Namespace, module: str, name: str, level: int) -> Optional[Tuple[Namespace, str]]:
        """
        Resolve relative import from cur_ns to module.name with level.
        
        Args:
            cur_ns: Current namespace
            module: Module name
            name: Name of the item to import
            level: Level of the relative import
        
        Returns:
            Tuple[Namespace, str]: Namespace and path of the imported module
        """
        if self.ns2path[cur_ns].endswith('__init__.py'):
            level -= 1
        rel_ns = cur_ns.relative_ns(module.split('.'), level)
        root_path = get_root(self.ns2path[cur_ns], cur_ns.names)
        if os.path.isfile(rel_ns.to_filepath(root_path)):
            rel_ns_path = rel_ns.to_filepath(root_path)
            self.ns2path[rel_ns] = rel_ns_path
            return rel_ns, rel_ns_path
        
        elif os.path.isfile(rel_ns.to_dirpath(root_path)):
            succ_rel_ns = rel_ns.next_ns([name])
            
            if os.path.isfile(succ_rel_ns.to_filepath(root_path)):
                succ_rel_path = succ_rel_ns.to_filepath(root_path)
                self.ns2path[succ_rel_ns] = succ_rel_path
                return succ_rel_ns, succ_rel_path
            
            elif os.path.isfile(succ_rel_ns.to_dirpath(root_path)):
                succ_rel_path = succ_rel_ns.to_dirpath(root_path)
                self.ns2path[succ_rel_ns] = succ_rel_path
                return succ_rel_ns, succ_rel_path
            
            else:
                rel_path = rel_ns.to_dirpath(root_path)
                self.ns2path[rel_ns] = rel_path
                return rel_ns, rel_path
            
        return None

    def get_import(self, cur_ns: Namespace, ir: IRImport) -> Optional[Tuple[Namespace, str]]:
        """
        Get namespace and path of the imported module from cur_ns and ir.
        
        Args:
            cur_ns: Current namespace
            ir: Import statement
        
        Returns:
            Tuple[Namespace, str]: Namespace and path of the imported module
        """
        if isinstance(ir.stmt, ast.Import):
            return self.resolve_import(ir.name)
        elif isinstance(ir.stmt, ast.ImportFrom):
            if ir.level == 0:
                ret = self.resolve_importfrom(ir.module, ir.name)
                # assert ret is not None, f"Failed to resolve import: {ir.module}, {ir.name}"
                return ret
            else:
                ret = self.resolve_rel_importfrom(cur_ns, ir.module, ir.name, ir.level)
                # assert ret is not None, f"Failed to resolve relative import: {ir.module}, {ir.name}, {ir.level}"
                return ret
        return None
