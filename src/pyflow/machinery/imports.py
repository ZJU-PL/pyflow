
"""
Import management and module loading for PyFlow.

This module provides functionality for tracking module imports, managing import
graphs, and handling dynamic module loading during analysis. It includes custom
import hooks and loaders to intercept import operations and build dependency
graphs.
"""

import copy
import importlib
import os
import sys
from importlib import abc
from pyflow.machinery.utils import join_ns, to_mod_name


def get_custom_loader(ig_obj):
    """
    Create a custom loader factory that modifies an ImportManager object.
    
    This function returns a custom SourceLoader class that intercepts module
    loading operations to track import dependencies in the import graph.
    
    Args:
        ig_obj (ImportManager): The import manager to track imports in.
        
    Returns:
        type: A custom loader class.
    """

    class CustomLoader(abc.SourceLoader):
        """
        Custom loader that tracks module imports in the import graph.
        
        This loader intercepts module loading to build dependency relationships
        and track file paths for each imported module.
        """
        
        def __init__(self, fullname, path):
            """
            Initialize the custom loader.
            
            Args:
                fullname (str): The full module name being loaded.
                path (str): The file path of the module.
            """
            self.fullname = fullname
            self.path = path

            # Track the import in the import graph
            ig_obj.create_edge(self.fullname)
            if not ig_obj.get_node(self.fullname):
                ig_obj.create_node(self.fullname)
                ig_obj.set_filepath(self.fullname, self.path)

        def get_filename(self, fullname):
            """
            Get the filename for the module.
            
            Args:
                fullname (str): The full module name.
                
            Returns:
                str: The file path.
            """
            return self.path

        def get_data(self, filename):
            """
            Get the data for the module (empty for tracking purposes).
            
            Args:
                filename (str): The filename.
                
            Returns:
                str: Empty string (we don't actually load the module content).
            """
            return ""

    return CustomLoader


class ImportManager(object):
    """
    Manages module imports and tracks import dependencies.
    
    This class provides functionality for tracking module imports, building
    import graphs, and managing custom import hooks. It can intercept import
    operations to build comprehensive dependency graphs for analysis.
    """
    
    def __init__(self):
        """Initialize the import manager with empty state."""
        self.import_graph = dict()  # Maps module names to import information
        self.current_module = ""    # Currently being processed module
        self.input_file = ""        # Currently being processed file
        self.mod_dir = None         # Module directory being analyzed
        self.old_path_hooks = None  # Backup of original path hooks
        self.old_path = None        # Backup of original sys.path

    def set_pkg(self, input_pkg):
        """
        Set the package directory being analyzed.
        
        Args:
            input_pkg (str): The package directory path.
        """
        self.mod_dir = input_pkg

    def get_mod_dir(self):
        """
        Get the package directory being analyzed.
        
        Returns:
            str: The package directory path.
        """
        return self.mod_dir

    def get_node(self, name):
        """
        Get a module node from the import graph.
        
        Args:
            name (str): The module name to look up.
            
        Returns:
            dict or None: The module information if found, None otherwise.
        """
        if name in self.import_graph:
            return self.import_graph[name]

    def create_node(self, name):
        """
        Create a new module node in the import graph.
        
        Args:
            name (str): The module name to create.
            
        Returns:
            dict: The created module node.
            
        Raises:
            ImportManagerError: If name is invalid or node already exists.
        """
        if not name or not isinstance(name, str):
            raise ImportManagerError("Invalid node name")

        if self.get_node(name):
            raise ImportManagerError("Can't create a node a second time")

        self.import_graph[name] = {"filename": "", "imports": set()}
        return self.import_graph[name]

    def create_edge(self, dest):
        """
        Create an import edge from current module to destination.
        
        Args:
            dest (str): The destination module name.
            
        Raises:
            ImportManagerError: If dest is invalid or current module doesn't exist.
        """
        if not dest or not isinstance(dest, str):
            raise ImportManagerError("Invalid node name")

        node = self.get_node(self._get_module_path())
        if not node:
            raise ImportManagerError("Can't add edge to a non existing node")

        node["imports"].add(dest)

    def _clear_caches(self):
        importlib.invalidate_caches()
        sys.path_importer_cache.clear()
        # TODO: maybe not do that since it empties the whole cache
        for name in self.import_graph:
            if name in sys.modules:
                del sys.modules[name]

    def _get_module_path(self):
        return self.current_module

    def set_current_mod(self, name, fname):
        self.current_module = name
        self.input_file = os.path.abspath(fname)

    def get_filepath(self, modname):
        if modname in self.import_graph:
            return self.import_graph[modname]["filename"]

    def set_filepath(self, node_name, filename):
        if not filename or not isinstance(filename, str):
            raise ImportManagerError("Invalid node name")

        node = self.get_node(node_name)
        if not node:
            raise ImportManagerError("Node does not exist")

        node["filename"] = os.path.abspath(filename)

    def get_imports(self, modname):
        if modname not in self.import_graph:
            return []
        return self.import_graph[modname]["imports"]

    def _is_init_file(self):
        return self.input_file.endswith("__init__.py")

    def _handle_import_level(self, name, level):
        # add a dot for each level
        package = self._get_module_path().split(".")
        if level > len(package):
            raise ImportError("Attempting import beyond top level package")

        mod_name = ("." * level) + name
        # When an __init__ file is analyzed,
        # then the module name doesn't contain
        # the __init__ part in it,
        # so special care must be taken for levels.
        if self._is_init_file() and level >= 1:
            if level != 1:
                level -= 1
                package = package[:-level]
        else:
            package = package[:-level]

        return mod_name, ".".join(package)

    def _do_import(self, mod_name, package):
        if mod_name in sys.modules:
            self.create_edge(mod_name)
            return sys.modules[mod_name]

        try:
            module_spec = importlib.util.find_spec(mod_name, package=package)
        except ModuleNotFoundError:
            module_spec = None

        if module_spec is None:
            return importlib.import_module(mod_name, package=package)

        return importlib.util.module_from_spec(module_spec)

    def handle_import(self, name, level):
        # We currently don't support builtin modules because they're frozen.
        # Add an edge and continue.
        # TODO: identify a way to include frozen modules
        root = name.split(".")[0]
        if root in sys.builtin_module_names:
            self.create_edge(root)
            return

        # Import the module
        try:
            mod_name, package = self._handle_import_level(name, level)
        except ImportError:
            return

        parent = ".".join(mod_name.split(".")[:-1])
        parent_name = ".".join(name.split(".")[:-1])
        combos = [
            (mod_name, package),
            (parent, package),
            (join_ns(package, name), ""),
            (join_ns(package, parent_name), ""),
        ]

        mod = None
        for mn, pkg in combos:
            try:
                mod = self._do_import(mn, pkg)
                break
            except Exception:
                continue

        if not mod:
            return

        if not hasattr(mod, "__file__") or not mod.__file__:
            return
        if self.mod_dir not in mod.__file__:
            return
        fname = mod.__file__
        if fname.endswith("__init__.py"):
            fname = os.path.split(fname)[0]

        return to_mod_name(os.path.relpath(fname, self.mod_dir))

    def get_import_graph(self):
        return self.import_graph

    def install_hooks(self):
        """
        Install custom import hooks to intercept module loading.
        
        This method sets up custom import hooks that will track all module
        imports during analysis, building the import graph automatically.
        """
        loader = get_custom_loader(self)
        self.old_path_hooks = copy.deepcopy(sys.path_hooks)
        self.old_path = copy.deepcopy(sys.path)

        loader_details = loader, importlib.machinery.all_suffixes()
        sys.path_hooks.insert(
            0, importlib.machinery.FileFinder.path_hook(loader_details)
        )
        sys.path.insert(0, os.path.abspath(self.mod_dir))

        self._clear_caches()

    def remove_hooks(self):
        """
        Remove custom import hooks and restore original state.
        
        This method restores the original import system state after analysis
        is complete, ensuring no side effects remain.
        """
        sys.path_hooks = self.old_path_hooks
        sys.path = self.old_path

        self._clear_caches()


class ImportManagerError(Exception):
    """Exception raised for import manager related errors."""
    pass