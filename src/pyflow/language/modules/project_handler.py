"""Project handler for discovering and processing Python modules.

This module provides utilities for discovering Python modules in directories
and projects. It handles:
- Directory scanning: Finding all Python files in a directory
- Module discovery: Recursively finding modules in a project
- Module naming: Generating qualified module names from file paths

Key functions:
- get_directory_modules: Get modules in a single directory
- get_modules: Recursively discover modules in a project
"""

import os

from .project_resolution import ProjectContext

# Bug K fix: the original code used a module-level mutable list ``_local_modules``
# as a cache.  The cache was never cleared between calls, so if
# ``get_directory_modules`` was called for a second (different) directory in the
# same process it would return the stale results from the first call.
# The fix uses a dict keyed by directory so each directory has its own cache
# entry and results are never mixed.
_local_modules_cache: dict = {}


def get_directory_modules(directory):
    """Get all Python modules in a directory.

    Returns a list of (module_name, file_path) tuples for all Python
    files in the directory. Results are cached per directory.

    Args:
        directory: Directory path to scan (or file path, will use parent)

    Returns:
        list: List of (module_name, file_path) tuples
            Example: [('__init__', 'example/import_test_project/__init__.py'), ...]
    """
    if not os.path.isdir(directory):
        # example/import_test_project/A.py -> example/import_test_project
        directory = os.path.dirname(directory)

    if directory == "":
        return []

    # Bug K fix: use per-directory cache instead of a single shared list.
    if directory in _local_modules_cache:
        return _local_modules_cache[directory]

    modules = []
    for path in os.listdir(directory):
        if _is_python_file(path):
            # A.py -> A
            module_name = os.path.splitext(path)[0]
            modules.append((module_name, os.path.join(directory, path)))

    _local_modules_cache[directory] = modules
    return modules


def get_modules(path, prepend_module_root=True):
    """Recursively discover all Python modules in a project.

    Walks the directory tree starting from path and finds all Python files,
    generating qualified module names based on directory structure.

    Args:
        path: Root directory path to scan
        prepend_module_root: Whether to prepend root directory name to module names

    Returns:
        list: List of (qualified_module_name, file_path) tuples
            Example: [('test_project.utils', 'example/test_project/utils.py'), ...]
    """
    module_root = os.path.split(path)[1]
    project = ProjectContext(os.path.dirname(os.path.abspath(path)) or os.curdir)
    modules = list()
    for root, directories, filenames in os.walk(path):
        for filename in filenames:
            if _is_python_file(filename):
                file_path = os.path.join(root, filename)
                qualified_name = project.module_name_from_path(file_path)
                if filename == "__init__.py":
                    module_path = root
                else:
                    module_path = file_path

                if not prepend_module_root and qualified_name.startswith(
                    module_root + "."
                ):
                    qualified_name = qualified_name[len(module_root) + 1 :]

                modules.append((qualified_name, module_path))

    return modules


def _is_python_file(path):
    """Check if a path is a Python file.

    Args:
        path: File path to check

    Returns:
        bool: True if path has .py extension
    """
    if os.path.splitext(path)[1] == ".py":
        return True
    return False
