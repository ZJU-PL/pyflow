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


_local_modules = list()


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
    if _local_modules and os.path.dirname(_local_modules[0][1]) == directory:
        return _local_modules

    if not os.path.isdir(directory):
        # example/import_test_project/A.py -> example/import_test_project
        directory = os.path.dirname(directory)

    if directory == '':
        return _local_modules

    for path in os.listdir(directory):
        if _is_python_file(path):
            # A.py -> A
            module_name = os.path.splitext(path)[0]
            _local_modules.append((module_name, os.path.join(directory, path)))

    return _local_modules


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
    modules = list()
    for root, directories, filenames in os.walk(path):
        for filename in filenames:
            if _is_python_file(filename):
                directory = os.path.dirname(
                    os.path.realpath(
                        os.path.join(
                            root,
                            filename
                        )
                    )
                ).split(module_root)[-1].replace(
                    os.sep,  # e.g. '/'
                    '.'
                )
                directory = directory.replace('.', '', 1)

                module_name_parts = []
                if prepend_module_root:
                    module_name_parts.append(module_root)
                if directory:
                    module_name_parts.append(directory)

                if filename == '__init__.py':
                    path = root
                else:
                    module_name_parts.append(os.path.splitext(filename)[0])
                    path = os.path.join(root, filename)

                modules.append(('.'.join(module_name_parts), path))

    return modules


def _is_python_file(path):
    """Check if a path is a Python file.
    
    Args:
        path: File path to check
        
    Returns:
        bool: True if path has .py extension
    """
    if os.path.splitext(path)[1] == '.py':
        return True
    return False