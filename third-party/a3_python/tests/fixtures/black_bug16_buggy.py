"""Buggy version of black gen_python_files_in_dir (black#16).

The bug: child.resolve().relative_to(root) raises ValueError when child
is a symbolic link pointing outside the root directory.  There is no
try/except to handle this case.
"""
import re
from pathlib import Path


def gen_python_files_in_dir(path, root, include, exclude, report):
    """Generate all files under `path` whose paths are not excluded by the
    `exclude` regex, but are included by the `include` regex.

    `report` is where output about exclusions goes.
    """
    assert root.is_absolute(), f"INTERNAL ERROR: `root` must be absolute but is {root}"
    for child in path.iterdir():
        normalized_path = "/" + child.resolve().relative_to(root).as_posix()
        if child.is_dir():
            normalized_path += "/"
        exclude_match = exclude.search(normalized_path)
        if exclude_match and exclude_match.group() != normalized_path:
            report.path_ignored(child, f"matches --exclude={exclude.pattern}")
            continue
        if child.is_dir():
            yield from gen_python_files_in_dir(child, root, include, exclude, report)
        elif child.is_file():
            include_match = include.search(child.name)
            if include_match:
                yield child
