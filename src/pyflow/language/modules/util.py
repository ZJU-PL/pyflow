"""Utility functions for module discovery and AST manipulation.

This module provides utilities for:
- AST iteration: Iterating over AST node fields, children, and statements
- Local module discovery: Finding local (project) modules from import statements
- Path utilities: Finding files by extension
- AST manipulation: Unit-based AST manipulation with parent tracking

Key functions:
- iter_fields: Iterate over AST node fields
- iter_child_nodes: Iterate over AST child nodes
- iter_stmt_children: Iterate over statement children
- find_local_modules: Find local modules from import statements
- get_path_by_extension: Find files by extension
"""

import ast
import os
import pkgutil
import sys
from _ast import *

import astor


def iter_fields(node):
    """Iterate over AST node fields.
    
    Yields (fieldname, value) tuples for each field in node._fields
    that is present on the node.
    
    Args:
        node: AST node to iterate over
        
    Yields:
        tuple: (fieldname, value) for each field
    """
    for field in node._fields:
        try:
            yield field, getattr(node, field)
        except AttributeError:
            pass


def iter_child_nodes(node):
    """Iterate over direct child nodes of an AST node.
    
    Yields all fields that are AST nodes and all items in fields
    that are lists of AST nodes.
    
    Args:
        node: AST node to iterate over
        
    Yields:
        AST: Direct child nodes
    """
    for name, field in iter_fields(node):
        if isinstance(field, AST):
            yield field
        elif isinstance(field, list):
            for item in field:
                if isinstance(item, AST):
                    yield item


def iter_stmt_children(node):
    """Iterate over statement children of an AST node.
    
    Yields all fields that are statement nodes and all items in fields
    that are lists of statement nodes.
    
    Args:
        node: AST node to iterate over
        
    Yields:
        ast.stmt: Direct statement child nodes
    """
    children = []
    for name, field in iter_fields(node):
        if isinstance(field, ast.stmt):
            yield field
        elif isinstance(field, list):
            for item in field:
                if isinstance(item, ast.stmt):
                    yield item


def find_local_modules(import_smts):
    """Find local (project) modules from import statements.
    
    Parses import statements and identifies modules that are not standard
    library or installed packages (i.e., local project modules).
    
    Args:
        import_smts: List of import statement strings
        
    Returns:
        list: List of local module names (not in standard library)
    """
    smts = "\n".join(import_smts)
    tree = ast.parse(smts, mode="exec")
    search_path = ["."]
    module_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for nn in node.names:
                module_names.add(nn.name.split(".")[0])
        if isinstance(node, ast.ImportFrom):
            if node.level == 2:
                search_path += [".."]
            if node.module is not None:
                module_names.add(node.module.split(".")[0])
            else:
                for nn in node.names:
                    module_names.add(nn.name)
    module_name_plus = [
        "random",
        "unittest",
        "warning",
        "os",
        "pandas",
        "IPython",
        "seaborn",
        "matplotlib",
        "sklearn",
        "numpy",
        "scipy",
        "math",
        "matplotlib",
    ]
    search_path = list(set(search_path))
    all_modules = [x[1] for x in pkgutil.iter_modules(path=search_path)]
    all_modules += list(sys.builtin_module_names) + module_name_plus
    result = []
    for m_name in module_names:
        if m_name not in all_modules:
            result += [m_name]
    return result


def get_path_by_extension(root_dir, num_of_required_paths, flag=".ipynb"):
    """Find files by extension in a directory tree.
    
    Recursively searches for files with a specific extension, stopping
    when the required number of paths is found.
    
    Args:
        root_dir: Root directory to search
        num_of_required_paths: Maximum number of paths to return
        flag: File extension to search for (default: ".ipynb")
        
    Returns:
        list: List of file paths matching the extension
    """
    paths = []
    for root, dirs, files in os.walk(root_dir):
        files = [f for f in files if not f[0] == "."]
        dirs[:] = [d for d in dirs if not d[0] == "."]
        for file in files:
            if file.endswith(flag):
                paths.append(os.path.join(root, file))
                if len(paths) == num_of_required_paths:
                    return paths
    return paths


class Unit:
    """Represents an AST node with parent tracking for manipulation.
    
    Unit wraps an AST node with its parent, enabling AST manipulation
    operations like insertion and removal. It maintains parent-child
    relationships for statement-level operations.
    
    Attributes:
        node: AST node being wrapped
        parent: Parent AST node (has 'body' attribute)
    """
    def __init__(self, node, parent):
        """Initialize unit.
        
        Args:
            node: AST node to wrap
            parent: Parent AST node
        """
        self.node = node
        self.parent = parent
        # other params such lineno, col offset
        # block info

    def __str__(self):
        """String representation of the node.
        
        Returns:
            str: AST dump of the node
        """
        # string representation
        return ast.dump(self.node)

    def search_for_pos(self, stmt_lst, current_stmt):
        """Find position of current statement in a list.
        
        Args:
            stmt_lst: List of statements to search
            current_stmt: Statement to find
            
        Returns:
            int: Index of statement, or -1 if not found
        """
        for i, stmt in enumerate(stmt_lst):
            #        print(astor.to_source(stmt), astor.to_source(current_stmt))
            if stmt == current_stmt:
                return i
        return -1

    def insert_stmt_before(self, new_stmt):
        """Insert a statement before this node.
        
        Args:
            new_stmt: AST statement node to insert
            
        Raises:
            Exception: If insertion fails (no parent or no body)
        """
        if self.parent is not None and hasattr(self.parent, "body"):
            try:
                pos = self.parent.body.index(self.node)
                self.parent.body.insert(pos, new_stmt)
            except Exception as e:
                raise Exception("Insertion Failure")
        else:
            raise Exception("Error!!")

    def insert_stmts_before(self, new_stmts):
        """Insert multiple statements before this node (replacing it).
        
        Args:
            new_stmts: List of AST statement nodes to insert
            
        Raises:
            Exception: If insertion fails (no parent or no body)
        """
        if self.parent is not None and hasattr(self.parent, "body"):
            try:
                pos = self.parent.body.index(self.node)

                self.parent.body[pos : pos + 1] = new_stmts
            except Exception as e:
                raise Exception("Insertion Failure")
        else:
            raise Exception("Error!!")

    def insert_after(self, new_stmt):
        """Insert a statement after this node.
        
        Args:
            new_stmt: AST statement node to insert
            
        Raises:
            Exception: If insertion fails (no parent or no body)
        """
        if self.parent is not None and hasattr(self.parent, "body"):
            try:
                pos = self.parent.body.index(self.node)
                self.parent.body.insert(pos + 1, new_stmt)
            except Exception as e:
                raise Exception("Insertion Failure")
        else:
            raise Exception("Error!!")

    def remove():
        """Remove this node (not implemented)."""
        return None

    def replace():
        """Replace this node (not implemented)."""
        return 0


def UnitWalker(module_node):
    """Walk AST at statement level, yielding Unit objects.
    
    Performs breadth-first traversal of AST, yielding Unit objects
    for each statement node. Maintains parent-child relationships
    for AST manipulation.
    
    Args:
        module_node: AST Module node to walk
        
    Yields:
        Unit: Unit object for each statement node
    """
    # this code is adapted from the implementation of ast.walk
    # it does only handle statement level
    # offset to the first
    from collections import deque

    init_stmts = []
    for node in module_node.body:
        node.parent = module_node
        init_stmts += [node]
    todo = deque(init_stmts)
    parent = module_node
    while todo:
        node = todo.popleft()
        yield Unit(node, node.parent)
        if hasattr(node, "body"):
            for ch_node in node.body:
                ch_node.parent = node
                todo.append(ch_node)


class StmtIterator:
    """Iterator for AST statements with manipulation capabilities.
    
    StmtIterator provides an iterator interface for traversing AST statements
    with support for insertion, removal, and replacement operations.
    Note: This class is incomplete and not fully implemented.
    
    Attributes:
        src: Source code string
        ast: Parsed AST tree
        working_stack: Stack of statement lists to process
    """
    def __init__(self, src):
        """Initialize statement iterator.
        
        Args:
            src: Source code string to parse
        """
        self.src = src
        self.ast = ast.parse(src)
        assert hasattr(self.ast, "body")
        self.working_stack = [self.ast.body]

    def __iter__(self):
        """Return iterator (self).
        
        Returns:
            StmtIterator: Self
        """
        return self

    def __next__(self):
        """Get next statement (not implemented).
        
        Raises:
            Exception: StopIteration (not implemented)
        """
        # needs to return statement with the block information to allow
        # insertion and removal
        current_loc = 0
        raise Exception("StopIteration")

    def insert_before(self, new_stmt):
        """Insert statement before current (not implemented)."""
        pass

    def insert_after(self, new_stmt):
        """Insert statement after current (not implemented)."""
        pass

    def remove(self):
        """Remove current statement (not implemented)."""
        pass

    def replace(self, new_stmt):
        """Replace current statement (not implemented)."""
        pass
