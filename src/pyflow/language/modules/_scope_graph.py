"""Scope graph construction for name resolution.

This module provides ScopeGraph, which builds scope graphs for Python code
to enable name resolution. It tracks:
- Scopes: Module, function, and class scopes
- Declarations: Names declared in each scope
- References: Names referenced in each scope
- Inheritance: Class inheritance relationships
- Method Resolution Order (MRO): MRO for class method resolution

The scope graph enables precise name resolution by tracking where names
are declared and referenced across different scopes.
"""

import ast
import queue

import networkx as nx


class ScopeGraph(ast.NodeVisitor):
    """Builds scope graphs for name resolution.

    ScopeGraph traverses AST and builds graphs representing:
    - Scope relationships: Parent-child relationships between scopes
    - Declarations: Names declared in each scope
    - References: Names referenced in each scope
    - Inheritance: Class inheritance relationships
    - Method Resolution Order: MRO for resolving method calls

    Attributes:
        sg: Scope graph (directed graph of scopes)
        ig: Inheritance graph (directed graph of class inheritance)
        imports: Dictionary mapping scopes to imported names
        MRO_graph: Dictionary mapping classes to their base classes
        parent_relations: Dictionary mapping scopes to parent scopes
        references: Dictionary mapping scopes to referenced names
        declarations: Dictionary mapping scopes to declared names
        current_scope_name: Current scope being processed
    """

    def __init__(self) -> None:
        """Initialize scope graph builder.

        The central concepts in the framework are declarations, references, and scopes.
        """
        self.sg = nx.DiGraph()  # scope graph
        self.ig = nx.DiGraph()  # inheritance graph
        self.imports = {}  # save information about imported names and scopes
        self.MRO_graph = {}  # method resolution order
        self.parent_relations = {}  # parent relations among scopes
        self.references = {}  # dictionary for refereced names
        self.declarations = {}  # dictionary for declared names
        self.contained_scopes = {}  # parent scope -> list of child scopes
        self.declared_names = {}  # scope -> deduplicated declarations
        self.current_scope_name = None

    def build(self, ast_tree):
        """Build scope graph from AST tree.

        Traverses AST and builds scope graph, tracking declarations,
        references, and inheritance relationships.

        Args:
            ast_tree: AST tree to process
        """
        self.visit(ast_tree)
        return self

    def visit_FunctionDef(self, node):
        """Visit function definition node.

        Records function declaration and creates new scope for function body.

        Args:
            node: FunctionDef AST node

        Returns:
            ast.FunctionDef: Node (unchanged)
        """
        self.declarations[self.current_scope_name].append(node.name)
        self._add_declared()

        save_scope_name = self.current_scope_name
        self.current_scope_name = node.name
        self._add_scope_name(self.current_scope_name, save_scope_name)
        self._add_contained()

        if self.current_scope_name not in self.references:
            self.references[self.current_scope_name] = []

        if self.current_scope_name not in self.declarations:
            self.declarations[self.current_scope_name] = []

        self.generic_visit(node)
        self.current_scope_name = save_scope_name
        return node

    def visit_ClassDef(self, node):
        """Visit class definition node.

        Records class declaration, inheritance relationships, and creates
        new scope for class body.

        Args:
            node: ClassDef AST node

        Returns:
            ast.ClassDef: Node (unchanged)
        """
        # let's ignore basename is in the form of X.B.C which is annolying
        for bc in node.bases:
            if hasattr(bc, "id"):
                self.ig.add_edge(node.name, bc.id)
                if node.name in self.MRO_graph:
                    self.MRO_graph[node.name].append(bc.id)
                else:
                    self.MRO_graph[node.name] = [bc.id]

        self.declarations[self.current_scope_name].append(node.name)
        self._add_declared()

        save_scope_name = self.current_scope_name
        self.current_scope_name = node.name
        self._add_scope_name(self.current_scope_name, save_scope_name)
        self._add_contained()

        if self.current_scope_name not in self.references:
            self.references[self.current_scope_name] = []

        if self.current_scope_name not in self.declarations:
            self.declarations[self.current_scope_name] = []

        self.generic_visit(node)
        self.current_scope_name = save_scope_name
        return node

    def visit_Module(self, node):
        """Visit module node.

        Creates module scope and processes module body.

        Args:
            node: Module AST node

        Returns:
            ast.Module: Node (unchanged)
        """
        save_scope_name = self.current_scope_name
        self.current_scope_name = "Mod"
        self.sg.add_node(self.current_scope_name)

        if self.current_scope_name not in self.references:
            self.references[self.current_scope_name] = []

        if self.current_scope_name not in self.declarations:
            self.declarations[self.current_scope_name] = []

        self.generic_visit(node)
        self.current_scope_name = save_scope_name
        return node

    def visit_Name(self, node):
        """Visit name node.

        Records name as declaration (Store) or reference (Load/Del).

        Args:
            node: Name AST node
        """
        if isinstance(node.ctx, (ast.Load, ast.Del)):
            # this is
            self.references[self.current_scope_name].append(node.id)
        elif isinstance(node.ctx, ast.Store):
            self.declarations[self.current_scope_name].append(node.id)
            self._add_declared()

    def visit_Global(self, node):
        pass

    def visit_Nonlocal(self, node):
        pass

    def visit_Import(self, node):
        """Visit import statement.

        Records imported names in current scope.

        Args:
            node: Import AST node
        """
        for alias in node.names:
            if alias.asname is not None:
                name = alias.asname
            else:
                name = alias.name
            if self.current_scope_name not in self.imports:
                self.imports[self.current_scope_name] = []
            self.imports[self.current_scope_name].append(alias.name)

    def visit_ImportFrom(self, node):
        """Visit import from statement.

        Records imported names in current scope.

        Args:
            node: ImportFrom AST node
        """
        for alias in node.names:
            if alias.asname is not None:
                name = alias.asname
            else:
                name = alias.name
            if self.current_scope_name not in self.imports:
                self.imports[self.current_scope_name] = []
            self.imports[self.current_scope_name].append(alias.name)

    def resolve(self, name, working_scope):
        """Resolve a name in a given working scope.

        Finds the name in the given working scope, following parent scope
        relationships. A path with fewer parent transitions is more specific
        than a path with more parent transitions.

        Args:
            name: Name to resolve
            working_scope: Scope to start resolution from

        Returns:
            dict | None: Resolution metadata or None if unresolved
        """
        scope = working_scope
        visited = set()
        distance = 0
        while scope is not None and scope not in visited:
            visited.add(scope)

            if name in self.declarations.get(scope, ()):
                return {
                    "name": name,
                    "scope": scope,
                    "kind": "declaration",
                    "distance": distance,
                }

            if name in self.imports.get(scope, ()):
                return {
                    "name": name,
                    "scope": scope,
                    "kind": "import",
                    "distance": distance,
                }

            scope = self.parent_relations.get(scope)
            distance += 1

        return None

    def add_scope(self, scope_name, parent_name):
        """Add a scope with parent relationship.

        Args:
            scope_name: Name of scope to add
            parent_name: Name of parent scope
        """
        self._add_scope_name(scope_name, parent_name)
        if parent_name is not None:
            contained = self.contained_scopes.setdefault(parent_name, [])
            if scope_name not in contained:
                contained.append(scope_name)

    def add_reference(self, scope_name, name, ctx):
        """Add a name reference in a scope.

        Records a name reference (load/del) or declaration (store) in a scope.

        Bug M fix: the original code used ``self.references[scope_name] = name``
        and ``self.declarations[scope_name] = name``, which *replaced* the
        entire list with a single string.  Subsequent calls for the same scope
        would overwrite all previously recorded names.  The fix uses ``.append``
        (after ensuring the list exists) so that all names are accumulated.

        Args:
            scope_name: Scope name
            name: Name being referenced/declared
            ctx: Context ("load", "del", or "store")

        Raises:
            Exception: If context is unknown
        """
        if ctx in ("load", "del"):
            # deletion is treated as a use of the reference
            if scope_name not in self.references:
                self.references[scope_name] = []
            self.references[scope_name].append(name)  # Bug M fix: was = name

        elif ctx == "store":
            if scope_name not in self.declarations:
                self.declarations[scope_name] = []
            self.declarations[scope_name].append(name)  # Bug M fix: was = name
            # Keep deduplicated declaration cache in sync for explicit updates.
            raw = self.declarations.get(scope_name, ())
            deduped = []
            seen = set()
            for declared in raw:
                if declared not in seen:
                    seen.add(declared)
                    deduped.append(declared)
            self.declared_names[scope_name] = deduped

        else:
            raise Exception("Unknown context for given name reference")

    def _add_contained(self):
        """Track the current scope as contained by its parent."""
        scope_name = self.current_scope_name
        parent_name = self.parent_relations.get(scope_name)
        if parent_name is None:
            return
        contained = self.contained_scopes.setdefault(parent_name, [])
        if scope_name not in contained:
            contained.append(scope_name)

    def _add_declared(self):
        """Refresh deduplicated declarations for the current scope."""
        scope_name = self.current_scope_name
        if scope_name is None:
            return
        raw = self.declarations.get(scope_name, ())
        deduped = []
        seen = set()
        for name in raw:
            if name not in seen:
                seen.add(name)
                deduped.append(name)
        self.declared_names[scope_name] = deduped

    def _add_scope_name(self, scope_name, parent_name):
        """Add scope name with parent relationship.

        Args:
            scope_name: Name of scope
            parent_name: Name of parent scope
        """
        self.parent_relations[scope_name] = parent_name
        self.sg.add_node(scope_name)
        if parent_name is not None:
            self.sg.add_node(parent_name)
            self.sg.add_edge(parent_name, scope_name)

    def get_parent(self, scope_name):
        """Get parent scope for a scope.

        Args:
            scope_name: Name of scope

        Returns:
            str: Parent scope name

        Raises:
            Exception: If parent scope not found
        """
        # map scope to its parent scope
        if scope_name in self.parent_relations:
            return self.parent_relations[scope_name]
        raise Exception("Failed to locate parent scope!")

    def print_out(self):
        print(self.MRO_graph)

        # for k, v in self.references.items():
        #    print(k, v )
        # for k, v in self.declarations.items():
        #    print(k, v )

    def MRO_resolve(self, start_name):
        """Compute the MRO traversal order for a class.

        Bug L fix: the original method computed ``cls_name_order`` but never
        returned it — the result was silently discarded.  The method now
        returns the computed list.

        Also note: the traversal uses a FIFO queue (BFS), not DFS, despite
        the variable being named ``dfs_queue``.  The variable has been renamed
        to ``bfs_queue`` for clarity.
        """
        if start_name not in self.MRO_graph:
            raise Exception("Cannot locate the given name")

        init_names = self.MRO_graph[start_name]

        cls_name_order = []
        is_visited = set()
        bfs_queue = queue.Queue()  # Bug L fix: renamed from dfs_queue (it's BFS)

        for name in init_names:
            bfs_queue.put(name)

        while not bfs_queue.empty():
            cur_name = bfs_queue.get()
            if cur_name not in is_visited:
                is_visited.add(cur_name)
            else:
                continue
            cls_name_order.append(cur_name)
            if cur_name in self.MRO_graph:
                tmp_names = self.MRO_graph[cur_name]
                for name in tmp_names:
                    bfs_queue.put(name)

        return cls_name_order  # Bug L fix: was missing — result was never returned

    def MRO_resolve_method(self, cls_name, method_name):
        """Resolve method using Method Resolution Order (MRO).

        Given a class name and method name, uses MRO to find which class
        defines the method. Performs breadth-first search through inheritance
        hierarchy following MRO.

        Args:
            cls_name: Name of class to start search from
            method_name: Name of method to find

        Returns:
            str: Name of class that defines the method, or None if not found
        """
        if cls_name not in self.MRO_graph:
            # raise Exception("Cannot locate the given name", cls_name)
            return None

        init_names = self.MRO_graph[cls_name]

        cls_name_order = []
        is_visited = set()
        dfs_queue = queue.Queue()

        target_cls_name = None

        for name in init_names:
            dfs_queue.put(name)

        while not dfs_queue.empty():
            cur_name = dfs_queue.get()
            if cur_name not in is_visited:
                is_visited.add(cur_name)
            else:
                continue
            cls_name_order.append(cur_name)
            if cur_name not in self.declarations:
                continue
            if method_name in self.declarations[cur_name]:
                target_cls_name = cur_name
                break

            if cur_name in self.MRO_graph:
                tmp_names = self.MRO_graph[cur_name]
                for name in tmp_names:
                    dfs_queue.put(name)
        return target_cls_name

    def test(self):
        # print(self.MRO_garph
        pass

    def test_MRO_resolve(self, start_name):
        # self.MRO_resolve(start_name)
        target_cls_name = self.MRO_resolve_method("D", "rk")
        print(target_cls_name)
        pass


# need to write resolve a method name


def create_MRO():
    pass


def test_this_module():
    pass


if __name__ == "__main__":
    test_this_module()
