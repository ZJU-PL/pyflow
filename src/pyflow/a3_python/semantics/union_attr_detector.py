"""
AST-based Union-type attribute access detector.

Detects patterns where a variable with a Union type annotation (or a type
alias resolving to Union) has its children iterated, and variant-specific
attributes are accessed on child elements without isinstance guards.

Key bug pattern (BugsInPy black#2):
    LN = Union[Node, Leaf]

    def generate_ignored_nodes(leaf: Leaf) -> Iterator[LN]:
        container: Optional[LN] = container_of(leaf)
        while container is not None:
            # container.children yields LN items, but code doesn't check
            # if child is Node or Leaf before accessing variant-specific attrs
            yield container
            container = container.next_sibling

Fix pattern:
    - Add isinstance(child, Node) / isinstance(child, Leaf) before accessing
      variant-specific attributes (.column, .children recursion, etc.)
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple


@dataclass
class UnionAttrBug:
    """A union-type attribute access bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'union_children_no_isinstance'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_union_attr_bugs(file_path: Path) -> List[UnionAttrBug]:
    """Scan a single Python file for union-type attribute access patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _UnionAttrVisitor(str(file_path), source)
    visitor.visit(tree)
    return visitor.bugs


def _extract_union_names(annotation: ast.expr) -> Optional[Set[str]]:
    """Extract class names from a Union[A, B, ...] or Optional[X] annotation.

    Returns a set of names if the annotation is a Union, else None.
    """
    # Union[A, B]  ->  ast.Subscript(value=Name('Union'), slice=Tuple([Name('A'), Name('B')]))
    if isinstance(annotation, ast.Subscript):
        base = annotation.value
        if isinstance(base, ast.Name) and base.id in ('Union', 'Optional'):
            if base.id == 'Optional':
                # Optional[X] == Union[X, None]
                inner = annotation.slice
                if isinstance(inner, ast.Name):
                    return {inner.id, 'None'}
                elif isinstance(inner, ast.Subscript):
                    # Optional[Union[A, B]]
                    inner_names = _extract_union_names(inner)
                    if inner_names:
                        inner_names.add('None')
                        return inner_names
            else:
                # Union[A, B, ...]
                slc = annotation.slice
                if isinstance(slc, ast.Tuple):
                    names = set()
                    for elt in slc.elts:
                        if isinstance(elt, ast.Name):
                            names.add(elt.id)
                        elif isinstance(elt, ast.Constant) and elt.value is None:
                            names.add('None')
                    if len(names) >= 2:
                        return names
        # Handle attribute-based annotations (e.g., typing.Union)
        elif isinstance(base, ast.Attribute) and base.attr in ('Union', 'Optional'):
            return _extract_union_names(
                ast.Subscript(value=ast.Name(id=base.attr), slice=annotation.slice)
            )
    return None


class _UnionAttrVisitor(ast.NodeVisitor):
    """AST visitor detecting missing isinstance guard on Union-typed variables."""

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.bugs: List[UnionAttrBug] = []
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None
        # Map type alias names to their union member names
        self._union_aliases: Dict[str, Set[str]] = {}
        # Collect module-level type aliases first
        self._scan_aliases_from_source()

    def _scan_aliases_from_source(self):
        """Pre-scan for type alias assignments like LN = Union[Node, Leaf]."""
        try:
            tree = ast.parse(self.source)
        except SyntaxError:
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Subscript):
                    union_names = _extract_union_names(node.value)
                    if union_names:
                        self._union_aliases[target.id] = union_names

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_func(node)

    def _visit_func(self, node):
        old_func = self._current_function
        if self._current_class:
            self._current_function = f"{self._current_class}.{node.name}"
        else:
            self._current_function = node.name

        self._analyze_function(node)
        self._current_function = old_func

    def _analyze_function(self, func_node):
        """Analyze a function for union-type attribute access without isinstance."""
        # Check for partial isinstance discrimination in .children iteration
        # (works regardless of type annotations — catches implicit polymorphism)
        self._check_partial_isinstance_discrimination(func_node.body)

        # Step 1: Collect variables with union types (from params and local annotations)
        union_vars = self._collect_union_vars(func_node)
        if not union_vars:
            return

        # Step 2: Find for-loops iterating .children of union-typed variables
        self._check_children_iteration(func_node.body, union_vars)

        # Step 3: Check direct attribute access on union-typed variables
        # without isinstance guard
        self._check_direct_attr_access(func_node.body, union_vars)

    def _collect_union_vars(self, func_node) -> Dict[str, Set[str]]:
        """Collect variables with Union type annotations.

        Returns dict mapping variable name -> set of union member type names.
        """
        union_vars: Dict[str, Set[str]] = {}

        # Check function parameters
        for arg in func_node.args.args + func_node.args.kwonlyargs:
            if arg.annotation:
                members = self._resolve_union(arg.annotation)
                if members and _has_class_variants(members):
                    union_vars[arg.arg] = members

        # Check local annotations (var: Type = ...) in function body
        for node in ast.walk(func_node):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                members = self._resolve_union(node.annotation)
                if members and _has_class_variants(members):
                    union_vars[node.target.id] = members

        return union_vars

    def _resolve_union(self, annotation: ast.expr) -> Optional[Set[str]]:
        """Resolve an annotation to its union member names.

        Handles direct Union[A, B], Optional[X], and type aliases.
        """
        # Direct Union/Optional
        union_names = _extract_union_names(annotation)
        if union_names:
            return union_names

        # Type alias reference (e.g., LN where LN = Union[Node, Leaf])
        if isinstance(annotation, ast.Name) and annotation.id in self._union_aliases:
            return self._union_aliases[annotation.id]

        # Optional[AliasName]
        if isinstance(annotation, ast.Subscript):
            base = annotation.value
            if isinstance(base, ast.Name) and base.id == 'Optional':
                inner = annotation.slice
                if isinstance(inner, ast.Name) and inner.id in self._union_aliases:
                    members = self._union_aliases[inner.id].copy()
                    members.add('None')
                    return members

        return None

    def _check_children_iteration(
        self,
        stmts: list,
        union_vars: Dict[str, Set[str]],
    ):
        """Find for-loops over .children of union-typed vars, check loop body."""
        for stmt in stmts:
            if isinstance(stmt, ast.For):
                iter_var, source_var = self._get_children_iteration(stmt)
                if source_var and source_var in union_vars:
                    # Loop variable inherits union type from .children
                    loop_var = iter_var
                    if loop_var and not self._has_isinstance_guard(stmt.body, loop_var):
                        # Check if loop body accesses attributes on loop_var
                        attr_accesses = self._find_attr_accesses(stmt.body, loop_var)
                        if attr_accesses:
                            attr_names = ', '.join(f'.{a}' for a in attr_accesses[:3])
                            members_str = ', '.join(
                                sorted(m for m in union_vars[source_var] if m != 'None')
                            )
                            self.bugs.append(UnionAttrBug(
                                file_path=self.file_path,
                                line_number=stmt.lineno,
                                function_name=self._current_function or '<module>',
                                pattern='union_children_no_isinstance',
                                reason=(
                                    f"For-loop iterates over '{source_var}.children' "
                                    f"(Union type: {members_str}). "
                                    f"Loop variable '{loop_var}' has attribute access "
                                    f"({attr_names}) without isinstance guard. "
                                    f"Children may be different types requiring "
                                    f"type-specific handling."
                                ),
                                confidence=0.55,
                                variable=loop_var,
                            ))

            # Recurse into nested blocks
            if isinstance(stmt, (ast.For, ast.While)):
                self._check_children_iteration(stmt.body, union_vars)
                self._check_children_iteration(stmt.orelse, union_vars)
            elif isinstance(stmt, ast.If):
                self._check_children_iteration(stmt.body, union_vars)
                self._check_children_iteration(stmt.orelse, union_vars)
            elif isinstance(stmt, ast.With):
                self._check_children_iteration(stmt.body, union_vars)
            elif isinstance(stmt, (ast.Try,)):
                self._check_children_iteration(stmt.body, union_vars)
                for handler in stmt.handlers:
                    self._check_children_iteration(handler.body, union_vars)
                self._check_children_iteration(stmt.orelse, union_vars)
                self._check_children_iteration(stmt.finalbody, union_vars)

    def _check_direct_attr_access(
        self,
        stmts: list,
        union_vars: Dict[str, Set[str]],
    ):
        """Check for attribute access on union-typed vars without isinstance."""
        for stmt in stmts:
            # Skip if the statement is an isinstance guard itself
            if isinstance(stmt, ast.If):
                guarded_vars = self._isinstance_guarded_vars(stmt.test)
                # Check the else branch for unguarded union vars
                remaining_vars = {
                    k: v for k, v in union_vars.items() if k not in guarded_vars
                }
                if remaining_vars:
                    self._check_direct_attr_access(stmt.orelse, remaining_vars)
                # The if-body is guarded for guarded_vars — recurse with rest
                unguarded_in_body = {
                    k: v for k, v in union_vars.items() if k not in guarded_vars
                }
                if unguarded_in_body:
                    self._check_direct_attr_access(stmt.body, unguarded_in_body)
                continue

            # For while loops, check the body
            if isinstance(stmt, (ast.For, ast.While)):
                self._check_direct_attr_access(stmt.body, union_vars)
                continue

            # Look for attribute access on union vars in this statement
            for node in ast.walk(stmt):
                if isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name) and node.value.id in union_vars:
                        var_name = node.value.id
                        attr_name = node.attr
                        # Skip common attributes present on all objects
                        if attr_name in _COMMON_ATTRS:
                            continue
                        members = union_vars[var_name]
                        members_str = ', '.join(
                            sorted(m for m in members if m != 'None')
                        )
                        self.bugs.append(UnionAttrBug(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            function_name=self._current_function or '<module>',
                            pattern='union_attr_no_isinstance',
                            reason=(
                                f"Attribute '.{attr_name}' accessed on "
                                f"'{var_name}' (Union type: {members_str}) "
                                f"without isinstance guard. Attribute may "
                                f"not exist on all union variants."
                            ),
                            confidence=0.45,
                            variable=var_name,
                        ))
                        # Only report once per variable per statement
                        break

    def _check_partial_isinstance_discrimination(self, stmts: list):
        """Detect loops over .children with partial isinstance discrimination.

        Fires when:
        - A for-loop iterates over .children (any source, not just Union-typed)
        - The loop body uses isinstance(loop_var, T) for at least one type T
        - But there are also code paths that use loop_var.type without isinstance
        This indicates the code handles some child subtypes but not others.
        """
        for stmt in stmts:
            if isinstance(stmt, ast.For):
                loop_var, source_var = self._get_children_iteration(stmt)
                if loop_var and source_var:
                    isinstance_types = self._collect_isinstance_types(
                        stmt.body, loop_var
                    )
                    if isinstance_types:
                        # Loop has isinstance for some types — check for
                        # unguarded .type comparisons on the same variable
                        unguarded = self._find_unguarded_type_comparisons(
                            stmt.body, loop_var
                        )
                        if unguarded:
                            checked_str = ', '.join(sorted(isinstance_types))
                            self.bugs.append(UnionAttrBug(
                                file_path=self.file_path,
                                line_number=stmt.lineno,
                                function_name=(
                                    self._current_function or '<module>'
                                ),
                                pattern='partial_isinstance_children',
                                reason=(
                                    f"Loop iterates '{source_var}.children' "
                                    f"and checks isinstance({loop_var}, "
                                    f"{checked_str}) but also uses "
                                    f"'{loop_var}.type' on line(s) "
                                    f"{', '.join(str(l) for l in unguarded)}"
                                    f" without isinstance guard. Children "
                                    f"may include types not covered by the "
                                    f"isinstance checks."
                                ),
                                confidence=0.50,
                                variable=loop_var,
                            ))

            # Recurse into nested blocks
            if isinstance(stmt, (ast.For, ast.While)):
                self._check_partial_isinstance_discrimination(stmt.body)
                self._check_partial_isinstance_discrimination(stmt.orelse)
            elif isinstance(stmt, ast.If):
                self._check_partial_isinstance_discrimination(stmt.body)
                self._check_partial_isinstance_discrimination(stmt.orelse)
            elif isinstance(stmt, ast.With):
                self._check_partial_isinstance_discrimination(stmt.body)
            elif isinstance(stmt, ast.Try):
                self._check_partial_isinstance_discrimination(stmt.body)
                for handler in stmt.handlers:
                    self._check_partial_isinstance_discrimination(handler.body)
                self._check_partial_isinstance_discrimination(stmt.orelse)
                self._check_partial_isinstance_discrimination(stmt.finalbody)

    @staticmethod
    def _collect_isinstance_types(stmts: list, var_name: str) -> Set[str]:
        """Collect type names used in isinstance(var_name, T) within stmts."""
        types_found: Set[str] = set()
        for stmt in stmts:
            for node in ast.walk(stmt):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == 'isinstance'
                        and len(node.args) >= 2
                        and isinstance(node.args[0], ast.Name)
                        and node.args[0].id == var_name):
                    type_arg = node.args[1]
                    if isinstance(type_arg, ast.Name):
                        types_found.add(type_arg.id)
                    elif isinstance(type_arg, ast.Tuple):
                        for elt in type_arg.elts:
                            if isinstance(elt, ast.Name):
                                types_found.add(elt.id)
        return types_found

    @staticmethod
    def _find_unguarded_type_comparisons(
        stmts: list, var_name: str
    ) -> List[int]:
        """Find lines where var.type is compared without isinstance guard.

        Returns line numbers of unguarded .type comparisons.
        """
        unguarded_lines: List[int] = []
        for stmt in stmts:
            # If this statement IS an isinstance guard, skip its body
            if isinstance(stmt, ast.If):
                test_has_isinstance = False
                for node in ast.walk(stmt.test):
                    if (isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Name)
                            and node.func.id == 'isinstance'
                            and len(node.args) >= 1
                            and isinstance(node.args[0], ast.Name)
                            and node.args[0].id == var_name):
                        test_has_isinstance = True
                        break
                if test_has_isinstance:
                    # The if-body is guarded; check else for unguarded uses
                    unguarded_lines.extend(
                        _UnionAttrVisitor._find_unguarded_type_comparisons(
                            stmt.orelse, var_name
                        )
                    )
                    continue
                # Not an isinstance guard — check the condition itself and body
                for node in ast.walk(stmt.test):
                    if (isinstance(node, ast.Attribute)
                            and node.attr == 'type'
                            and isinstance(node.value, ast.Name)
                            and node.value.id == var_name):
                        unguarded_lines.append(node.lineno)
                unguarded_lines.extend(
                    _UnionAttrVisitor._find_unguarded_type_comparisons(
                        stmt.body, var_name
                    )
                )
                unguarded_lines.extend(
                    _UnionAttrVisitor._find_unguarded_type_comparisons(
                        stmt.orelse, var_name
                    )
                )
                continue

            # Regular statement — check for var.type access
            for node in ast.walk(stmt):
                if (isinstance(node, ast.Attribute)
                        and node.attr == 'type'
                        and isinstance(node.value, ast.Name)
                        and node.value.id == var_name):
                    unguarded_lines.append(node.lineno)
        return unguarded_lines

    @staticmethod
    def _get_children_iteration(for_node: ast.For) -> Tuple[Optional[str], Optional[str]]:
        """Check if for-loop iterates over obj.children.

        Handles patterns:
          for child in container.children:
          for child in list(container.children):
          for i, child in enumerate(container.children):
          for i, child in enumerate(list(container.children)):

        Returns (loop_var_name, source_var_name) or (None, None).
        """
        loop_var = _extract_loop_var(for_node.target)
        if not loop_var:
            return None, None

        source_var = _extract_children_source(for_node.iter)
        if source_var:
            return loop_var, source_var
        return None, None

    @staticmethod
    def _has_isinstance_guard(stmts: list, var_name: str) -> bool:
        """Check if any statement in stmts contains isinstance(var_name, ...)."""
        for stmt in stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    if (isinstance(node.func, ast.Name)
                            and node.func.id == 'isinstance'
                            and len(node.args) >= 1
                            and isinstance(node.args[0], ast.Name)
                            and node.args[0].id == var_name):
                        return True
        return False

    @staticmethod
    def _isinstance_guarded_vars(test: ast.expr) -> Set[str]:
        """Extract variable names guarded by isinstance in an if-test."""
        guarded = set()
        for node in ast.walk(test):
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Name)
                        and node.func.id == 'isinstance'
                        and len(node.args) >= 1
                        and isinstance(node.args[0], ast.Name)):
                    guarded.add(node.args[0].id)
        return guarded

    @staticmethod
    def _find_attr_accesses(stmts: list, var_name: str) -> List[str]:
        """Find attribute accesses on var_name in a list of statements."""
        attrs = []
        seen = set()
        for stmt in stmts:
            for node in ast.walk(stmt):
                if (isinstance(node, ast.Attribute)
                        and isinstance(node.value, ast.Name)
                        and node.value.id == var_name
                        and node.attr not in seen
                        and node.attr not in _COMMON_ATTRS):
                    attrs.append(node.attr)
                    seen.add(node.attr)
        return attrs


def _has_class_variants(members: Set[str]) -> bool:
    """Check if union has at least 2 class-type variants (not just None)."""
    class_types = {m for m in members if m != 'None'}
    return len(class_types) >= 2


def _extract_loop_var(target: ast.expr) -> Optional[str]:
    """Extract the element variable name from a for-loop target.

    Handles:  for child in ...        -> 'child'
              for i, child in ...     -> 'child'
              for (i, child) in ...   -> 'child'
    """
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Tuple) and len(target.elts) == 2:
        # for i, child in enumerate(...) — the element var is the second
        if isinstance(target.elts[1], ast.Name):
            return target.elts[1].id
    return None


def _extract_children_source(iter_expr: ast.expr) -> Optional[str]:
    """Extract source variable from .children access, unwrapping enumerate/list.

    Handles:
        obj.children                         -> 'obj'
        list(obj.children)                   -> 'obj'
        enumerate(obj.children)              -> 'obj'
        enumerate(list(obj.children))        -> 'obj'
    """
    # Direct: obj.children
    if isinstance(iter_expr, ast.Attribute) and iter_expr.attr == 'children':
        if isinstance(iter_expr.value, ast.Name):
            return iter_expr.value.id
        return None

    # Wrapped in a call: list(...) or enumerate(...)
    if isinstance(iter_expr, ast.Call) and len(iter_expr.args) == 1:
        func = iter_expr.func
        if isinstance(func, ast.Name) and func.id in ('list', 'enumerate'):
            # Recurse to unwrap nested calls
            return _extract_children_source(iter_expr.args[0])

    return None


# Attributes common to virtually all Python objects — skip these
_COMMON_ATTRS = frozenset({
    '__class__', '__dict__', '__doc__', '__init__', '__repr__', '__str__',
    '__hash__', '__eq__', '__ne__', '__bool__',
    # Common tree-node attributes present on both Node and Leaf
    'type', 'parent', 'prefix', 'next_sibling', 'prev_sibling',
    'get_lineno', 'changed', 'was_changed', 'was_checked',
})
