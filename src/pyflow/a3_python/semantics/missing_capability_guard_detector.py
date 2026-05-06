"""
AST-based missing-capability-guard detector.

Detects patterns where a method is called on an object without first checking
a boolean capability attribute that gates whether the method is valid.

Key bug pattern (BugsInPy keras#3):
    # Layer class defines: supports_masking = False
    # Layer class defines: def compute_mask(self, ...): ...
    #
    # In _clone_functional_model:
    for node in nodes:
        layer = node.outbound_layer
        output_masks = to_list(layer.compute_mask(...))  # BUG!

Fix pattern:
    if layer.supports_masking:
        output_masks = to_list(layer.compute_mask(...))
    else:
        output_masks = [None] * len(output_tensors)

The general pattern: a class defines a boolean attribute `supports_X` / `has_X` /
`can_X` (defaulting to False) AND a method whose name relates to X. Calling the
method without checking the boolean attribute first is a missing-guard bug.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple


# Prefixes that indicate a boolean capability attribute
_CAPABILITY_PREFIXES = ('supports_', 'has_', 'can_')

# Minimum word length for stem matching
_MIN_STEM_LEN = 3


@dataclass
class CapabilityGuardBug:
    """A missing-capability-guard bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'missing_capability_guard'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_project_for_capability_guard_bugs(
    file_paths: List[Path],
) -> List[CapabilityGuardBug]:
    """Scan a project for missing capability guard bugs.

    Two-pass approach:
      Pass 1: Collect capability attribute → method mappings from class defs.
      Pass 2: Find method calls that lack a guard on the capability attribute.
    """
    # Pass 1: collect capability mappings from all files
    cap_map = _CapabilityMap()
    for fp in file_paths:
        _collect_capability_attributes(fp, cap_map)

    if not cap_map.method_to_caps:
        return []

    # Pass 2: find unguarded calls
    bugs: List[CapabilityGuardBug] = []
    for fp in file_paths:
        bugs.extend(_find_unguarded_capability_calls(fp, cap_map))
    return bugs


# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------

@dataclass
class _CapabilityEntry:
    """One capability: a boolean attribute on a class and the methods it gates."""
    class_name: str
    attr_name: str          # e.g. 'supports_masking'
    method_names: Set[str]  # e.g. {'compute_mask'}
    file_path: str


class _CapabilityMap:
    """Maps method names → list of capability entries that gate them."""

    def __init__(self):
        # method_name → [CapabilityEntry, ...]
        self.method_to_caps: Dict[str, List[_CapabilityEntry]] = {}

    def add(self, entry: _CapabilityEntry):
        for method in entry.method_names:
            self.method_to_caps.setdefault(method, []).append(entry)


# ---------------------------------------------------------------------------
# Pass 1: collect capability attributes from class definitions
# ---------------------------------------------------------------------------

def _collect_capability_attributes(file_path: Path, cap_map: _CapabilityMap):
    """Scan *file_path* for classes that define capability boolean attributes."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        _process_class(node, str(file_path), cap_map)


def _process_class(class_node: ast.ClassDef, file_path: str, cap_map: _CapabilityMap):
    """Extract capability attributes and related methods from a class."""
    # Step 1: find boolean capability attributes (class-level assignments)
    cap_attrs: Dict[str, str] = {}  # attr_name → capability_word
    for stmt in class_node.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    attr_name = target.id
                    cap_word = _extract_capability_word(attr_name)
                    if cap_word and _is_false_literal(stmt.value):
                        cap_attrs[attr_name] = cap_word

    if not cap_attrs:
        return

    # Step 2: find methods in the class
    method_names: Set[str] = set()
    for stmt in class_node.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not stmt.name.startswith('_') or stmt.name.startswith('__'):
                pass  # include both public and dunder
            method_names.add(stmt.name)

    # Step 3: match methods to capability attributes via stem matching
    for attr_name, cap_word in cap_attrs.items():
        related_methods: Set[str] = set()
        for method_name in method_names:
            if method_name.startswith('__') and method_name.endswith('__'):
                continue  # skip dunder methods
            if _stems_match(cap_word, method_name):
                related_methods.add(method_name)

        if related_methods:
            entry = _CapabilityEntry(
                class_name=class_node.name,
                attr_name=attr_name,
                method_names=related_methods,
                file_path=file_path,
            )
            cap_map.add(entry)


def _extract_capability_word(attr_name: str) -> Optional[str]:
    """Extract the capability word from an attribute name.

    Returns the word after a capability prefix, or None if no prefix matches.
    E.g., 'supports_masking' → 'masking', 'has_header' → 'header'.
    """
    for prefix in _CAPABILITY_PREFIXES:
        if attr_name.startswith(prefix) and len(attr_name) > len(prefix):
            return attr_name[len(prefix):]
    return None


def _is_false_literal(node: ast.expr) -> bool:
    """Check if an AST node is a False literal."""
    if isinstance(node, ast.Constant) and node.value is False:
        return True
    # Python 3.7 compat
    if isinstance(node, ast.NameConstant) and node.value is False:
        return True
    return False


def _stems_match(capability_word: str, method_name: str) -> bool:
    """Check if a method name is semantically related to a capability word.

    E.g., capability_word='masking', method_name='compute_mask' → True
    because 'mask' is a common stem.
    """
    cap_stems = _derive_stems(capability_word)
    method_words = set(method_name.split('_'))

    for stem in cap_stems:
        if len(stem) < _MIN_STEM_LEN:
            continue
        for word in method_words:
            if len(word) < _MIN_STEM_LEN:
                continue
            # Check bidirectional containment
            if stem in word or word in stem:
                return True
    return False


def _derive_stems(word: str) -> Set[str]:
    """Derive possible stems from a word by stripping common suffixes."""
    stems = {word}
    for suffix in ('ing', 'ed', 'tion', 'ation', 'ment', 'ness', 'able', 'ible', 's'):
        if word.endswith(suffix) and len(word) - len(suffix) >= _MIN_STEM_LEN:
            stems.add(word[:-len(suffix)])
    return stems


# ---------------------------------------------------------------------------
# Pass 2: find unguarded method calls
# ---------------------------------------------------------------------------

def _find_unguarded_capability_calls(
    file_path: Path,
    cap_map: _CapabilityMap,
) -> List[CapabilityGuardBug]:
    """Find method calls that lack a capability guard."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    bugs: List[CapabilityGuardBug] = []
    visitor = _UnguardedCallVisitor(str(file_path), cap_map)
    visitor.visit(tree)
    return visitor.bugs


class _UnguardedCallVisitor(ast.NodeVisitor):
    """AST visitor that finds method calls lacking a capability guard."""

    def __init__(self, file_path: str, cap_map: _CapabilityMap):
        self.file_path = file_path
        self.cap_map = cap_map
        self.bugs: List[CapabilityGuardBug] = []
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None

    def visit_ClassDef(self, node: ast.ClassDef):
        old = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_func(node)

    def _visit_func(self, node):
        old = self._current_function
        if self._current_class:
            self._current_function = f"{self._current_class}.{node.name}"
        else:
            self._current_function = node.name

        self._scan_function(node)
        self._current_function = old

    def _scan_function(self, func_node):
        """Scan a function body for unguarded capability method calls."""
        # Collect all method calls: (obj_name, method_name, lineno)
        calls = self._collect_method_calls(func_node)

        for obj_name, method_name, lineno in calls:
            if method_name not in self.cap_map.method_to_caps:
                continue

            for cap_entry in self.cap_map.method_to_caps[method_name]:
                # Skip if the method call is on 'self' and we're in the
                # defining class — the class itself knows its own capability
                if (obj_name == 'self'
                        and self._current_class == cap_entry.class_name):
                    continue

                # Check if the capability attribute is guarded
                if self._is_guarded(func_node, obj_name, cap_entry.attr_name,
                                    lineno):
                    continue

                self.bugs.append(CapabilityGuardBug(
                    file_path=self.file_path,
                    line_number=lineno,
                    function_name=self._current_function or '<module>',
                    pattern='missing_capability_guard',
                    reason=(
                        f"Method '{obj_name}.{method_name}()' (line {lineno}) "
                        f"is called without checking '{obj_name}.{cap_entry.attr_name}' first. "
                        f"Class '{cap_entry.class_name}' defines "
                        f"'{cap_entry.attr_name} = False' by default, so "
                        f"'{method_name}()' may fail or produce incorrect results "
                        f"for objects that don't support this capability."
                    ),
                    confidence=0.75,
                    variable=obj_name,
                ))

    @staticmethod
    def _collect_method_calls(func_node) -> List[Tuple[str, str, int]]:
        """Collect all method calls (obj.method(...)) in the function."""
        calls = []
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            method_name = node.func.attr
            obj = node.func.value
            # Direct: obj.method(...)
            if isinstance(obj, ast.Name):
                calls.append((obj.id, method_name, node.func.lineno))
        return calls

    @staticmethod
    def _is_guarded(func_node, obj_name: str, attr_name: str,
                    call_lineno: int) -> bool:
        """Check if a method call is guarded by an attribute check.

        Looks for ``if obj.attr_name:`` or ``if obj.attr_name:`` enclosing
        the call site.
        """
        for node in ast.walk(func_node):
            if not isinstance(node, ast.If):
                continue

            # Check if the test references obj.attr_name
            if not _test_checks_attr(node.test, obj_name, attr_name):
                continue

            # Check if the call_lineno is inside this if-body
            for child in ast.walk(node):
                if getattr(child, 'lineno', 0) == call_lineno:
                    return True

        return False


def _test_checks_attr(test_node, obj_name: str, attr_name: str) -> bool:
    """Check if a test expression references obj.attr_name.

    Handles:
    - ``if obj.attr:``  (truthy check)
    - ``if not obj.attr:`` (falsy check — call would be in else)
    - ``if obj.attr is not None:``
    - ``if hasattr(obj, 'attr'):``
    """
    # Direct: if obj.attr
    if (isinstance(test_node, ast.Attribute)
            and isinstance(test_node.value, ast.Name)
            and test_node.value.id == obj_name
            and test_node.attr == attr_name):
        return True

    # Negated: if not obj.attr
    if isinstance(test_node, ast.UnaryOp) and isinstance(test_node.op, ast.Not):
        return _test_checks_attr(test_node.operand, obj_name, attr_name)

    # Comparison: if obj.attr is not None / if obj.attr == True
    if isinstance(test_node, ast.Compare):
        left = test_node.left
        if (isinstance(left, ast.Attribute)
                and isinstance(left.value, ast.Name)
                and left.value.id == obj_name
                and left.attr == attr_name):
            return True

    # BoolOp: if obj.attr and ..., if obj.attr or ...
    if isinstance(test_node, ast.BoolOp):
        for val in test_node.values:
            if _test_checks_attr(val, obj_name, attr_name):
                return True

    # hasattr(obj, 'attr')
    if isinstance(test_node, ast.Call):
        if (isinstance(test_node.func, ast.Name)
                and test_node.func.id == 'hasattr'
                and len(test_node.args) >= 2):
            arg0, arg1 = test_node.args[0], test_node.args[1]
            if isinstance(arg0, ast.Name) and arg0.id == obj_name:
                if (isinstance(arg1, ast.Constant)
                        and arg1.value == attr_name):
                    return True

    return False
