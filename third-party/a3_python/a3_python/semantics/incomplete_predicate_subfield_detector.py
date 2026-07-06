"""
AST-based incomplete-predicate sub-field validation detector.

Detects predicate functions (``is_*``, ``has_*``, ``check_*``) that check
properties of a parameter via attribute access but fail to validate a
collection sub-attribute (e.g. ``sub_fields``, ``children``, ``args``) on
the same parameter.  When the sub-attribute holds items of the same type,
skipping the recursive check may cause incorrect True returns, leading to
None / NULL_PTR downstream.

Key bug pattern (BugsInPy fastapi#11):
    def is_scalar_field(field: Field) -> bool:
        return (
            field.shape == Shape.SINGLETON
            and not lenient_issubclass(field.type_, BaseModel)
            and not lenient_issubclass(field.type_, sequence_types + (dict,))
            and not isinstance(field.schema, params.Body)
        )

    # field.sub_fields is never checked – Union types with non-scalar
    # sub-fields are wrongly classified as scalar.

Fix pattern:
    - After the top-level property checks, iterate ``field.sub_fields``
      and recursively apply the same predicate.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple


# Attribute name fragments that indicate a collection of sub-components
_SUB_COMPONENT_PATTERNS = (
    'sub_fields', 'sub_field', 'subfields', 'sub_items',
    'children', 'child_nodes',
    'args', 'arguments',
    'elements', 'members',
    'variants', 'alternatives',
)


@dataclass
class IncompletePredicateSubfieldBug:
    """An incomplete predicate sub-field validation bug."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'missing_subfield_check'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_incomplete_predicate_subfield_bugs(
    file_path: Path,
) -> List[IncompletePredicateSubfieldBug]:
    """Scan a Python file for incomplete predicate sub-field checks."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _PredicateSubfieldVisitor(str(file_path), tree)
    visitor.scan()
    return visitor.bugs


# ── helpers ──────────────────────────────────────────────────────────


def _is_predicate_name(name: str) -> bool:
    """Return True if *name* looks like a predicate function."""
    return name.startswith(('is_', 'has_', 'check_'))


def _is_sub_component_attr(attr_name: str) -> bool:
    """Return True if *attr_name* looks like a sub-component collection."""
    lower = attr_name.lower()
    for pat in _SUB_COMPONENT_PATTERNS:
        if pat in lower:
            return True
    return False


def _attrs_accessed_on(node: ast.AST, param_name: str) -> Set[str]:
    """Collect attribute names accessed on *param_name* inside *node*."""
    attrs: Set[str] = set()
    for child in ast.walk(node):
        if (isinstance(child, ast.Attribute)
                and isinstance(child.value, ast.Name)
                and child.value.id == param_name):
            attrs.add(child.attr)
    return attrs


def _has_type_check_call(node: ast.AST) -> bool:
    """Return True if *node* contains isinstance/issubclass calls (or wrappers)."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if isinstance(func, ast.Name):
            if func.id in ('isinstance', 'issubclass'):
                return True
            # Custom wrappers like lenient_issubclass
            if 'isinstance' in func.id.lower() or 'issubclass' in func.id.lower():
                return True
        elif isinstance(func, ast.Attribute):
            if func.attr in ('isinstance', 'issubclass'):
                return True
            if 'isinstance' in func.attr.lower() or 'issubclass' in func.attr.lower():
                return True
    return False


def _class_defined_attrs(tree: ast.Module, type_name: str) -> Set[str]:
    """Collect attribute names defined on class *type_name* in the module."""
    attrs: Set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != type_name:
            continue
        for item in node.body:
            # Class-level annotations  (e.g. ``sub_fields: list``)
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                attrs.add(item.target.id)
            # Class-level assignments  (e.g. ``sub_fields = []``)
            elif isinstance(item, ast.Assign):
                for tgt in item.targets:
                    if isinstance(tgt, ast.Name):
                        attrs.add(tgt.id)
            # __init__ assignments  (e.g. ``self.sub_fields = …``)
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name == '__init__':
                    for child in ast.walk(item):
                        if (isinstance(child, ast.Attribute)
                                and isinstance(child.value, ast.Name)
                                and child.value.id == 'self'
                                and isinstance(child.ctx, ast.Store)):
                            attrs.add(child.attr)
    return attrs


def _module_wide_attrs_for_type(
    tree: ast.Module, type_name: str
) -> Set[str]:
    """Collect all attribute names known for *type_name* in the module.

    Combines:
    1. Attributes accessed on parameters annotated as *type_name*.
    2. Attributes defined on a class named *type_name* in the module.
    3. Attributes accessed on any variable that shares ≥2 attribute
       names with parameters of type *type_name* (duck-typing heuristic).
    """
    # 1. Parameter-based attributes
    param_attrs: Set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for arg in node.args.args:
            ann = arg.annotation
            if ann is None:
                continue
            if isinstance(ann, ast.Name) and ann.id == type_name:
                param_attrs |= _attrs_accessed_on(node, arg.arg)
            elif isinstance(ann, ast.Attribute):
                if ann.attr == type_name:
                    param_attrs |= _attrs_accessed_on(node, arg.arg)

    # 2. Class-definition attributes
    class_attrs = _class_defined_attrs(tree, type_name)

    # 3. Duck-typing: scan all attribute accesses in the module.
    #    If a variable accesses ≥2 attributes from param_attrs, add its
    #    other attributes to the result.
    all_var_attrs: Dict[str, Set[str]] = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)):
            all_var_attrs.setdefault(node.value.id, set()).add(node.attr)

    duck_attrs: Set[str] = set()
    if param_attrs:
        for _var, var_attrs in all_var_attrs.items():
            if len(var_attrs & param_attrs) >= 2:
                duck_attrs |= var_attrs

    return param_attrs | class_attrs | duck_attrs


# ── main visitor ─────────────────────────────────────────────────────


class _PredicateSubfieldVisitor:
    """Scan for predicate functions that miss sub-component validation."""

    def __init__(self, file_path: str, tree: ast.Module):
        self.file_path = file_path
        self.tree = tree
        self.bugs: List[IncompletePredicateSubfieldBug] = []

    def scan(self) -> None:
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _is_predicate_name(node.name):
                continue
            self._check_predicate(node)

    # ── core check ───────────────────────────────────────────────────

    def _check_predicate(self, func: ast.FunctionDef) -> None:
        # Must have at least one parameter (besides self)
        params = func.args.args
        if not params:
            return

        # Skip 'self'/'cls' and pick the first real parameter
        start = 0
        if params[0].arg in ('self', 'cls'):
            start = 1
        if start >= len(params):
            return
        param = params[start]
        param_name = param.arg

        # Require a type annotation so we can do module-wide lookup
        type_name = self._extract_type_name(param.annotation)

        # Gather attributes accessed on the parameter inside the predicate
        local_attrs = _attrs_accessed_on(func, param_name)
        if len(local_attrs) < 2:
            return  # too few accesses to be a meaningful property check

        # Require some form of type/class checking in the function body
        if not _has_type_check_call(func):
            return

        # Find sub-component-like attributes NOT checked by this predicate
        missing_sub_attrs: Set[str] = set()

        # Strategy 1: module-wide attribute analysis (needs type annotation)
        if type_name:
            module_attrs = _module_wide_attrs_for_type(self.tree, type_name)
            for attr in module_attrs:
                if _is_sub_component_attr(attr) and attr not in local_attrs:
                    missing_sub_attrs.add(attr)

        # Strategy 2: check local attrs for hints – if we see attrs like
        # "shape", "type_" but not "sub_fields" and the name contains
        # "field" or "node", that's suspicious even without type annotation
        if not missing_sub_attrs and not type_name:
            if any(kw in param_name.lower() for kw in ('field', 'node', 'item', 'element')):
                for pat in _SUB_COMPONENT_PATTERNS:
                    if pat not in local_attrs:
                        # Only flag if the name is closely related to param
                        if param_name.lower().rstrip('s') in pat or pat.startswith('sub_'):
                            missing_sub_attrs.add(pat)

        if not missing_sub_attrs:
            return

        # Build bug report
        missing_str = ', '.join(sorted(missing_sub_attrs))
        accessed_str = ', '.join(sorted(local_attrs)[:5])

        self.bugs.append(IncompletePredicateSubfieldBug(
            file_path=self.file_path,
            line_number=func.lineno,
            function_name=func.name,
            pattern='missing_subfield_check',
            reason=(
                f"Predicate '{func.name}' checks attributes ({accessed_str}) "
                f"of parameter '{param_name}' but does not validate "
                f"sub-component attribute(s) ({missing_str}). "
                f"If '{missing_str}' contains items that violate the predicate, "
                f"the function may return an incorrect result, causing "
                f"NULL_PTR downstream."
            ),
            confidence=0.65,
            variable=param_name,
        ))

    @staticmethod
    def _extract_type_name(annotation) -> Optional[str]:
        """Extract a simple type name from an annotation node."""
        if annotation is None:
            return None
        if isinstance(annotation, ast.Name):
            return annotation.id
        if isinstance(annotation, ast.Attribute):
            return annotation.attr
        # Subscript like Optional[Field] – extract inner
        if isinstance(annotation, ast.Subscript):
            return _PredicateSubfieldVisitor._extract_type_name(annotation.value)
        return None
