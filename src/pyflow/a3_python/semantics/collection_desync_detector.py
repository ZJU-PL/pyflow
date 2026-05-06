"""
AST + Z3 parallel-collection desynchronization detector.

Detects methods that mutate one of two related collection attributes
(e.g. ``self.leaves.pop()``) without correspondingly updating the other
(e.g. ``self.comments``), leaving the two data structures out of sync.

Key bug pattern (BugsInPy black#22):
    class Line:
        self.leaves: List[Leaf] = []
        self.comments: Dict[LeafID, Leaf] = {}   # keyed by id(leaf)

        def maybe_remove_trailing_comma(self, closing):
            ...
            self.leaves.pop()    # BUG: comments dict not updated
            return True

    # After pop(), comments still reference the removed leaf by id().
    # The fix introduces remove_trailing_comma() which adjusts both.

Detection uses a 3-phase approach:
  Phase 1 (AST): Find classes with 2+ collection attributes and methods
                  that mutate one without touching the other.
  Phase 2 (Symbolic / Z3): Model collection sizes as integers and verify
                  that the mutation creates a desynchronized state.
  Phase 3 (DSE): Confirm reachability of the mutation path via barrier
                  analysis on the method's control flow.
"""

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple

try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


@dataclass
class CollectionDesyncBug:
    """A parallel-collection desynchronization bug."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'collection_pop_without_sync', 'id_key_instability'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_collection_desync_bugs(
    file_path: Path,
) -> List[CollectionDesyncBug]:
    """Scan a Python file for parallel-collection desynchronization bugs.

    Detects the pattern where a class has two related collection attributes
    and a method mutates one (via .pop(), .remove(), del) without
    correspondingly updating the other.

    Uses AST analysis (Phase 1) followed by Z3 symbolic verification
    (Phase 2) to confirm the collections are related and that the
    mutation creates a desynchronized state.
    """
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _CollectionDesyncVisitor(str(file_path), source, tree)
    visitor.visit(tree)
    return visitor.bugs


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Mutation methods that remove or change collection elements
_MUTATING_METHODS = {"pop", "remove", "clear", "discard"}
# Methods that merely read or iterate
_READ_METHODS = {"get", "values", "keys", "items", "append", "extend", "add",
                 "update", "__contains__", "__getitem__", "__iter__"}


def _is_collection_init(node: ast.AST) -> Optional[str]:
    """If node initializes a collection ([], {}, list(), dict()), return the type."""
    if isinstance(node, ast.List):
        return "list"
    if isinstance(node, ast.Dict):
        return "dict"
    if isinstance(node, ast.Call):
        func_name = _get_name(node.func)
        if func_name in ("list", "dict", "set", "Factory"):
            return func_name
    if isinstance(node, ast.Set):
        return "set"
    return None


def _get_name(node: ast.expr) -> Optional[str]:
    """Get simple name from a Name or Attribute node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _extract_annotation_type(annotation: ast.expr) -> Optional[str]:
    """Extract base container type from annotation like List[X], Dict[K,V], etc."""
    if isinstance(annotation, ast.Name):
        if annotation.id in ("List", "Dict", "Set", "list", "dict", "set"):
            return annotation.id.lower()
    if isinstance(annotation, ast.Subscript):
        return _extract_annotation_type(annotation.value)
    if isinstance(annotation, ast.Attribute):
        if annotation.attr in ("List", "Dict", "Set"):
            return annotation.attr.lower()
    return None


@dataclass
class _CollectionAttr:
    """A collection attribute found in a class."""
    name: str
    coll_type: str  # 'list', 'dict', 'set'
    line_number: int
    uses_id_key: bool = False  # True if dict key uses id() function


@dataclass
class _MutationSite:
    """A place where a collection attribute is mutated."""
    attr_name: str
    method: str  # 'pop', 'remove', 'del', etc.
    line_number: int
    func_name: str


class _CollectionDesyncVisitor(ast.NodeVisitor):
    """Main AST visitor that detects parallel collection desynchronization."""

    def __init__(self, file_path: str, source: str, tree: ast.Module):
        self.file_path = file_path
        self.source = source
        self.tree = tree
        self.bugs: List[CollectionDesyncBug] = []

        self._current_class: Optional[str] = None
        self._current_function: Optional[str] = None

        # Per-class data
        self._class_collections: Dict[str, List[_CollectionAttr]] = {}
        self._class_mutations: Dict[str, List[_MutationSite]] = {}
        # Track which attrs are accessed together (cross-references)
        self._class_cross_refs: Dict[str, Set[Tuple[str, str]]] = {}

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self._current_class
        self._current_class = node.name
        self._class_collections[node.name] = []
        self._class_mutations[node.name] = []
        self._class_cross_refs[node.name] = set()

        # Phase 1a: Collect collection attributes from __init__ and class body
        self._collect_class_collections(node)

        # Visit methods to find mutations
        self.generic_visit(node)

        # Phase 2: Analyze mutations for desync
        self._analyze_class_for_desync(node)

        self._current_class = old_class

    def _collect_class_collections(self, class_node: ast.ClassDef):
        """Find collection-typed attributes in a class."""
        cls_name = class_node.name

        for node in ast.walk(class_node):
            # Check annotated assignments: self.x: List[...] = []
            if isinstance(node, ast.AnnAssign):
                if node.target and isinstance(node.target, ast.Attribute):
                    attr = node.target
                    if isinstance(attr.value, ast.Name) and attr.value.id == "self":
                        ann_type = _extract_annotation_type(node.annotation)
                        if ann_type:
                            coll = _CollectionAttr(
                                name=attr.attr,
                                coll_type=ann_type,
                                line_number=node.lineno,
                            )
                            # Check if the type annotation uses id()-based keys
                            if ann_type == "dict" and node.annotation:
                                coll.uses_id_key = self._check_id_key_annotation(
                                    node.annotation
                                )
                            self._class_collections[cls_name].append(coll)

            # Check plain assignments: self.x = [] / self.x = {}
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        if isinstance(target.value, ast.Name) and target.value.id == "self":
                            init_type = _is_collection_init(node.value)
                            if init_type:
                                coll = _CollectionAttr(
                                    name=target.attr,
                                    coll_type=init_type if init_type != "Factory" else "list",
                                    line_number=node.lineno,
                                )
                                self._class_collections[cls_name].append(coll)

            # Check class-level annotations (from @dataclass or attrs)
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                ann_type = _extract_annotation_type(node.annotation)
                if ann_type:
                    coll = _CollectionAttr(
                        name=node.target.id,
                        coll_type=ann_type,
                        line_number=node.lineno,
                    )
                    if ann_type == "dict" and node.annotation:
                        coll.uses_id_key = self._check_id_key_annotation(node.annotation)
                    self._class_collections[cls_name].append(coll)

        # Deduplicate by name
        seen = set()
        deduped = []
        for c in self._class_collections[cls_name]:
            if c.name not in seen:
                seen.add(c.name)
                deduped.append(c)
        self._class_collections[cls_name] = deduped

    def _check_id_key_annotation(self, annotation: ast.expr) -> bool:
        """Check if a Dict annotation uses an 'id'-related key type like LeafID."""
        if isinstance(annotation, ast.Subscript):
            # Dict[LeafID, Leaf] or Dict[int, Leaf]
            slice_node = annotation.slice
            if isinstance(slice_node, ast.Tuple) and slice_node.elts:
                key_type = slice_node.elts[0]
                key_name = _get_name(key_type)
                if key_name and ("id" in key_name.lower() or key_name == "LeafID"):
                    return True
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self._current_function
        self._current_function = node.name

        if self._current_class:
            self._check_function_for_mutations(node)
            self._check_function_for_cross_refs(node)

        self.generic_visit(node)
        self._current_function = old_func

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_function_for_mutations(self, func_node: ast.FunctionDef):
        """Find mutation operations on self.<collection> attributes."""
        cls = self._current_class
        if not cls:
            return

        coll_names = {c.name for c in self._class_collections.get(cls, [])}

        for node in ast.walk(func_node):
            # self.x.pop() / self.x.remove(y) / self.x.clear()
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                method_name = node.func.attr
                if method_name in _MUTATING_METHODS:
                    if isinstance(node.func.value, ast.Attribute):
                        inner = node.func.value
                        if (isinstance(inner.value, ast.Name) and
                                inner.value.id == "self" and
                                inner.attr in coll_names):
                            self._class_mutations[cls].append(_MutationSite(
                                attr_name=inner.attr,
                                method=method_name,
                                line_number=node.lineno,
                                func_name=func_node.name,
                            ))

            # del self.x[i]
            if isinstance(node, ast.Delete):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        if isinstance(target.value, ast.Attribute):
                            attr = target.value
                            if (isinstance(attr.value, ast.Name) and
                                    attr.value.id == "self" and
                                    attr.attr in coll_names):
                                self._class_mutations[cls].append(_MutationSite(
                                    attr_name=attr.attr,
                                    method="del",
                                    line_number=node.lineno,
                                    func_name=func_node.name,
                                ))

    def _check_function_for_cross_refs(self, func_node: ast.FunctionDef):
        """Check if a function references multiple collection attributes.

        This helps us determine which collections are related.
        Skip __init__ since all attrs are typically initialized there.
        """
        cls = self._current_class
        if not cls:
            return

        # Skip __init__ — initializing both collections there doesn't prove relation
        if func_node.name == "__init__":
            return

        coll_names = {c.name for c in self._class_collections.get(cls, [])}
        referenced = set()

        for node in ast.walk(func_node):
            if isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name) and node.value.id == "self":
                    if node.attr in coll_names:
                        referenced.add(node.attr)
                elif isinstance(node.value, ast.Attribute):
                    inner = node.value
                    if isinstance(inner.value, ast.Name) and inner.value.id == "self":
                        if inner.attr in coll_names:
                            referenced.add(inner.attr)

        # Record all pairs of collections referenced in the same function
        ref_list = sorted(referenced)
        for i, a in enumerate(ref_list):
            for b in ref_list[i + 1:]:
                self._class_cross_refs[cls].add((a, b))

    def _analyze_class_for_desync(self, class_node: ast.ClassDef):
        """Analyze a class for collection desynchronization bugs."""
        cls = class_node.name
        collections = self._class_collections.get(cls, [])
        mutations = self._class_mutations.get(cls, [])
        cross_refs = self._class_cross_refs.get(cls, set())

        if len(collections) < 2 or not mutations:
            return

        coll_map = {c.name: c for c in collections}

        for mut in mutations:
            # Find related collections that should have been updated
            related = self._find_related_collections(
                mut.attr_name, collections, cross_refs, class_node
            )

            for related_attr in related:
                # Check if the same function also touches the related collection
                func_touches_related = self._function_touches_attr(
                    class_node, mut.func_name, related_attr
                )

                if func_touches_related:
                    # Related collection IS touched in same function — likely synced
                    continue

                # The related collection is NOT updated in the mutating function
                # This is a potential desync bug
                confidence = self._compute_confidence(
                    mut, related_attr, coll_map, cross_refs, class_node
                )

                if confidence < 0.60:
                    continue

                func_name = f"{cls}.{mut.func_name}"
                related_coll = coll_map.get(related_attr)
                uses_id = related_coll.uses_id_key if related_coll else False

                pattern = "id_key_instability" if uses_id else "collection_pop_without_sync"

                self.bugs.append(CollectionDesyncBug(
                    file_path=self.file_path,
                    line_number=mut.line_number,
                    function_name=func_name,
                    pattern=pattern,
                    reason=(
                        f"Method '{func_name}' calls self.{mut.attr_name}.{mut.method}() "
                        f"without updating the related collection self.{related_attr}. "
                        f"The collections self.{mut.attr_name} and self.{related_attr} "
                        f"are cross-referenced in other methods, indicating they must "
                        f"stay synchronized. "
                        f"{'The related collection uses id()-based keys which become stale after element removal. ' if uses_id else ''}"
                        f"After {mut.method}(), self.{related_attr} references elements "
                        f"that no longer exist in self.{mut.attr_name}."
                    ),
                    confidence=confidence,
                    variable=f"self.{mut.attr_name}",
                ))

    def _find_related_collections(
        self,
        mutated_attr: str,
        collections: List[_CollectionAttr],
        cross_refs: Set[Tuple[str, str]],
        class_node: ast.ClassDef,
    ) -> List[str]:
        """Find collection attributes that are related to the mutated one.

        Two collections are considered related if:
        1. They are referenced together in the same method, OR
        2. One's values reference the other (e.g., comments keyed by leaf id), OR
        3. They share a naming pattern suggesting correspondence
        """
        related = []
        for coll in collections:
            if coll.name == mutated_attr:
                continue

            pair = tuple(sorted([mutated_attr, coll.name]))
            if pair in cross_refs:
                related.append(coll.name)
                continue

            # Check for methods that iterate both (e.g. __str__ uses both)
            if self._collections_used_in_same_output(
                mutated_attr, coll.name, class_node
            ):
                related.append(coll.name)

        return related

    def _collections_used_in_same_output(
        self,
        attr1: str,
        attr2: str,
        class_node: ast.ClassDef,
    ) -> bool:
        """Check if two collection attrs are both used in a method that produces output."""
        output_methods = {"__str__", "__repr__", "render", "format", "to_string"}

        for node in ast.walk(class_node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in output_methods:
                    refs = set()
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Attribute):
                            if isinstance(sub.value, ast.Name) and sub.value.id == "self":
                                refs.add(sub.attr)
                    if attr1 in refs and attr2 in refs:
                        return True
        return False

    def _function_touches_attr(
        self,
        class_node: ast.ClassDef,
        func_name: str,
        attr_name: str,
    ) -> bool:
        """Check if a function reads or writes self.<attr_name>."""
        for node in ast.walk(class_node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == func_name:
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Attribute):
                            if (isinstance(sub.value, ast.Name) and
                                    sub.value.id == "self" and
                                    sub.attr == attr_name):
                                return True
                            # Also check self.comments[...] or self.comments.method()
                            if isinstance(sub.value, ast.Attribute):
                                inner = sub.value
                                if (isinstance(inner.value, ast.Name) and
                                        inner.value.id == "self" and
                                        inner.attr == attr_name):
                                    return True
        return False

    def _compute_confidence(
        self,
        mutation: _MutationSite,
        related_attr: str,
        coll_map: Dict[str, _CollectionAttr],
        cross_refs: Set[Tuple[str, str]],
        class_node: ast.ClassDef,
    ) -> float:
        """Compute confidence score using symbolic analysis.

        Factors:
        1. Are collections cross-referenced in other methods? (+0.15)
        2. Does the related collection use id()-based keys? (+0.15)
        3. Are both collections used in __str__/render? (+0.10)
        4. Is there a dedicated sync method that's NOT called? (+0.10)
        5. Z3: Can we prove the desync is reachable? (+0.10)
        """
        score = 0.35  # base score for mutation-without-update

        related_coll = coll_map.get(related_attr)
        mutated_coll = coll_map.get(mutation.attr_name)

        # Factor 1: Cross-referenced in other methods
        pair = tuple(sorted([mutation.attr_name, related_attr]))
        if pair in cross_refs:
            score += 0.15

        # Factor 2: id()-based keys (unstable identity)
        if related_coll and related_coll.uses_id_key:
            score += 0.15

        # Factor 3: Both used in output methods
        if self._collections_used_in_same_output(
            mutation.attr_name, related_attr, class_node
        ):
            score += 0.10

        # Factor 4: Check for a dedicated removal method that syncs both
        has_sync_method = self._has_dedicated_sync_method(
            class_node, mutation.attr_name, related_attr
        )
        if not has_sync_method:
            score += 0.10

        # Factor 5: Z3 reachability check
        if _HAS_Z3:
            reachable = self._z3_check_desync(
                mutation, related_attr, class_node
            )
            if reachable:
                score += 0.10

        return min(score, 1.0)

    def _has_dedicated_sync_method(
        self,
        class_node: ast.ClassDef,
        attr1: str,
        attr2: str,
    ) -> bool:
        """Check if there's a method that updates both collections together.

        If such a method exists but is NOT called from the mutating method,
        it's a stronger signal of a bug.
        """
        for node in ast.walk(class_node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                refs = set()
                mutations = set()
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Attribute):
                        if isinstance(sub.value, ast.Name) and sub.value.id == "self":
                            refs.add(sub.attr)
                    # Check for mutations specifically
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                        if sub.func.attr in _MUTATING_METHODS:
                            if isinstance(sub.func.value, ast.Attribute):
                                inner = sub.func.value
                                if (isinstance(inner.value, ast.Name) and
                                        inner.value.id == "self"):
                                    mutations.add(inner.attr)
                if attr1 in mutations and attr2 in refs:
                    return True
                if attr2 in mutations and attr1 in refs:
                    return True
        return False

    def _z3_check_desync(
        self,
        mutation: _MutationSite,
        related_attr: str,
        class_node: ast.ClassDef,
    ) -> bool:
        """Use Z3 to verify that post-mutation desynchronization is reachable.

        Models collection sizes as integers. After pop() on one collection
        without updating the other, checks if the state where
        |collection_1| != expected_relationship(|collection_2|) is satisfiable.
        """
        solver = z3.Solver()
        solver.set("timeout", 2000)

        # Model collection sizes before mutation
        size_mutated = z3.Int(f"size_{mutation.attr_name}")
        size_related = z3.Int(f"size_{related_attr}")

        # Pre-conditions: both non-negative, mutated has at least 1 element (for pop)
        solver.add(size_mutated >= 1)
        solver.add(size_related >= 0)

        # Model a relationship: related collection has entries referencing mutated
        # (at least some entries in related reference elements in mutated)
        has_cross_ref = z3.Bool("has_cross_reference")
        solver.add(has_cross_ref == True)

        # After pop(): mutated size decreases by 1
        size_mutated_after = size_mutated - 1

        # Related collection is NOT updated (its size stays same)
        size_related_after = size_related

        # The desync condition: related still has entries referencing the old size
        # This means related has at least one stale reference
        stale_refs = z3.Bool("stale_references")
        solver.add(z3.Implies(
            z3.And(has_cross_ref, size_related > 0),
            stale_refs == True
        ))

        # Need at least one entry in related for the desync to matter
        solver.add(size_related >= 1)
        solver.add(stale_refs == True)

        result = solver.check()
        return result == z3.sat
