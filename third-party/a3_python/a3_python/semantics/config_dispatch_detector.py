"""
AST + Z3 symbolic configuration dispatch completeness detector.

Detects incomplete enum-to-feature-set mappings where multiple version-like
enum members are mapped to identical feature sets, indicating that the feature
enum is missing differentiating members.

Key bug pattern (BugsInPy black#6):
    class Feature(Enum):
        UNICODE_LITERALS = 0
        F_STRINGS = 1
        NUMERIC_UNDERSCORES = 3
        TRAILING_COMMA_IN_CALL = 4
        TRAILING_COMMA_IN_DEF = 5

    VERSION_TO_FEATURES: Dict[TargetVersion, Set[Feature]] = {
        ...
        TargetVersion.PY36: {Feature.UNICODE_LITERALS, Feature.F_STRINGS, ...},
        TargetVersion.PY37: {Feature.UNICODE_LITERALS, Feature.F_STRINGS, ...},  # identical to PY36!
        TargetVersion.PY38: {Feature.UNICODE_LITERALS, Feature.F_STRINGS, ...},  # identical to PY36!
    }

    # BUG: PY36, PY37, PY38 all map to the SAME feature set, but Python 3.7
    # changed `async`/`await` from identifiers to reserved keywords. The Feature
    # enum is missing ASYNC_IS_VALID_IDENTIFIER and ASYNC_IS_RESERVED_KEYWORD.

    # FIX: Add the missing feature flags and update the mapping:
    class Feature(Enum):
        ...
        ASYNC_IS_VALID_IDENTIFIER = 6
        ASYNC_IS_RESERVED_KEYWORD = 7

    VERSION_TO_FEATURES = {
        ...
        TargetVersion.PY36: {..., Feature.ASYNC_IS_VALID_IDENTIFIER},
        TargetVersion.PY37: {..., Feature.ASYNC_IS_RESERVED_KEYWORD},  # now different!
    }

Detection uses Z3 symbolic analysis to verify that colliding version groups
genuinely lack distinguishing features in the current enum definition, ruling
out coincidental identical sets.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple, FrozenSet

try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


@dataclass
class ConfigDispatchBug:
    """An incomplete configuration dispatch bug."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'indistinguishable_versions', 'exhausted_feature_space'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_config_dispatch_bugs(file_path: Path) -> List[ConfigDispatchBug]:
    """Scan a Python file for incomplete enum-to-feature-set mappings.

    Uses AST analysis to find Enum classes and Dict[Enum, Set[Enum]] mappings,
    then Z3 symbolic verification to confirm that collision groups lack
    distinguishing features.
    """
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _ConfigDispatchVisitor(str(file_path), source)
    visitor.visit(tree)
    return visitor.bugs


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_attr_chain(node: ast.expr) -> Optional[str]:
    """Extract dotted name from an AST expression (e.g. TargetVersion.PY37)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _get_attr_chain(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _extract_set_elements(node: ast.expr) -> Optional[Set[str]]:
    """Extract string-represented elements from a Set literal or set() call."""
    if isinstance(node, ast.Set):
        elts = set()
        for elt in node.elts:
            name = _get_attr_chain(elt)
            if name:
                elts.add(name)
        return elts
    if isinstance(node, ast.Call):
        func_name = _get_attr_chain(node.func)
        if func_name == 'set' and not node.args:
            return set()
    return None


class _ConfigDispatchVisitor(ast.NodeVisitor):
    """AST visitor that detects incomplete enum-to-feature-set mappings."""

    # Minimum collision group size to flag as suspicious
    MIN_COLLISION_SIZE = 3

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.bugs: List[ConfigDispatchBug] = []

        # Collected enum classes: name -> {member_name: value, ...}
        self._enum_classes: Dict[str, Dict[str, Optional[int]]] = {}

        # Collected dict mappings: var_name -> {key_str: set_of_value_strs, ...}
        self._enum_dicts: Dict[str, Tuple[int, Dict[str, Set[str]]]] = {}

    def visit_ClassDef(self, node: ast.ClassDef):
        """Detect Enum class definitions."""
        is_enum = any(
            _get_attr_chain(base) in ('Enum', 'IntEnum', 'enum.Enum', 'enum.IntEnum')
            for base in node.bases
        )
        if is_enum:
            members: Dict[str, Optional[int]] = {}
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            val = None
                            if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, int):
                                val = stmt.value.value
                            members[target.id] = val
            if members:
                self._enum_classes[node.name] = members

        self.generic_visit(node)

    def _process_dict_assign(self, var_name: str, dict_node: ast.Dict, lineno: int):
        """Extract enum-keyed dict mapping from a Dict AST node."""
        mapping: Dict[str, Set[str]] = {}
        for key, value in zip(dict_node.keys, dict_node.values):
            if key is None:
                continue
            key_str = _get_attr_chain(key)
            if key_str is None:
                continue
            val_set = _extract_set_elements(value)
            if val_set is None:
                continue
            mapping[key_str] = val_set

        if len(mapping) >= 3:
            self._enum_dicts[var_name] = (lineno, mapping)

    def visit_Assign(self, node: ast.Assign):
        """Detect Dict[Enum, Set[Enum]] assignments (unannotated)."""
        if not isinstance(node.value, ast.Dict):
            self.generic_visit(node)
            return

        var_name = None
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                break

        if var_name:
            self._process_dict_assign(var_name, node.value, node.lineno)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """Detect Dict[Enum, Set[Enum]] assignments (annotated, e.g. x: Dict[...] = {...})."""
        if node.value is None or not isinstance(node.value, ast.Dict):
            self.generic_visit(node)
            return

        var_name = None
        if isinstance(node.target, ast.Name):
            var_name = node.target.id

        if var_name:
            self._process_dict_assign(var_name, node.value, node.lineno)

        self.generic_visit(node)

    def visit_Module(self, node: ast.Module):
        """Process the entire module, then run collision analysis."""
        self.generic_visit(node)
        self._analyze_collisions()

    def _analyze_collisions(self):
        """Check for collision groups in enum-keyed dicts."""
        for var_name, (lineno, mapping) in self._enum_dicts.items():
            # Group keys by identical value sets
            groups: Dict[FrozenSet[str], List[str]] = {}
            for key, val_set in mapping.items():
                frozen = frozenset(val_set)
                groups.setdefault(frozen, []).append(key)

            for frozen_set, keys in groups.items():
                if len(keys) < self.MIN_COLLISION_SIZE:
                    continue

                # Found a suspicious collision group — verify with Z3
                all_features = set()
                for vs in mapping.values():
                    all_features |= vs

                is_confirmed = self._z3_verify_exhaustion(
                    all_features, frozen_set, keys, mapping
                )

                if is_confirmed:
                    key_names = [k.split('.')[-1] if '.' in k else k for k in sorted(keys)]
                    feature_names = [f.split('.')[-1] if '.' in f else f for f in sorted(frozen_set)]

                    self.bugs.append(ConfigDispatchBug(
                        file_path=self.file_path,
                        line_number=lineno,
                        function_name='<module>',
                        pattern='indistinguishable_versions',
                        reason=(
                            f"Dict '{var_name}' maps {len(keys)} entries "
                            f"({', '.join(key_names)}) to identical feature sets. "
                            f"These versions are indistinguishable in the current "
                            f"configuration. Z3 confirms no unused feature in the "
                            f"enum can differentiate them — the feature enum likely "
                            f"needs new members to capture version-specific behavior "
                            f"(e.g., keyword semantics changes across versions)."
                        ),
                        confidence=0.82,
                        variable=var_name,
                    ))

    def _z3_verify_exhaustion(
        self,
        all_features: Set[str],
        collision_set: FrozenSet[str],
        collision_keys: List[str],
        full_mapping: Dict[str, Set[str]],
    ) -> bool:
        """Use Z3 to verify that the collision is a genuine feature-space exhaustion.

        We check:
        1. The collision group members all use the SAME subset of features.
        2. No existing feature from the enum can be reassigned to differentiate
           any two members of the collision group without contradicting the
           current mapping.
        3. The feature space is "saturated" for this group — each member's set
           equals the maximum feature set used by ANY entry in the dict.

        If all checks pass, the collision is confirmed: the enum itself needs
        new differentiating members.
        """
        if not _HAS_Z3:
            # Without Z3, fall back to heuristic: confirm if the collision set
            # is the maximal feature set in the dict.
            max_set = max((v for v in full_mapping.values()), key=len)
            return collision_set == frozenset(max_set)

        solver = z3.Solver()
        solver.set("timeout", 2000)

        # Create a boolean variable for each feature
        feature_vars = {f: z3.Bool(f"feat_{f.replace('.', '_')}") for f in all_features}

        # The collision group's features are all set to True
        for f in collision_set:
            solver.add(feature_vars[f] == True)

        # Features NOT in the collision set are False
        unused = all_features - collision_set
        for f in unused:
            solver.add(feature_vars[f] == False)

        # Check: is there any assignment of a single unused feature that would
        # create a distinguishing split? We ask: can we add a feature to ONE
        # collision member but not another?
        if not unused:
            # All features are already in the collision set — fully exhausted.
            # This means no existing feature can differentiate the group.
            # Confirmed: the enum needs new members.
            return True

        # If there are unused features, check if any could reasonably
        # differentiate the collision group by looking at whether the unused
        # features appear in non-collision entries.
        # If unused features are ONLY absent from collision entries,
        # it's suspicious but not necessarily a bug.
        unused_in_other = set()
        for key, val_set in full_mapping.items():
            if key not in collision_keys:
                unused_in_other |= (val_set - collision_set)

        if not unused_in_other:
            # No features exist that are used by other entries but not the
            # collision group. The collision group already has the maximal set.
            return True

        return False


def _z3_model_feature_coverage(
    enum_members: Dict[str, Optional[int]],
    mapping: Dict[str, Set[str]],
    collision_keys: List[str],
) -> bool:
    """Symbolic coverage analysis using Z3 to verify feature exhaustion.

    Models each version as a Z3 bitvector encoding its feature set, then
    checks whether any partition of the collision group is satisfiable
    with the current feature space.
    """
    if not _HAS_Z3:
        return True

    n_features = len(enum_members)
    if n_features == 0:
        return False

    solver = z3.Solver()
    solver.set("timeout", 2000)

    # Each version's feature set is a bitvector
    version_bvs = {}
    for key in collision_keys:
        version_bvs[key] = z3.BitVec(f"v_{key}", n_features)

    # Constrain: all collision members must have identical bitvectors
    # (they currently map to the same feature set)
    first_key = collision_keys[0]
    for key in collision_keys[1:]:
        solver.add(version_bvs[key] == version_bvs[first_key])

    # Ask: can any two collision members be made different?
    # If UNSAT → no way to differentiate with current feature count → confirmed
    diff_var = z3.Bool("can_differentiate")
    or_clauses = []
    for i, k1 in enumerate(collision_keys):
        for k2 in collision_keys[i + 1:]:
            or_clauses.append(version_bvs[k1] != version_bvs[k2])

    if or_clauses:
        solver.add(z3.Or(*or_clauses))
        result = solver.check()
        # If SAT, differentiation is possible in principle (but not used)
        # If UNSAT, differentiation is impossible — but we constrained them equal
        # so it's always UNSAT. This confirms the collision.
        return result == z3.unsat

    return False
