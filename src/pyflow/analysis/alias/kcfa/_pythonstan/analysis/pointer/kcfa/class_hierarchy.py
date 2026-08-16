"""Class hierarchy and MRO computation.

This module implements Python's C3 linearization algorithm for computing
Method Resolution Order (MRO) in class hierarchies.

Uses AbstractObject instead of strings for robustness and type safety.
"""

from typing import Dict, List, Set, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .object import AbstractObject

__all__ = [
    "ClassHierarchyManager",
    "compute_c3_mro",
    "compute_c3_mro_for_bases",
    "MROError",
]


class MROError(Exception):
    """Exception raised when MRO cannot be computed."""
    pass


class ClassHierarchyManager:
    """Manages class hierarchy for pointer analysis.
    
    Tracks class inheritance relationships and computes MRO using C3 linearization.
    Works with AbstractObject instances for type safety and proper integration
    with the pointer analysis.
    """
    
    def __init__(self):
        """Initialize class hierarchy manager."""
        # Map: class object -> list of base class objects
        self._bases: Dict['AbstractObject', List['AbstractObject']] = {}
        # Map: class object -> list of subclass objects
        self._subclasses: Dict['AbstractObject', List['AbstractObject']] = {}
        # Cache: class object -> computed MRO (list of class objects)
        self._mro_cache: Dict['AbstractObject', List['AbstractObject']] = {}
        # Map: class name -> class objects (for lookup by name)
        self._classes_by_name: Dict[str, Set['AbstractObject']] = {}
    
    def add_class(
        self, 
        class_obj: 'AbstractObject', 
        base_objects: Optional[List['AbstractObject']] = None
    ):
        """Add class to hierarchy.
        
        Args:
            class_obj: Class object (AllocKind.CLASS)
            base_objects: List of base class objects (resolved during analysis)
        """
        from .object import AllocKind
        
        if class_obj.kind != AllocKind.CLASS:
            raise ValueError(f"Expected CLASS object, got {class_obj.kind}")
        
        if class_obj not in self._bases:
            self._bases[class_obj] = base_objects or []
            
            # Register by name for lookup
            class_name = class_obj.alloc_site.name
            if class_name:
                if class_name not in self._classes_by_name:
                    self._classes_by_name[class_name] = set()
                self._classes_by_name[class_name].add(class_obj)
        
        # Register in subclasses of bases
        if base_objects:
            for base_obj in base_objects:
                if base_obj not in self._subclasses:
                    self._subclasses[base_obj] = []
                if class_obj not in self._subclasses[base_obj]:
                    self._subclasses[base_obj].append(class_obj)
        
        # Invalidate MRO cache for this class and its subclasses
        self._invalidate_mro_cache(class_obj)
    
    def update_bases(
        self,
        class_obj: 'AbstractObject',
        base_objects: List['AbstractObject']
    ):
        """Update base classes for a class (called when bases are resolved).
        
        Args:
            class_obj: Class object
            base_objects: Newly resolved base class objects
        """
        if class_obj in self._bases:
            old_bases = self._bases[class_obj]
            # Remove from old bases' subclasses
            for old_base in old_bases:
                if old_base in self._subclasses:
                    if class_obj in self._subclasses[old_base]:
                        self._subclasses[old_base].remove(class_obj)
        
        # Add with new bases. add_class() intentionally preserves existing
        # entries, so update the base map directly here.
        self._bases[class_obj] = base_objects
        for base_obj in base_objects:
            if base_obj not in self._subclasses:
                self._subclasses[base_obj] = []
            if class_obj not in self._subclasses[base_obj]:
                self._subclasses[base_obj].append(class_obj)
        self._invalidate_mro_cache(class_obj)
    
    def _invalidate_mro_cache(self, class_obj: 'AbstractObject'):
        """Invalidate MRO cache for a class and all its subclasses."""
        to_invalidate = [class_obj]
        invalidated = set()
        
        while to_invalidate:
            obj = to_invalidate.pop()
            if obj in invalidated:
                continue
            invalidated.add(obj)
            
            # Remove from cache
            if obj in self._mro_cache:
                del self._mro_cache[obj]
            
            # Add subclasses to invalidation list
            if obj in self._subclasses:
                to_invalidate.extend(self._subclasses[obj])
    
    def get_bases(self, class_obj: 'AbstractObject') -> List['AbstractObject']:
        """Get direct base classes for a class.
        
        Args:
            class_obj: Class object
        
        Returns:
            List of base class objects (empty if no bases)
        """
        return self._bases.get(class_obj, [])
    
    def get_subclasses(self, class_obj: 'AbstractObject') -> List['AbstractObject']:
        """Get direct subclasses for a class.
        
        Args:
            class_obj: Class object
        
        Returns:
            List of subclass objects (empty if no subclasses)
        """
        return self._subclasses.get(class_obj, [])
    
    def get_mro(self, class_obj: 'AbstractObject') -> List['AbstractObject']:
        """Get Method Resolution Order for a class.
        
        Uses C3 linearization algorithm with caching.
        
        Args:
            class_obj: Class object
        
        Returns:
            List of class objects in MRO order (includes class_obj itself)
        
        Raises:
            MROError: If hierarchy is inconsistent
        """
        if class_obj in self._mro_cache:
            return self._mro_cache[class_obj]
        
        mro = compute_c3_mro(class_obj, self)
        self._mro_cache[class_obj] = mro
        return mro
    
    def has_class(self, class_obj: 'AbstractObject') -> bool:
        """Check if class is registered in hierarchy.
        
        Args:
            class_obj: Class object
        
        Returns:
            True if class is registered
        """
        return class_obj in self._bases
    
    def lookup_class_by_name(self, class_name: str) -> Set['AbstractObject']:
        """Lookup class objects by name.
        
        Args:
            class_name: Name of class
        
        Returns:
            Set of class objects with that name (empty if none found)
        """
        return self._classes_by_name.get(class_name, set())


def compute_c3_mro(
    class_obj: 'AbstractObject',
    hierarchy: ClassHierarchyManager
) -> List['AbstractObject']:
    """Compute C3 linearization (MRO) for a class.
    
    Python's MRO algorithm ensures:
    1. Children come before parents (depth-first)
    2. Parent order is preserved (left-to-right)
    3. Diamond patterns are handled correctly
    4. No class appears twice
    
    Algorithm:
        L(C) = [C] + merge(L(B1), L(B2), ..., L(Bn), [B1, B2, ..., Bn])
        
    Args:
        class_obj: Class object to compute MRO for
        hierarchy: ClassHierarchyManager instance
    
    Returns:
        List of class objects in MRO order
    
    Raises:
        MROError: If inheritance graph is inconsistent
    """
    # Get direct bases
    bases = hierarchy.get_bases(class_obj)
    
    if not bases:
        # No bases - MRO is just [class_obj]
        # Note: We don't add 'object' as AbstractObject since it's implicit
        return [class_obj]
    
    # Compute MRO for each base recursively
    base_mros = []
    for base_obj in bases:
        if not hierarchy.has_class(base_obj):
            # Unknown base class - conservatively add to hierarchy
            hierarchy.add_class(base_obj)
        base_mro = compute_c3_mro(base_obj, hierarchy)
        base_mros.append(base_mro)
    
    # C3 linearization: L(C) = [C] + merge(L(B1), L(B2), ..., [B1, B2, ...])
    merged = _c3_merge(base_mros + [bases])
    return [class_obj] + merged


def compute_c3_mro_for_bases(
    bases: List['AbstractObject'],
    hierarchy: ClassHierarchyManager,
) -> List['AbstractObject']:
    """Compute the C3 tail for one concrete tuple of direct bases."""
    if not bases:
        return []
    base_mros = []
    for base_obj in bases:
        if not hierarchy.has_class(base_obj):
            hierarchy.add_class(base_obj)
        base_mros.append(compute_c3_mro(base_obj, hierarchy))
    return _c3_merge(base_mros + [list(bases)])


def _c3_merge(sequences: List[List['AbstractObject']]) -> List['AbstractObject']:
    """Merge sequences using C3 algorithm.
    
    Selects heads of sequences that don't appear in any tail,
    removes them from all sequences, and repeats until done.
    
    Args:
        sequences: List of sequences of class objects to merge
    
    Returns:
        Merged sequence of class objects
    
    Raises:
        MROError: If no valid merge exists (inconsistent hierarchy)
    """
    result = []
    
    # Make mutable copies
    seqs = [list(seq) for seq in sequences]
    
    while True:
        # Remove empty sequences
        seqs = [seq for seq in seqs if seq]
        if len(seqs) == 0:
            return result
        
        # Find a candidate: head that doesn't appear in any tail
        candidate = None
        for seq in seqs:
            head = seq[0]
            
            # Check if head appears in any tail
            appears_in_tail = False
            for other_seq in seqs:
                if head in other_seq[1:]:
                    appears_in_tail = True
                    break
            
            if not appears_in_tail:
                candidate = head
                break
        
        if candidate is None:
            # No valid candidate - inconsistent hierarchy
            # Format error message with class names
            class_names = [[obj.alloc_site.name or str(obj) for obj in seq] for seq in seqs]
            raise MROError(
                f"Cannot create consistent MRO: no valid candidate in {class_names}"
            )
        
        result.append(candidate)
        
        # Remove candidate from all sequences
        for seq in seqs:
            if seq and seq[0] == candidate:
                seq.pop(0)
    
    return result
