"""
Symbolic heap model for Z3-based program analysis.

Heap is modeled as a map from ObjId (object identity) to object records.
This separates identity from value, making aliasing expressible.

Object records track:
- Type (list, tuple, dict, etc.)
- For sequences (list/tuple): length and element map
- For dicts: key-value map

Heap observers enable structural reasoning without pattern matching:
- SeqLen(obj_id): length of a sequence
- DictSize(obj_id): number of keys in a dict
- HasKey(dict_id, key): whether dict contains key
"""

import z3
from dataclasses import dataclass, field
from typing import Dict, Optional, Set


@dataclass
class SequenceObject:
    """A list or tuple object."""
    obj_type: str  # "list" or "tuple"
    length: z3.ExprRef  # Symbolic length (Z3 Int)
    elements: Dict[int, 'SymbolicValue'] = field(default_factory=dict)  # Concrete indices -> values
    
    def copy(self):
        from ..z3model.values import SymbolicValue
        return SequenceObject(
            obj_type=self.obj_type,
            length=self.length,
            elements=self.elements.copy()
        )


@dataclass
class DictObject:
    """A dict object."""
    keys: set = field(default_factory=set)  # Known keys (concrete)
    values: Dict = field(default_factory=dict)  # key -> SymbolicValue
    
    def copy(self):
        return DictObject(
            keys=self.keys.copy(),
            values=self.values.copy()
        )


@dataclass
class StringObject:
    """A string object."""
    value: str  # Concrete string value (for now)
    
    def copy(self):
        return StringObject(value=self.value)


@dataclass
class IteratorObject:
    """An iterator object."""
    collection_ref: 'SymbolicValue'  # Reference to the collection being iterated
    current_index: z3.ExprRef  # Current position in iteration (symbolic)
    
    def copy(self):
        return IteratorObject(
            collection_ref=self.collection_ref,
            current_index=self.current_index
        )


@dataclass
class SliceObject:
    """A slice object (start:stop:step)."""
    start: 'SymbolicValue'  # Start index (or None)
    stop: 'SymbolicValue'   # Stop index (or None)
    step: 'SymbolicValue'   # Step value (or None)
    
    def copy(self):
        return SliceObject(
            start=self.start,
            stop=self.stop,
            step=self.step
        )


@dataclass
class DictViewObject:
    """A dict view object (keys, values, or items view)."""
    dict_ref: 'SymbolicValue'  # Reference to the dict
    view_type: str  # "keys", "values", or "items"
    
    def copy(self):
        return DictViewObject(
            dict_ref=self.dict_ref,
            view_type=self.view_type
        )


@dataclass
class SymbolicHeap:
    """
    Symbolic heap representation.
    
    Tracks allocated objects with their type and contents.
    Maintains heap observers for structural reasoning.
    """
    
    next_obj_id: int = 1000  # Start ObjIds at 1000 to avoid confusion with small ints
    sequences: Dict[int, SequenceObject] = field(default_factory=dict)  # ObjId -> SequenceObject
    dicts: Dict[int, DictObject] = field(default_factory=dict)  # ObjId -> DictObject
    strings: Dict[int, StringObject] = field(default_factory=dict)  # ObjId -> StringObject
    iterators: Dict[int, IteratorObject] = field(default_factory=dict)  # ObjId -> IteratorObject
    slices: Dict[int, SliceObject] = field(default_factory=dict)  # ObjId -> SliceObject
    dict_views: Dict[int, DictViewObject] = field(default_factory=dict)  # ObjId -> DictViewObject
    allocated_objects: Dict[int, str] = field(default_factory=dict)
    
    # Heap observers for structural reasoning (without pattern matching)
    seq_len_observers: Dict[int, z3.ArithRef] = field(default_factory=dict)  # ObjId -> SeqLen(obj)
    dict_size_observers: Dict[int, z3.ArithRef] = field(default_factory=dict)  # ObjId -> DictSize(obj)
    has_key_observers: Dict[tuple, z3.BoolRef] = field(default_factory=dict)  # (dict_id, key_hash) -> HasKey(dict, key)
    
    def allocate(self, obj_type: str) -> int:
        """
        Allocate a new object and return its ObjId.
        """
        obj_id = self.next_obj_id
        self.next_obj_id += 1
        self.allocated_objects[obj_id] = obj_type
        return obj_id
    
    def allocate_sequence(self, obj_type: str, length: z3.ExprRef, elements: Dict[int, 'SymbolicValue'] = None) -> int:
        """
        Allocate a list or tuple with given length.
        
        Also initializes SeqLen observer for structural reasoning.
        """
        obj_id = self.allocate(obj_type)
        self.sequences[obj_id] = SequenceObject(
            obj_type=obj_type,
            length=length,
            elements=elements or {}
        )
        # Initialize SeqLen observer and constrain it to the sequence's length
        # The observer will be returned by get_seq_len_observer and must equal length
        seq_len = self.get_seq_len_observer(obj_id)
        # Note: The constraint seq_len == length will be added by constrain_observers()
        return obj_id
    
    def allocate_dict(self, keys: set = None, values: Dict = None) -> int:
        """
        Allocate a dict.
        
        Also initializes DictSize observer for structural reasoning.
        """
        obj_id = self.allocate("dict")
        self.dicts[obj_id] = DictObject(
            keys=keys or set(),
            values=values or {}
        )
        # Initialize DictSize observer
        dict_size = self.get_dict_size_observer(obj_id)
        # Note: The constraint dict_size == len(keys) will be added by constrain_observers()
        return obj_id
    
    def allocate_string(self, value: str) -> int:
        """Allocate a string object."""
        obj_id = self.allocate("str")
        self.strings[obj_id] = StringObject(value=value)
        return obj_id

    def allocate_list(self, length: z3.ExprRef | None = None, elements: Dict[int, "SymbolicValue"] | None = None) -> int:
        """
        Allocate a list object.

        Convenience wrapper used by higher-level semantics.
        """
        return self.allocate_sequence("list", length if length is not None else z3.IntVal(0), elements or {})
    
    def allocate_iterator(self, collection: 'SymbolicValue') -> int:
        """Allocate an iterator object."""
        obj_id = self.allocate("iterator")
        self.iterators[obj_id] = IteratorObject(
            collection_ref=collection,
            current_index=z3.Int(f"iter_idx_{obj_id}")
        )
        return obj_id
    
    def allocate_slice(self, start: 'SymbolicValue', stop: 'SymbolicValue', step: 'SymbolicValue') -> int:
        """Allocate a slice object."""
        obj_id = self.allocate("slice")
        self.slices[obj_id] = SliceObject(
            start=start,
            stop=stop,
            step=step
        )
        return obj_id
    
    def allocate_dict_view(self, dict_obj: 'SymbolicValue', view_type: str) -> int:
        """
        Allocate a dict view object (keys, values, or items).
        
        Args:
            dict_obj: The dict SymbolicValue being viewed
            view_type: "keys", "values", or "items"
        
        Returns:
            ObjId for the view object
        """
        obj_id = self.allocate("dict_view")
        self.dict_views[obj_id] = DictViewObject(
            dict_ref=dict_obj,
            view_type=view_type
        )
        return obj_id
    
    def get_sequence(self, obj_id: int) -> Optional[SequenceObject]:
        """Get sequence object by ID."""
        return self.sequences.get(obj_id)
    
    def get_dict(self, obj_id: int) -> Optional[DictObject]:
        """Get dict object by ID."""
        return self.dicts.get(obj_id)
    
    def get_string(self, obj_id: int) -> Optional[str]:
        """Get string value by object ID."""
        string_obj = self.strings.get(obj_id)
        if string_obj:
            return string_obj.value
        return None
    
    def allocate_tuple(self, length: int) -> int:
        """
        Allocate a tuple with concrete length.
        
        Helper for creating tuples with known size (e.g., sys.version_info).
        """
        return self.allocate_sequence("tuple", z3.IntVal(length), {})
    
    # Heap observer methods for structural reasoning
    
    def get_seq_len_observer(self, obj_id: int) -> z3.ArithRef:
        """
        Get or create a SeqLen observer for a sequence object.
        
        Returns a Z3 Int symbolic variable representing the length of the sequence.
        The observer is constrained to equal the sequence's length field.
        """
        if obj_id not in self.seq_len_observers:
            self.seq_len_observers[obj_id] = z3.Int(f"SeqLen_{obj_id}")
        return self.seq_len_observers[obj_id]
    
    def get_dict_size_observer(self, obj_id: int) -> z3.ArithRef:
        """
        Get or create a DictSize observer for a dict object.
        
        Returns a Z3 Int symbolic variable representing the number of keys in the dict.
        The observer is constrained to equal len(dict.keys).
        """
        if obj_id not in self.dict_size_observers:
            self.dict_size_observers[obj_id] = z3.Int(f"DictSize_{obj_id}")
        return self.dict_size_observers[obj_id]
    
    def get_has_key_observer(self, dict_id: int, key_val: 'SymbolicValue') -> z3.BoolRef:
        """
        Get or create a HasKey observer for a dict and key.
        
        Returns a Z3 Bool representing whether the dict contains the key.
        
        Note: For concrete keys, we use the key value as a hash.
        For symbolic keys, we create a fresh observer.
        """
        # Create a hashable key for the observer map
        # For concrete values, use their representation
        key_hash = id(key_val)  # Use object identity as hash for now
        observer_key = (dict_id, key_hash)
        
        if observer_key not in self.has_key_observers:
            self.has_key_observers[observer_key] = z3.Bool(f"HasKey_{dict_id}_{key_hash}")
        return self.has_key_observers[observer_key]
    
    def constrain_observers(self) -> list:
        """
        Generate Z3 constraints that tie observers to heap state.
        
        Returns a list of Z3 constraints that enforce:
        - SeqLen(obj) == obj.length for all sequences
        - DictSize(obj) == len(obj.keys) for all dicts
        - HasKey(dict, key) ⟺ key in dict.keys for known keys
        
        These constraints maintain semantic faithfulness of observers.
        """
        constraints = []
        
        # Constrain SeqLen observers to match actual lengths
        for obj_id, observer in self.seq_len_observers.items():
            if obj_id in self.sequences:
                seq = self.sequences[obj_id]
                constraints.append(observer == seq.length)
        
        # Constrain DictSize observers to match actual key counts
        for obj_id, observer in self.dict_size_observers.items():
            if obj_id in self.dicts:
                dict_obj = self.dicts[obj_id]
                constraints.append(observer == len(dict_obj.keys))
        
        # HasKey observers: for known concrete keys, enforce correctness
        # (More complex: would need to track which keys are in the dict symbolically)
        # For now, we leave this as a TODO - proper symbolic key membership
        # requires more sophisticated modeling
        
        return constraints
    
    def set_tuple_element(self, tuple_id: int, index: int, value: 'SymbolicValue') -> None:
        """
        Set a tuple element at a concrete index.
        
        Helper for populating tuples with concrete structure.
        """
        if tuple_id in self.sequences:
            self.sequences[tuple_id].elements[index] = value
    
    def copy(self) -> 'SymbolicHeap':
        """Create a copy of the heap for branching paths."""
        return SymbolicHeap(
            next_obj_id=self.next_obj_id,
            sequences={k: v.copy() for k, v in self.sequences.items()},
            dicts={k: v.copy() for k, v in self.dicts.items()},
            strings={k: v.copy() for k, v in self.strings.items()},
            iterators={k: v.copy() for k, v in self.iterators.items()},
            slices={k: v.copy() for k, v in self.slices.items()},
            dict_views={k: v.copy() for k, v in self.dict_views.items()},
            allocated_objects=self.allocated_objects.copy(),
            seq_len_observers=self.seq_len_observers.copy(),
            dict_size_observers=self.dict_size_observers.copy(),
            has_key_observers=self.has_key_observers.copy()
        )
