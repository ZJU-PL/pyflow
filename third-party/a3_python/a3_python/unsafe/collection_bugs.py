"""
Collection-related crash bug detection - DEPRECATED.

NOTE: This module is no longer used. The bugs it was designed to detect
are now handled by the existing DIV_ZERO and BOUNDS detectors through
improved lattice tracking:

- EMPTY_COLLECTION_DIV → DIV_ZERO
  Because len([]) = 0, and we track zeroness through len() calls.
  
- EMPTY_COLLECTION_INDEX → BOUNDS
  Because we track Emptiness and raise confidence when emptiness = EMPTY.
  
- SCALE_ZERO_NORMALIZE → DIV_ZERO
  Because we track may_contain_zeros for arrays.
  
- DICT_KEY_MISSING → BOUNDS (KeyError)
  Because we track DictKeySet and raise confidence when key is missing.

The key insight is that specialized bug types are unnecessary when the
underlying lattice properly tracks the properties that lead to crashes.
"""

# This file is kept for reference but the predicates are not registered.
