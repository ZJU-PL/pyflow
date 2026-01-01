"""Lifetime analysis database structures.

This package provides database schema and data structure classes used by lifetime
analysis to store and manipulate analysis results efficiently.

Key components:
- Schema: Abstract base class for database schemas
- Structure: Structured data representation
- TupleSet: Set operations on tuple data
- Mapping: Key-value mapping structures
- Lattice: Lattice-based data structures for analysis

These database structures enable efficient storage and querying of lifetime
analysis results, supporting complex set operations and lattice computations.
"""

from . import base, structure, tupleset, mapping, lattice
