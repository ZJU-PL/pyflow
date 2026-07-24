"""Store graph for PyFlow analysis.

This package provides the core store graph data structure that models object
relationships, slot assignments, and memory locations in Python programs.

Key components:
- StoreGraph: Main graph structure representing object relationships
- ObjectNode: Represents objects in memory
- SlotNode: Represents named storage locations (locals, attributes, etc.)
- CanonicalObjects: Canonical naming for objects and types
- ExtendedTypes: Type system extensions for analysis
- SetManager: Efficient set operations for analysis

The store graph serves as the foundation for all PyFlow analyses, providing
a unified representation of program state and enabling precise inter-procedural
analysis across function boundaries.
"""

from . import storegraph, canonicalobjects, extendedtypes, setmanager, annotations
