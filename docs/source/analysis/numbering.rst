Program Point Numbering
=========================

The numbering module assigns unique identifiers to program points within
the intermediate representation.  These identifiers are used throughout
PyFlow's analysis infrastructure for indexing, comparison, and efficient
lookup of analysis results.

Key Features
------------

- **Unique Identification**: Every program point receives a distinct numeric
  or symbolic identifier
- **Consistent Mapping**: Maintains a stable mapping between source locations
  and internal identifiers across analysis runs
- **Fast Lookup**: Enables O(1) access to per-point analysis data

Usage
-----

Numbering is used internally by most analysis modules.  It is typically not
used directly by end users but underpins:

- Data flow lattice storage (per-point facts)
- Graph edge indexing (CFG, DDG, PDG)
- Analysis result caching and invalidation

See Also
--------

- :doc:`/ir/cfg` — Control Flow Graph construction (primary consumer)
- :doc:`/ir/dataflow` — Data flow IR that uses point numbering
