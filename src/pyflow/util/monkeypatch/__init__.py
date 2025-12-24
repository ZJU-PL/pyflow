"""
Extended Python standard library modules (monkey patches).

This package provides extended versions of Python standard library modules
with additional functionality needed by pyflow's static analysis. The "x"
prefix indicates these are extended versions that augment or replace standard
library functionality.

Modules:
    xcollections: Extended collections with lazydict and weakcache
    xmath: Extended math utilities (numbits, bijection)
    xnamedtuple: Extended namedtuple that supports adding methods
    xtypes: Extended types module with additional type definitions

These modules are used throughout pyflow for:
- Canonical object caching (weakcache)
- Lazy dictionary initialization (lazydict)
- Type checking and stub generation (xtypes)
- Creating named tuples with custom methods (xnamedtuple)
- Mathematical operations for analysis (xmath)
"""

