"""Shape analysis model classes.

This package provides model classes and data structures used by shape analysis
to represent expressions, slots, reference counts, configurations, and path information.

Key components:
- Canonical: Canonical object management for shape analysis
- Expressions: Expression representation in shape analysis
- Slots: Slot modeling for data structure shapes
- ReferenceCount: Reference counting for shape inference
- Configuration: Shape configuration management
- Secondary: Secondary analysis structures
- PathInformation: Path-sensitive shape information

These model classes enable shape analysis to precisely track data structure
shapes and properties across complex program structures.
"""

from . import (
    canonical,
    expressions,
    slots,
    referencecount,
    configuration,
    secondary,
    pathinformation,
)
