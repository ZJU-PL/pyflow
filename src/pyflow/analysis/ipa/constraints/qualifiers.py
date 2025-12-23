"""Qualifiers for object names in IPA.

Qualifiers indicate the scope and lifetime of objects in inter-procedural
analysis. They help determine how objects flow between contexts and whether
they escape their defining scope.

Qualifiers:
- HZ: Heap zone (local heap allocation)
- DN: Downward (passed down to callees)
- UP: Upward (returned from callees)
- GLBL: Global (existing objects, constants)
"""

HZ = "HZ"  # Heap zone - local heap allocation
DN = "DN"  # Downward - passed down to callees
UP = "UP"  # Upward - returned from callees
GLBL = "GLBL"  # Global - existing objects, constants
