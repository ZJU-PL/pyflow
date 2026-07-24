"""Abstract domain lattice library for pyflow.

Provides a collection of lattice (abstract domain) implementations
ported from Pysa's ``source/domains/``.  All domains implement the
:class:`AbstractDomain` interface and support the standard lattice
operations: join, meet, leq, widen, subtract, and the part-based
transform/reduce/partition dispatch system.
"""

from .base import (
    AbstractDomain,
    Part,
    PartId,
    TransformOp,
    ReduceOp,
    PartitionOp,
    OP_MAP,
    OP_ADD,
    OP_FILTER,
    OP_FILTER_MAP,
    OP_EXPAND,
    OP_ACC,
    OP_EXISTS,
    OP_BY,
    OP_BY_FILTER,
    EP_LOCAL,
    EP_CONST,
    check_lattice_properties,
)
from .set_domain import SetDomain
from .element_set_domain import ElementSetDomain
from .inverted_set_domain import InvertedSetDomain
from .over_under_set_domain import OverUnderSetDomain, Approximation
from .topped_set_domain import ToppedSetDomain
from .bucketed_element_set_domain import BucketedElementSetDomain
from .map_domain import MapDomain
from .product_domain import ProductDomain
from .flat_domain import FlatDomain
from .tree_domain import TreeDomain
from .rooted_tree_domain import RootedTreeDomain
from .simple_domain import SimpleDomain
from .wrapper_domain import WrapperDomain

__all__ = [
    "AbstractDomain",
    "Part",
    "PartId",
    "TransformOp",
    "ReduceOp",
    "PartitionOp",
    "OP_MAP",
    "OP_ADD",
    "OP_FILTER",
    "OP_FILTER_MAP",
    "OP_EXPAND",
    "OP_ACC",
    "OP_EXISTS",
    "OP_BY",
    "OP_BY_FILTER",
    "EP_LOCAL",
    "EP_CONST",
    "check_lattice_properties",
    "SetDomain",
    "ElementSetDomain",
    "InvertedSetDomain",
    "OverUnderSetDomain",
    "Approximation",
    "ToppedSetDomain",
    "BucketedElementSetDomain",
    "MapDomain",
    "ProductDomain",
    "FlatDomain",
    "TreeDomain",
    "RootedTreeDomain",
    "SimpleDomain",
    "WrapperDomain",
]
