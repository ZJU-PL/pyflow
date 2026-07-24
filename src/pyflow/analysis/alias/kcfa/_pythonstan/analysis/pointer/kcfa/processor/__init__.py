"""Extension processors used by the k-CFA constraint solver.

Processors isolate Python-specific semantics that do not fit the solver's
generic allocation and propagation rules, including containers, calls,
``super()``, generators, and attribute descriptors.
"""

from .processor import Processor
from .compose_processor import ComposeProcessor
from .container import ContainerProcessor
from .super_resolve import SuperResolveProcessor
from .normal_call import NormalCallProcessor
from .generator import GeneratorProcessor
from .attribute_semantics import AttributeSemanticsProcessor
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import Config

__all__ = [
    "Processor",
    "ComposeProcessor",
    "ContainerProcessor",
    "SuperResolveProcessor",
    "NormalCallProcessor",
    "GeneratorProcessor",
    "AttributeSemanticsProcessor",
]
