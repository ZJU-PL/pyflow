"""
Barrier-Based Library Contracts Framework

This package provides a formal framework for specifying semantic contracts
for library functions, enabling deferred constraint propagation for proving
safety properties via barrier certificates.

The framework integrates with the 5-layer barrier synthesis architecture:
    Layer 1-2: SOS/SDP - Contracts become polynomial constraints
    Layer 3: CEGAR - Contracts provide refinement predicates
    Layer 4: ICE Learning - Contracts generate training samples
    Layer 5: IC3/PDR - Contracts encode as CHC clauses

Architecture:
    barriers/
    ├── __init__.py           # This file
    ├── intervals.py          # Interval abstract domain
    ├── abstract_values.py    # AbstractValue, AbstractTensor
    ├── deferred.py           # DeferredBarrier, DeferredConstraint
    ├── contracts.py          # LibraryContract, ContractRegistry
    ├── propagation.py        # Constraint propagation engine
    ├── verification.py       # Barrier verification
    └── torch/                # PyTorch contracts
        ├── __init__.py
        ├── _registry.py      # Registration utilities
        ├── core.py           # torch.* (2000+ contracts)
        ├── tensor.py         # Tensor methods (500+ contracts)
        ├── nn_modules.py     # torch.nn.* modules (300+ contracts)
        ├── nn_functional.py  # torch.nn.functional.* (400+ contracts)
        ├── linalg.py         # torch.linalg.* (100+ contracts)
        ├── fft.py            # torch.fft.* (50+ contracts)
        ├── special.py        # torch.special.* (100+ contracts)
        ├── distributions.py  # torch.distributions.* (200+ contracts)
        ├── optim.py          # torch.optim.* (100+ contracts)
        ├── sparse.py         # torch.sparse.* (50+ contracts)
        ├── cuda.py           # torch.cuda.* (50+ contracts)
        └── autograd.py       # torch.autograd.* (50+ contracts)

Usage:
    from a3_python.contracts.barriers import (
        Interval,
        DeferredBarrier,
        ContractRegistry,
        load_torch_contracts,
    )
    
    registry = load_torch_contracts()
    contract = registry.get("torch.nn.functional", "cosine_similarity")
    
    # Get return interval
    interval = contract.get_return_interval()  # [-1, 1]
    
    # Create deferred barrier for later verification
    barrier = DeferredBarrier.from_contract(contract, "result_var")
    
    # After arithmetic: result_var - 3
    propagated = barrier.subtract(Interval.point(3))  # [-4, -2]
    
    # Check safety
    if propagated.current_interval.excludes_zero():
        print("Division is SAFE by deferred barrier")
"""

__version__ = "2.0.0"

# Core interval domain
from .intervals import (
    Interval,
    IntervalVector,
    IntervalMatrix,
    ExtendedReal,
    POSITIVE_INF,
    NEGATIVE_INF,
)

# Abstract values
from .abstract_values import (
    AbstractValue,
    AbstractTensor,
    AbstractScalar,
    AbstractSequence,
    AbstractDict,
    Shape,
    DType,
    Device,
)

# Deferred barriers
from .deferred import (
    DeferredBarrier,
    DeferredConstraint,
    ConstraintKind,
    BarrierStrength,
    BarrierResult,
    BarrierProof,
    TransformationTrace,
)

# Contracts
from .contracts import (
    LibraryContract,
    FunctionContract,
    MethodContract,
    ModuleContract,
    PropertyContract,
    ContractRegistry,
    ContractBuilder,
    Precondition,
    Postcondition,
    Invariant,
)

# Device analysis
from .device_analyzer import (
    DeviceAnalyzer,
    DeviceMismatchBug,
    AnalysisState,
    analyze_device_mismatches,
)

# Deferred barrier with device tracking
from .deferred import (
    DeviceBarrier,
)

__all__ = [
    # Version
    "__version__",
    # Intervals
    "Interval",
    "IntervalVector",
    "IntervalMatrix",
    "ExtendedReal",
    "POSITIVE_INF",
    "NEGATIVE_INF",
    # Abstract values
    "AbstractValue",
    "AbstractTensor",
    "AbstractScalar",
    "AbstractSequence",
    "AbstractDict",
    "Shape",
    "DType",
    "Device",
    # Deferred barriers
    "DeferredBarrier",
    "DeferredConstraint",
    "ConstraintKind",
    "BarrierStrength",
    "BarrierResult",
    "BarrierProof",
    "TransformationTrace",
    "DeviceBarrier",
    # Contracts
    "LibraryContract",
    "FunctionContract",
    "MethodContract",
    "ModuleContract",
    "PropertyContract",
    "ContractRegistry",
    "ContractBuilder",
    "Precondition",
    "Postcondition",
    "Invariant",
    # Device analysis
    "DeviceAnalyzer",
    "DeviceMismatchBug",
    "AnalysisState",
    "analyze_device_mismatches",
    # Loaders
    "load_all_contracts",
    "load_torch_contracts",
]


def load_all_contracts() -> "ContractRegistry":
    """
    Load all library contracts into a registry.
    
    This loads contracts for:
    - PyTorch (torch.*, torch.nn.*, etc.)
    - NumPy (future)
    - Standard library (future)
    
    Returns:
        ContractRegistry with all registered contracts
    """
    from .contracts import ContractRegistry
    from .torch import register_all_torch_contracts
    
    registry = ContractRegistry()
    register_all_torch_contracts(registry)
    
    return registry


def load_torch_contracts() -> "ContractRegistry":
    """
    Load only PyTorch contracts.
    
    Returns:
        ContractRegistry with PyTorch contracts
    """
    from .contracts import ContractRegistry
    from .torch import register_all_torch_contracts
    
    registry = ContractRegistry()
    register_all_torch_contracts(registry)
    
    return registry
