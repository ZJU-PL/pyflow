"""
PyTorch Contracts Package

This package provides barrier-based contracts for PyTorch functions, methods, 
and modules. These contracts specify:

1. **Interval Bounds**: Output value ranges (e.g., sigmoid → [0, 1])
2. **Device Requirements**: Which operations require same-device tensors
3. **Preconditions**: Input requirements (e.g., log requires positive input)
4. **Shape Preservation**: Which operations preserve tensor shape
5. **Non-negativity/Positivity Guarantees**: Mathematical guarantees

Coverage:
    - torch.* core functions (~1000 contracts)
    - torch.Tensor methods (~500 contracts)
    - torch.nn.functional.* (~400 contracts)
    - torch.nn.* modules (~300 contracts)
    - torch.linalg.* (~100 contracts)
    - torch.fft.* (~50 contracts)
    - torch.special.* (~100 contracts)
    - torch.distributions.* (~200 contracts)

Total: ~2700+ contracts

Device Barriers:
----------------
A key feature is detection of device mismatch errors. Many PyTorch operations
require all input tensors to be on the same device. When tensors on different
devices are combined, PyTorch raises RuntimeError.

Example:
    a = torch.tensor([1.0]).cuda()  # GPU tensor
    b = torch.tensor([2.0])          # CPU tensor
    c = a + b  # RuntimeError: tensors on different devices

The contracts track device requirements via `requires_same_device=True` and
enable static detection of such errors before runtime.

Usage:
------
    from a3_python.contracts.barriers.torch import (
        get_torch_contract,
        register_all_torch_contracts,
        TORCH_REGISTRY
    )
    
    # Get a specific contract
    sigmoid_contract = get_torch_contract("torch", "sigmoid")
    
    # Check output bounds
    output_interval = sigmoid_contract.return_interval  # [0, 1]
    
    # Check device requirements
    add_contract = get_torch_contract("torch", "add")
    if add_contract.requires_same_device:
        # Verify tensors are on same device before operation
        pass
"""

from .registry import (
    TORCH_REGISTRY,
    register_all_torch_contracts,
    get_torch_contract,
    bulk_register,
    # Quick contract creators
    interval,
    positive,
    non_negative,
    probability,
    symmetric_unit,
    angle,
    unbounded,
    shape_preserving,
    # Shape helpers
    broadcast_shapes,
    matmul_shape,
    conv_output_shape,
    # Device helpers
    same_device_as_first,
    check_all_same_device,
)

from .core import register_core_contracts
from .tensor import register_tensor_contracts
from .nn_functional import register_nn_functional_contracts
from .nn_modules import register_nn_module_contracts
from .linalg import register_linalg_contracts
from .fft import register_fft_contracts
from .special import register_special_contracts
from .distributions import register_distribution_contracts
from .optim import register_optim_contracts
from .autograd import register_autograd_contracts
from .cuda import register_cuda_contracts
from .sparse import register_sparse_contracts
from .distributed import register_distributed_contracts
from .jit import register_jit_contracts
from .data import register_data_contracts
from .quantization import register_quantization_contracts
from .onnx import register_onnx_contracts
from .profiler import register_profiler_contracts
from .utils import register_utils_contracts
from .backends import register_backends_contracts
from .export_compile import register_export_compile_contracts
from .hub_package import register_hub_package_contracts
from .amp import register_amp_contracts
from .experimental import register_experimental_contracts
from .accelerators import register_accelerator_contracts

__all__ = [
    # Registry
    "TORCH_REGISTRY",
    "register_all_torch_contracts",
    "get_torch_contract",
    "bulk_register",
    
    # Quick contract creators
    "interval",
    "positive",
    "non_negative",
    "probability",
    "symmetric_unit",
    "angle",
    "unbounded",
    "shape_preserving",
    
    # Shape helpers
    "broadcast_shapes",
    "matmul_shape",
    "conv_output_shape",
    
    # Device helpers
    "same_device_as_first",
    "check_all_same_device",
    
    # Registration functions
    "register_core_contracts",
    "register_tensor_contracts",
    "register_nn_functional_contracts",
    "register_nn_module_contracts",
    "register_linalg_contracts",
    "register_fft_contracts",
    "register_special_contracts",
    "register_distribution_contracts",
    "register_optim_contracts",
    "register_autograd_contracts",
    "register_cuda_contracts",
    "register_sparse_contracts",
    "register_distributed_contracts",
    "register_jit_contracts",
    "register_data_contracts",
    "register_quantization_contracts",
    "register_onnx_contracts",
    "register_profiler_contracts",
    "register_utils_contracts",
    "register_backends_contracts",
    "register_export_compile_contracts",
    "register_hub_package_contracts",
    "register_amp_contracts",
    "register_experimental_contracts",
    "register_accelerator_contracts",
]
