"""
PyTorch Backends Contracts - torch.backends.*

This module provides contracts for PyTorch backend configuration:
- torch.backends.cudnn (cuDNN library)
- torch.backends.cuda (CUDA backend)
- torch.backends.mkl (Intel MKL)
- torch.backends.mkldnn (oneDNN/MKL-DNN)
- torch.backends.openmp (OpenMP)
- torch.backends.opt_einsum (einsum optimization)
- torch.backends.mps (Metal Performance Shaders)
- torch.backends.quantized (quantized backends)

Device Barrier Considerations:
- Backend configurations affect device-specific behavior
- cuDNN settings only apply to CUDA operations
- MPS settings only apply to Apple Silicon
- Quantized backends may have device restrictions
"""

from typing import Dict, List, Any, Optional
from ..intervals import Interval
from ..contracts import (
    ContractRegistry,
    FunctionContract,
    PropertyContract,
)


# ============================================================================
# cuDNN Backend
# ============================================================================

def _register_cudnn(registry: ContractRegistry) -> None:
    """Register cuDNN backend contracts."""
    
    # torch.backends.cudnn.version
    registry.register(FunctionContract(
        name="torch.backends.cudnn.version",
        qualname="torch.backends.cudnn.version",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, float('inf')),  # Version number or None
        preconditions=[],
        postconditions=[
            ("version_returned", "Returns cuDNN version or None"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get cuDNN version",
    ))
    
    # torch.backends.cudnn.is_available
    registry.register(FunctionContract(
        name="torch.backends.cudnn.is_available",
        qualname="torch.backends.cudnn.is_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("availability_checked", "Returns True if cuDNN is available"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if cuDNN is available",
    ))
    
    # torch.backends.cudnn.enabled (property)
    registry.register(PropertyContract(
        name="torch.backends.cudnn.enabled",
        qualname="torch.backends.cudnn.enabled",
        return_interval=None,  # Boolean
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_bool", "Returns current enabled state"),
        ],
        setter_preconditions=[],
        setter_postconditions=[
            ("enabled_set", "cuDNN enabled state updated"),
        ],
        docstring="Enable/disable cuDNN",
    ))
    
    # torch.backends.cudnn.benchmark (property)
    registry.register(PropertyContract(
        name="torch.backends.cudnn.benchmark",
        qualname="torch.backends.cudnn.benchmark",
        return_interval=None,  # Boolean
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_bool", "Returns current benchmark state"),
        ],
        setter_preconditions=[],
        setter_postconditions=[
            ("benchmark_set", "cuDNN benchmark mode updated"),
        ],
        docstring="Enable/disable cuDNN benchmarking for fastest algorithms",
    ))
    
    # torch.backends.cudnn.benchmark_limit (property)
    registry.register(PropertyContract(
        name="torch.backends.cudnn.benchmark_limit",
        qualname="torch.backends.cudnn.benchmark_limit",
        return_interval=Interval(0, float('inf')),
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_int", "Returns current benchmark limit"),
        ],
        setter_preconditions=[
            ("non_negative", "Limit must be non-negative"),
        ],
        setter_postconditions=[
            ("limit_set", "Benchmark limit updated"),
        ],
        docstring="Limit on cuDNN benchmark runs (0 = no limit)",
    ))
    
    # torch.backends.cudnn.deterministic (property)
    registry.register(PropertyContract(
        name="torch.backends.cudnn.deterministic",
        qualname="torch.backends.cudnn.deterministic",
        return_interval=None,  # Boolean
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_bool", "Returns current deterministic state"),
        ],
        setter_preconditions=[],
        setter_postconditions=[
            ("deterministic_set", "Deterministic mode updated"),
        ],
        docstring="Enable/disable deterministic cuDNN algorithms",
    ))
    
    # torch.backends.cudnn.allow_tf32 (property)
    registry.register(PropertyContract(
        name="torch.backends.cudnn.allow_tf32",
        qualname="torch.backends.cudnn.allow_tf32",
        return_interval=None,  # Boolean
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_bool", "Returns TF32 allowance state"),
        ],
        setter_preconditions=[],
        setter_postconditions=[
            ("tf32_set", "TF32 allowance updated"),
        ],
        docstring="Allow TensorFloat-32 in cuDNN convolutions",
    ))


# ============================================================================
# CUDA Backend
# ============================================================================

def _register_cuda_backend(registry: ContractRegistry) -> None:
    """Register CUDA backend contracts."""
    
    # torch.backends.cuda.is_built
    registry.register(FunctionContract(
        name="torch.backends.cuda.is_built",
        qualname="torch.backends.cuda.is_built",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if PyTorch built with CUDA"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if PyTorch was built with CUDA support",
    ))
    
    # torch.backends.cuda.matmul.allow_tf32 (property)
    registry.register(PropertyContract(
        name="torch.backends.cuda.matmul.allow_tf32",
        qualname="torch.backends.cuda.matmul.allow_tf32",
        return_interval=None,  # Boolean
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_bool", "Returns TF32 allowance for matmul"),
        ],
        setter_preconditions=[],
        setter_postconditions=[
            ("tf32_matmul_set", "TF32 matmul setting updated"),
        ],
        docstring="Allow TensorFloat-32 in matrix multiplications",
    ))
    
    # torch.backends.cuda.matmul.allow_fp16_reduced_precision_reduction (property)
    registry.register(PropertyContract(
        name="torch.backends.cuda.matmul.allow_fp16_reduced_precision_reduction",
        qualname="torch.backends.cuda.matmul.allow_fp16_reduced_precision_reduction",
        return_interval=None,  # Boolean
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_bool", "Returns FP16 reduction allowance"),
        ],
        setter_preconditions=[],
        setter_postconditions=[
            ("fp16_reduction_set", "FP16 reduction setting updated"),
        ],
        docstring="Allow FP16 reduced precision reductions",
    ))
    
    # torch.backends.cuda.matmul.allow_bf16_reduced_precision_reduction (property)
    registry.register(PropertyContract(
        name="torch.backends.cuda.matmul.allow_bf16_reduced_precision_reduction",
        qualname="torch.backends.cuda.matmul.allow_bf16_reduced_precision_reduction",
        return_interval=None,  # Boolean
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_bool", "Returns BF16 reduction allowance"),
        ],
        setter_preconditions=[],
        setter_postconditions=[
            ("bf16_reduction_set", "BF16 reduction setting updated"),
        ],
        docstring="Allow BF16 reduced precision reductions",
    ))
    
    # torch.backends.cuda.flash_sdp_enabled
    registry.register(FunctionContract(
        name="torch.backends.cuda.flash_sdp_enabled",
        qualname="torch.backends.cuda.flash_sdp_enabled",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns Flash Attention SDP state"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if Flash Attention SDP is enabled",
    ))
    
    # torch.backends.cuda.enable_flash_sdp
    registry.register(FunctionContract(
        name="torch.backends.cuda.enable_flash_sdp",
        qualname="torch.backends.cuda.enable_flash_sdp",
        param_names=["enabled"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("flash_sdp_set", "Flash Attention SDP state updated"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable Flash Attention SDP",
    ))
    
    # torch.backends.cuda.mem_efficient_sdp_enabled
    registry.register(FunctionContract(
        name="torch.backends.cuda.mem_efficient_sdp_enabled",
        qualname="torch.backends.cuda.mem_efficient_sdp_enabled",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns memory-efficient SDP state"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if memory-efficient SDP is enabled",
    ))
    
    # torch.backends.cuda.enable_mem_efficient_sdp
    registry.register(FunctionContract(
        name="torch.backends.cuda.enable_mem_efficient_sdp",
        qualname="torch.backends.cuda.enable_mem_efficient_sdp",
        param_names=["enabled"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("mem_efficient_sdp_set", "Memory-efficient SDP state updated"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable memory-efficient SDP",
    ))
    
    # torch.backends.cuda.math_sdp_enabled
    registry.register(FunctionContract(
        name="torch.backends.cuda.math_sdp_enabled",
        qualname="torch.backends.cuda.math_sdp_enabled",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns math SDP state"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if math SDP is enabled",
    ))
    
    # torch.backends.cuda.enable_math_sdp
    registry.register(FunctionContract(
        name="torch.backends.cuda.enable_math_sdp",
        qualname="torch.backends.cuda.enable_math_sdp",
        param_names=["enabled"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("math_sdp_set", "Math SDP state updated"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable math SDP",
    ))
    
    # torch.backends.cuda.cudnn_sdp_enabled
    registry.register(FunctionContract(
        name="torch.backends.cuda.cudnn_sdp_enabled",
        qualname="torch.backends.cuda.cudnn_sdp_enabled",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns cuDNN SDP state"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if cuDNN SDP is enabled",
    ))
    
    # torch.backends.cuda.enable_cudnn_sdp
    registry.register(FunctionContract(
        name="torch.backends.cuda.enable_cudnn_sdp",
        qualname="torch.backends.cuda.enable_cudnn_sdp",
        param_names=["enabled"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("cudnn_sdp_set", "cuDNN SDP state updated"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable cuDNN SDP",
    ))
    
    # torch.backends.cuda.preferred_linalg_library
    registry.register(FunctionContract(
        name="torch.backends.cuda.preferred_linalg_library",
        qualname="torch.backends.cuda.preferred_linalg_library",
        param_names=["backend"],
        param_intervals={},
        return_interval=None,  # Returns context manager or sets
        preconditions=[
            ("valid_backend", "backend must be valid library name"),
        ],
        postconditions=[
            ("library_set", "Linear algebra library preference set"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set preferred CUDA linear algebra library",
    ))
    
    # torch.backends.cuda.cufft_plan_cache
    registry.register(PropertyContract(
        name="torch.backends.cuda.cufft_plan_cache",
        qualname="torch.backends.cuda.cufft_plan_cache",
        return_interval=None,  # Returns cache object
        getter_preconditions=[],
        getter_postconditions=[
            ("cache_returned", "Returns cuFFT plan cache"),
        ],
        setter_preconditions=[],
        setter_postconditions=[],
        docstring="Access cuFFT plan cache for the current device",
    ))


# ============================================================================
# MKL Backend
# ============================================================================

def _register_mkl(registry: ContractRegistry) -> None:
    """Register MKL backend contracts."""
    
    # torch.backends.mkl.is_available
    registry.register(FunctionContract(
        name="torch.backends.mkl.is_available",
        qualname="torch.backends.mkl.is_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if MKL is available"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if Intel MKL is available",
    ))
    
    # torch.backends.mkl.verbose (context manager or property)
    registry.register(FunctionContract(
        name="torch.backends.mkl.verbose",
        qualname="torch.backends.mkl.verbose",
        param_names=["enable"],
        param_intervals={},
        return_interval=None,  # Context manager
        preconditions=[],
        postconditions=[
            ("verbose_set", "MKL verbose mode configured"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable MKL verbose mode",
    ))


# ============================================================================
# MKL-DNN (oneDNN) Backend
# ============================================================================

def _register_mkldnn(registry: ContractRegistry) -> None:
    """Register MKL-DNN/oneDNN backend contracts."""
    
    # torch.backends.mkldnn.is_available
    registry.register(FunctionContract(
        name="torch.backends.mkldnn.is_available",
        qualname="torch.backends.mkldnn.is_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if MKL-DNN is available"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if MKL-DNN (oneDNN) is available",
    ))
    
    # torch.backends.mkldnn.verbose (context manager or property)
    registry.register(FunctionContract(
        name="torch.backends.mkldnn.verbose",
        qualname="torch.backends.mkldnn.verbose",
        param_names=["enable"],
        param_intervals={},
        return_interval=None,  # Context manager
        preconditions=[],
        postconditions=[
            ("verbose_set", "MKL-DNN verbose mode configured"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable MKL-DNN verbose mode",
    ))


# ============================================================================
# OpenMP Backend
# ============================================================================

def _register_openmp(registry: ContractRegistry) -> None:
    """Register OpenMP backend contracts."""
    
    # torch.backends.openmp.is_available
    registry.register(FunctionContract(
        name="torch.backends.openmp.is_available",
        qualname="torch.backends.openmp.is_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if OpenMP is available"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if OpenMP is available",
    ))


# ============================================================================
# opt_einsum Backend
# ============================================================================

def _register_opt_einsum(registry: ContractRegistry) -> None:
    """Register opt_einsum backend contracts."""
    
    # torch.backends.opt_einsum.is_available
    registry.register(FunctionContract(
        name="torch.backends.opt_einsum.is_available",
        qualname="torch.backends.opt_einsum.is_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if opt_einsum is available"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if opt_einsum is available",
    ))
    
    # torch.backends.opt_einsum.enabled (property)
    registry.register(PropertyContract(
        name="torch.backends.opt_einsum.enabled",
        qualname="torch.backends.opt_einsum.enabled",
        return_interval=None,  # Boolean
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_bool", "Returns current enabled state"),
        ],
        setter_preconditions=[],
        setter_postconditions=[
            ("enabled_set", "opt_einsum enabled state updated"),
        ],
        docstring="Enable/disable opt_einsum for einsum operations",
    ))
    
    # torch.backends.opt_einsum.strategy (property)
    registry.register(PropertyContract(
        name="torch.backends.opt_einsum.strategy",
        qualname="torch.backends.opt_einsum.strategy",
        return_interval=None,  # String
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_str", "Returns current optimization strategy"),
        ],
        setter_preconditions=[
            ("valid_strategy", "Strategy must be valid opt_einsum strategy"),
        ],
        setter_postconditions=[
            ("strategy_set", "Optimization strategy updated"),
        ],
        docstring="Get/set opt_einsum optimization strategy",
    ))


# ============================================================================
# MPS Backend (Apple Silicon)
# ============================================================================

def _register_mps(registry: ContractRegistry) -> None:
    """Register MPS (Metal Performance Shaders) backend contracts."""
    
    # torch.backends.mps.is_available
    registry.register(FunctionContract(
        name="torch.backends.mps.is_available",
        qualname="torch.backends.mps.is_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if MPS is available"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if MPS (Apple Silicon) is available",
    ))
    
    # torch.backends.mps.is_built
    registry.register(FunctionContract(
        name="torch.backends.mps.is_built",
        qualname="torch.backends.mps.is_built",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if PyTorch built with MPS"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if PyTorch was built with MPS support",
    ))


# ============================================================================
# Quantized Backend
# ============================================================================

def _register_quantized(registry: ContractRegistry) -> None:
    """Register quantized backend contracts."""
    
    # torch.backends.quantized.engine (property)
    registry.register(PropertyContract(
        name="torch.backends.quantized.engine",
        qualname="torch.backends.quantized.engine",
        return_interval=None,  # String
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_str", "Returns current quantized engine"),
        ],
        setter_preconditions=[
            ("valid_engine", "Engine must be valid (fbgemm, qnnpack, onednn, x86)"),
        ],
        setter_postconditions=[
            ("engine_set", "Quantized engine updated"),
        ],
        docstring="Get/set quantized computation engine",
    ))
    
    # torch.backends.quantized.supported_engines
    registry.register(PropertyContract(
        name="torch.backends.quantized.supported_engines",
        qualname="torch.backends.quantized.supported_engines",
        return_interval=None,  # List of strings
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_list", "Returns list of supported engines"),
        ],
        setter_preconditions=[],
        setter_postconditions=[],
        docstring="Get list of supported quantized engines",
    ))


# ============================================================================
# CPU Backend
# ============================================================================

def _register_cpu(registry: ContractRegistry) -> None:
    """Register CPU backend contracts."""
    
    # torch.cpu.is_available
    registry.register(FunctionContract(
        name="torch.cpu.is_available",
        qualname="torch.cpu.is_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean (always True)
        preconditions=[],
        postconditions=[
            ("always_true", "CPU is always available"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if CPU is available (always True)",
    ))
    
    # torch.cpu.current_device
    registry.register(FunctionContract(
        name="torch.cpu.current_device",
        qualname="torch.cpu.current_device",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, 0),  # Always 0 for CPU
        preconditions=[],
        postconditions=[
            ("returns_zero", "Returns 0 (CPU has one device)"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get current CPU device (always 0)",
    ))
    
    # torch.cpu.device_count
    registry.register(FunctionContract(
        name="torch.cpu.device_count",
        qualname="torch.cpu.device_count",
        param_names=[],
        param_intervals={},
        return_interval=Interval(1, 1),  # Always 1 for CPU
        preconditions=[],
        postconditions=[
            ("returns_one", "Returns 1 (one CPU device)"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get CPU device count (always 1)",
    ))
    
    # torch.cpu.synchronize
    registry.register(FunctionContract(
        name="torch.cpu.synchronize",
        qualname="torch.cpu.synchronize",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("synchronized", "CPU operations synchronized (no-op)"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Synchronize CPU operations (no-op for CPU)",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_backends_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.backends.* contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_cudnn(registry)
    _register_cuda_backend(registry)
    _register_mkl(registry)
    _register_mkldnn(registry)
    _register_openmp(registry)
    _register_opt_einsum(registry)
    _register_mps(registry)
    _register_quantized(registry)
    _register_cpu(registry)


# Export
__all__ = [
    "register_backends_contracts",
]
