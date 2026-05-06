"""
PyTorch XLA and Accelerator Contracts

This module provides contracts for:
- torch_xla (TPU/XLA support)
- torch.xpu (Intel XPU/GPU)
- torch.mtia (Meta Training and Inference Accelerator)
- torch.maia (Microsoft AI Accelerator)
- torch.privateuseone (custom accelerator backend)

Device Barrier Considerations:
- Different accelerators have distinct device types
- Cross-device operations require explicit transfers
- Each accelerator has specific memory constraints
"""

from typing import Dict, List, Any, Optional
from ..intervals import Interval
from ..contracts import (
    ContractRegistry,
    FunctionContract,
    MethodContract,
    ModuleContract,
    PropertyContract,
)


# ============================================================================
# torch.xpu - Intel XPU (GPU) Support
# ============================================================================

def _register_xpu(registry: ContractRegistry) -> None:
    """Register Intel XPU contracts."""
    
    # torch.xpu.is_available
    registry.register(FunctionContract(
        name="torch.xpu.is_available",
        qualname="torch.xpu.is_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if XPU is available"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if Intel XPU is available",
    ))
    
    # torch.xpu.device_count
    registry.register(FunctionContract(
        name="torch.xpu.device_count",
        qualname="torch.xpu.device_count",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[
            ("count_returned", "Returns number of XPU devices"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get number of Intel XPU devices",
    ))
    
    # torch.xpu.current_device
    registry.register(FunctionContract(
        name="torch.xpu.current_device",
        qualname="torch.xpu.current_device",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[
            ("xpu_available", "XPU must be available"),
        ],
        postconditions=[
            ("device_returned", "Returns current XPU device index"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Get current XPU device",
    ))
    
    # torch.xpu.set_device
    registry.register(FunctionContract(
        name="torch.xpu.set_device",
        qualname="torch.xpu.set_device",
        param_names=["device"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_device", "device must be valid XPU device"),
        ],
        postconditions=[
            ("device_set", "Current XPU device changed"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set current XPU device",
    ))
    
    # torch.xpu.synchronize
    registry.register(FunctionContract(
        name="torch.xpu.synchronize",
        qualname="torch.xpu.synchronize",
        param_names=["device"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("synchronized", "XPU operations completed"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Synchronize XPU operations",
    ))
    
    # torch.xpu.empty_cache
    registry.register(FunctionContract(
        name="torch.xpu.empty_cache",
        qualname="torch.xpu.empty_cache",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("cache_emptied", "XPU memory cache released"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Release unused XPU memory",
    ))
    
    # torch.xpu.memory_allocated
    registry.register(FunctionContract(
        name="torch.xpu.memory_allocated",
        qualname="torch.xpu.memory_allocated",
        param_names=["device"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[
            ("bytes_returned", "Returns allocated memory in bytes"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get allocated XPU memory",
    ))
    
    # torch.xpu.max_memory_allocated
    registry.register(FunctionContract(
        name="torch.xpu.max_memory_allocated",
        qualname="torch.xpu.max_memory_allocated",
        param_names=["device"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[
            ("max_bytes", "Returns peak allocated memory"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get peak XPU memory allocation",
    ))
    
    # torch.xpu.reset_peak_memory_stats
    registry.register(FunctionContract(
        name="torch.xpu.reset_peak_memory_stats",
        qualname="torch.xpu.reset_peak_memory_stats",
        param_names=["device"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("stats_reset", "Peak memory stats reset"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Reset XPU peak memory stats",
    ))


# ============================================================================
# torch_xla (TPU Support)
# ============================================================================

def _register_xla(registry: ContractRegistry) -> None:
    """Register torch_xla contracts (TPU support)."""
    
    # torch_xla.core.xla_model.xla_device
    registry.register(FunctionContract(
        name="torch_xla.core.xla_model.xla_device",
        qualname="torch_xla.core.xla_model.xla_device",
        param_names=["n", "devkind"],
        param_intervals={},
        return_interval=None,  # Returns device
        preconditions=[],
        postconditions=[
            ("device_returned", "Returns XLA device"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Get XLA (TPU) device",
    ))
    
    # torch_xla.core.xla_model.get_ordinal
    registry.register(FunctionContract(
        name="torch_xla.core.xla_model.get_ordinal",
        qualname="torch_xla.core.xla_model.get_ordinal",
        param_names=["defval"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[
            ("ordinal_returned", "Returns device ordinal"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get XLA device ordinal",
    ))
    
    # torch_xla.core.xla_model.all_reduce
    registry.register(FunctionContract(
        name="torch_xla.core.xla_model.all_reduce",
        qualname="torch_xla.core.xla_model.all_reduce",
        param_names=["reduce_type", "inputs", "scale", "groups", "pin_layout"],
        param_intervals={},
        return_interval=None,  # Returns reduced tensors
        preconditions=[],
        postconditions=[
            ("reduced", "All-reduce operation completed"),
        ],
        requires_same_device=True,  # All inputs same XLA device
        may_raise=["RuntimeError"],
        docstring="Perform XLA all-reduce",
    ))
    
    # torch_xla.core.xla_model.mark_step
    registry.register(FunctionContract(
        name="torch_xla.core.xla_model.mark_step",
        qualname="torch_xla.core.xla_model.mark_step",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("step_marked", "XLA compilation/execution triggered"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Mark step for XLA compilation",
    ))
    
    # torch_xla.core.xla_model.optimizer_step
    registry.register(FunctionContract(
        name="torch_xla.core.xla_model.optimizer_step",
        qualname="torch_xla.core.xla_model.optimizer_step",
        param_names=["optimizer", "barrier", "optimizer_args", "groups", "pin_layout"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("step_completed", "Optimizer step with gradient sync"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="XLA optimizer step with gradient sync",
    ))
    
    # torch_xla.core.xla_model.save
    registry.register(FunctionContract(
        name="torch_xla.core.xla_model.save",
        qualname="torch_xla.core.xla_model.save",
        param_names=["data", "file_or_path", "master_only", "global_master"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("saved", "Data saved from XLA device"),
        ],
        requires_same_device=False,
        may_raise=["IOError"],
        docstring="Save data from XLA device",
    ))
    
    # torch_xla.core.xla_model.xrt_world_size
    registry.register(FunctionContract(
        name="torch_xla.core.xla_model.xrt_world_size",
        qualname="torch_xla.core.xla_model.xrt_world_size",
        param_names=["defval"],
        param_intervals={},
        return_interval=Interval(1, float('inf')),
        preconditions=[],
        postconditions=[
            ("world_size", "Returns XRT world size"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get XRT distributed world size",
    ))
    
    # torch_xla.debug.metrics.metrics_report
    registry.register(FunctionContract(
        name="torch_xla.debug.metrics.metrics_report",
        qualname="torch_xla.debug.metrics.metrics_report",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[],
        postconditions=[
            ("report_generated", "XLA metrics report generated"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get XLA performance metrics report",
    ))


# ============================================================================  
# Private Use One (Custom Backend)
# ============================================================================

def _register_privateuseone(registry: ContractRegistry) -> None:
    """Register PrivateUse1 custom backend contracts."""
    
    # torch._register_device_module
    registry.register(FunctionContract(
        name="torch._register_device_module",
        qualname="torch._register_device_module",
        param_names=["device_type", "module"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_device_type", "device_type must be valid"),
        ],
        postconditions=[
            ("module_registered", "Device module registered"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Register custom device module",
    ))
    
    # torch.utils.rename_privateuse1_backend
    registry.register(FunctionContract(
        name="torch.utils.rename_privateuse1_backend",
        qualname="torch.utils.rename_privateuse1_backend",
        param_names=["backend_name"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_name", "backend_name must be valid identifier"),
        ],
        postconditions=[
            ("renamed", "PrivateUse1 backend renamed"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Rename PrivateUse1 backend",
    ))
    
    # torch.utils.generate_methods_for_privateuse1_backend
    registry.register(FunctionContract(
        name="torch.utils.generate_methods_for_privateuse1_backend",
        qualname="torch.utils.generate_methods_for_privateuse1_backend",
        param_names=["for_tensor", "for_module", "for_storage"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("methods_generated", "Backend methods generated"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Generate methods for custom backend",
    ))


# ============================================================================
# Meta/Fake Tensor Support
# ============================================================================

def _register_meta(registry: ContractRegistry) -> None:
    """Register meta/fake tensor contracts."""
    
    # torch.empty on meta device
    registry.register(FunctionContract(
        name="torch.empty_meta",
        qualname="torch.empty",
        param_names=["*size", "out", "dtype", "layout", "device", "requires_grad",
                    "pin_memory", "memory_format"],
        param_intervals={},
        return_interval=None,  # Returns meta tensor
        preconditions=[
            ("device_meta", "device must be 'meta'"),
        ],
        postconditions=[
            ("meta_created", "Meta tensor created (no storage)"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create tensor on meta device (no storage)",
    ))
    
    # torch._subclasses.FakeTensor
    registry.register(ModuleContract(
        name="torch._subclasses.FakeTensor",
        qualname="torch._subclasses.FakeTensor",
        init_param_names=["fake_mode", "elem", "device", "constant"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("no_storage", "FakeTensor has no actual storage"),
        ],
        docstring="Fake tensor for tracing without data",
    ))
    
    # torch._subclasses.FakeTensorMode
    registry.register(ModuleContract(
        name="torch._subclasses.FakeTensorMode",
        qualname="torch._subclasses.FakeTensorMode",
        init_param_names=["allow_non_fake_inputs", "allow_fallback_kernels",
                         "shape_env", "static_shapes"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("mode_active", "FakeTensor mode configuration"),
        ],
        docstring="Context manager for fake tensor mode",
    ))
    
    # torch.device("meta")
    registry.register(FunctionContract(
        name="torch.device_meta",
        qualname="torch.device",
        param_names=["type", "index"],
        param_intervals={},
        return_interval=None,  # Returns device
        preconditions=[],
        postconditions=[
            ("meta_device", "Returns meta device"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create meta device object",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_accelerator_contracts(registry: ContractRegistry) -> None:
    """
    Register all accelerator-related contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_xpu(registry)
    _register_xla(registry)
    _register_privateuseone(registry)
    _register_meta(registry)


# Export
__all__ = [
    "register_accelerator_contracts",
]
