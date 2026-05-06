"""
PyTorch AMP Contracts - torch.amp (Automatic Mixed Precision)

This module provides contracts for PyTorch's automatic mixed precision:
- torch.amp.autocast
- torch.amp.GradScaler
- Precision and scaling operations

Device Barrier Considerations:
- AMP is typically used with CUDA devices
- autocast context applies to operations within scope
- GradScaler handles gradient scaling for mixed precision
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
# torch.amp.autocast
# ============================================================================

def _register_autocast(registry: ContractRegistry) -> None:
    """Register autocast contracts."""
    
    # torch.amp.autocast (context manager)
    registry.register(ModuleContract(
        name="torch.amp.autocast",
        qualname="torch.amp.autocast",
        init_param_names=["device_type", "dtype", "enabled", "cache_enabled"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("context_configured", "Autocast context is configured"),
        ],
        docstring="Context manager for automatic mixed precision",
    ))
    
    # autocast.__enter__
    registry.register(MethodContract(
        name="torch.amp.autocast.__enter__",
        qualname="torch.amp.autocast.__enter__",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("autocast_enabled", "Autocast is now enabled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enter autocast context",
    ))
    
    # autocast.__exit__
    registry.register(MethodContract(
        name="torch.amp.autocast.__exit__",
        qualname="torch.amp.autocast.__exit__",
        param_names=["self", "exc_type", "exc_val", "exc_tb"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("autocast_restored", "Previous autocast state restored"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Exit autocast context",
    ))
    
    # torch.amp.custom_fwd
    registry.register(FunctionContract(
        name="torch.amp.custom_fwd",
        qualname="torch.amp.custom_fwd",
        param_names=["fwd", "device_type", "cast_inputs"],
        param_intervals={},
        return_interval=None,  # Decorator
        preconditions=[],
        postconditions=[
            ("decorator_returned", "Returns decorated forward function"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Decorator for custom autograd function forward",
    ))
    
    # torch.amp.custom_bwd
    registry.register(FunctionContract(
        name="torch.amp.custom_bwd",
        qualname="torch.amp.custom_bwd",
        param_names=["bwd", "device_type"],
        param_intervals={},
        return_interval=None,  # Decorator
        preconditions=[],
        postconditions=[
            ("decorator_returned", "Returns decorated backward function"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Decorator for custom autograd function backward",
    ))
    
    # torch.cuda.amp.autocast (legacy alias)
    registry.register(ModuleContract(
        name="torch.cuda.amp.autocast",
        qualname="torch.cuda.amp.autocast",
        init_param_names=["enabled", "dtype", "cache_enabled"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("cuda_autocast", "CUDA autocast context"),
        ],
        docstring="Legacy CUDA autocast context manager",
    ))
    
    # torch.cpu.amp.autocast
    registry.register(ModuleContract(
        name="torch.cpu.amp.autocast",
        qualname="torch.cpu.amp.autocast",
        init_param_names=["enabled", "dtype", "cache_enabled"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("cpu_autocast", "CPU autocast context"),
        ],
        docstring="CPU autocast context manager (for bfloat16)",
    ))
    
    # torch.is_autocast_enabled
    registry.register(FunctionContract(
        name="torch.is_autocast_enabled",
        qualname="torch.is_autocast_enabled",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if CUDA autocast enabled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if CUDA autocast is enabled",
    ))
    
    # torch.is_autocast_cpu_enabled
    registry.register(FunctionContract(
        name="torch.is_autocast_cpu_enabled",
        qualname="torch.is_autocast_cpu_enabled",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if CPU autocast enabled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if CPU autocast is enabled",
    ))
    
    # torch.get_autocast_dtype
    registry.register(FunctionContract(
        name="torch.get_autocast_dtype",
        qualname="torch.get_autocast_dtype",
        param_names=["device_type"],
        param_intervals={},
        return_interval=None,  # dtype
        preconditions=[],
        postconditions=[
            ("dtype_returned", "Returns current autocast dtype"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get current autocast dtype for device type",
    ))
    
    # torch.set_autocast_dtype
    registry.register(FunctionContract(
        name="torch.set_autocast_dtype",
        qualname="torch.set_autocast_dtype",
        param_names=["device_type", "dtype"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_dtype", "dtype must be valid autocast dtype"),
        ],
        postconditions=[
            ("dtype_set", "Autocast dtype updated"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set autocast dtype for device type",
    ))
    
    # torch.autocast_increment_nesting
    registry.register(FunctionContract(
        name="torch.autocast_increment_nesting",
        qualname="torch.autocast_increment_nesting",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, float('inf')),  # Returns nesting level
        preconditions=[],
        postconditions=[
            ("nesting_incremented", "Autocast nesting level increased"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Increment autocast nesting counter",
    ))
    
    # torch.autocast_decrement_nesting
    registry.register(FunctionContract(
        name="torch.autocast_decrement_nesting",
        qualname="torch.autocast_decrement_nesting",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[
            ("positive_nesting", "Nesting level must be positive"),
        ],
        postconditions=[
            ("nesting_decremented", "Autocast nesting level decreased"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Decrement autocast nesting counter",
    ))
    
    # torch.clear_autocast_cache
    registry.register(FunctionContract(
        name="torch.clear_autocast_cache",
        qualname="torch.clear_autocast_cache",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("cache_cleared", "Autocast cache cleared"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Clear autocast weight cache",
    ))


# ============================================================================
# torch.amp.GradScaler (and torch.cuda.amp.GradScaler)
# ============================================================================

def _register_grad_scaler(registry: ContractRegistry) -> None:
    """Register GradScaler contracts."""
    
    # torch.amp.GradScaler
    registry.register(ModuleContract(
        name="torch.amp.GradScaler",
        qualname="torch.amp.GradScaler",
        init_param_names=["device", "init_scale", "growth_factor", "backoff_factor",
                         "growth_interval", "enabled"],
        init_param_intervals={
            "init_scale": Interval(0.0, float('inf')),
            "growth_factor": Interval(1.0, float('inf')),
            "backoff_factor": Interval(0.0, 1.0),
            "growth_interval": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("scale_positive", "Current scale is positive"),
        ],
        docstring="Gradient scaler for mixed precision training",
    ))
    
    # GradScaler.scale
    registry.register(MethodContract(
        name="torch.amp.GradScaler.scale",
        qualname="torch.amp.GradScaler.scale",
        param_names=["self", "outputs"],
        param_intervals={},
        return_interval=None,  # Returns scaled outputs
        preconditions=[],
        postconditions=[
            ("outputs_scaled", "Outputs multiplied by current scale"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Scale loss or outputs for mixed precision",
    ))
    
    # GradScaler.unscale_
    registry.register(MethodContract(
        name="torch.amp.GradScaler.unscale_",
        qualname="torch.amp.GradScaler.unscale_",
        param_names=["self", "optimizer"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("not_already_unscaled", "Gradients not already unscaled"),
        ],
        postconditions=[
            ("gradients_unscaled", "Gradients divided by scale"),
            ("infs_detected", "Infinite gradients detected"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Unscale gradients in optimizer params",
    ))
    
    # GradScaler.step
    registry.register(MethodContract(
        name="torch.amp.GradScaler.step",
        qualname="torch.amp.GradScaler.step",
        param_names=["self", "optimizer", "*args", "**kwargs"],
        param_intervals={},
        return_interval=None,  # Optional return from optimizer.step
        preconditions=[],
        postconditions=[
            ("step_completed", "Optimizer step executed if gradients valid"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Step optimizer if gradients are valid",
    ))
    
    # GradScaler.update
    registry.register(MethodContract(
        name="torch.amp.GradScaler.update",
        qualname="torch.amp.GradScaler.update",
        param_names=["self", "new_scale"],
        param_intervals={
            "new_scale": Interval(0.0, float('inf')),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("scale_updated", "Scale updated based on gradient validity"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Update scale based on gradient status",
    ))
    
    # GradScaler.get_scale
    registry.register(MethodContract(
        name="torch.amp.GradScaler.get_scale",
        qualname="torch.amp.GradScaler.get_scale",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0.0, float('inf')),
        preconditions=[],
        postconditions=[
            ("scale_returned", "Returns current scale value"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get current scale value",
    ))
    
    # GradScaler.get_growth_factor
    registry.register(MethodContract(
        name="torch.amp.GradScaler.get_growth_factor",
        qualname="torch.amp.GradScaler.get_growth_factor",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(1.0, float('inf')),
        preconditions=[],
        postconditions=[
            ("factor_returned", "Returns growth factor"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get growth factor",
    ))
    
    # GradScaler.set_growth_factor
    registry.register(MethodContract(
        name="torch.amp.GradScaler.set_growth_factor",
        qualname="torch.amp.GradScaler.set_growth_factor",
        param_names=["self", "new_factor"],
        param_intervals={
            "new_factor": Interval(1.0, float('inf')),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("factor_set", "Growth factor updated"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Set growth factor",
    ))
    
    # GradScaler.get_backoff_factor
    registry.register(MethodContract(
        name="torch.amp.GradScaler.get_backoff_factor",
        qualname="torch.amp.GradScaler.get_backoff_factor",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0.0, 1.0),
        preconditions=[],
        postconditions=[
            ("factor_returned", "Returns backoff factor"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get backoff factor",
    ))
    
    # GradScaler.set_backoff_factor
    registry.register(MethodContract(
        name="torch.amp.GradScaler.set_backoff_factor",
        qualname="torch.amp.GradScaler.set_backoff_factor",
        param_names=["self", "new_factor"],
        param_intervals={
            "new_factor": Interval(0.0, 1.0),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("factor_set", "Backoff factor updated"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Set backoff factor",
    ))
    
    # GradScaler.get_growth_interval
    registry.register(MethodContract(
        name="torch.amp.GradScaler.get_growth_interval",
        qualname="torch.amp.GradScaler.get_growth_interval",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(1, float('inf')),
        preconditions=[],
        postconditions=[
            ("interval_returned", "Returns growth interval"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get growth interval",
    ))
    
    # GradScaler.set_growth_interval
    registry.register(MethodContract(
        name="torch.amp.GradScaler.set_growth_interval",
        qualname="torch.amp.GradScaler.set_growth_interval",
        param_names=["self", "new_interval"],
        param_intervals={
            "new_interval": Interval(1, float('inf')),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("interval_set", "Growth interval updated"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Set growth interval",
    ))
    
    # GradScaler.is_enabled
    registry.register(MethodContract(
        name="torch.amp.GradScaler.is_enabled",
        qualname="torch.amp.GradScaler.is_enabled",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns enabled state"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if scaler is enabled",
    ))
    
    # GradScaler.state_dict
    registry.register(MethodContract(
        name="torch.amp.GradScaler.state_dict",
        qualname="torch.amp.GradScaler.state_dict",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns dict
        preconditions=[],
        postconditions=[
            ("state_returned", "Returns scaler state dictionary"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get scaler state dictionary",
    ))
    
    # GradScaler.load_state_dict
    registry.register(MethodContract(
        name="torch.amp.GradScaler.load_state_dict",
        qualname="torch.amp.GradScaler.load_state_dict",
        param_names=["self", "state_dict"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_state", "state_dict must be valid scaler state"),
        ],
        postconditions=[
            ("state_loaded", "Scaler state restored"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Load scaler state from dictionary",
    ))
    
    # torch.cuda.amp.GradScaler (legacy alias)
    registry.register(ModuleContract(
        name="torch.cuda.amp.GradScaler",
        qualname="torch.cuda.amp.GradScaler",
        init_param_names=["init_scale", "growth_factor", "backoff_factor",
                         "growth_interval", "enabled"],
        init_param_intervals={
            "init_scale": Interval(0.0, float('inf')),
            "growth_factor": Interval(1.0, float('inf')),
            "backoff_factor": Interval(0.0, 1.0),
            "growth_interval": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("cuda_scaler", "CUDA-specific gradient scaler"),
        ],
        docstring="Legacy CUDA gradient scaler",
    ))


# ============================================================================
# Precision Utilities
# ============================================================================

def _register_precision_utils(registry: ContractRegistry) -> None:
    """Register precision utility contracts."""
    
    # torch.set_float32_matmul_precision
    registry.register(FunctionContract(
        name="torch.set_float32_matmul_precision",
        qualname="torch.set_float32_matmul_precision",
        param_names=["precision"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_precision", "precision must be 'highest', 'high', or 'medium'"),
        ],
        postconditions=[
            ("precision_set", "Matmul precision updated"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set float32 matrix multiplication precision",
    ))
    
    # torch.get_float32_matmul_precision
    registry.register(FunctionContract(
        name="torch.get_float32_matmul_precision",
        qualname="torch.get_float32_matmul_precision",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[],
        postconditions=[
            ("precision_returned", "Returns current matmul precision"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get float32 matrix multiplication precision",
    ))
    
    # torch.use_deterministic_algorithms
    registry.register(FunctionContract(
        name="torch.use_deterministic_algorithms",
        qualname="torch.use_deterministic_algorithms",
        param_names=["mode", "warn_only"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("determinism_set", "Deterministic algorithm mode configured"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable deterministic algorithms",
    ))
    
    # torch.are_deterministic_algorithms_enabled
    registry.register(FunctionContract(
        name="torch.are_deterministic_algorithms_enabled",
        qualname="torch.are_deterministic_algorithms_enabled",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns deterministic mode status"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if deterministic algorithms are enabled",
    ))
    
    # torch.is_deterministic_algorithms_warn_only_enabled
    registry.register(FunctionContract(
        name="torch.is_deterministic_algorithms_warn_only_enabled",
        qualname="torch.is_deterministic_algorithms_warn_only_enabled",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns warn_only status"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if deterministic algorithms warn-only mode",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_amp_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.amp contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_autocast(registry)
    _register_grad_scaler(registry)
    _register_precision_utils(registry)


# Export
__all__ = [
    "register_amp_contracts",
]
