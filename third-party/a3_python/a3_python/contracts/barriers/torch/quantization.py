"""
PyTorch Quantization Contracts - torch.quantization / torch.ao.quantization

This module provides contracts for PyTorch's quantization toolkit:
- Quantization observers
- Quantization-aware training (QAT)
- Post-training quantization (PTQ)
- Quantized operations
- FX graph mode quantization

Device Barrier Considerations:
- Quantized models typically run on CPU
- Some quantized backends support CUDA (but with limitations)
- Observer and FakeQuantize modules track statistics on the same device
- Quantized tensors have specific dtype requirements
"""

from typing import Dict, List, Any, Optional, Callable
from ..intervals import Interval
from ..contracts import (
    ContractRegistry,
    FunctionContract,
    MethodContract,
    ModuleContract,
)


# ============================================================================
# Observers
# ============================================================================

def _register_observers(registry: ContractRegistry) -> None:
    """Register quantization observer contracts."""
    
    # ObserverBase
    registry.register(ModuleContract(
        name="torch.quantization.ObserverBase",
        qualname="torch.quantization.ObserverBase",
        init_param_names=["dtype"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("statistics_tracked", "Tracks min/max or histogram"),
        ],
        docstring="Base class for quantization observers",
    ))
    
    # MinMaxObserver
    registry.register(ModuleContract(
        name="torch.quantization.MinMaxObserver",
        qualname="torch.quantization.MinMaxObserver",
        init_param_names=["dtype", "qscheme", "reduce_range", "quant_min", "quant_max"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("min_val", "Tracks minimum observed value"),
            ("max_val", "Tracks maximum observed value"),
        ],
        docstring="Observer using running min/max",
    ))
    
    # MovingAverageMinMaxObserver
    registry.register(ModuleContract(
        name="torch.quantization.MovingAverageMinMaxObserver",
        qualname="torch.quantization.MovingAverageMinMaxObserver",
        init_param_names=["averaging_constant", "dtype", "qscheme", "reduce_range",
                         "quant_min", "quant_max"],
        init_param_intervals={
            "averaging_constant": Interval(0.0, 1.0),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("ema_min_max", "Exponential moving average of min/max"),
        ],
        docstring="Observer using moving average min/max",
    ))
    
    # PerChannelMinMaxObserver
    registry.register(ModuleContract(
        name="torch.quantization.PerChannelMinMaxObserver",
        qualname="torch.quantization.PerChannelMinMaxObserver",
        init_param_names=["ch_axis", "dtype", "qscheme", "reduce_range",
                         "quant_min", "quant_max"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("per_channel_stats", "Stats tracked per channel"),
        ],
        docstring="Per-channel min/max observer",
    ))
    
    # HistogramObserver
    registry.register(ModuleContract(
        name="torch.quantization.HistogramObserver",
        qualname="torch.quantization.HistogramObserver",
        init_param_names=["bins", "upsample_rate", "dtype", "qscheme", "reduce_range"],
        init_param_intervals={
            "bins": Interval(1, float('inf')),
            "upsample_rate": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("histogram", "Maintains histogram of values"),
        ],
        docstring="Observer using histogram for better accuracy",
    ))
    
    # Observer.calculate_qparams
    registry.register(MethodContract(
        name="torch.quantization.ObserverBase.calculate_qparams",
        qualname="torch.quantization.ObserverBase.calculate_qparams",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns (scale, zero_point)
        preconditions=[
            ("has_stats", "Observer must have collected statistics"),
        ],
        postconditions=[
            ("qparams_computed", "Returns scale and zero_point tensors"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Calculate quantization parameters from statistics",
    ))


# ============================================================================
# Fake Quantization
# ============================================================================

def _register_fake_quantize(registry: ContractRegistry) -> None:
    """Register fake quantization contracts."""
    
    # FakeQuantize
    registry.register(ModuleContract(
        name="torch.quantization.FakeQuantize",
        qualname="torch.quantization.FakeQuantize",
        init_param_names=["observer", "quant_min", "quant_max", "observer_kwargs"],
        init_param_intervals={},
        forward_return_interval=None,  # Same interval as input (simulated quant)
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("fake_quant", "Simulates quantization during training"),
            ("observer_attached", "Has observer for statistics"),
        ],
        docstring="Fake quantization module for QAT",
    ))
    
    # FakeQuantize.forward
    registry.register(MethodContract(
        name="torch.quantization.FakeQuantize.forward",
        qualname="torch.quantization.FakeQuantize.forward",
        param_names=["self", "X"],
        param_intervals={},
        return_interval=None,  # Quantized then dequantized
        preconditions=[],
        postconditions=[
            ("simulated_quant", "Output simulates quantization effects"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Apply fake quantization",
    ))
    
    # FakeQuantizeBase.enable_observer
    registry.register(MethodContract(
        name="torch.quantization.FakeQuantize.enable_observer",
        qualname="torch.quantization.FakeQuantize.enable_observer",
        param_names=["self", "enabled"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("observer_state", "Observer enabled/disabled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable observer",
    ))
    
    # FakeQuantizeBase.enable_fake_quant
    registry.register(MethodContract(
        name="torch.quantization.FakeQuantize.enable_fake_quant",
        qualname="torch.quantization.FakeQuantize.enable_fake_quant",
        param_names=["self", "enabled"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("fake_quant_state", "Fake quantization enabled/disabled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable fake quantization",
    ))


# ============================================================================
# QConfig
# ============================================================================

def _register_qconfig(registry: ContractRegistry) -> None:
    """Register QConfig contracts."""
    
    # QConfig
    registry.register(FunctionContract(
        name="torch.quantization.QConfig",
        qualname="torch.quantization.QConfig",
        param_names=["activation", "weight"],
        param_intervals={},
        return_interval=None,  # Returns QConfig namedtuple
        preconditions=[
            ("valid_activation", "activation must be observer/fakequant constructor"),
            ("valid_weight", "weight must be observer/fakequant constructor"),
        ],
        postconditions=[
            ("qconfig_created", "Returns QConfig for quantization"),
        ],
        requires_same_device=False,
        may_raise=["TypeError"],
        docstring="Create quantization configuration",
    ))
    
    # QConfigMapping (for FX)
    registry.register(ModuleContract(
        name="torch.ao.quantization.QConfigMapping",
        qualname="torch.ao.quantization.QConfigMapping",
        init_param_names=[],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("mapping", "Maps module types/names to QConfigs"),
        ],
        docstring="Mapping of modules to their QConfigs",
    ))
    
    # Default QConfigs
    registry.register(FunctionContract(
        name="torch.quantization.get_default_qconfig",
        qualname="torch.quantization.get_default_qconfig",
        param_names=["backend"],
        param_intervals={},
        return_interval=None,  # Returns QConfig
        preconditions=[
            ("valid_backend", "backend must be 'fbgemm', 'qnnpack', or 'onednn'"),
        ],
        postconditions=[
            ("default_qconfig", "Returns default QConfig for backend"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Get default QConfig for backend",
    ))
    
    registry.register(FunctionContract(
        name="torch.quantization.get_default_qat_qconfig",
        qualname="torch.quantization.get_default_qat_qconfig",
        param_names=["backend"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_backend", "backend must be 'fbgemm', 'qnnpack', or 'onednn'"),
        ],
        postconditions=[
            ("qat_qconfig", "Returns default QAT QConfig"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Get default QAT QConfig for backend",
    ))


# ============================================================================
# Quantization Workflow
# ============================================================================

def _register_workflow(registry: ContractRegistry) -> None:
    """Register quantization workflow contracts."""
    
    # prepare
    registry.register(FunctionContract(
        name="torch.quantization.prepare",
        qualname="torch.quantization.prepare",
        param_names=["model", "inplace", "allow_list", "observer_non_leaf_module_list",
                    "prepare_custom_config_dict"],
        param_intervals={},
        return_interval=None,  # Returns prepared model
        preconditions=[
            ("has_qconfig", "Model must have qconfig attribute set"),
        ],
        postconditions=[
            ("observers_inserted", "Observers inserted for calibration"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Prepare model for post-training quantization",
    ))
    
    # prepare_qat
    registry.register(FunctionContract(
        name="torch.quantization.prepare_qat",
        qualname="torch.quantization.prepare_qat",
        param_names=["model", "mapping", "inplace"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("has_qconfig", "Model must have qconfig"),
            ("train_mode", "Model should be in train mode"),
        ],
        postconditions=[
            ("qat_prepared", "FakeQuantize modules inserted"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Prepare model for quantization-aware training",
    ))
    
    # convert
    registry.register(FunctionContract(
        name="torch.quantization.convert",
        qualname="torch.quantization.convert",
        param_names=["module", "mapping", "inplace", "remove_qconfig",
                    "convert_custom_config_dict"],
        param_intervals={},
        return_interval=None,  # Returns quantized model
        preconditions=[
            ("prepared", "Model must be prepared with observers"),
            ("calibrated", "Observers should have calibration data"),
        ],
        postconditions=[
            ("quantized", "Model converted to quantized version"),
        ],
        requires_same_device=False,  # Usually moves to CPU
        may_raise=["RuntimeError"],
        docstring="Convert prepared model to quantized model",
    ))
    
    # quantize
    registry.register(FunctionContract(
        name="torch.quantization.quantize",
        qualname="torch.quantization.quantize",
        param_names=["model", "run_fn", "run_args", "mapping", "inplace"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("has_qconfig", "Model must have qconfig"),
        ],
        postconditions=[
            ("fully_quantized", "Model is fully quantized"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Quantize model (prepare + calibrate + convert)",
    ))
    
    # quantize_dynamic
    registry.register(FunctionContract(
        name="torch.quantization.quantize_dynamic",
        qualname="torch.quantization.quantize_dynamic",
        param_names=["model", "qconfig_spec", "dtype", "mapping", "inplace"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("dynamically_quantized", "Model uses dynamic quantization"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Apply dynamic quantization to model",
    ))
    
    # quantize_qat
    registry.register(FunctionContract(
        name="torch.quantization.quantize_qat",
        qualname="torch.quantization.quantize_qat",
        param_names=["model", "run_fn", "run_args", "inplace"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("has_qconfig", "Model must have qconfig"),
        ],
        postconditions=[
            ("qat_complete", "Model trained with QAT and converted"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Complete QAT workflow",
    ))


# ============================================================================
# FX Graph Mode Quantization
# ============================================================================

def _register_fx_quantization(registry: ContractRegistry) -> None:
    """Register FX graph mode quantization contracts."""
    
    # prepare_fx
    registry.register(FunctionContract(
        name="torch.ao.quantization.quantize_fx.prepare_fx",
        qualname="torch.ao.quantization.quantize_fx.prepare_fx",
        param_names=["model", "qconfig_mapping", "example_inputs",
                    "prepare_custom_config", "backend_config"],
        param_intervals={},
        return_interval=None,  # Returns GraphModule
        preconditions=[
            ("traceable", "Model must be symbolically traceable"),
        ],
        postconditions=[
            ("fx_prepared", "Returns prepared GraphModule"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Prepare model for FX quantization",
    ))
    
    # prepare_qat_fx
    registry.register(FunctionContract(
        name="torch.ao.quantization.quantize_fx.prepare_qat_fx",
        qualname="torch.ao.quantization.quantize_fx.prepare_qat_fx",
        param_names=["model", "qconfig_mapping", "example_inputs",
                    "prepare_custom_config", "backend_config"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("traceable", "Model must be symbolically traceable"),
        ],
        postconditions=[
            ("fx_qat_prepared", "Returns QAT-prepared GraphModule"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Prepare model for FX QAT",
    ))
    
    # convert_fx
    registry.register(FunctionContract(
        name="torch.ao.quantization.quantize_fx.convert_fx",
        qualname="torch.ao.quantization.quantize_fx.convert_fx",
        param_names=["graph_module", "convert_custom_config", "backend_config"],
        param_intervals={},
        return_interval=None,  # Returns quantized GraphModule
        preconditions=[
            ("prepared", "Model must be prepared with prepare_fx"),
        ],
        postconditions=[
            ("fx_converted", "Returns quantized GraphModule"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert prepared FX model to quantized",
    ))
    
    # convert_to_reference_fx
    registry.register(FunctionContract(
        name="torch.ao.quantization.quantize_fx.convert_to_reference_fx",
        qualname="torch.ao.quantization.quantize_fx.convert_to_reference_fx",
        param_names=["graph_module", "convert_custom_config", "backend_config"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("prepared", "Model must be prepared"),
        ],
        postconditions=[
            ("reference_converted", "Returns reference quantized model"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert to reference quantized model",
    ))


# ============================================================================
# Quantized Operations
# ============================================================================

def _register_quantized_ops(registry: ContractRegistry) -> None:
    """Register quantized operation contracts."""
    
    # torch.quantize_per_tensor
    registry.register(FunctionContract(
        name="torch.quantize_per_tensor",
        qualname="torch.quantize_per_tensor",
        param_names=["input", "scale", "zero_point", "dtype"],
        param_intervals={
            "scale": Interval(0.0, float('inf')),  # Scale must be positive
        },
        return_interval=None,  # Returns quantized tensor
        preconditions=[
            ("valid_dtype", "dtype must be quint8, qint8, qint32, or quint4x2"),
        ],
        postconditions=[
            ("quantized", "Returns quantized tensor"),
        ],
        requires_same_device=True,  # Input and output same device
        may_raise=["RuntimeError"],
        docstring="Quantize tensor with per-tensor parameters",
    ))
    
    # torch.quantize_per_channel
    registry.register(FunctionContract(
        name="torch.quantize_per_channel",
        qualname="torch.quantize_per_channel",
        param_names=["input", "scales", "zero_points", "axis", "dtype"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("scales_match", "scales length must match input.shape[axis]"),
            ("zero_points_match", "zero_points length must match"),
        ],
        postconditions=[
            ("per_channel_quantized", "Returns per-channel quantized tensor"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Quantize tensor with per-channel parameters",
    ))
    
    # torch.dequantize
    registry.register(FunctionContract(
        name="torch.dequantize",
        qualname="torch.dequantize",
        param_names=["tensor"],
        param_intervals={},
        return_interval=None,  # Returns float tensor
        preconditions=[
            ("is_quantized", "tensor must be quantized"),
        ],
        postconditions=[
            ("dequantized", "Returns float tensor"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Dequantize quantized tensor",
    ))
    
    # Quantized tensor properties
    registry.register(MethodContract(
        name="torch.Tensor.q_scale",
        qualname="torch.Tensor.q_scale",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[
            ("is_quantized", "Tensor must be quantized"),
            ("per_tensor", "Must be per-tensor quantized"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return quantization scale",
    ))
    
    registry.register(MethodContract(
        name="torch.Tensor.q_zero_point",
        qualname="torch.Tensor.q_zero_point",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns int
        preconditions=[
            ("is_quantized", "Tensor must be quantized"),
            ("per_tensor", "Must be per-tensor quantized"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return quantization zero point",
    ))
    
    registry.register(MethodContract(
        name="torch.Tensor.int_repr",
        qualname="torch.Tensor.int_repr",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns int tensor
        preconditions=[
            ("is_quantized", "Tensor must be quantized"),
        ],
        postconditions=[
            ("int_values", "Returns underlying integer values"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Return integer representation of quantized tensor",
    ))


# ============================================================================
# Quantized Modules
# ============================================================================

def _register_quantized_modules(registry: ContractRegistry) -> None:
    """Register quantized nn module contracts."""
    
    # Quantized Linear
    registry.register(ModuleContract(
        name="torch.nn.quantized.Linear",
        qualname="torch.nn.quantized.Linear",
        init_param_names=["in_features", "out_features", "bias", "dtype"],
        init_param_intervals={
            "in_features": Interval(1, float('inf')),
            "out_features": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=True,
        forward_preserves_device=True,
        state_invariants=[
            ("quantized_weight", "Weight is quantized"),
            ("quantized_output", "Output is quantized"),
        ],
        docstring="Quantized linear layer",
    ))
    
    # Quantized Conv2d
    registry.register(ModuleContract(
        name="torch.nn.quantized.Conv2d",
        qualname="torch.nn.quantized.Conv2d",
        init_param_names=["in_channels", "out_channels", "kernel_size", "stride",
                         "padding", "dilation", "groups", "bias", "padding_mode"],
        init_param_intervals={
            "in_channels": Interval(1, float('inf')),
            "out_channels": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=True,
        forward_preserves_device=True,
        state_invariants=[
            ("quantized_weight", "Weight is quantized"),
        ],
        docstring="Quantized 2D convolution",
    ))
    
    # Dynamic Quantized Linear
    registry.register(ModuleContract(
        name="torch.nn.quantized.dynamic.Linear",
        qualname="torch.nn.quantized.dynamic.Linear",
        init_param_names=["in_features", "out_features", "bias", "dtype"],
        init_param_intervals={
            "in_features": Interval(1, float('inf')),
            "out_features": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=True,
        forward_preserves_device=True,
        state_invariants=[
            ("dynamic_quant", "Activation quantized dynamically"),
        ],
        docstring="Dynamic quantized linear layer",
    ))
    
    # Quantized functional operations
    registry.register(FunctionContract(
        name="torch.nn.quantized.functional.linear",
        qualname="torch.nn.quantized.functional.linear",
        param_names=["input", "weight", "bias", "scale", "zero_point"],
        param_intervals={
            "scale": Interval(0, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("quantized_input", "input must be quantized"),
            ("quantized_weight", "weight must be quantized"),
        ],
        postconditions=[
            ("quantized_output", "Output is quantized"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Quantized linear function",
    ))


# ============================================================================
# Backend Configuration
# ============================================================================

def _register_backend_config(registry: ContractRegistry) -> None:
    """Register backend configuration contracts."""
    
    # BackendConfig
    registry.register(ModuleContract(
        name="torch.ao.quantization.BackendConfig",
        qualname="torch.ao.quantization.BackendConfig",
        init_param_names=["name"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("backend_patterns", "Defines quantizable patterns for backend"),
        ],
        docstring="Configuration for quantization backend",
    ))
    
    # get_native_backend_config
    registry.register(FunctionContract(
        name="torch.ao.quantization.get_native_backend_config",
        qualname="torch.ao.quantization.get_native_backend_config",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("native_config", "Returns native backend config"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get native (PyTorch) backend config",
    ))


# ============================================================================
# Quantized Backends
# ============================================================================

def _register_backends(registry: ContractRegistry) -> None:
    """Register quantization backend contracts."""
    
    # torch.backends.quantized.engine
    registry.register(FunctionContract(
        name="torch.backends.quantized.engine",
        qualname="torch.backends.quantized.engine",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Get current quantization engine",
    ))
    
    # torch.backends.quantized.supported_engines
    registry.register(FunctionContract(
        name="torch.backends.quantized.supported_engines",
        qualname="torch.backends.quantized.supported_engines",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns list of strings
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Get list of supported quantization engines",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_quantization_contracts(registry: ContractRegistry) -> None:
    """
    Register all quantization contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_observers(registry)
    _register_fake_quantize(registry)
    _register_qconfig(registry)
    _register_workflow(registry)
    _register_fx_quantization(registry)
    _register_quantized_ops(registry)
    _register_quantized_modules(registry)
    _register_backend_config(registry)
    _register_backends(registry)


# Export
__all__ = [
    "register_quantization_contracts",
]
