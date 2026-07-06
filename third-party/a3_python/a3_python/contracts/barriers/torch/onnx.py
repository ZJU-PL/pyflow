"""
PyTorch ONNX Export Contracts - torch.onnx

This module provides contracts for PyTorch's ONNX export functionality:
- Model export to ONNX format
- ONNX operator registration
- Export validation
- Symbolic functions

Device Barrier Considerations:
- ONNX export typically requires model on CPU
- Some operators have device-specific behavior
- Exported model is device-agnostic
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
# ONNX Export Functions
# ============================================================================

def _register_export(registry: ContractRegistry) -> None:
    """Register ONNX export contracts."""
    
    # torch.onnx.export
    registry.register(FunctionContract(
        name="torch.onnx.export",
        qualname="torch.onnx.export",
        param_names=["model", "args", "f", "export_params", "verbose", "training",
                    "input_names", "output_names", "operator_export_type",
                    "opset_version", "do_constant_folding", "dynamic_axes",
                    "keep_initializers_as_inputs", "custom_opsets",
                    "export_modules_as_functions"],
        param_intervals={
            "opset_version": Interval(7, 20),  # Supported ONNX opset range
        },
        return_interval=None,
        preconditions=[
            ("model_callable", "model must be callable or nn.Module"),
            ("args_provided", "Example inputs must be provided"),
            ("file_writable", "f must be writable path or file-like"),
        ],
        postconditions=[
            ("onnx_exported", "Model exported to ONNX format"),
        ],
        requires_same_device=False,  # Export works regardless of device
        may_raise=["RuntimeError", "ONNXExportError"],
        docstring="Export model to ONNX format",
    ))
    
    # torch.onnx.dynamo_export
    registry.register(FunctionContract(
        name="torch.onnx.dynamo_export",
        qualname="torch.onnx.dynamo_export",
        param_names=["model", "args", "kwargs", "export_options"],
        param_intervals={},
        return_interval=None,  # Returns ExportOutput
        preconditions=[
            ("model_callable", "model must be callable"),
        ],
        postconditions=[
            ("dynamo_exported", "Model exported using TorchDynamo"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Export model using TorchDynamo (new export path)",
    ))
    
    # torch.onnx.export_to_pretty_string
    registry.register(FunctionContract(
        name="torch.onnx.export_to_pretty_string",
        qualname="torch.onnx.export_to_pretty_string",
        param_names=["model", "args", "f", "export_params", "verbose", "training",
                    "input_names", "output_names", "operator_export_type",
                    "opset_version", "do_constant_folding", "dynamic_axes",
                    "keep_initializers_as_inputs", "custom_opsets",
                    "export_modules_as_functions", "google_printer"],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[],
        postconditions=[
            ("string_returned", "Returns ONNX model as string"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Export model and return as pretty-printed string",
    ))
    
    # torch.onnx.select_model_mode_for_export
    registry.register(FunctionContract(
        name="torch.onnx.select_model_mode_for_export",
        qualname="torch.onnx.select_model_mode_for_export",
        param_names=["model", "mode"],
        param_intervals={},
        return_interval=None,  # Context manager
        preconditions=[],
        postconditions=[
            ("mode_set", "Model set to specified mode for export"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Context manager to set model mode for export",
    ))


# ============================================================================
# Operator Registration
# ============================================================================

def _register_operators(registry: ContractRegistry) -> None:
    """Register ONNX operator registration contracts."""
    
    # torch.onnx.register_custom_op_symbolic
    registry.register(FunctionContract(
        name="torch.onnx.register_custom_op_symbolic",
        qualname="torch.onnx.register_custom_op_symbolic",
        param_names=["symbolic_name", "symbolic_fn", "opset_version"],
        param_intervals={
            "opset_version": Interval(1, 20),
        },
        return_interval=None,
        preconditions=[
            ("valid_name", "symbolic_name must be valid op name"),
            ("valid_fn", "symbolic_fn must be valid symbolic function"),
        ],
        postconditions=[
            ("registered", "Custom op symbolic registered"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Register custom operator symbolic function",
    ))
    
    # torch.onnx.unregister_custom_op_symbolic
    registry.register(FunctionContract(
        name="torch.onnx.unregister_custom_op_symbolic",
        qualname="torch.onnx.unregister_custom_op_symbolic",
        param_names=["symbolic_name", "opset_version"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("was_registered", "Op must have been registered"),
        ],
        postconditions=[
            ("unregistered", "Custom op symbolic unregistered"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Unregister custom operator symbolic",
    ))
    
    # torch.onnx.is_in_onnx_export
    registry.register(FunctionContract(
        name="torch.onnx.is_in_onnx_export",
        qualname="torch.onnx.is_in_onnx_export",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if currently in ONNX export context",
    ))


# ============================================================================
# Verification
# ============================================================================

def _register_verification(registry: ContractRegistry) -> None:
    """Register ONNX verification contracts."""
    
    # torch.onnx.verification.verify_onnx_program
    registry.register(FunctionContract(
        name="torch.onnx.verification.verify_onnx_program",
        qualname="torch.onnx.verification.verify_onnx_program",
        param_names=["onnx_program", "args", "kwargs"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_program", "onnx_program must be valid ExportOutput"),
        ],
        postconditions=[
            ("verified", "ONNX program outputs match PyTorch"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "AssertionError"],
        docstring="Verify ONNX export matches PyTorch outputs",
    ))
    
    # torch.onnx.verification.find_mismatch
    registry.register(FunctionContract(
        name="torch.onnx.verification.find_mismatch",
        qualname="torch.onnx.verification.find_mismatch",
        param_names=["model", "args", "kwargs", "opset_version"],
        param_intervals={},
        return_interval=None,  # Returns mismatch info
        preconditions=[],
        postconditions=[
            ("mismatch_found", "Returns info about any output mismatches"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Find mismatches between PyTorch and ONNX",
    ))


# ============================================================================
# Export Options
# ============================================================================

def _register_export_options(registry: ContractRegistry) -> None:
    """Register export options contracts."""
    
    # ExportOptions
    registry.register(ModuleContract(
        name="torch.onnx.ExportOptions",
        qualname="torch.onnx.ExportOptions",
        init_param_names=["dynamic_shapes", "op_level_debug", "diagnostic_options"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="Options for dynamo_export",
    ))
    
    # DiagnosticOptions
    registry.register(ModuleContract(
        name="torch.onnx.DiagnosticOptions",
        qualname="torch.onnx.DiagnosticOptions",
        init_param_names=["verbosity_level", "warnings_as_errors"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="Diagnostic options for export",
    ))


# ============================================================================
# JIT Graph Utilities
# ============================================================================

def _register_jit_utils(registry: ContractRegistry) -> None:
    """Register JIT-related ONNX utilities."""
    
    # torch.onnx._type_utils (internal but commonly used)
    registry.register(FunctionContract(
        name="torch.onnx.symbolic_helper._parse_arg",
        qualname="torch.onnx.symbolic_helper._parse_arg",
        param_names=["value", "desc"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("arg_parsed", "Argument parsed to Python value"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Parse JIT graph argument to Python value",
    ))
    
    registry.register(FunctionContract(
        name="torch.onnx.symbolic_helper._get_tensor_sizes",
        qualname="torch.onnx.symbolic_helper._get_tensor_sizes",
        param_names=["input", "allow_unk"],
        param_intervals={},
        return_interval=None,  # Returns list of sizes
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Get tensor sizes from JIT value",
    ))
    
    registry.register(FunctionContract(
        name="torch.onnx.symbolic_helper._get_tensor_dim_size",
        qualname="torch.onnx.symbolic_helper._get_tensor_dim_size",
        param_names=["input", "dim"],
        param_intervals={},
        return_interval=None,  # Returns int or None
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Get size of specific dimension",
    ))


# ============================================================================
# ONNX Utilities
# ============================================================================

def _register_utils(registry: ContractRegistry) -> None:
    """Register ONNX utility contracts."""
    
    # torch.onnx.utils.unconvertible_ops
    registry.register(FunctionContract(
        name="torch.onnx.utils.unconvertible_ops",
        qualname="torch.onnx.utils.unconvertible_ops",
        param_names=["model", "args", "training", "opset_version"],
        param_intervals={},
        return_interval=None,  # Returns set of unconvertible ops
        preconditions=[],
        postconditions=[
            ("ops_listed", "Returns set of ops that can't be exported"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Find ops that can't be exported to ONNX",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_onnx_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.onnx contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_export(registry)
    _register_operators(registry)
    _register_verification(registry)
    _register_export_options(registry)
    _register_jit_utils(registry)
    _register_utils(registry)


# Export
__all__ = [
    "register_onnx_contracts",
]
