"""
PyTorch JIT Contracts - torch.jit (TorchScript)

This module provides contracts for PyTorch's JIT compilation:
- Script and trace compilation
- Scripted functions and modules
- JIT utilities
- Graph manipulation

Device Barrier Considerations:
- Scripted models preserve device placement
- Traced models capture device at trace time
- JIT fusion may affect device placement in some cases
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
# Script and Trace
# ============================================================================

def _register_script_trace(registry: ContractRegistry) -> None:
    """Register scripting and tracing contracts."""
    
    # torch.jit.script
    registry.register(FunctionContract(
        name="torch.jit.script",
        qualname="torch.jit.script",
        param_names=["obj", "_rcb", "_frames_up", "_check_constraints"],
        param_intervals={},
        return_interval=None,  # Returns ScriptModule or ScriptFunction
        preconditions=[
            ("scriptable", "obj must be scriptable (no unsupported Python)"),
        ],
        postconditions=[
            ("scripted", "Returns TorchScript representation"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "ScriptError"],
        docstring="Convert Python function/module to TorchScript",
    ))
    
    # torch.jit.trace
    registry.register(FunctionContract(
        name="torch.jit.trace",
        qualname="torch.jit.trace",
        param_names=["func", "example_inputs", "optimize", "check_trace",
                    "check_inputs", "check_tolerance", "strict", "_force_outplace",
                    "_module_class", "_compilation_unit"],
        param_intervals={
            "check_tolerance": Interval(0.0, float('inf')),
        },
        return_interval=None,  # Returns ScriptModule
        preconditions=[
            ("callable", "func must be callable"),
            ("inputs_provided", "example_inputs must be provided"),
        ],
        postconditions=[
            ("traced", "Returns traced TorchScript module"),
            ("device_captured", "Device placement captured from example_inputs"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "TracingCheckError"],
        docstring="Trace module/function with example inputs",
    ))
    
    # torch.jit.trace_module
    registry.register(FunctionContract(
        name="torch.jit.trace_module",
        qualname="torch.jit.trace_module",
        param_names=["mod", "inputs", "optimize", "check_trace",
                    "check_inputs", "check_tolerance", "strict", "_force_outplace",
                    "_module_class", "_compilation_unit"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("module", "mod must be nn.Module"),
            ("inputs_dict", "inputs must be dict[str, tuple]"),
        ],
        postconditions=[
            ("traced", "Returns traced module with multiple methods"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Trace module with multiple method inputs",
    ))
    
    # torch.jit.freeze
    registry.register(FunctionContract(
        name="torch.jit.freeze",
        qualname="torch.jit.freeze",
        param_names=["mod", "preserved_attrs", "optimize_numerics"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("scripted", "mod must be ScriptModule"),
        ],
        postconditions=[
            ("frozen", "Parameters and buffers become constants"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Freeze scripted module (inline parameters)",
    ))
    
    # torch.jit.optimize_for_inference
    registry.register(FunctionContract(
        name="torch.jit.optimize_for_inference",
        qualname="torch.jit.optimize_for_inference",
        param_names=["mod", "other_methods"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("scripted", "mod must be ScriptModule"),
        ],
        postconditions=[
            ("optimized", "Module optimized for inference"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Optimize scripted module for inference",
    ))


# ============================================================================
# Save and Load
# ============================================================================

def _register_save_load(registry: ContractRegistry) -> None:
    """Register save/load contracts."""
    
    # torch.jit.save
    registry.register(FunctionContract(
        name="torch.jit.save",
        qualname="torch.jit.save",
        param_names=["m", "f", "_extra_files"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("scripted", "m must be ScriptModule or ScriptFunction"),
            ("file_writable", "f must be writable path or file-like"),
        ],
        postconditions=[
            ("saved", "TorchScript saved to file"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "IOError"],
        docstring="Save TorchScript module to file",
    ))
    
    # torch.jit.load
    registry.register(FunctionContract(
        name="torch.jit.load",
        qualname="torch.jit.load",
        param_names=["f", "map_location", "_extra_files"],
        param_intervals={},
        return_interval=None,  # Returns ScriptModule
        preconditions=[
            ("file_exists", "f must be readable path or file-like"),
            ("valid_format", "File must contain valid TorchScript"),
        ],
        postconditions=[
            ("loaded", "Returns ScriptModule from file"),
        ],
        requires_same_device=False,  # map_location handles device
        may_raise=["RuntimeError", "IOError"],
        docstring="Load TorchScript module from file",
    ))
    
    # torch.jit.export
    registry.register(FunctionContract(
        name="torch.jit.export",
        qualname="torch.jit.export",
        param_names=["fn"],
        param_intervals={},
        return_interval=None,  # Returns decorated function
        preconditions=[],
        postconditions=[
            ("marked", "Function marked for export in script"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Mark method for export in scripted module",
    ))


# ============================================================================
# Annotations
# ============================================================================

def _register_annotations(registry: ContractRegistry) -> None:
    """Register type annotation helpers."""
    
    # torch.jit.annotate
    registry.register(FunctionContract(
        name="torch.jit.annotate",
        qualname="torch.jit.annotate",
        param_names=["the_type", "the_value"],
        param_intervals={},
        return_interval=None,  # Returns the_value with type hint
        preconditions=[],
        postconditions=[
            ("annotated", "Value annotated with type for TorchScript"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Annotate value with type for TorchScript",
    ))
    
    # torch.jit.ignore
    registry.register(FunctionContract(
        name="torch.jit.ignore",
        qualname="torch.jit.ignore",
        param_names=["drop", "fn"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("ignored", "Function ignored by TorchScript compiler"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Mark function to be ignored by TorchScript",
    ))
    
    # torch.jit.unused
    registry.register(FunctionContract(
        name="torch.jit.unused",
        qualname="torch.jit.unused",
        param_names=["fn"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("marked_unused", "Function raises if called in script"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Mark function as unused (raises if called)",
    ))
    
    # torch.jit.interface
    registry.register(FunctionContract(
        name="torch.jit.interface",
        qualname="torch.jit.interface",
        param_names=["obj"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("class", "obj must be a class"),
        ],
        postconditions=[
            ("interface_defined", "Interface type defined for TorchScript"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Define interface type for TorchScript",
    ))
    
    # torch.jit.isinstance
    registry.register(FunctionContract(
        name="torch.jit.isinstance",
        qualname="torch.jit.isinstance",
        param_names=["obj", "target_type"],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="TorchScript-compatible isinstance check",
    ))


# ============================================================================
# ScriptModule Operations
# ============================================================================

def _register_script_module(registry: ContractRegistry) -> None:
    """Register ScriptModule contracts."""
    
    # ScriptModule forward
    registry.register(MethodContract(
        name="torch.jit.ScriptModule.forward",
        qualname="torch.jit.ScriptModule.forward",
        param_names=["self", "*args", "**kwargs"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("scripted_execution", "Executes TorchScript graph"),
        ],
        requires_same_device=True,  # Preserves original device requirements
        may_raise=["RuntimeError"],
        docstring="Execute scripted forward pass",
    ))
    
    # ScriptModule.save
    registry.register(MethodContract(
        name="torch.jit.ScriptModule.save",
        qualname="torch.jit.ScriptModule.save",
        param_names=["self", "f", "_extra_files"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("saved", "Module saved to file"),
        ],
        requires_same_device=False,
        may_raise=["IOError"],
        docstring="Save module to file",
    ))
    
    # ScriptModule._c attribute access (underlying ScriptModule)
    registry.register(MethodContract(
        name="torch.jit.ScriptModule.graph",
        qualname="torch.jit.ScriptModule.graph",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns Graph
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Get IR graph of forward method",
    ))
    
    # ScriptModule.code
    registry.register(MethodContract(
        name="torch.jit.ScriptModule.code",
        qualname="torch.jit.ScriptModule.code",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Get Python-like code representation",
    ))
    
    # ScriptModule.inlined_graph
    registry.register(MethodContract(
        name="torch.jit.ScriptModule.inlined_graph",
        qualname="torch.jit.ScriptModule.inlined_graph",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns Graph
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Get inlined IR graph",
    ))
    
    # ScriptModule.define
    registry.register(MethodContract(
        name="torch.jit.ScriptModule.define",
        qualname="torch.jit.ScriptModule.define",
        param_names=["self", "src"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_torchscript", "src must be valid TorchScript"),
        ],
        postconditions=[
            ("method_defined", "New method added to module"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Define new method from TorchScript source",
    ))


# ============================================================================
# Fork and Wait (Async)
# ============================================================================

def _register_async(registry: ContractRegistry) -> None:
    """Register async execution contracts."""
    
    # torch.jit.fork
    registry.register(FunctionContract(
        name="torch.jit.fork",
        qualname="torch.jit.fork",
        param_names=["func", "*args", "**kwargs"],
        param_intervals={},
        return_interval=None,  # Returns Future
        preconditions=[
            ("scriptable", "func must be scriptable"),
        ],
        postconditions=[
            ("async_started", "Async execution started"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Fork async execution (returns Future)",
    ))
    
    # torch.jit.wait
    registry.register(FunctionContract(
        name="torch.jit.wait",
        qualname="torch.jit.wait",
        param_names=["future"],
        param_intervals={},
        return_interval=None,  # Returns result of future
        preconditions=[
            ("valid_future", "future must be from fork()"),
        ],
        postconditions=[
            ("result_ready", "Returns result when ready"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Wait for forked execution result",
    ))


# ============================================================================
# Frontend Utilities
# ============================================================================

def _register_frontend(registry: ContractRegistry) -> None:
    """Register frontend utility contracts."""
    
    # torch.jit.is_scripting
    registry.register(FunctionContract(
        name="torch.jit.is_scripting",
        qualname="torch.jit.is_scripting",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if currently compiling with TorchScript",
    ))
    
    # torch.jit.is_tracing
    registry.register(FunctionContract(
        name="torch.jit.is_tracing",
        qualname="torch.jit.is_tracing",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if currently tracing",
    ))
    
    # torch.jit.set_fusion_strategy
    registry.register(FunctionContract(
        name="torch.jit.set_fusion_strategy",
        qualname="torch.jit.set_fusion_strategy",
        param_names=["strategy"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_strategy", "strategy must be list of (type, depth) tuples"),
        ],
        postconditions=[
            ("strategy_set", "Fusion strategy configured"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Set JIT fusion strategy",
    ))
    
    # torch.jit.fuser
    registry.register(FunctionContract(
        name="torch.jit.fuser",
        qualname="torch.jit.fuser",
        param_names=["name"],
        param_intervals={},
        return_interval=None,  # Context manager
        preconditions=[
            ("valid_fuser", "name must be 'fuser0', 'fuser1', 'fuser2', or 'none'"),
        ],
        postconditions=[
            ("fuser_active", "Specified fuser active in context"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Context manager for specific fuser",
    ))
    
    # torch.jit.enable_onednn_fusion
    registry.register(FunctionContract(
        name="torch.jit.enable_onednn_fusion",
        qualname="torch.jit.enable_onednn_fusion",
        param_names=["enabled"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("onednn_set", "OneDNN fusion enabled/disabled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable OneDNN JIT fusion",
    ))


# ============================================================================
# Profiling
# ============================================================================

def _register_profiling(registry: ContractRegistry) -> None:
    """Register JIT profiling contracts."""
    
    # torch.jit.profile_execution
    registry.register(FunctionContract(
        name="torch.jit.profile_execution",
        qualname="torch.jit.profile_execution",
        param_names=["enable"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("profiling_set", "Execution profiling enabled/disabled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable JIT execution profiling",
    ))


# ============================================================================
# Mobile Export
# ============================================================================

def _register_mobile(registry: ContractRegistry) -> None:
    """Register mobile export contracts."""
    
    # torch.jit._export_opnames
    registry.register(FunctionContract(
        name="torch.jit._export_opnames",
        qualname="torch.jit._export_opnames",
        param_names=["m"],
        param_intervals={},
        return_interval=None,  # Returns set of op names
        preconditions=[
            ("scripted", "m must be ScriptModule"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Export operator names used in module",
    ))
    
    # torch.jit.mobile_optimizer.optimize_for_mobile
    registry.register(FunctionContract(
        name="torch.utils.mobile_optimizer.optimize_for_mobile",
        qualname="torch.utils.mobile_optimizer.optimize_for_mobile",
        param_names=["script_module", "optimization_blocklist", "preserved_methods",
                    "backend"],
        param_intervals={},
        return_interval=None,  # Returns optimized ScriptModule
        preconditions=[
            ("scripted", "script_module must be ScriptModule"),
        ],
        postconditions=[
            ("mobile_optimized", "Module optimized for mobile deployment"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Optimize scripted module for mobile",
    ))


# ============================================================================
# Quantization Related
# ============================================================================

def _register_quantization(registry: ContractRegistry) -> None:
    """Register JIT quantization-related contracts."""
    
    # torch.jit.quantized patterns
    registry.register(FunctionContract(
        name="torch.jit._quantized",
        qualname="torch.jit._quantized",
        param_names=["fn"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Internal quantization decorator",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_jit_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.jit contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_script_trace(registry)
    _register_save_load(registry)
    _register_annotations(registry)
    _register_script_module(registry)
    _register_async(registry)
    _register_frontend(registry)
    _register_profiling(registry)
    _register_mobile(registry)
    _register_quantization(registry)


# Export
__all__ = [
    "register_jit_contracts",
]
