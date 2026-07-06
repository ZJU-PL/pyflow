"""
PyTorch Autograd Contracts - torch.autograd

This module provides contracts for PyTorch's automatic differentiation system:
- Gradient computation (backward, grad)
- Custom Functions
- Gradient hooks
- Gradient checking utilities
- Profiling

Device Barrier Considerations:
- Gradients are computed on the same device as the tensor
- Custom backward functions must maintain device consistency
- Gradient accumulation requires tensors on same device
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
# Core Gradient Computation
# ============================================================================

def _register_grad_computation(registry: ContractRegistry) -> None:
    """Register gradient computation contracts."""
    
    # torch.autograd.backward
    registry.register(FunctionContract(
        name="torch.autograd.backward",
        qualname="torch.autograd.backward",
        param_names=["tensors", "grad_tensors", "retain_graph", "create_graph", 
                    "grad_variables", "inputs"],
        param_intervals={},
        return_interval=None,  # Returns None, gradients are stored in .grad
        preconditions=[
            ("requires_grad", "At least one tensor must require grad"),
            ("grad_tensors_match", "grad_tensors must match shape/device of tensors"),
        ],
        postconditions=[
            ("gradients_computed", "Leaf tensors have gradients in .grad"),
        ],
        requires_same_device=True,  # tensors and grad_tensors must match device
        may_raise=["RuntimeError"],
        docstring="Compute gradients of tensors w.r.t. graph leaves",
    ))
    
    # torch.autograd.grad
    registry.register(FunctionContract(
        name="torch.autograd.grad",
        qualname="torch.autograd.grad",
        param_names=["outputs", "inputs", "grad_outputs", "retain_graph", 
                    "create_graph", "only_inputs", "allow_unused", 
                    "is_grads_batched", "materialize_grads"],
        param_intervals={},
        return_interval=None,  # Returns tuple of gradients
        preconditions=[
            ("outputs_require_grad", "outputs must be part of computation graph"),
            ("grad_outputs_match", "grad_outputs must match shape/device of outputs"),
        ],
        postconditions=[
            ("gradients_returned", "Returns tuple of gradients for each input"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Compute and return gradients for inputs",
    ))
    
    # torch.autograd.functional.jacobian
    registry.register(FunctionContract(
        name="torch.autograd.functional.jacobian",
        qualname="torch.autograd.functional.jacobian",
        param_names=["func", "inputs", "create_graph", "strict", "vectorize", "strategy"],
        param_intervals={},
        return_interval=None,  # Returns Jacobian tensor(s)
        preconditions=[
            ("func_callable", "func must be callable"),
            ("inputs_tensors", "inputs must be tensor or tuple of tensors"),
        ],
        postconditions=[
            ("jacobian_computed", "Returns Jacobian matrix of func at inputs"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Compute Jacobian of function at inputs",
    ))
    
    # torch.autograd.functional.hessian
    registry.register(FunctionContract(
        name="torch.autograd.functional.hessian",
        qualname="torch.autograd.functional.hessian",
        param_names=["func", "inputs", "create_graph", "strict", "vectorize", "outer_jacobian_strategy"],
        param_intervals={},
        return_interval=None,  # Returns Hessian tensor(s)
        preconditions=[
            ("func_callable", "func must be callable"),
            ("func_scalar_output", "func must return scalar"),
        ],
        postconditions=[
            ("hessian_computed", "Returns Hessian matrix of func at inputs"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Compute Hessian of scalar function at inputs",
    ))
    
    # torch.autograd.functional.vjp
    registry.register(FunctionContract(
        name="torch.autograd.functional.vjp",
        qualname="torch.autograd.functional.vjp",
        param_names=["func", "inputs", "v", "create_graph", "strict"],
        param_intervals={},
        return_interval=None,  # Returns (output, vjp)
        preconditions=[
            ("v_matches_output", "v must match shape/device of func output"),
        ],
        postconditions=[
            ("vjp_computed", "Returns function output and vector-Jacobian product"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Compute vector-Jacobian product",
    ))
    
    # torch.autograd.functional.jvp
    registry.register(FunctionContract(
        name="torch.autograd.functional.jvp",
        qualname="torch.autograd.functional.jvp",
        param_names=["func", "inputs", "v", "create_graph", "strict"],
        param_intervals={},
        return_interval=None,  # Returns (output, jvp)
        preconditions=[
            ("v_matches_input", "v must match shape/device of inputs"),
        ],
        postconditions=[
            ("jvp_computed", "Returns function output and Jacobian-vector product"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Compute Jacobian-vector product",
    ))
    
    # torch.autograd.functional.vhp
    registry.register(FunctionContract(
        name="torch.autograd.functional.vhp",
        qualname="torch.autograd.functional.vhp",
        param_names=["func", "inputs", "v", "create_graph", "strict"],
        param_intervals={},
        return_interval=None,  # Returns (grad, vhp)
        preconditions=[
            ("func_scalar", "func must return scalar"),
            ("v_matches_input", "v must match shape/device of inputs"),
        ],
        postconditions=[
            ("vhp_computed", "Returns gradient and vector-Hessian product"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Compute vector-Hessian product",
    ))
    
    # torch.autograd.functional.hvp
    registry.register(FunctionContract(
        name="torch.autograd.functional.hvp",
        qualname="torch.autograd.functional.hvp",
        param_names=["func", "inputs", "v", "create_graph", "strict"],
        param_intervals={},
        return_interval=None,  # Returns (grad, hvp)
        preconditions=[
            ("func_scalar", "func must return scalar"),
            ("v_matches_input", "v must match shape/device of inputs"),
        ],
        postconditions=[
            ("hvp_computed", "Returns gradient and Hessian-vector product"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Compute Hessian-vector product",
    ))


# ============================================================================
# Custom Function
# ============================================================================

def _register_custom_function(registry: ContractRegistry) -> None:
    """Register custom autograd.Function contracts."""
    
    # Function.apply (staticmethod)
    registry.register(FunctionContract(
        name="torch.autograd.Function.apply",
        qualname="torch.autograd.Function.apply",
        param_names=["*args", "**kwargs"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("forward_defined", "forward() must be defined"),
        ],
        postconditions=[
            ("ctx_saved", "Context saved for backward pass"),
        ],
        requires_same_device=True,  # Must maintain device consistency
        may_raise=["RuntimeError"],
        docstring="Apply custom autograd function",
    ))
    
    # Function.forward (staticmethod)
    registry.register(FunctionContract(
        name="torch.autograd.Function.forward",
        qualname="torch.autograd.Function.forward",
        param_names=["ctx", "*args", "**kwargs"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("tensors_saved", "ctx.save_for_backward called if needed"),
        ],
        requires_same_device=True,  # Output should match input device
        may_raise=[],
        docstring="Forward pass of custom function",
    ))
    
    # Function.backward (staticmethod)
    registry.register(FunctionContract(
        name="torch.autograd.Function.backward",
        qualname="torch.autograd.Function.backward",
        param_names=["ctx", "*grad_outputs"],
        param_intervals={},
        return_interval=None,  # Returns gradients
        preconditions=[
            ("saved_tensors_available", "ctx.saved_tensors available from forward"),
        ],
        postconditions=[
            ("grad_count_matches", "Number of gradients matches forward inputs"),
            ("grad_device_matches", "Gradients on same device as inputs"),
        ],
        requires_same_device=True,
        may_raise=[],
        docstring="Backward pass computing gradients",
    ))
    
    # Function.setup_context
    registry.register(FunctionContract(
        name="torch.autograd.Function.setup_context",
        qualname="torch.autograd.Function.setup_context",
        param_names=["ctx", "inputs", "output"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("context_setup", "Context properly configured for backward"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Setup context for backward (new-style Functions)",
    ))
    
    # FunctionCtx.save_for_backward
    registry.register(MethodContract(
        name="torch.autograd.function.FunctionCtx.save_for_backward",
        qualname="torch.autograd.function.FunctionCtx.save_for_backward",
        param_names=["self", "*tensors"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("called_in_forward", "Must be called during forward"),
        ],
        postconditions=[
            ("tensors_saved", "Tensors available via ctx.saved_tensors"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Save tensors for backward pass",
    ))
    
    # FunctionCtx.mark_dirty
    registry.register(MethodContract(
        name="torch.autograd.function.FunctionCtx.mark_dirty",
        qualname="torch.autograd.function.FunctionCtx.mark_dirty",
        param_names=["self", "*args"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("input_tensors", "Arguments must be input tensors"),
        ],
        postconditions=[
            ("marked_dirty", "Tensors marked as modified in-place"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Mark tensors as modified in-place",
    ))
    
    # FunctionCtx.mark_non_differentiable
    registry.register(MethodContract(
        name="torch.autograd.function.FunctionCtx.mark_non_differentiable",
        qualname="torch.autograd.function.FunctionCtx.mark_non_differentiable",
        param_names=["self", "*args"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("output_tensors", "Arguments must be output tensors"),
        ],
        postconditions=[
            ("marked_non_diff", "Tensors marked as not requiring gradient"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Mark outputs as non-differentiable",
    ))
    
    # FunctionCtx.set_materialize_grads
    registry.register(MethodContract(
        name="torch.autograd.function.FunctionCtx.set_materialize_grads",
        qualname="torch.autograd.function.FunctionCtx.set_materialize_grads",
        param_names=["self", "value"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("materialize_set", "Gradient materialization behavior configured"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Configure gradient materialization",
    ))


# ============================================================================
# Gradient Mode Context Managers
# ============================================================================

def _register_grad_mode(registry: ContractRegistry) -> None:
    """Register gradient mode context managers."""
    
    # torch.no_grad
    registry.register(FunctionContract(
        name="torch.no_grad",
        qualname="torch.no_grad",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("grad_disabled", "Operations don't track gradients"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Disable gradient computation",
    ))
    
    # torch.enable_grad
    registry.register(FunctionContract(
        name="torch.enable_grad",
        qualname="torch.enable_grad",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("grad_enabled", "Gradient computation enabled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable gradient computation",
    ))
    
    # torch.set_grad_enabled
    registry.register(FunctionContract(
        name="torch.set_grad_enabled",
        qualname="torch.set_grad_enabled",
        param_names=["mode"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("grad_mode_set", "Gradient mode set to specified value"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Set gradient computation mode",
    ))
    
    # torch.is_grad_enabled
    registry.register(FunctionContract(
        name="torch.is_grad_enabled",
        qualname="torch.is_grad_enabled",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if gradient computation is enabled",
    ))
    
    # torch.inference_mode
    registry.register(FunctionContract(
        name="torch.inference_mode",
        qualname="torch.inference_mode",
        param_names=["mode"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("inference_mode", "Inference mode with more aggressive optimization"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable inference mode (more optimized than no_grad)",
    ))
    
    # torch.is_inference_mode_enabled
    registry.register(FunctionContract(
        name="torch.is_inference_mode_enabled",
        qualname="torch.is_inference_mode_enabled",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if inference mode is enabled",
    ))


# ============================================================================
# Gradient Checking
# ============================================================================

def _register_grad_check(registry: ContractRegistry) -> None:
    """Register gradient checking utilities."""
    
    # torch.autograd.gradcheck
    registry.register(FunctionContract(
        name="torch.autograd.gradcheck",
        qualname="torch.autograd.gradcheck",
        param_names=["func", "inputs", "eps", "atol", "rtol", "raise_exception",
                    "check_sparse_nnz", "nondet_tol", "check_undefined_grad",
                    "check_grad_dtypes", "check_batched_grad", "check_forward_ad",
                    "check_backward_ad", "fast_mode", "masked"],
        param_intervals={
            "eps": Interval(1e-10, 1e-2),
            "atol": Interval(0.0, float('inf')),
            "rtol": Interval(0.0, float('inf')),
        },
        return_interval=None,  # Returns bool
        preconditions=[
            ("func_callable", "func must be callable"),
            ("inputs_require_grad", "inputs must require grad for float types"),
        ],
        postconditions=[
            ("gradients_verified", "Analytic gradients match numerical"),
        ],
        requires_same_device=True,
        may_raise=["GradcheckError"],
        docstring="Check analytic vs numerical gradients",
    ))
    
    # torch.autograd.gradgradcheck
    registry.register(FunctionContract(
        name="torch.autograd.gradgradcheck",
        qualname="torch.autograd.gradgradcheck",
        param_names=["func", "inputs", "grad_outputs", "eps", "atol", "rtol",
                    "gen_non_contig_grad_outputs", "raise_exception",
                    "nondet_tol", "check_undefined_grad", "check_grad_dtypes",
                    "check_batched_grad", "check_fwd_over_rev", "check_rev_over_rev",
                    "fast_mode", "masked"],
        param_intervals={
            "eps": Interval(1e-10, 1e-2),
            "atol": Interval(0.0, float('inf')),
            "rtol": Interval(0.0, float('inf')),
        },
        return_interval=None,  # Returns bool
        preconditions=[
            ("func_callable", "func must be callable"),
        ],
        postconditions=[
            ("second_order_verified", "Second-order gradients verified"),
        ],
        requires_same_device=True,
        may_raise=["GradcheckError"],
        docstring="Check second-order gradients",
    ))


# ============================================================================
# Hooks
# ============================================================================

def _register_hooks(registry: ContractRegistry) -> None:
    """Register gradient hook utilities."""
    
    # Tensor.register_hook
    registry.register(MethodContract(
        name="torch.Tensor.register_hook",
        qualname="torch.Tensor.register_hook",
        param_names=["self", "hook"],
        param_intervals={},
        return_interval=None,  # Returns RemovableHandle
        preconditions=[
            ("requires_grad", "Tensor must require grad"),
            ("hook_callable", "hook must be callable(grad) -> grad or None"),
        ],
        postconditions=[
            ("hook_registered", "Hook called during backward"),
        ],
        requires_same_device=True,  # Hook must maintain device
        may_raise=["RuntimeError"],
        docstring="Register backward hook on tensor",
    ))
    
    # Tensor.register_post_accumulate_grad_hook
    registry.register(MethodContract(
        name="torch.Tensor.register_post_accumulate_grad_hook",
        qualname="torch.Tensor.register_post_accumulate_grad_hook",
        param_names=["self", "hook"],
        param_intervals={},
        return_interval=None,  # Returns RemovableHandle
        preconditions=[
            ("is_leaf", "Tensor must be leaf"),
            ("requires_grad", "Tensor must require grad"),
        ],
        postconditions=[
            ("hook_registered", "Hook called after gradient accumulation"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Register post-accumulation hook",
    ))
    
    # Module.register_forward_hook
    registry.register(MethodContract(
        name="torch.nn.Module.register_forward_hook",
        qualname="torch.nn.Module.register_forward_hook",
        param_names=["self", "hook", "prepend", "with_kwargs"],
        param_intervals={},
        return_interval=None,  # Returns RemovableHandle
        preconditions=[
            ("hook_callable", "hook must be callable(module, input, output)"),
        ],
        postconditions=[
            ("hook_registered", "Hook called after forward"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Register forward hook on module",
    ))
    
    # Module.register_forward_pre_hook
    registry.register(MethodContract(
        name="torch.nn.Module.register_forward_pre_hook",
        qualname="torch.nn.Module.register_forward_pre_hook",
        param_names=["self", "hook", "prepend", "with_kwargs"],
        param_intervals={},
        return_interval=None,  # Returns RemovableHandle
        preconditions=[
            ("hook_callable", "hook must be callable(module, input)"),
        ],
        postconditions=[
            ("hook_registered", "Hook called before forward"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Register pre-forward hook on module",
    ))
    
    # Module.register_backward_hook (deprecated but still used)
    registry.register(MethodContract(
        name="torch.nn.Module.register_backward_hook",
        qualname="torch.nn.Module.register_backward_hook",
        param_names=["self", "hook"],
        param_intervals={},
        return_interval=None,  # Returns RemovableHandle
        preconditions=[
            ("hook_callable", "hook must be callable(module, grad_input, grad_output)"),
        ],
        postconditions=[
            ("hook_registered", "Hook called during backward"),
        ],
        requires_same_device=True,
        may_raise=[],
        docstring="Register backward hook on module (deprecated)",
    ))
    
    # Module.register_full_backward_hook
    registry.register(MethodContract(
        name="torch.nn.Module.register_full_backward_hook",
        qualname="torch.nn.Module.register_full_backward_hook",
        param_names=["self", "hook", "prepend"],
        param_intervals={},
        return_interval=None,  # Returns RemovableHandle
        preconditions=[
            ("hook_callable", "hook must be callable(module, grad_input, grad_output)"),
        ],
        postconditions=[
            ("hook_registered", "Full backward hook registered"),
        ],
        requires_same_device=True,
        may_raise=[],
        docstring="Register full backward hook on module",
    ))
    
    # Module.register_full_backward_pre_hook
    registry.register(MethodContract(
        name="torch.nn.Module.register_full_backward_pre_hook",
        qualname="torch.nn.Module.register_full_backward_pre_hook",
        param_names=["self", "hook", "prepend"],
        param_intervals={},
        return_interval=None,  # Returns RemovableHandle
        preconditions=[
            ("hook_callable", "hook must be callable(module, grad_output)"),
        ],
        postconditions=[
            ("hook_registered", "Pre-backward hook registered"),
        ],
        requires_same_device=True,
        may_raise=[],
        docstring="Register pre-backward hook on module",
    ))
    
    # Module.register_state_dict_pre_hook
    registry.register(MethodContract(
        name="torch.nn.Module.register_state_dict_pre_hook",
        qualname="torch.nn.Module.register_state_dict_pre_hook",
        param_names=["self", "hook"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("hook_registered", "Called before state_dict()"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Register state dict pre-hook",
    ))
    
    # Module.register_load_state_dict_post_hook
    registry.register(MethodContract(
        name="torch.nn.Module.register_load_state_dict_post_hook",
        qualname="torch.nn.Module.register_load_state_dict_post_hook",
        param_names=["self", "hook"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("hook_registered", "Called after load_state_dict()"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Register load state dict post-hook",
    ))


# ============================================================================
# Profiling
# ============================================================================

def _register_profiling(registry: ContractRegistry) -> None:
    """Register autograd profiling contracts."""
    
    # torch.autograd.profiler.profile
    registry.register(FunctionContract(
        name="torch.autograd.profiler.profile",
        qualname="torch.autograd.profiler.profile",
        param_names=["enabled", "use_cuda", "record_shapes", "with_flops",
                    "profile_memory", "with_stack", "with_modules", "use_kineto",
                    "use_cpu", "experimental_config"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("profiling_active", "Profiling active within context"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Profile autograd operations",
    ))
    
    # torch.autograd.profiler.record_function
    registry.register(FunctionContract(
        name="torch.autograd.profiler.record_function",
        qualname="torch.autograd.profiler.record_function",
        param_names=["name"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("function_recorded", "Operations labeled with name in profile"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Label operations in profiler",
    ))
    
    # torch.autograd.profiler.emit_nvtx
    registry.register(FunctionContract(
        name="torch.autograd.profiler.emit_nvtx",
        qualname="torch.autograd.profiler.emit_nvtx",
        param_names=["enabled", "record_shapes"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("cuda_available", "CUDA must be available"),
        ],
        postconditions=[
            ("nvtx_markers", "NVTX markers emitted for CUDA ops"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Emit NVTX markers for CUDA profiling",
    ))


# ============================================================================
# Anomaly Detection
# ============================================================================

def _register_anomaly_detection(registry: ContractRegistry) -> None:
    """Register anomaly detection contracts."""
    
    # torch.autograd.set_detect_anomaly
    registry.register(FunctionContract(
        name="torch.autograd.set_detect_anomaly",
        qualname="torch.autograd.set_detect_anomaly",
        param_names=["mode", "check_nan"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("anomaly_detection", "Anomaly detection enabled/disabled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable anomaly detection in autograd",
    ))
    
    # torch.autograd.detect_anomaly (context manager)
    registry.register(FunctionContract(
        name="torch.autograd.detect_anomaly",
        qualname="torch.autograd.detect_anomaly",
        param_names=["check_nan"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("anomaly_detection", "Anomaly detection active in context"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Context manager for anomaly detection",
    ))


# ============================================================================
# Graph Utilities
# ============================================================================

def _register_graph_utilities(registry: ContractRegistry) -> None:
    """Register autograd graph utility contracts."""
    
    # torch.autograd.graph.saved_tensors_hooks
    registry.register(FunctionContract(
        name="torch.autograd.graph.saved_tensors_hooks",
        qualname="torch.autograd.graph.saved_tensors_hooks",
        param_names=["pack_hook", "unpack_hook"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("hooks_callable", "pack_hook and unpack_hook must be callable"),
        ],
        postconditions=[
            ("hooks_active", "Hooks called on save_for_backward tensors"),
        ],
        requires_same_device=True,  # Must maintain device on unpack
        may_raise=[],
        docstring="Set global hooks for saved tensors",
    ))
    
    # torch.autograd.graph.allow_mutation_on_saved_tensors
    registry.register(FunctionContract(
        name="torch.autograd.graph.allow_mutation_on_saved_tensors",
        qualname="torch.autograd.graph.allow_mutation_on_saved_tensors",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("mutation_allowed", "Saved tensors can be mutated in context"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Allow mutation of saved tensors",
    ))
    
    # torch.autograd.graph.disable_saved_tensors_hooks
    registry.register(FunctionContract(
        name="torch.autograd.graph.disable_saved_tensors_hooks",
        qualname="torch.autograd.graph.disable_saved_tensors_hooks",
        param_names=["error_message"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("hooks_disabled", "Saved tensor hooks raise error"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Disable saved tensor hooks",
    ))
    
    # torch.autograd.graph.increment_version
    registry.register(FunctionContract(
        name="torch.autograd.graph.increment_version",
        qualname="torch.autograd.graph.increment_version",
        param_names=["tensor"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("version_incremented", "Tensor version incremented"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Increment tensor version counter",
    ))


# ============================================================================
# Forward AD
# ============================================================================

def _register_forward_ad(registry: ContractRegistry) -> None:
    """Register forward-mode automatic differentiation contracts."""
    
    # torch.autograd.forward_ad.dual_level
    registry.register(FunctionContract(
        name="torch.autograd.forward_ad.dual_level",
        qualname="torch.autograd.forward_ad.dual_level",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("dual_level_active", "Forward AD dual level is active"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enter forward AD dual level context",
    ))
    
    # torch.autograd.forward_ad.make_dual
    registry.register(FunctionContract(
        name="torch.autograd.forward_ad.make_dual",
        qualname="torch.autograd.forward_ad.make_dual",
        param_names=["tensor", "tangent", "level"],
        param_intervals={},
        return_interval=None,  # Returns dual tensor
        preconditions=[
            ("tangent_matches", "tangent must match tensor shape and dtype"),
        ],
        postconditions=[
            ("dual_created", "Dual tensor with primal and tangent"),
        ],
        requires_same_device=True,  # tangent must be on same device
        may_raise=["RuntimeError"],
        docstring="Create dual tensor for forward AD",
    ))
    
    # torch.autograd.forward_ad.unpack_dual
    registry.register(FunctionContract(
        name="torch.autograd.forward_ad.unpack_dual",
        qualname="torch.autograd.forward_ad.unpack_dual",
        param_names=["tensor", "level"],
        param_intervals={},
        return_interval=None,  # Returns (primal, tangent)
        preconditions=[],
        postconditions=[
            ("dual_unpacked", "Returns primal and tangent components"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Unpack dual tensor into primal and tangent",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_autograd_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.autograd contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_grad_computation(registry)
    _register_custom_function(registry)
    _register_grad_mode(registry)
    _register_grad_check(registry)
    _register_hooks(registry)
    _register_profiling(registry)
    _register_anomaly_detection(registry)
    _register_graph_utilities(registry)
    _register_forward_ad(registry)


# Export
__all__ = [
    "register_autograd_contracts",
]
