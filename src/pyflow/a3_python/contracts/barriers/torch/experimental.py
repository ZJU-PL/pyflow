"""
PyTorch Masked Operations and Experimental APIs Contracts

This module provides contracts for:
- torch.masked (masked tensor operations)
- torch.signal (signal processing)  
- torch.func (functional transforms like vmap, grad)
- torch.ao (architecture optimization)
- Various experimental and extension APIs

Device Barrier Considerations:
- Masked operations preserve device placement
- Functional transforms respect device of input tensors
- AO operations may have device-specific implementations
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
# torch.masked - Masked Tensor Operations  
# ============================================================================

def _register_masked(registry: ContractRegistry) -> None:
    """Register torch.masked contracts."""
    
    # torch.masked.masked_tensor
    registry.register(FunctionContract(
        name="torch.masked.masked_tensor",
        qualname="torch.masked.masked_tensor",
        param_names=["data", "mask", "requires_grad"],
        param_intervals={},
        return_interval=None,  # Returns MaskedTensor
        preconditions=[
            ("same_shape", "data and mask must have same shape"),
            ("mask_bool", "mask must be boolean tensor"),
        ],
        postconditions=[
            ("masked_created", "MaskedTensor created"),
        ],
        requires_same_device=True,  # data and mask same device
        may_raise=["RuntimeError"],
        docstring="Create a masked tensor",
    ))
    
    # torch.masked.as_masked_tensor
    registry.register(FunctionContract(
        name="torch.masked.as_masked_tensor",
        qualname="torch.masked.as_masked_tensor",
        param_names=["data", "mask"],
        param_intervals={},
        return_interval=None,  # Returns MaskedTensor
        preconditions=[
            ("same_shape", "data and mask must have same shape"),
        ],
        postconditions=[
            ("view_created", "MaskedTensor view created"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Create MaskedTensor view (no copy)",
    ))
    
    # Masked reduction operations
    for op in ["sum", "prod", "mean", "amax", "amin", "median", "std", "var"]:
        registry.register(FunctionContract(
            name=f"torch.masked.{op}",
            qualname=f"torch.masked.{op}",
            param_names=["input", "dim", "keepdim", "dtype"],
            param_intervals={},
            return_interval=None,
            preconditions=[
                ("valid_dim", "dim must be valid dimension"),
            ],
            postconditions=[
                (f"masked_{op}", f"Masked {op} computed"),
            ],
            requires_same_device=False,
            may_raise=["RuntimeError"],
            docstring=f"Compute masked {op} reduction",
        ))
    
    # torch.masked.softmax
    registry.register(FunctionContract(
        name="torch.masked.softmax",
        qualname="torch.masked.softmax",
        param_names=["input", "dim", "dtype"],
        param_intervals={},
        return_interval=Interval(0.0, 1.0),
        preconditions=[],
        postconditions=[
            ("softmax_computed", "Masked softmax computed"),
            ("sums_to_one", "Unmasked elements sum to 1 along dim"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute masked softmax",
    ))
    
    # torch.masked.log_softmax
    registry.register(FunctionContract(
        name="torch.masked.log_softmax",
        qualname="torch.masked.log_softmax",
        param_names=["input", "dim", "dtype"],
        param_intervals={},
        return_interval=Interval(float('-inf'), 0.0),
        preconditions=[],
        postconditions=[
            ("log_softmax_computed", "Masked log softmax computed"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute masked log softmax",
    ))
    
    # torch.masked.softmin
    registry.register(FunctionContract(
        name="torch.masked.softmin",
        qualname="torch.masked.softmin",
        param_names=["input", "dim", "dtype"],
        param_intervals={},
        return_interval=Interval(0.0, 1.0),
        preconditions=[],
        postconditions=[
            ("softmin_computed", "Masked softmin computed"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute masked softmin",
    ))
    
    # torch.masked.normalize
    registry.register(FunctionContract(
        name="torch.masked.normalize",
        qualname="torch.masked.normalize",
        param_names=["input", "p", "dim", "eps", "dtype"],
        param_intervals={
            "p": Interval(0.0, float('inf')),
            "eps": Interval(0.0, float('inf')),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("normalized", "Masked normalization applied"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute masked Lp normalization",
    ))
    
    # torch.masked.cumsum
    registry.register(FunctionContract(
        name="torch.masked.cumsum",
        qualname="torch.masked.cumsum",
        param_names=["input", "dim", "dtype"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_dim", "dim must be valid dimension"),
        ],
        postconditions=[
            ("cumsum_computed", "Masked cumulative sum computed"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute masked cumulative sum",
    ))
    
    # torch.masked.cumprod
    registry.register(FunctionContract(
        name="torch.masked.cumprod",
        qualname="torch.masked.cumprod",
        param_names=["input", "dim", "dtype"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_dim", "dim must be valid dimension"),
        ],
        postconditions=[
            ("cumprod_computed", "Masked cumulative product computed"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute masked cumulative product",
    ))


# ============================================================================
# torch.func - Functional Transforms (JAX-like)
# ============================================================================

def _register_func(registry: ContractRegistry) -> None:
    """Register torch.func (functorch) contracts."""
    
    # torch.func.vmap
    registry.register(FunctionContract(
        name="torch.func.vmap",
        qualname="torch.func.vmap",
        param_names=["func", "in_dims", "out_dims", "randomness", "chunk_size"],
        param_intervals={},
        return_interval=None,  # Returns vectorized function
        preconditions=[
            ("func_callable", "func must be callable"),
        ],
        postconditions=[
            ("vectorized", "Returns vectorized version of func"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Vectorizing map - batch dimension transformation",
    ))
    
    # torch.func.grad
    registry.register(FunctionContract(
        name="torch.func.grad",
        qualname="torch.func.grad",
        param_names=["func", "argnums", "has_aux"],
        param_intervals={},
        return_interval=None,  # Returns gradient function
        preconditions=[
            ("scalar_output", "func must return scalar for grad"),
        ],
        postconditions=[
            ("grad_func", "Returns function computing gradients"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute gradients of a scalar function",
    ))
    
    # torch.func.grad_and_value
    registry.register(FunctionContract(
        name="torch.func.grad_and_value",
        qualname="torch.func.grad_and_value",
        param_names=["func", "argnums", "has_aux"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("scalar_output", "func must return scalar"),
        ],
        postconditions=[
            ("grad_value_func", "Returns function giving (grad, value)"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute both gradient and function value",
    ))
    
    # torch.func.vjp
    registry.register(FunctionContract(
        name="torch.func.vjp",
        qualname="torch.func.vjp",
        param_names=["func", "*primals", "has_aux"],
        param_intervals={},
        return_interval=None,  # Returns (output, vjp_fn)
        preconditions=[],
        postconditions=[
            ("vjp_computed", "Returns (output, vjp_function)"),
        ],
        requires_same_device=True,  # Primals same device
        may_raise=["RuntimeError"],
        docstring="Compute vector-Jacobian product function",
    ))
    
    # torch.func.jvp
    registry.register(FunctionContract(
        name="torch.func.jvp",
        qualname="torch.func.jvp",
        param_names=["func", "primals", "tangents", "has_aux", "strict"],
        param_intervals={},
        return_interval=None,  # Returns (output, jvp)
        preconditions=[
            ("same_structure", "primals and tangents must match"),
        ],
        postconditions=[
            ("jvp_computed", "Returns (output, jvp)"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Compute Jacobian-vector product",
    ))
    
    # torch.func.jacrev
    registry.register(FunctionContract(
        name="torch.func.jacrev",
        qualname="torch.func.jacrev",
        param_names=["func", "argnums", "has_aux", "chunk_size"],
        param_intervals={},
        return_interval=None,  # Returns Jacobian function
        preconditions=[],
        postconditions=[
            ("jacrev_func", "Returns reverse-mode Jacobian function"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute Jacobian using reverse-mode AD",
    ))
    
    # torch.func.jacfwd
    registry.register(FunctionContract(
        name="torch.func.jacfwd",
        qualname="torch.func.jacfwd",
        param_names=["func", "argnums", "has_aux", "randomness"],
        param_intervals={},
        return_interval=None,  # Returns Jacobian function
        preconditions=[],
        postconditions=[
            ("jacfwd_func", "Returns forward-mode Jacobian function"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute Jacobian using forward-mode AD",
    ))
    
    # torch.func.hessian
    registry.register(FunctionContract(
        name="torch.func.hessian",
        qualname="torch.func.hessian",
        param_names=["func", "argnums"],
        param_intervals={},
        return_interval=None,  # Returns Hessian function
        preconditions=[
            ("scalar_output", "func must return scalar"),
        ],
        postconditions=[
            ("hessian_func", "Returns Hessian computation function"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Compute Hessian of scalar function",
    ))
    
    # torch.func.functionalize
    registry.register(FunctionContract(
        name="torch.func.functionalize",
        qualname="torch.func.functionalize",
        param_names=["func", "remove"],
        param_intervals={},
        return_interval=None,  # Returns functionalized callable
        preconditions=[],
        postconditions=[
            ("functionalized", "Returns mutation-free version"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Remove mutations from a function",
    ))
    
    # torch.func.stack_module_state
    registry.register(FunctionContract(
        name="torch.func.stack_module_state",
        qualname="torch.func.stack_module_state",
        param_names=["models"],
        param_intervals={},
        return_interval=None,  # Returns (params, buffers)
        preconditions=[
            ("same_architecture", "All models must have same architecture"),
        ],
        postconditions=[
            ("stacked", "Returns stacked (params, buffers)"),
        ],
        requires_same_device=True,  # All models same device
        may_raise=["RuntimeError"],
        docstring="Stack parameters from multiple model instances",
    ))
    
    # torch.func.functional_call
    registry.register(FunctionContract(
        name="torch.func.functional_call",
        qualname="torch.func.functional_call",
        param_names=["module", "parameter_and_buffer_dicts", "args", "kwargs",
                    "tie_weights", "strict"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("called", "Module called with replacement params/buffers"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Call module with replacement parameters",
    ))
    
    # torch.func.replace_all_batch_norm_modules_
    registry.register(FunctionContract(
        name="torch.func.replace_all_batch_norm_modules_",
        qualname="torch.func.replace_all_batch_norm_modules_",
        param_names=["root"],
        param_intervals={},
        return_interval=None,  # Returns modified module
        preconditions=[],
        postconditions=[
            ("bn_replaced", "BatchNorm replaced with GroupNorm"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Replace BatchNorm with GroupNorm for vmap compatibility",
    ))


# ============================================================================
# torch.signal - Signal Processing
# ============================================================================

def _register_signal(registry: ContractRegistry) -> None:
    """Register torch.signal contracts."""
    
    # torch.signal.windows module
    window_functions = [
        "bartlett", "blackman", "cosine", "exponential",
        "gaussian", "general_cosine", "general_hamming",
        "hamming", "hann", "kaiser", "nuttall",
        "triang", "tukey", "chebwin"
    ]
    
    for window in window_functions:
        registry.register(FunctionContract(
            name=f"torch.signal.windows.{window}",
            qualname=f"torch.signal.windows.{window}",
            param_names=["M", "sym", "dtype", "layout", "device", "requires_grad"],
            param_intervals={
                "M": Interval(0, float('inf')),
            },
            return_interval=Interval(0.0, 1.0),  # Most windows in [0, 1]
            preconditions=[],
            postconditions=[
                (f"{window}_created", f"{window.capitalize()} window created"),
            ],
            requires_same_device=False,
            may_raise=[],
            docstring=f"Create {window} window function",
        ))
    
    # Kaiser-bessel derived window
    registry.register(FunctionContract(
        name="torch.signal.windows.kaiser_bessel_derived",
        qualname="torch.signal.windows.kaiser_bessel_derived",
        param_names=["M", "beta", "sym", "dtype", "layout", "device", "requires_grad"],
        param_intervals={
            "M": Interval(0, float('inf')),
            "beta": Interval(0, float('inf')),
        },
        return_interval=Interval(0.0, 1.0),
        preconditions=[],
        postconditions=[
            ("kbd_created", "Kaiser-Bessel derived window created"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create Kaiser-Bessel derived window",
    ))


# ============================================================================
# torch.ao - Architecture Optimization
# ============================================================================

def _register_ao(registry: ContractRegistry) -> None:
    """Register torch.ao (architecture optimization) contracts."""
    
    # torch.ao.nn.qat - Quantization Aware Training modules
    qat_modules = [
        "Linear", "Conv1d", "Conv2d", "Conv3d",
        "ConvBn1d", "ConvBn2d", "ConvBn3d",
        "ConvBnReLU1d", "ConvBnReLU2d", "ConvBnReLU3d",
        "ConvReLU1d", "ConvReLU2d", "ConvReLU3d",
    ]
    
    for mod in qat_modules:
        registry.register(ModuleContract(
            name=f"torch.ao.nn.qat.{mod}",
            qualname=f"torch.ao.nn.qat.{mod}",
            init_param_names=["*args", "qconfig", "**kwargs"],
            init_param_intervals={},
            forward_return_interval=None,
            forward_requires_same_device=True,
            forward_preserves_device=True,
            state_invariants=[
                ("qat_enabled", "QAT fake quantization enabled"),
            ],
            docstring=f"QAT version of {mod}",
        ))
    
    # torch.ao.nn.quantized modules
    quantized_modules = [
        "Linear", "Conv1d", "Conv2d", "Conv3d",
        "BatchNorm2d", "BatchNorm3d",
        "ReLU", "ReLU6", "Sigmoid", "Hardtanh", "LeakyReLU",
        "Embedding", "EmbeddingBag",
        "LSTM", "GRU", "LSTMCell", "GRUCell",
    ]
    
    for mod in quantized_modules:
        registry.register(ModuleContract(
            name=f"torch.ao.nn.quantized.{mod}",
            qualname=f"torch.ao.nn.quantized.{mod}",
            init_param_names=["*args", "**kwargs"],
            init_param_intervals={},
            forward_return_interval=None,
            forward_requires_same_device=True,
            forward_preserves_device=True,
            state_invariants=[
                ("quantized", "Weights are quantized"),
            ],
            docstring=f"Quantized version of {mod}",
        ))
    
    # torch.ao.nn.quantized.dynamic modules
    dynamic_modules = ["Linear", "LSTM", "GRU", "LSTMCell", "GRUCell"]
    
    for mod in dynamic_modules:
        registry.register(ModuleContract(
            name=f"torch.ao.nn.quantized.dynamic.{mod}",
            qualname=f"torch.ao.nn.quantized.dynamic.{mod}",
            init_param_names=["*args", "**kwargs"],
            init_param_intervals={},
            forward_return_interval=None,
            forward_requires_same_device=True,
            forward_preserves_device=True,
            state_invariants=[
                ("dynamic_quant", "Dynamic quantization applied"),
            ],
            docstring=f"Dynamically quantized {mod}",
        ))
    
    # torch.ao.ns (numeric suite) for debugging quantization
    registry.register(FunctionContract(
        name="torch.ao.ns.extract_single_layer_model",
        qualname="torch.ao.ns.extract_single_layer_model",
        param_names=["model", "layer_name"],
        param_intervals={},
        return_interval=None,  # Returns extracted model
        preconditions=[
            ("layer_exists", "layer_name must exist in model"),
        ],
        postconditions=[
            ("layer_extracted", "Single layer model extracted"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Extract single layer for numeric comparison",
    ))
    
    # torch.ao.ns.compare_model_outputs
    registry.register(FunctionContract(
        name="torch.ao.ns.compare_model_outputs",
        qualname="torch.ao.ns.compare_model_outputs",
        param_names=["model1", "model2", "sample_input"],
        param_intervals={},
        return_interval=None,  # Returns comparison dict
        preconditions=[],
        postconditions=[
            ("compared", "Model outputs compared"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Compare outputs of two models",
    ))
    
    # torch.ao.pruning
    registry.register(FunctionContract(
        name="torch.ao.pruning.sparsify",
        qualname="torch.ao.pruning.sparsify",
        param_names=["model", "config"],
        param_intervals={},
        return_interval=None,  # Returns sparse model
        preconditions=[],
        postconditions=[
            ("sparsified", "Model weights sparsified"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Apply sparsity to model weights",
    ))


# ============================================================================
# torch.nn.utils.prune - Pruning Utilities
# ============================================================================

def _register_prune(registry: ContractRegistry) -> None:
    """Register pruning utility contracts."""
    
    # torch.nn.utils.prune.l1_unstructured
    registry.register(FunctionContract(
        name="torch.nn.utils.prune.l1_unstructured",
        qualname="torch.nn.utils.prune.l1_unstructured",
        param_names=["module", "name", "amount"],
        param_intervals={
            "amount": Interval(0.0, 1.0),
        },
        return_interval=None,  # Returns module
        preconditions=[
            ("has_param", "module must have parameter 'name'"),
        ],
        postconditions=[
            ("pruned", "L1 unstructured pruning applied"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Apply L1 unstructured pruning",
    ))
    
    # torch.nn.utils.prune.random_unstructured
    registry.register(FunctionContract(
        name="torch.nn.utils.prune.random_unstructured",
        qualname="torch.nn.utils.prune.random_unstructured",
        param_names=["module", "name", "amount"],
        param_intervals={
            "amount": Interval(0.0, 1.0),
        },
        return_interval=None,
        preconditions=[
            ("has_param", "module must have parameter 'name'"),
        ],
        postconditions=[
            ("pruned", "Random unstructured pruning applied"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Apply random unstructured pruning",
    ))
    
    # torch.nn.utils.prune.ln_structured
    registry.register(FunctionContract(
        name="torch.nn.utils.prune.ln_structured",
        qualname="torch.nn.utils.prune.ln_structured",
        param_names=["module", "name", "amount", "n", "dim"],
        param_intervals={
            "amount": Interval(0.0, 1.0),
        },
        return_interval=None,
        preconditions=[
            ("has_param", "module must have parameter 'name'"),
        ],
        postconditions=[
            ("structured_pruned", "Ln structured pruning applied"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Apply Ln structured pruning along dimension",
    ))
    
    # torch.nn.utils.prune.random_structured
    registry.register(FunctionContract(
        name="torch.nn.utils.prune.random_structured",
        qualname="torch.nn.utils.prune.random_structured",
        param_names=["module", "name", "amount", "dim"],
        param_intervals={
            "amount": Interval(0.0, 1.0),
        },
        return_interval=None,
        preconditions=[
            ("has_param", "module must have parameter 'name'"),
        ],
        postconditions=[
            ("random_structured", "Random structured pruning applied"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Apply random structured pruning",
    ))
    
    # torch.nn.utils.prune.global_unstructured
    registry.register(FunctionContract(
        name="torch.nn.utils.prune.global_unstructured",
        qualname="torch.nn.utils.prune.global_unstructured",
        param_names=["parameters", "pruning_method", "amount"],
        param_intervals={
            "amount": Interval(0.0, 1.0),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("globally_pruned", "Global unstructured pruning applied"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Apply global unstructured pruning across parameters",
    ))
    
    # torch.nn.utils.prune.remove
    registry.register(FunctionContract(
        name="torch.nn.utils.prune.remove",
        qualname="torch.nn.utils.prune.remove",
        param_names=["module", "name"],
        param_intervals={},
        return_interval=None,  # Returns module
        preconditions=[
            ("is_pruned", "Parameter must be pruned"),
        ],
        postconditions=[
            ("pruning_removed", "Pruning reparameterization removed"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Remove pruning reparameterization",
    ))
    
    # torch.nn.utils.prune.is_pruned
    registry.register(FunctionContract(
        name="torch.nn.utils.prune.is_pruned",
        qualname="torch.nn.utils.prune.is_pruned",
        param_names=["module"],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if any parameter pruned"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if module has any pruned parameters",
    ))


# ============================================================================
# torch.serialization - Advanced Serialization
# ============================================================================

def _register_serialization(registry: ContractRegistry) -> None:
    """Register serialization contracts."""
    
    # torch.save (comprehensive)
    registry.register(FunctionContract(
        name="torch.save",
        qualname="torch.save",
        param_names=["obj", "f", "pickle_module", "pickle_protocol",
                    "_use_new_zipfile_serialization", "_disable_byteorder_record"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("serializable", "obj must be serializable"),
        ],
        postconditions=[
            ("saved", "Object saved to file"),
        ],
        requires_same_device=False,
        may_raise=["IOError", "PicklingError"],
        docstring="Save object to file",
    ))
    
    # torch.load (comprehensive)
    registry.register(FunctionContract(
        name="torch.load",
        qualname="torch.load",
        param_names=["f", "map_location", "pickle_module", "weights_only",
                    "mmap", "**pickle_load_args"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("file_exists", "f must exist or be file-like"),
        ],
        postconditions=[
            ("loaded", "Object loaded from file"),
            ("device_mapped", "Tensors moved to map_location"),
        ],
        requires_same_device=False,
        may_raise=["IOError", "UnpicklingError"],
        docstring="Load object from file with optional device mapping",
    ))
    
    # torch.serialization.register_package
    registry.register(FunctionContract(
        name="torch.serialization.register_package",
        qualname="torch.serialization.register_package",
        param_names=["priority", "tagger", "deserializer"],
        param_intervals={
            "priority": Interval(0, float('inf')),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("package_registered", "Serialization package registered"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Register custom serialization package",
    ))
    
    # torch.get_default_dtype
    registry.register(FunctionContract(
        name="torch.get_default_dtype",
        qualname="torch.get_default_dtype",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns dtype
        preconditions=[],
        postconditions=[
            ("dtype_returned", "Returns default float dtype"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get default floating point dtype",
    ))
    
    # torch.set_default_dtype
    registry.register(FunctionContract(
        name="torch.set_default_dtype",
        qualname="torch.set_default_dtype",
        param_names=["d"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("float_dtype", "d must be floating point dtype"),
        ],
        postconditions=[
            ("dtype_set", "Default dtype updated"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set default floating point dtype",
    ))
    
    # torch.get_default_device  
    registry.register(FunctionContract(
        name="torch.get_default_device",
        qualname="torch.get_default_device",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns device
        preconditions=[],
        postconditions=[
            ("device_returned", "Returns default device"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get default device for tensor creation",
    ))
    
    # torch.set_default_device
    registry.register(FunctionContract(
        name="torch.set_default_device",
        qualname="torch.set_default_device",
        param_names=["device"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_device", "device must be valid"),
        ],
        postconditions=[
            ("device_set", "Default device updated"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set default device for tensor creation",
    ))


# ============================================================================
# torch.overrides - Operator Overloading
# ============================================================================

def _register_overrides(registry: ContractRegistry) -> None:
    """Register torch override contracts."""
    
    # torch.overrides.get_overridable_functions
    registry.register(FunctionContract(
        name="torch.overrides.get_overridable_functions",
        qualname="torch.overrides.get_overridable_functions",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns dict
        preconditions=[],
        postconditions=[
            ("functions_returned", "Returns overridable functions dict"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get all __torch_function__ overridable functions",
    ))
    
    # torch.overrides.get_testing_overrides
    registry.register(FunctionContract(
        name="torch.overrides.get_testing_overrides",
        qualname="torch.overrides.get_testing_overrides",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns dict
        preconditions=[],
        postconditions=[
            ("overrides_returned", "Returns testing overrides dict"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get testing overrides for __torch_function__",
    ))
    
    # torch.overrides.handle_torch_function
    registry.register(FunctionContract(
        name="torch.overrides.handle_torch_function",
        qualname="torch.overrides.handle_torch_function",
        param_names=["public_api", "relevant_args", "*args", "**kwargs"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("handled", "__torch_function__ dispatch handled"),
        ],
        requires_same_device=False,
        may_raise=["TypeError"],
        docstring="Handle __torch_function__ dispatch",
    ))
    
    # torch.overrides.has_torch_function
    registry.register(FunctionContract(
        name="torch.overrides.has_torch_function",
        qualname="torch.overrides.has_torch_function",
        param_names=["relevant_args"],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if any arg has __torch_function__"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if any argument has __torch_function__",
    ))
    
    # torch.overrides.is_tensor_like
    registry.register(FunctionContract(
        name="torch.overrides.is_tensor_like",
        qualname="torch.overrides.is_tensor_like",
        param_names=["inp"],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if inp is tensor-like"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if input is tensor-like",
    ))
    
    # torch.overrides.wrap_torch_function
    registry.register(FunctionContract(
        name="torch.overrides.wrap_torch_function",
        qualname="torch.overrides.wrap_torch_function",
        param_names=["dispatcher"],
        param_intervals={},
        return_interval=None,  # Decorator
        preconditions=[],
        postconditions=[
            ("wrapped", "Function wrapped with __torch_function__ dispatch"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Decorator to add __torch_function__ dispatch",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_experimental_contracts(registry: ContractRegistry) -> None:
    """
    Register all experimental and advanced API contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_masked(registry)
    _register_func(registry)
    _register_signal(registry)
    _register_ao(registry)
    _register_prune(registry)
    _register_serialization(registry)
    _register_overrides(registry)


# Export
__all__ = [
    "register_experimental_contracts",
]
