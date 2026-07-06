"""
PyTorch Utilities Contracts - torch.utils.*

This module provides contracts for PyTorch utility modules:
- torch.utils.checkpoint (gradient checkpointing)
- torch.utils.bottleneck (profiling)
- torch.utils.hooks (debugging hooks)
- torch.utils.cpp_extension (C++/CUDA extensions)
- torch.utils.tensorboard (TensorBoard logging)
- torch.utils.benchmark (microbenchmarking)
- torch.utils.model_zoo (pretrained model loading)

Device Barrier Considerations:
- Checkpoint functions preserve device placement
- TensorBoard logging handles tensors from any device
- Benchmarking can test device-specific performance
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
# Gradient Checkpointing
# ============================================================================

def _register_checkpoint(registry: ContractRegistry) -> None:
    """Register gradient checkpointing contracts."""
    
    # torch.utils.checkpoint.checkpoint
    registry.register(FunctionContract(
        name="torch.utils.checkpoint.checkpoint",
        qualname="torch.utils.checkpoint.checkpoint",
        param_names=["function", "*args", "use_reentrant", "context_fn",
                    "determinism_check", "debug", "preserve_rng_state"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("function_callable", "function must be callable"),
            ("requires_grad", "At least one input should require grad"),
        ],
        postconditions=[
            ("forward_executed", "Forward pass computed"),
            ("activations_not_saved", "Intermediate activations not saved"),
        ],
        requires_same_device=True,  # Inputs/outputs same device
        may_raise=["RuntimeError"],
        docstring="Checkpoint a function to save memory (recompute in backward)",
    ))
    
    # torch.utils.checkpoint.checkpoint_sequential
    registry.register(FunctionContract(
        name="torch.utils.checkpoint.checkpoint_sequential",
        qualname="torch.utils.checkpoint.checkpoint_sequential",
        param_names=["functions", "segments", "input", "use_reentrant",
                    "preserve_rng_state"],
        param_intervals={
            "segments": Interval(1, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("functions_sequential", "functions must be Sequential or list"),
        ],
        postconditions=[
            ("checkpointed", "Sequential computation checkpointed"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Checkpoint sequential computation in segments",
    ))
    
    # torch.utils.checkpoint.set_checkpoint_early_stop
    registry.register(FunctionContract(
        name="torch.utils.checkpoint.set_checkpoint_early_stop",
        qualname="torch.utils.checkpoint.set_checkpoint_early_stop",
        param_names=["enable"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("early_stop_set", "Early stop behavior configured"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Enable/disable early stopping for checkpointing",
    ))


# ============================================================================
# Benchmark
# ============================================================================

def _register_benchmark(registry: ContractRegistry) -> None:
    """Register benchmarking contracts."""
    
    # torch.utils.benchmark.Timer
    registry.register(ModuleContract(
        name="torch.utils.benchmark.Timer",
        qualname="torch.utils.benchmark.Timer",
        init_param_names=["stmt", "setup", "global_setup", "timer", "globals",
                         "label", "sub_label", "description", "env",
                         "num_threads", "language"],
        init_param_intervals={
            "num_threads": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("timer_ready", "Timer ready to measure"),
        ],
        docstring="Timer for microbenchmarking",
    ))
    
    # Timer.timeit
    registry.register(MethodContract(
        name="torch.utils.benchmark.Timer.timeit",
        qualname="torch.utils.benchmark.Timer.timeit",
        param_names=["self", "number"],
        param_intervals={
            "number": Interval(1, float('inf')),
        },
        return_interval=None,  # Returns Measurement
        preconditions=[],
        postconditions=[
            ("measured", "Returns timing measurement"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Run timer and return measurement",
    ))
    
    # Timer.blocked_autorange
    registry.register(MethodContract(
        name="torch.utils.benchmark.Timer.blocked_autorange",
        qualname="torch.utils.benchmark.Timer.blocked_autorange",
        param_names=["self", "callback", "min_run_time"],
        param_intervals={
            "min_run_time": Interval(0.0, float('inf')),
        },
        return_interval=None,  # Returns Measurement
        preconditions=[],
        postconditions=[
            ("autoranged", "Automatically determines iteration count"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Time with automatic iteration count",
    ))
    
    # Timer.adaptive_autorange
    registry.register(MethodContract(
        name="torch.utils.benchmark.Timer.adaptive_autorange",
        qualname="torch.utils.benchmark.Timer.adaptive_autorange",
        param_names=["self", "threshold", "max_run_time", "callback", "min_run_time"],
        param_intervals={
            "threshold": Interval(0.0, 1.0),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("adaptive_measured", "Adaptive measurement complete"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Adaptive timing with convergence threshold",
    ))
    
    # Compare
    registry.register(ModuleContract(
        name="torch.utils.benchmark.Compare",
        qualname="torch.utils.benchmark.Compare",
        init_param_names=["results"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("results_stored", "Comparison results stored"),
        ],
        docstring="Compare benchmark results",
    ))
    
    # Compare.print
    registry.register(MethodContract(
        name="torch.utils.benchmark.Compare.print",
        qualname="torch.utils.benchmark.Compare.print",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("printed", "Comparison table printed"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Print comparison table",
    ))


# ============================================================================
# TensorBoard
# ============================================================================

def _register_tensorboard(registry: ContractRegistry) -> None:
    """Register TensorBoard contracts."""
    
    # torch.utils.tensorboard.SummaryWriter
    registry.register(ModuleContract(
        name="torch.utils.tensorboard.SummaryWriter",
        qualname="torch.utils.tensorboard.SummaryWriter",
        init_param_names=["log_dir", "comment", "purge_step", "max_queue",
                         "flush_secs", "filename_suffix"],
        init_param_intervals={
            "max_queue": Interval(1, float('inf')),
            "flush_secs": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("log_dir_set", "Log directory configured"),
        ],
        docstring="TensorBoard summary writer",
    ))
    
    # SummaryWriter.add_scalar
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_scalar",
        qualname="torch.utils.tensorboard.SummaryWriter.add_scalar",
        param_names=["self", "tag", "scalar_value", "global_step", "walltime",
                    "new_style", "double_precision"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("scalar_logged", "Scalar value logged"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Log scalar value",
    ))
    
    # SummaryWriter.add_scalars
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_scalars",
        qualname="torch.utils.tensorboard.SummaryWriter.add_scalars",
        param_names=["self", "main_tag", "tag_scalar_dict", "global_step", "walltime"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("scalars_logged", "Multiple scalars logged"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Log multiple scalar values",
    ))
    
    # SummaryWriter.add_histogram
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_histogram",
        qualname="torch.utils.tensorboard.SummaryWriter.add_histogram",
        param_names=["self", "tag", "values", "global_step", "bins", "walltime",
                    "max_bins"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("histogram_logged", "Histogram logged"),
        ],
        requires_same_device=False,  # Converts to CPU for logging
        may_raise=[],
        docstring="Log histogram",
    ))
    
    # SummaryWriter.add_image
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_image",
        qualname="torch.utils.tensorboard.SummaryWriter.add_image",
        param_names=["self", "tag", "img_tensor", "global_step", "walltime",
                    "dataformats"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_image", "img_tensor must be 2D or 3D"),
        ],
        postconditions=[
            ("image_logged", "Image logged"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Log image",
    ))
    
    # SummaryWriter.add_images
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_images",
        qualname="torch.utils.tensorboard.SummaryWriter.add_images",
        param_names=["self", "tag", "img_tensor", "global_step", "walltime",
                    "dataformats"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_images", "img_tensor must be 3D or 4D batch"),
        ],
        postconditions=[
            ("images_logged", "Images logged"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Log batch of images",
    ))
    
    # SummaryWriter.add_figure
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_figure",
        qualname="torch.utils.tensorboard.SummaryWriter.add_figure",
        param_names=["self", "tag", "figure", "global_step", "close", "walltime"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("matplotlib_figure", "figure must be matplotlib Figure"),
        ],
        postconditions=[
            ("figure_logged", "Matplotlib figure logged"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Log matplotlib figure",
    ))
    
    # SummaryWriter.add_video
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_video",
        qualname="torch.utils.tensorboard.SummaryWriter.add_video",
        param_names=["self", "tag", "vid_tensor", "global_step", "fps", "walltime"],
        param_intervals={
            "fps": Interval(1, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("5d_tensor", "vid_tensor must be 5D (N,T,C,H,W)"),
        ],
        postconditions=[
            ("video_logged", "Video logged"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Log video",
    ))
    
    # SummaryWriter.add_audio
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_audio",
        qualname="torch.utils.tensorboard.SummaryWriter.add_audio",
        param_names=["self", "tag", "snd_tensor", "global_step", "sample_rate",
                    "walltime"],
        param_intervals={
            "sample_rate": Interval(1, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("1d_tensor", "snd_tensor must be 1D"),
        ],
        postconditions=[
            ("audio_logged", "Audio logged"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Log audio",
    ))
    
    # SummaryWriter.add_text
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_text",
        qualname="torch.utils.tensorboard.SummaryWriter.add_text",
        param_names=["self", "tag", "text_string", "global_step", "walltime"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("text_logged", "Text logged"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Log text",
    ))
    
    # SummaryWriter.add_graph
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_graph",
        qualname="torch.utils.tensorboard.SummaryWriter.add_graph",
        param_names=["self", "model", "input_to_model", "verbose", "use_strict_trace"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("model_callable", "model must be callable"),
        ],
        postconditions=[
            ("graph_logged", "Model graph logged"),
        ],
        requires_same_device=True,  # Model and input same device
        may_raise=["RuntimeError"],
        docstring="Log model graph",
    ))
    
    # SummaryWriter.add_embedding
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_embedding",
        qualname="torch.utils.tensorboard.SummaryWriter.add_embedding",
        param_names=["self", "mat", "metadata", "label_img", "global_step", "tag",
                    "metadata_header"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("2d_mat", "mat must be 2D (N, D)"),
        ],
        postconditions=[
            ("embedding_logged", "Embedding projector data logged"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Log embedding for TensorBoard projector",
    ))
    
    # SummaryWriter.add_pr_curve
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_pr_curve",
        qualname="torch.utils.tensorboard.SummaryWriter.add_pr_curve",
        param_names=["self", "tag", "labels", "predictions", "global_step",
                    "num_thresholds", "weights", "walltime"],
        param_intervals={
            "num_thresholds": Interval(1, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("labels_binary", "labels must be binary"),
            ("predictions_prob", "predictions must be probabilities"),
        ],
        postconditions=[
            ("pr_curve_logged", "Precision-recall curve logged"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Log precision-recall curve",
    ))
    
    # SummaryWriter.add_hparams
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_hparams",
        qualname="torch.utils.tensorboard.SummaryWriter.add_hparams",
        param_names=["self", "hparam_dict", "metric_dict", "hparam_domain_discrete",
                    "run_name", "global_step"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("hparams_logged", "Hyperparameters and metrics logged"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Log hyperparameters",
    ))
    
    # SummaryWriter.add_mesh
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.add_mesh",
        qualname="torch.utils.tensorboard.SummaryWriter.add_mesh",
        param_names=["self", "tag", "vertices", "colors", "faces", "config_dict",
                    "global_step", "walltime"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("vertices_3d", "vertices must be (N, V, 3)"),
        ],
        postconditions=[
            ("mesh_logged", "3D mesh logged"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Log 3D mesh",
    ))
    
    # SummaryWriter.flush
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.flush",
        qualname="torch.utils.tensorboard.SummaryWriter.flush",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("flushed", "All pending events written to disk"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Flush pending events to disk",
    ))
    
    # SummaryWriter.close
    registry.register(MethodContract(
        name="torch.utils.tensorboard.SummaryWriter.close",
        qualname="torch.utils.tensorboard.SummaryWriter.close",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("closed", "Writer closed"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Close writer",
    ))


# ============================================================================
# C++/CUDA Extensions
# ============================================================================

def _register_cpp_extension(registry: ContractRegistry) -> None:
    """Register C++/CUDA extension contracts."""
    
    # torch.utils.cpp_extension.load
    registry.register(FunctionContract(
        name="torch.utils.cpp_extension.load",
        qualname="torch.utils.cpp_extension.load",
        param_names=["name", "sources", "extra_cflags", "extra_cuda_cflags",
                    "extra_ldflags", "extra_include_paths", "build_directory",
                    "verbose", "with_cuda", "is_python_module", "is_standalone",
                    "keep_intermediates"],
        param_intervals={},
        return_interval=None,  # Returns loaded module
        preconditions=[
            ("sources_exist", "Source files must exist"),
            ("compiler_available", "C++ compiler must be available"),
        ],
        postconditions=[
            ("module_loaded", "C++ extension module loaded"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "CompilerError"],
        docstring="JIT compile and load C++/CUDA extension",
    ))
    
    # torch.utils.cpp_extension.load_inline
    registry.register(FunctionContract(
        name="torch.utils.cpp_extension.load_inline",
        qualname="torch.utils.cpp_extension.load_inline",
        param_names=["name", "cpp_sources", "cuda_sources", "functions",
                    "extra_cflags", "extra_cuda_cflags", "extra_ldflags",
                    "extra_include_paths", "build_directory", "verbose",
                    "with_cuda", "is_python_module", "with_pytorch_error_handling",
                    "keep_intermediates"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_sources", "Source code must be valid"),
        ],
        postconditions=[
            ("inline_loaded", "Inline extension loaded"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="JIT compile inline C++/CUDA code",
    ))
    
    # torch.utils.cpp_extension.CppExtension
    registry.register(FunctionContract(
        name="torch.utils.cpp_extension.CppExtension",
        qualname="torch.utils.cpp_extension.CppExtension",
        param_names=["name", "sources", "*args", "**kwargs"],
        param_intervals={},
        return_interval=None,  # Returns Extension object
        preconditions=[],
        postconditions=[
            ("extension_created", "Extension object for setup.py"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create C++ extension for setup.py",
    ))
    
    # torch.utils.cpp_extension.CUDAExtension
    registry.register(FunctionContract(
        name="torch.utils.cpp_extension.CUDAExtension",
        qualname="torch.utils.cpp_extension.CUDAExtension",
        param_names=["name", "sources", "*args", "**kwargs"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("cuda_available", "CUDA must be available"),
        ],
        postconditions=[
            ("cuda_extension_created", "CUDA extension object created"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create CUDA extension for setup.py",
    ))
    
    # torch.utils.cpp_extension.BuildExtension
    registry.register(ModuleContract(
        name="torch.utils.cpp_extension.BuildExtension",
        qualname="torch.utils.cpp_extension.BuildExtension",
        init_param_names=["*args", "**kwargs"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="Custom build_ext for C++/CUDA extensions",
    ))


# ============================================================================
# Model Zoo
# ============================================================================

def _register_model_zoo(registry: ContractRegistry) -> None:
    """Register model zoo contracts."""
    
    # torch.utils.model_zoo.load_url (deprecated, use hub.load_state_dict_from_url)
    registry.register(FunctionContract(
        name="torch.utils.model_zoo.load_url",
        qualname="torch.utils.model_zoo.load_url",
        param_names=["url", "model_dir", "map_location", "progress", "check_hash",
                    "file_name", "weights_only"],
        param_intervals={},
        return_interval=None,  # Returns state dict
        preconditions=[
            ("url_valid", "URL must be valid"),
        ],
        postconditions=[
            ("weights_downloaded", "Weights downloaded and loaded"),
        ],
        requires_same_device=False,  # map_location handles device
        may_raise=["RuntimeError", "HTTPError"],
        docstring="Download and load pretrained weights from URL",
    ))


# ============================================================================
# Hooks
# ============================================================================

def _register_hooks(registry: ContractRegistry) -> None:
    """Register hook utility contracts."""
    
    # torch.utils.hooks.RemovableHandle
    registry.register(ModuleContract(
        name="torch.utils.hooks.RemovableHandle",
        qualname="torch.utils.hooks.RemovableHandle",
        init_param_names=["hooks_dict"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("handle_valid", "Handle references registered hook"),
        ],
        docstring="Handle for removing registered hooks",
    ))
    
    # RemovableHandle.remove
    registry.register(MethodContract(
        name="torch.utils.hooks.RemovableHandle.remove",
        qualname="torch.utils.hooks.RemovableHandle.remove",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("hook_removed", "Hook is removed from registry"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Remove the registered hook",
    ))


# ============================================================================
# Collect Environment
# ============================================================================

def _register_collect_env(registry: ContractRegistry) -> None:
    """Register environment collection contracts."""
    
    # torch.utils.collect_env.get_pretty_env_info
    registry.register(FunctionContract(
        name="torch.utils.collect_env.get_pretty_env_info",
        qualname="torch.utils.collect_env.get_pretty_env_info",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[],
        postconditions=[
            ("info_collected", "Environment info collected"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get formatted environment information",
    ))


# ============================================================================
# Nested Tensor (experimental)
# ============================================================================

def _register_nested_tensor(registry: ContractRegistry) -> None:
    """Register nested tensor contracts."""
    
    # torch.nested.nested_tensor
    registry.register(FunctionContract(
        name="torch.nested.nested_tensor",
        qualname="torch.nested.nested_tensor",
        param_names=["tensor_list", "dtype", "layout", "device", "requires_grad",
                    "pin_memory"],
        param_intervals={},
        return_interval=None,  # Returns NestedTensor
        preconditions=[
            ("consistent_dims", "All tensors must have same number of dims"),
        ],
        postconditions=[
            ("nested_created", "Nested tensor created"),
        ],
        requires_same_device=True,  # All tensors same device
        may_raise=["RuntimeError"],
        docstring="Create nested tensor from list of tensors",
    ))
    
    # torch.nested.as_nested_tensor
    registry.register(FunctionContract(
        name="torch.nested.as_nested_tensor",
        qualname="torch.nested.as_nested_tensor",
        param_names=["tensor_list", "dtype", "layout", "device"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("nested_view", "Returns nested tensor view"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Create nested tensor view (no copy if possible)",
    ))
    
    # torch.nested.to_padded_tensor
    registry.register(FunctionContract(
        name="torch.nested.to_padded_tensor",
        qualname="torch.nested.to_padded_tensor",
        param_names=["input", "padding", "output_size"],
        param_intervals={},
        return_interval=None,  # Returns padded regular tensor
        preconditions=[
            ("is_nested", "input must be nested tensor"),
        ],
        postconditions=[
            ("padded", "Returns padded regular tensor"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert nested tensor to padded regular tensor",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_utils_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.utils.* contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_checkpoint(registry)
    _register_benchmark(registry)
    _register_tensorboard(registry)
    _register_cpp_extension(registry)
    _register_model_zoo(registry)
    _register_hooks(registry)
    _register_collect_env(registry)
    _register_nested_tensor(registry)


# Export
__all__ = [
    "register_utils_contracts",
]
