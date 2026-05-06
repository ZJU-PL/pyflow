"""
PyTorch CUDA Contracts - torch.cuda

This module provides contracts for PyTorch's CUDA operations:
- Device management
- Memory management
- Streams and events
- CUDA graphs
- Communication collectives
- Random number generation

Device Barrier Considerations:
- CUDA operations must be performed on CUDA tensors
- Cross-device operations may require explicit synchronization
- Memory operations affect specific GPU devices
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
# Device Management
# ============================================================================

def _register_device_management(registry: ContractRegistry) -> None:
    """Register CUDA device management contracts."""
    
    # torch.cuda.is_available
    registry.register(FunctionContract(
        name="torch.cuda.is_available",
        qualname="torch.cuda.is_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if CUDA is available",
    ))
    
    # torch.cuda.device_count
    registry.register(FunctionContract(
        name="torch.cuda.device_count",
        qualname="torch.cuda.device_count",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, 16),  # Practical GPU count limit
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return number of available CUDA devices",
    ))
    
    # torch.cuda.current_device
    registry.register(FunctionContract(
        name="torch.cuda.current_device",
        qualname="torch.cuda.current_device",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, 15),  # Device index
        preconditions=[
            ("cuda_available", "CUDA must be available"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return current CUDA device index",
    ))
    
    # torch.cuda.set_device
    registry.register(FunctionContract(
        name="torch.cuda.set_device",
        qualname="torch.cuda.set_device",
        param_names=["device"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_device", "device must be valid index or device object"),
        ],
        postconditions=[
            ("device_set", "Current device is set"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set current CUDA device",
    ))
    
    # torch.cuda.device (context manager)
    registry.register(FunctionContract(
        name="torch.cuda.device",
        qualname="torch.cuda.device",
        param_names=["device"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_device", "device must be valid"),
        ],
        postconditions=[
            ("device_context", "Device set for duration of context"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Context manager for CUDA device",
    ))
    
    # torch.cuda.get_device_name
    registry.register(FunctionContract(
        name="torch.cuda.get_device_name",
        qualname="torch.cuda.get_device_name",
        param_names=["device"],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[
            ("valid_device", "device must be valid index"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return name of CUDA device",
    ))
    
    # torch.cuda.get_device_capability
    registry.register(FunctionContract(
        name="torch.cuda.get_device_capability",
        qualname="torch.cuda.get_device_capability",
        param_names=["device"],
        param_intervals={},
        return_interval=None,  # Returns (major, minor) tuple
        preconditions=[
            ("valid_device", "device must be valid index"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return compute capability of CUDA device",
    ))
    
    # torch.cuda.get_device_properties
    registry.register(FunctionContract(
        name="torch.cuda.get_device_properties",
        qualname="torch.cuda.get_device_properties",
        param_names=["device"],
        param_intervals={},
        return_interval=None,  # Returns CudaDeviceProperties
        preconditions=[
            ("valid_device", "device must be valid"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return properties of CUDA device",
    ))
    
    # torch.cuda.get_arch_list
    registry.register(FunctionContract(
        name="torch.cuda.get_arch_list",
        qualname="torch.cuda.get_arch_list",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns list of arch strings
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return list of CUDA architectures built for",
    ))


# ============================================================================
# Memory Management
# ============================================================================

def _register_memory_management(registry: ContractRegistry) -> None:
    """Register CUDA memory management contracts."""
    
    # torch.cuda.empty_cache
    registry.register(FunctionContract(
        name="torch.cuda.empty_cache",
        qualname="torch.cuda.empty_cache",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("cache_cleared", "Unused cached memory released"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Release all cached memory from allocator",
    ))
    
    # torch.cuda.memory_allocated
    registry.register(FunctionContract(
        name="torch.cuda.memory_allocated",
        qualname="torch.cuda.memory_allocated",
        param_names=["device"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),  # Bytes
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return current GPU memory occupied by tensors (bytes)",
    ))
    
    # torch.cuda.max_memory_allocated
    registry.register(FunctionContract(
        name="torch.cuda.max_memory_allocated",
        qualname="torch.cuda.max_memory_allocated",
        param_names=["device"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return peak GPU memory allocated by tensors (bytes)",
    ))
    
    # torch.cuda.reset_max_memory_allocated
    registry.register(FunctionContract(
        name="torch.cuda.reset_max_memory_allocated",
        qualname="torch.cuda.reset_max_memory_allocated",
        param_names=["device"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("peak_reset", "Peak memory counter reset"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Reset peak memory stats",
    ))
    
    # torch.cuda.memory_reserved
    registry.register(FunctionContract(
        name="torch.cuda.memory_reserved",
        qualname="torch.cuda.memory_reserved",
        param_names=["device"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return current GPU memory cached by allocator (bytes)",
    ))
    
    # torch.cuda.max_memory_reserved
    registry.register(FunctionContract(
        name="torch.cuda.max_memory_reserved",
        qualname="torch.cuda.max_memory_reserved",
        param_names=["device"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return peak GPU memory cached by allocator (bytes)",
    ))
    
    # torch.cuda.reset_peak_memory_stats
    registry.register(FunctionContract(
        name="torch.cuda.reset_peak_memory_stats",
        qualname="torch.cuda.reset_peak_memory_stats",
        param_names=["device"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("stats_reset", "All peak memory stats reset"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Reset all peak memory stats",
    ))
    
    # torch.cuda.memory_stats
    registry.register(FunctionContract(
        name="torch.cuda.memory_stats",
        qualname="torch.cuda.memory_stats",
        param_names=["device"],
        param_intervals={},
        return_interval=None,  # Returns dict
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return dictionary of CUDA memory allocator stats",
    ))
    
    # torch.cuda.memory_summary
    registry.register(FunctionContract(
        name="torch.cuda.memory_summary",
        qualname="torch.cuda.memory_summary",
        param_names=["device", "abbreviated"],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return human-readable memory summary",
    ))
    
    # torch.cuda.memory_snapshot
    registry.register(FunctionContract(
        name="torch.cuda.memory_snapshot",
        qualname="torch.cuda.memory_snapshot",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns list
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return snapshot of CUDA memory allocator state",
    ))
    
    # torch.cuda.set_per_process_memory_fraction
    registry.register(FunctionContract(
        name="torch.cuda.set_per_process_memory_fraction",
        qualname="torch.cuda.set_per_process_memory_fraction",
        param_names=["fraction", "device"],
        param_intervals={
            "fraction": Interval(0.0, 1.0),
        },
        return_interval=None,
        preconditions=[
            ("valid_fraction", "fraction must be in [0, 1]"),
        ],
        postconditions=[
            ("limit_set", "Memory limit set for process"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set memory fraction for process",
    ))
    
    # torch.cuda.mem_get_info
    registry.register(FunctionContract(
        name="torch.cuda.mem_get_info",
        qualname="torch.cuda.mem_get_info",
        param_names=["device"],
        param_intervals={},
        return_interval=None,  # Returns (free, total)
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return (free, total) GPU memory in bytes",
    ))


# ============================================================================
# Synchronization
# ============================================================================

def _register_synchronization(registry: ContractRegistry) -> None:
    """Register CUDA synchronization contracts."""
    
    # torch.cuda.synchronize
    registry.register(FunctionContract(
        name="torch.cuda.synchronize",
        qualname="torch.cuda.synchronize",
        param_names=["device"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("all_complete", "All CUDA kernels on device have completed"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Wait for all kernels on device to complete",
    ))
    
    # torch.cuda.current_stream
    registry.register(FunctionContract(
        name="torch.cuda.current_stream",
        qualname="torch.cuda.current_stream",
        param_names=["device"],
        param_intervals={},
        return_interval=None,  # Returns Stream
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return current CUDA stream for device",
    ))
    
    # torch.cuda.default_stream
    registry.register(FunctionContract(
        name="torch.cuda.default_stream",
        qualname="torch.cuda.default_stream",
        param_names=["device"],
        param_intervals={},
        return_interval=None,  # Returns Stream
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return default CUDA stream for device",
    ))
    
    # torch.cuda.set_stream
    registry.register(FunctionContract(
        name="torch.cuda.set_stream",
        qualname="torch.cuda.set_stream",
        param_names=["stream"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_stream", "stream must be valid CUDA stream"),
        ],
        postconditions=[
            ("stream_set", "Current stream is set"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set current CUDA stream",
    ))


# ============================================================================
# Stream Class
# ============================================================================

def _register_stream(registry: ContractRegistry) -> None:
    """Register CUDA Stream class contracts."""
    
    # Stream.__init__
    registry.register(MethodContract(
        name="torch.cuda.Stream.__init__",
        qualname="torch.cuda.Stream.__init__",
        param_names=["self", "device", "priority"],
        param_intervals={
            "priority": Interval(-2, 0),  # CUDA priority range
        },
        return_interval=None,
        preconditions=[
            ("cuda_available", "CUDA must be available"),
        ],
        postconditions=[
            ("stream_created", "CUDA stream is created"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Create CUDA stream",
    ))
    
    # Stream.synchronize
    registry.register(MethodContract(
        name="torch.cuda.Stream.synchronize",
        qualname="torch.cuda.Stream.synchronize",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("stream_complete", "All operations on stream complete"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Wait for all operations on stream to complete",
    ))
    
    # Stream.wait_event
    registry.register(MethodContract(
        name="torch.cuda.Stream.wait_event",
        qualname="torch.cuda.Stream.wait_event",
        param_names=["self", "event"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_event", "event must be valid CUDA event"),
        ],
        postconditions=[
            ("wait_recorded", "Stream will wait for event"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Make stream wait for event",
    ))
    
    # Stream.wait_stream
    registry.register(MethodContract(
        name="torch.cuda.Stream.wait_stream",
        qualname="torch.cuda.Stream.wait_stream",
        param_names=["self", "stream"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_stream", "stream must be valid CUDA stream"),
        ],
        postconditions=[
            ("wait_recorded", "This stream will wait for other stream"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Make this stream wait for another stream",
    ))
    
    # Stream.record_event
    registry.register(MethodContract(
        name="torch.cuda.Stream.record_event",
        qualname="torch.cuda.Stream.record_event",
        param_names=["self", "event"],
        param_intervals={},
        return_interval=None,  # Returns Event
        preconditions=[],
        postconditions=[
            ("event_recorded", "Event recorded on stream"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Record event on stream",
    ))
    
    # Stream.query
    registry.register(MethodContract(
        name="torch.cuda.Stream.query",
        qualname="torch.cuda.Stream.query",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if all operations on stream complete",
    ))


# ============================================================================
# Event Class
# ============================================================================

def _register_event(registry: ContractRegistry) -> None:
    """Register CUDA Event class contracts."""
    
    # Event.__init__
    registry.register(MethodContract(
        name="torch.cuda.Event.__init__",
        qualname="torch.cuda.Event.__init__",
        param_names=["self", "enable_timing", "blocking", "interprocess"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("event_created", "CUDA event is created"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create CUDA event",
    ))
    
    # Event.record
    registry.register(MethodContract(
        name="torch.cuda.Event.record",
        qualname="torch.cuda.Event.record",
        param_names=["self", "stream"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("event_recorded", "Event recorded at current point in stream"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Record event on stream",
    ))
    
    # Event.wait
    registry.register(MethodContract(
        name="torch.cuda.Event.wait",
        qualname="torch.cuda.Event.wait",
        param_names=["self", "stream"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("wait_issued", "Stream will wait for event"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Make stream wait for event",
    ))
    
    # Event.synchronize
    registry.register(MethodContract(
        name="torch.cuda.Event.synchronize",
        qualname="torch.cuda.Event.synchronize",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("event_complete", "Event has completed"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Wait for event to complete",
    ))
    
    # Event.query
    registry.register(MethodContract(
        name="torch.cuda.Event.query",
        qualname="torch.cuda.Event.query",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if event has completed",
    ))
    
    # Event.elapsed_time
    registry.register(MethodContract(
        name="torch.cuda.Event.elapsed_time",
        qualname="torch.cuda.Event.elapsed_time",
        param_names=["self", "end_event"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),  # Milliseconds
        preconditions=[
            ("enable_timing", "Events must have timing enabled"),
            ("recorded", "Both events must be recorded"),
            ("completed", "Both events must be complete"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return elapsed time between events (ms)",
    ))


# ============================================================================
# CUDA Graphs
# ============================================================================

def _register_cuda_graphs(registry: ContractRegistry) -> None:
    """Register CUDA graph contracts."""
    
    # torch.cuda.graph (context manager)
    registry.register(FunctionContract(
        name="torch.cuda.graph",
        qualname="torch.cuda.graph",
        param_names=["cuda_graph", "pool", "stream", "capture_error_mode"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("cuda_11", "CUDA 11+ required for graphs"),
        ],
        postconditions=[
            ("graph_captured", "CUDA operations are captured to graph"),
        ],
        requires_same_device=True,  # All ops must be on same device
        may_raise=["RuntimeError"],
        docstring="Context manager for CUDA graph capture",
    ))
    
    # torch.cuda.make_graphed_callables
    registry.register(FunctionContract(
        name="torch.cuda.make_graphed_callables",
        qualname="torch.cuda.make_graphed_callables",
        param_names=["callables", "sample_args", "num_warmup_iters", "allow_unused_input",
                    "pool", "graph_stream", "capture_error_mode"],
        param_intervals={
            "num_warmup_iters": Interval(0, float('inf')),
        },
        return_interval=None,  # Returns graphed callables
        preconditions=[
            ("same_input_shapes", "Input shapes must be consistent"),
        ],
        postconditions=[
            ("callables_graphed", "Callables are wrapped with CUDA graphs"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Create CUDA graph-wrapped callables",
    ))
    
    # CUDAGraph class
    registry.register(ModuleContract(
        name="torch.cuda.CUDAGraph",
        qualname="torch.cuda.CUDAGraph",
        init_param_names=[],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=True,
        forward_preserves_device=True,
        state_invariants=[
            ("single_device", "All graph operations on same device"),
        ],
        docstring="CUDA graph for capturing and replaying operations",
    ))
    
    # CUDAGraph.capture_begin
    registry.register(MethodContract(
        name="torch.cuda.CUDAGraph.capture_begin",
        qualname="torch.cuda.CUDAGraph.capture_begin",
        param_names=["self", "pool", "capture_error_mode"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("not_capturing", "Graph must not be currently capturing"),
        ],
        postconditions=[
            ("capture_started", "Graph capture has begun"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Begin capturing CUDA graph",
    ))
    
    # CUDAGraph.capture_end
    registry.register(MethodContract(
        name="torch.cuda.CUDAGraph.capture_end",
        qualname="torch.cuda.CUDAGraph.capture_end",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_capturing", "Graph must be capturing"),
        ],
        postconditions=[
            ("capture_ended", "Graph capture completed"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="End capturing CUDA graph",
    ))
    
    # CUDAGraph.replay
    registry.register(MethodContract(
        name="torch.cuda.CUDAGraph.replay",
        qualname="torch.cuda.CUDAGraph.replay",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("graph_captured", "Graph must be captured"),
        ],
        postconditions=[
            ("graph_replayed", "Graph operations are replayed"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Replay captured CUDA graph",
    ))
    
    # CUDAGraph.reset
    registry.register(MethodContract(
        name="torch.cuda.CUDAGraph.reset",
        qualname="torch.cuda.CUDAGraph.reset",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("graph_reset", "Graph is reset and can be recaptured"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Reset CUDA graph",
    ))
    
    # CUDAGraph.debug_dump
    registry.register(MethodContract(
        name="torch.cuda.CUDAGraph.debug_dump",
        qualname="torch.cuda.CUDAGraph.debug_dump",
        param_names=["self", "debug_path"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("graph_captured", "Graph must be captured"),
        ],
        postconditions=[
            ("dump_created", "Debug dump written to path"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Dump CUDA graph for debugging",
    ))


# ============================================================================
# Random Number Generation
# ============================================================================

def _register_rng(registry: ContractRegistry) -> None:
    """Register CUDA RNG contracts."""
    
    # torch.cuda.manual_seed
    registry.register(FunctionContract(
        name="torch.cuda.manual_seed",
        qualname="torch.cuda.manual_seed",
        param_names=["seed"],
        param_intervals={
            "seed": Interval(0, 2**64 - 1),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("seed_set", "RNG seed set for current GPU"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Set RNG seed for current GPU",
    ))
    
    # torch.cuda.manual_seed_all
    registry.register(FunctionContract(
        name="torch.cuda.manual_seed_all",
        qualname="torch.cuda.manual_seed_all",
        param_names=["seed"],
        param_intervals={
            "seed": Interval(0, 2**64 - 1),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("all_seeds_set", "RNG seed set for all GPUs"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Set RNG seed for all GPUs",
    ))
    
    # torch.cuda.seed
    registry.register(FunctionContract(
        name="torch.cuda.seed",
        qualname="torch.cuda.seed",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("seed_random", "RNG seed set randomly for current GPU"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Set RNG to random seed for current GPU",
    ))
    
    # torch.cuda.seed_all
    registry.register(FunctionContract(
        name="torch.cuda.seed_all",
        qualname="torch.cuda.seed_all",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("all_seeds_random", "RNG seed set randomly for all GPUs"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Set RNG to random seed for all GPUs",
    ))
    
    # torch.cuda.initial_seed
    registry.register(FunctionContract(
        name="torch.cuda.initial_seed",
        qualname="torch.cuda.initial_seed",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, 2**64 - 1),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return current random seed for current GPU",
    ))
    
    # torch.cuda.get_rng_state
    registry.register(FunctionContract(
        name="torch.cuda.get_rng_state",
        qualname="torch.cuda.get_rng_state",
        param_names=["device"],
        param_intervals={},
        return_interval=None,  # Returns ByteTensor
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return RNG state for GPU as ByteTensor",
    ))
    
    # torch.cuda.get_rng_state_all
    registry.register(FunctionContract(
        name="torch.cuda.get_rng_state_all",
        qualname="torch.cuda.get_rng_state_all",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns list of ByteTensors
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return RNG state for all GPUs",
    ))
    
    # torch.cuda.set_rng_state
    registry.register(FunctionContract(
        name="torch.cuda.set_rng_state",
        qualname="torch.cuda.set_rng_state",
        param_names=["new_state", "device"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_state", "new_state must be ByteTensor from get_rng_state"),
        ],
        postconditions=[
            ("state_restored", "RNG state is restored"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set RNG state for GPU",
    ))
    
    # torch.cuda.set_rng_state_all
    registry.register(FunctionContract(
        name="torch.cuda.set_rng_state_all",
        qualname="torch.cuda.set_rng_state_all",
        param_names=["new_states"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_states", "new_states from get_rng_state_all"),
        ],
        postconditions=[
            ("all_states_restored", "RNG states restored for all GPUs"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set RNG state for all GPUs",
    ))


# ============================================================================
# AMP (Automatic Mixed Precision)
# ============================================================================

def _register_amp(registry: ContractRegistry) -> None:
    """Register CUDA AMP contracts."""
    
    # torch.cuda.amp.autocast
    registry.register(FunctionContract(
        name="torch.cuda.amp.autocast",
        qualname="torch.cuda.amp.autocast",
        param_names=["device_type", "dtype", "enabled", "cache_enabled"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("autocast_active", "Operations use automatic mixed precision"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Context manager for automatic mixed precision",
    ))
    
    # torch.cuda.amp.GradScaler
    registry.register(ModuleContract(
        name="torch.cuda.amp.GradScaler",
        qualname="torch.cuda.amp.GradScaler",
        init_param_names=["init_scale", "growth_factor", "backoff_factor",
                         "growth_interval", "enabled"],
        init_param_intervals={
            "init_scale": Interval(1.0, float('inf')),
            "growth_factor": Interval(1.0, float('inf')),
            "backoff_factor": Interval(0.0, 1.0),
            "growth_interval": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("scale_positive", "Scale is always positive"),
        ],
        docstring="Gradient scaler for mixed precision training",
    ))
    
    # GradScaler.scale
    registry.register(MethodContract(
        name="torch.cuda.amp.GradScaler.scale",
        qualname="torch.cuda.amp.GradScaler.scale",
        param_names=["self", "outputs"],
        param_intervals={},
        return_interval=None,  # Returns scaled outputs
        preconditions=[],
        postconditions=[
            ("outputs_scaled", "Outputs multiplied by scale factor"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Scale loss for mixed precision",
    ))
    
    # GradScaler.unscale_
    registry.register(MethodContract(
        name="torch.cuda.amp.GradScaler.unscale_",
        qualname="torch.cuda.amp.GradScaler.unscale_",
        param_names=["self", "optimizer"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("not_unscaled", "unscale_ not called since last update"),
        ],
        postconditions=[
            ("gradients_unscaled", "Optimizer gradients divided by scale"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Unscale optimizer gradients",
    ))
    
    # GradScaler.step
    registry.register(MethodContract(
        name="torch.cuda.amp.GradScaler.step",
        qualname="torch.cuda.amp.GradScaler.step",
        param_names=["self", "optimizer", "*args", "**kwargs"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("step_maybe_taken", "Optimizer step taken if no inf/nan"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Step optimizer if gradients are finite",
    ))
    
    # GradScaler.update
    registry.register(MethodContract(
        name="torch.cuda.amp.GradScaler.update",
        qualname="torch.cuda.amp.GradScaler.update",
        param_names=["self", "new_scale"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("scale_updated", "Scale adjusted based on gradient overflow"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Update scale factor based on overflow",
    ))
    
    # GradScaler.get_scale
    registry.register(MethodContract(
        name="torch.cuda.amp.GradScaler.get_scale",
        qualname="torch.cuda.amp.GradScaler.get_scale",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return current scale factor",
    ))
    
    # GradScaler.get_growth_factor
    registry.register(MethodContract(
        name="torch.cuda.amp.GradScaler.get_growth_factor",
        qualname="torch.cuda.amp.GradScaler.get_growth_factor",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(1, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return growth factor",
    ))
    
    # GradScaler.get_backoff_factor
    registry.register(MethodContract(
        name="torch.cuda.amp.GradScaler.get_backoff_factor",
        qualname="torch.cuda.amp.GradScaler.get_backoff_factor",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, 1),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return backoff factor",
    ))
    
    # GradScaler.state_dict
    registry.register(MethodContract(
        name="torch.cuda.amp.GradScaler.state_dict",
        qualname="torch.cuda.amp.GradScaler.state_dict",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns dict
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return scaler state as dict",
    ))
    
    # GradScaler.load_state_dict
    registry.register(MethodContract(
        name="torch.cuda.amp.GradScaler.load_state_dict",
        qualname="torch.cuda.amp.GradScaler.load_state_dict",
        param_names=["self", "state_dict"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_state_dict", "state_dict from state_dict()"),
        ],
        postconditions=[
            ("state_loaded", "Scaler state restored"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Load scaler state from dict",
    ))


# ============================================================================
# NCCL (Multi-GPU Communication)
# ============================================================================

def _register_nccl(registry: ContractRegistry) -> None:
    """Register NCCL communication contracts."""
    
    # torch.cuda.nccl.version
    registry.register(FunctionContract(
        name="torch.cuda.nccl.version",
        qualname="torch.cuda.nccl.version",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns version tuple
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return NCCL version",
    ))
    
    # torch.cuda.nccl.is_available
    registry.register(FunctionContract(
        name="torch.cuda.nccl.is_available",
        qualname="torch.cuda.nccl.is_available",
        param_names=["tensors"],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if NCCL is available for tensors",
    ))
    
    # torch.cuda.nccl.all_reduce
    registry.register(FunctionContract(
        name="torch.cuda.nccl.all_reduce",
        qualname="torch.cuda.nccl.all_reduce",
        param_names=["inputs", "outputs", "op", "streams", "comms"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("cuda_tensors", "All tensors must be on CUDA"),
            ("same_size", "All tensors must have same size"),
        ],
        postconditions=[
            ("reduced", "All outputs contain reduced values"),
        ],
        requires_same_device=False,  # Multi-device operation
        may_raise=["RuntimeError"],
        docstring="NCCL all-reduce across GPUs",
    ))
    
    # torch.cuda.nccl.reduce
    registry.register(FunctionContract(
        name="torch.cuda.nccl.reduce",
        qualname="torch.cuda.nccl.reduce",
        param_names=["inputs", "output", "root", "op", "streams", "comms"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("cuda_tensors", "All tensors must be on CUDA"),
        ],
        postconditions=[
            ("reduced_to_root", "Output on root contains reduced values"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="NCCL reduce to root GPU",
    ))
    
    # torch.cuda.nccl.broadcast
    registry.register(FunctionContract(
        name="torch.cuda.nccl.broadcast",
        qualname="torch.cuda.nccl.broadcast",
        param_names=["inputs", "root", "streams", "comms"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("cuda_tensors", "All tensors must be on CUDA"),
        ],
        postconditions=[
            ("broadcasted", "All tensors contain root values"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="NCCL broadcast from root GPU",
    ))
    
    # torch.cuda.nccl.all_gather
    registry.register(FunctionContract(
        name="torch.cuda.nccl.all_gather",
        qualname="torch.cuda.nccl.all_gather",
        param_names=["inputs", "outputs", "streams", "comms"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("cuda_tensors", "All tensors must be on CUDA"),
        ],
        postconditions=[
            ("gathered", "Each output contains all input values"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="NCCL all-gather across GPUs",
    ))
    
    # torch.cuda.nccl.reduce_scatter
    registry.register(FunctionContract(
        name="torch.cuda.nccl.reduce_scatter",
        qualname="torch.cuda.nccl.reduce_scatter",
        param_names=["inputs", "outputs", "op", "streams", "comms"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("cuda_tensors", "All tensors must be on CUDA"),
        ],
        postconditions=[
            ("reduce_scattered", "Each output contains portion of reduced values"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="NCCL reduce-scatter across GPUs",
    ))


# ============================================================================
# Miscellaneous CUDA Functions
# ============================================================================

def _register_misc(registry: ContractRegistry) -> None:
    """Register miscellaneous CUDA contracts."""
    
    # torch.cuda.init
    registry.register(FunctionContract(
        name="torch.cuda.init",
        qualname="torch.cuda.init",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("cuda_initialized", "CUDA runtime is initialized"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Initialize CUDA runtime",
    ))
    
    # torch.cuda.ipc_collect
    registry.register(FunctionContract(
        name="torch.cuda.ipc_collect",
        qualname="torch.cuda.ipc_collect",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("ipc_collected", "IPC handles are collected"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Force collection of IPC handles",
    ))
    
    # torch.cuda.get_sync_debug_mode
    registry.register(FunctionContract(
        name="torch.cuda.get_sync_debug_mode",
        qualname="torch.cuda.get_sync_debug_mode",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, 2),  # 0, 1, or 2
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Get current sync debug mode",
    ))
    
    # torch.cuda.set_sync_debug_mode
    registry.register(FunctionContract(
        name="torch.cuda.set_sync_debug_mode",
        qualname="torch.cuda.set_sync_debug_mode",
        param_names=["debug_mode"],
        param_intervals={
            "debug_mode": Interval(0, 2),
        },
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("mode_set", "Sync debug mode is set"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Set sync debug mode (0=disabled, 1=warn, 2=error)",
    ))
    
    # torch.cuda.can_device_access_peer
    registry.register(FunctionContract(
        name="torch.cuda.can_device_access_peer",
        qualname="torch.cuda.can_device_access_peer",
        param_names=["device", "peer_device"],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if device can access peer device memory",
    ))
    
    # torch.cuda.cudart
    registry.register(FunctionContract(
        name="torch.cuda.cudart",
        qualname="torch.cuda.cudart",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns cudart module
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return cudart module",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_cuda_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.cuda contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_device_management(registry)
    _register_memory_management(registry)
    _register_synchronization(registry)
    _register_stream(registry)
    _register_event(registry)
    _register_cuda_graphs(registry)
    _register_rng(registry)
    _register_amp(registry)
    _register_nccl(registry)
    _register_misc(registry)


# Export
__all__ = [
    "register_cuda_contracts",
]
