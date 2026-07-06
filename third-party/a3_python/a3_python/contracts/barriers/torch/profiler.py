"""
PyTorch Profiler Contracts - torch.profiler

This module provides contracts for PyTorch's profiling utilities:
- PyTorch Profiler
- TensorBoard integration
- Memory profiling
- Kineto traces

Device Barrier Considerations:
- Profiler works across CPU and CUDA
- CUDA profiling requires CUDA-enabled build
- Memory profiling tracks device-specific allocations
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
# Profiler Context
# ============================================================================

def _register_profiler(registry: ContractRegistry) -> None:
    """Register profiler context manager contracts."""
    
    # torch.profiler.profile
    registry.register(FunctionContract(
        name="torch.profiler.profile",
        qualname="torch.profiler.profile",
        param_names=["activities", "schedule", "on_trace_ready", "record_shapes",
                    "profile_memory", "with_stack", "with_flops", "with_modules",
                    "experimental_config", "use_cuda"],
        param_intervals={},
        return_interval=None,  # Context manager
        preconditions=[],
        postconditions=[
            ("profiling_active", "Profiling active within context"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Context manager for profiling",
    ))
    
    # profile.start
    registry.register(MethodContract(
        name="torch.profiler.profile.start",
        qualname="torch.profiler.profile.start",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("not_started", "Profiler not already started"),
        ],
        postconditions=[
            ("started", "Profiler is now running"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Start the profiler",
    ))
    
    # profile.stop
    registry.register(MethodContract(
        name="torch.profiler.profile.stop",
        qualname="torch.profiler.profile.stop",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_started", "Profiler must be running"),
        ],
        postconditions=[
            ("stopped", "Profiler has stopped"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Stop the profiler",
    ))
    
    # profile.step
    registry.register(MethodContract(
        name="torch.profiler.profile.step",
        qualname="torch.profiler.profile.step",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_running", "Profiler must be running"),
        ],
        postconditions=[
            ("stepped", "Step counter incremented"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Signal profiler that iteration step completed",
    ))
    
    # profile.export_chrome_trace
    registry.register(MethodContract(
        name="torch.profiler.profile.export_chrome_trace",
        qualname="torch.profiler.profile.export_chrome_trace",
        param_names=["self", "path"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("has_events", "Profiler must have collected events"),
        ],
        postconditions=[
            ("trace_exported", "Chrome trace written to path"),
        ],
        requires_same_device=False,
        may_raise=["IOError"],
        docstring="Export trace in Chrome trace format",
    ))
    
    # profile.export_stacks
    registry.register(MethodContract(
        name="torch.profiler.profile.export_stacks",
        qualname="torch.profiler.profile.export_stacks",
        param_names=["self", "path", "metric"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("with_stack", "Profiler must have with_stack=True"),
        ],
        postconditions=[
            ("stacks_exported", "Stack traces written to path"),
        ],
        requires_same_device=False,
        may_raise=["IOError"],
        docstring="Export stack traces for flame graph",
    ))
    
    # profile.key_averages
    registry.register(MethodContract(
        name="torch.profiler.profile.key_averages",
        qualname="torch.profiler.profile.key_averages",
        param_names=["self", "group_by_input_shape", "group_by_stack_n"],
        param_intervals={
            "group_by_stack_n": Interval(0, float('inf')),
        },
        return_interval=None,  # Returns EventList
        preconditions=[
            ("has_events", "Profiler must have events"),
        ],
        postconditions=[
            ("averages_computed", "Returns aggregated event statistics"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get average statistics per operator",
    ))
    
    # profile.events
    registry.register(MethodContract(
        name="torch.profiler.profile.events",
        qualname="torch.profiler.profile.events",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns EventList
        preconditions=[],
        postconditions=[
            ("events_returned", "Returns list of profiled events"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get list of all profiled events",
    ))


# ============================================================================
# Schedule
# ============================================================================

def _register_schedule(registry: ContractRegistry) -> None:
    """Register profiler schedule contracts."""
    
    # torch.profiler.schedule
    registry.register(FunctionContract(
        name="torch.profiler.schedule",
        qualname="torch.profiler.schedule",
        param_names=["wait", "warmup", "active", "repeat", "skip_first"],
        param_intervals={
            "wait": Interval(0, float('inf')),
            "warmup": Interval(0, float('inf')),
            "active": Interval(1, float('inf')),
            "repeat": Interval(0, float('inf')),
            "skip_first": Interval(0, float('inf')),
        },
        return_interval=None,  # Returns schedule callable
        preconditions=[
            ("active_positive", "active must be > 0"),
        ],
        postconditions=[
            ("schedule_created", "Returns schedule function"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Create profiling schedule",
    ))


# ============================================================================
# Activities
# ============================================================================

def _register_activities(registry: ContractRegistry) -> None:
    """Register profiler activity contracts."""
    
    # ProfilerActivity enum
    registry.register(FunctionContract(
        name="torch.profiler.ProfilerActivity.CPU",
        qualname="torch.profiler.ProfilerActivity.CPU",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Profile CPU activities",
    ))
    
    registry.register(FunctionContract(
        name="torch.profiler.ProfilerActivity.CUDA",
        qualname="torch.profiler.ProfilerActivity.CUDA",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("cuda_available", "CUDA must be available"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Profile CUDA activities",
    ))
    
    registry.register(FunctionContract(
        name="torch.profiler.ProfilerActivity.XPU",
        qualname="torch.profiler.ProfilerActivity.XPU",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("xpu_available", "XPU must be available"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Profile XPU activities",
    ))


# ============================================================================
# TensorBoard Integration
# ============================================================================

def _register_tensorboard(registry: ContractRegistry) -> None:
    """Register TensorBoard integration contracts."""
    
    # torch.profiler.tensorboard_trace_handler
    registry.register(FunctionContract(
        name="torch.profiler.tensorboard_trace_handler",
        qualname="torch.profiler.tensorboard_trace_handler",
        param_names=["dir_name", "worker_name", "use_gzip"],
        param_intervals={},
        return_interval=None,  # Returns handler callable
        preconditions=[
            ("dir_writable", "dir_name must be writable directory"),
        ],
        postconditions=[
            ("handler_created", "Returns on_trace_ready handler for TensorBoard"),
        ],
        requires_same_device=False,
        may_raise=["IOError"],
        docstring="Create TensorBoard trace handler",
    ))


# ============================================================================
# Record Function
# ============================================================================

def _register_record_function(registry: ContractRegistry) -> None:
    """Register record_function contracts."""
    
    # torch.profiler.record_function
    registry.register(FunctionContract(
        name="torch.profiler.record_function",
        qualname="torch.profiler.record_function",
        param_names=["name"],
        param_intervals={},
        return_interval=None,  # Context manager
        preconditions=[],
        postconditions=[
            ("region_recorded", "Code region labeled with name"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Context manager to label code region in profiler",
    ))
    
    # Also available as torch.autograd.profiler.record_function
    registry.register(FunctionContract(
        name="torch.autograd.profiler.record_function",
        qualname="torch.autograd.profiler.record_function",
        param_names=["name"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("region_recorded", "Code region labeled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Label code region in profiler",
    ))


# ============================================================================
# Memory Profiling
# ============================================================================

def _register_memory_profiling(registry: ContractRegistry) -> None:
    """Register memory profiling contracts."""
    
    # torch.cuda.memory._record_memory_history
    registry.register(FunctionContract(
        name="torch.cuda.memory._record_memory_history",
        qualname="torch.cuda.memory._record_memory_history",
        param_names=["enabled", "context", "stacks", "max_entries", "device"],
        param_intervals={
            "max_entries": Interval(1, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("cuda_available", "CUDA must be available"),
        ],
        postconditions=[
            ("recording_set", "Memory recording enabled/disabled"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Enable/disable CUDA memory history recording",
    ))
    
    # torch.cuda.memory._dump_snapshot
    registry.register(FunctionContract(
        name="torch.cuda.memory._dump_snapshot",
        qualname="torch.cuda.memory._dump_snapshot",
        param_names=["filename"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("recording_active", "Memory recording must be active"),
        ],
        postconditions=[
            ("snapshot_dumped", "Memory snapshot written to file"),
        ],
        requires_same_device=False,
        may_raise=["IOError"],
        docstring="Dump memory snapshot to file",
    ))
    
    # torch.cuda.memory._snapshot
    registry.register(FunctionContract(
        name="torch.cuda.memory._snapshot",
        qualname="torch.cuda.memory._snapshot",
        param_names=["device"],
        param_intervals={},
        return_interval=None,  # Returns snapshot dict
        preconditions=[],
        postconditions=[
            ("snapshot_returned", "Returns memory snapshot"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get current memory snapshot",
    ))


# ============================================================================
# Kineto/ITT
# ============================================================================

def _register_kineto(registry: ContractRegistry) -> None:
    """Register Kineto profiler contracts."""
    
    # torch.autograd.kineto_available
    registry.register(FunctionContract(
        name="torch.autograd.kineto_available",
        qualname="torch.autograd.kineto_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if Kineto profiler is available",
    ))
    
    # ITT instrumentation (Intel)
    registry.register(FunctionContract(
        name="torch.profiler.itt.mark",
        qualname="torch.profiler.itt.mark",
        param_names=["name"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("marked", "ITT marker placed"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Place ITT marker for Intel profilers",
    ))
    
    registry.register(FunctionContract(
        name="torch.profiler.itt.range_push",
        qualname="torch.profiler.itt.range_push",
        param_names=["name"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("range_started", "ITT range started"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Start ITT range",
    ))
    
    registry.register(FunctionContract(
        name="torch.profiler.itt.range_pop",
        qualname="torch.profiler.itt.range_pop",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("range_active", "Must have active range"),
        ],
        postconditions=[
            ("range_ended", "ITT range ended"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="End ITT range",
    ))


# ============================================================================
# Event Classes
# ============================================================================

def _register_events(registry: ContractRegistry) -> None:
    """Register profiler event contracts."""
    
    # FunctionEvent attributes
    registry.register(MethodContract(
        name="FunctionEvent.key",
        qualname="torch.autograd.profiler.FunctionEvent.key",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Event key/name",
    ))
    
    registry.register(MethodContract(
        name="FunctionEvent.cpu_time_total",
        qualname="torch.autograd.profiler.FunctionEvent.cpu_time_total",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),  # Microseconds
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Total CPU time in microseconds",
    ))
    
    registry.register(MethodContract(
        name="FunctionEvent.cuda_time_total",
        qualname="torch.autograd.profiler.FunctionEvent.cuda_time_total",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Total CUDA time in microseconds",
    ))
    
    registry.register(MethodContract(
        name="FunctionEvent.self_cpu_time_total",
        qualname="torch.autograd.profiler.FunctionEvent.self_cpu_time_total",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Self CPU time (excluding children)",
    ))
    
    registry.register(MethodContract(
        name="FunctionEvent.count",
        qualname="torch.autograd.profiler.FunctionEvent.count",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(1, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Number of times event occurred",
    ))
    
    # EventList methods
    registry.register(MethodContract(
        name="EventList.table",
        qualname="torch.autograd.profiler.EventList.table",
        param_names=["self", "sort_by", "row_limit", "max_src_column_width",
                    "max_name_column_width", "max_shapes_column_width",
                    "header", "top_level_events_only"],
        param_intervals={},
        return_interval=None,  # Returns string table
        preconditions=[],
        postconditions=[
            ("table_formatted", "Returns formatted table string"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Format events as table",
    ))
    
    registry.register(MethodContract(
        name="EventList.total_average",
        qualname="torch.autograd.profiler.EventList.total_average",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns FunctionEventAvg
        preconditions=[],
        postconditions=[
            ("avg_computed", "Returns average over all events"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Compute average over all events",
    ))


# ============================================================================
# FLOPS Counting
# ============================================================================

def _register_flops(registry: ContractRegistry) -> None:
    """Register FLOPS counting contracts."""
    
    # torch.utils.flop_counter.FlopCounterMode
    registry.register(ModuleContract(
        name="torch.utils.flop_counter.FlopCounterMode",
        qualname="torch.utils.flop_counter.FlopCounterMode",
        init_param_names=["mods", "depth", "display"],
        init_param_intervals={
            "depth": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("flops_counted", "Counts FLOPs in context"),
        ],
        docstring="Context manager for counting FLOPs",
    ))
    
    # FlopCounterMode.get_total_flops
    registry.register(MethodContract(
        name="FlopCounterMode.get_total_flops",
        qualname="torch.utils.flop_counter.FlopCounterMode.get_total_flops",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[
            ("flops_returned", "Returns total FLOP count"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get total FLOP count",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_profiler_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.profiler contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_profiler(registry)
    _register_schedule(registry)
    _register_activities(registry)
    _register_tensorboard(registry)
    _register_record_function(registry)
    _register_memory_profiling(registry)
    _register_kineto(registry)
    _register_events(registry)
    _register_flops(registry)


# Export
__all__ = [
    "register_profiler_contracts",
]
