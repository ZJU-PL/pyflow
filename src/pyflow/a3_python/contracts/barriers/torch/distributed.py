"""
PyTorch Distributed Training Contracts - torch.distributed

This module provides contracts for PyTorch's distributed training primitives:
- Process group management
- Collective communications (all_reduce, broadcast, etc.)
- Point-to-point communications
- Distributed data parallel
- RPC framework basics

Device Barrier Considerations:
- All tensors in collective operations must be on same device type
- NCCL backend requires CUDA tensors
- Gloo backend works with CPU tensors
- Cross-device collective operations are not supported within a single call
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
# Initialization and Process Groups
# ============================================================================

def _register_initialization(registry: ContractRegistry) -> None:
    """Register distributed initialization contracts."""
    
    # torch.distributed.init_process_group
    registry.register(FunctionContract(
        name="torch.distributed.init_process_group",
        qualname="torch.distributed.init_process_group",
        param_names=["backend", "init_method", "timeout", "world_size", "rank",
                    "store", "group_name", "pg_options"],
        param_intervals={
            "world_size": Interval(1, float('inf')),
            "rank": Interval(0, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("not_initialized", "Process group not already initialized"),
            ("valid_backend", "backend must be 'nccl', 'gloo', 'mpi', or 'ucc'"),
            ("rank_valid", "rank must be < world_size"),
        ],
        postconditions=[
            ("initialized", "Default process group is initialized"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "ValueError"],
        docstring="Initialize the default distributed process group",
    ))
    
    # torch.distributed.is_initialized
    registry.register(FunctionContract(
        name="torch.distributed.is_initialized",
        qualname="torch.distributed.is_initialized",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if default process group is initialized",
    ))
    
    # torch.distributed.is_available
    registry.register(FunctionContract(
        name="torch.distributed.is_available",
        qualname="torch.distributed.is_available",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if distributed package is available",
    ))
    
    # torch.distributed.is_nccl_available
    registry.register(FunctionContract(
        name="torch.distributed.is_nccl_available",
        qualname="torch.distributed.is_nccl_available",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if NCCL backend is available",
    ))
    
    # torch.distributed.is_gloo_available
    registry.register(FunctionContract(
        name="torch.distributed.is_gloo_available",
        qualname="torch.distributed.is_gloo_available",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if Gloo backend is available",
    ))
    
    # torch.distributed.is_mpi_available
    registry.register(FunctionContract(
        name="torch.distributed.is_mpi_available",
        qualname="torch.distributed.is_mpi_available",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if MPI backend is available",
    ))
    
    # torch.distributed.destroy_process_group
    registry.register(FunctionContract(
        name="torch.distributed.destroy_process_group",
        qualname="torch.distributed.destroy_process_group",
        param_names=["group"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
        ],
        postconditions=[
            ("destroyed", "Process group is destroyed"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Destroy the specified process group",
    ))
    
    # torch.distributed.get_backend
    registry.register(FunctionContract(
        name="torch.distributed.get_backend",
        qualname="torch.distributed.get_backend",
        param_names=["group"],
        param_intervals={},
        return_interval=None,  # Returns Backend enum
        preconditions=[
            ("initialized", "Process group must be initialized"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return the backend of the process group",
    ))
    
    # torch.distributed.get_rank
    registry.register(FunctionContract(
        name="torch.distributed.get_rank",
        qualname="torch.distributed.get_rank",
        param_names=["group"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[
            ("initialized", "Process group must be initialized"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return rank of current process in group",
    ))
    
    # torch.distributed.get_world_size
    registry.register(FunctionContract(
        name="torch.distributed.get_world_size",
        qualname="torch.distributed.get_world_size",
        param_names=["group"],
        param_intervals={},
        return_interval=Interval(1, float('inf')),
        preconditions=[
            ("initialized", "Process group must be initialized"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return world size of the process group",
    ))
    
    # torch.distributed.new_group
    registry.register(FunctionContract(
        name="torch.distributed.new_group",
        qualname="torch.distributed.new_group",
        param_names=["ranks", "timeout", "backend", "pg_options"],
        param_intervals={},
        return_interval=None,  # Returns ProcessGroup
        preconditions=[
            ("initialized", "Default process group must be initialized"),
            ("valid_ranks", "ranks must be subset of world ranks"),
        ],
        postconditions=[
            ("group_created", "New process group is created"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "ValueError"],
        docstring="Create new process group with subset of ranks",
    ))


# ============================================================================
# Collective Operations
# ============================================================================

def _register_collectives(registry: ContractRegistry) -> None:
    """Register collective communication contracts."""
    
    # torch.distributed.broadcast
    registry.register(FunctionContract(
        name="torch.distributed.broadcast",
        qualname="torch.distributed.broadcast",
        param_names=["tensor", "src", "group", "async_op"],
        param_intervals={
            "src": Interval(0, float('inf')),
        },
        return_interval=None,  # Returns Work if async_op
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("valid_src", "src must be valid rank in group"),
            ("tensor_contiguous", "tensor should be contiguous"),
        ],
        postconditions=[
            ("broadcasted", "All ranks have tensor from src"),
        ],
        requires_same_device=True,  # All tensors same device type
        may_raise=["RuntimeError"],
        docstring="Broadcast tensor from src to all ranks",
    ))
    
    # torch.distributed.all_reduce
    registry.register(FunctionContract(
        name="torch.distributed.all_reduce",
        qualname="torch.distributed.all_reduce",
        param_names=["tensor", "op", "group", "async_op"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("tensor_contiguous", "tensor should be contiguous"),
            ("same_shape", "All tensors must have same shape"),
        ],
        postconditions=[
            ("reduced", "All ranks have reduced result"),
        ],
        requires_same_device=True,  # NCCL requires CUDA, Gloo requires CPU
        may_raise=["RuntimeError"],
        docstring="Reduce tensor across all ranks (in-place)",
    ))
    
    # torch.distributed.reduce
    registry.register(FunctionContract(
        name="torch.distributed.reduce",
        qualname="torch.distributed.reduce",
        param_names=["tensor", "dst", "op", "group", "async_op"],
        param_intervals={
            "dst": Interval(0, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("valid_dst", "dst must be valid rank in group"),
        ],
        postconditions=[
            ("reduced_to_dst", "dst rank has reduced result"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Reduce tensor to dst rank",
    ))
    
    # torch.distributed.all_gather
    registry.register(FunctionContract(
        name="torch.distributed.all_gather",
        qualname="torch.distributed.all_gather",
        param_names=["tensor_list", "tensor", "group", "async_op"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("list_size", "tensor_list size == world_size"),
            ("same_shape", "All tensors must have same shape"),
        ],
        postconditions=[
            ("gathered", "tensor_list[i] contains tensor from rank i"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Gather tensors from all ranks to all ranks",
    ))
    
    # torch.distributed.gather
    registry.register(FunctionContract(
        name="torch.distributed.gather",
        qualname="torch.distributed.gather",
        param_names=["tensor", "gather_list", "dst", "group", "async_op"],
        param_intervals={
            "dst": Interval(0, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("valid_dst", "dst must be valid rank"),
            ("gather_list_on_dst", "Only dst needs gather_list"),
        ],
        postconditions=[
            ("gathered_to_dst", "dst has all tensors in gather_list"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Gather tensors to dst rank",
    ))
    
    # torch.distributed.scatter
    registry.register(FunctionContract(
        name="torch.distributed.scatter",
        qualname="torch.distributed.scatter",
        param_names=["tensor", "scatter_list", "src", "group", "async_op"],
        param_intervals={
            "src": Interval(0, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("valid_src", "src must be valid rank"),
            ("scatter_list_on_src", "Only src needs scatter_list"),
        ],
        postconditions=[
            ("scattered", "Each rank receives scatter_list[rank]"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Scatter tensors from src to all ranks",
    ))
    
    # torch.distributed.reduce_scatter
    registry.register(FunctionContract(
        name="torch.distributed.reduce_scatter",
        qualname="torch.distributed.reduce_scatter",
        param_names=["output", "input_list", "op", "group", "async_op"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("list_size", "input_list size == world_size"),
        ],
        postconditions=[
            ("reduce_scattered", "Each rank has portion of reduced result"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Reduce then scatter to all ranks",
    ))
    
    # torch.distributed.all_to_all
    registry.register(FunctionContract(
        name="torch.distributed.all_to_all",
        qualname="torch.distributed.all_to_all",
        param_names=["output_tensor_list", "input_tensor_list", "group", "async_op"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("equal_sizes", "All tensors must have same size"),
        ],
        postconditions=[
            ("exchanged", "Each rank sends/receives from all others"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="All-to-all tensor exchange",
    ))
    
    # torch.distributed.all_to_all_single
    registry.register(FunctionContract(
        name="torch.distributed.all_to_all_single",
        qualname="torch.distributed.all_to_all_single",
        param_names=["output", "input", "output_split_sizes", "input_split_sizes",
                    "group", "async_op"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
        ],
        postconditions=[
            ("exchanged", "All-to-all with variable sizes"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="All-to-all with single tensors",
    ))
    
    # torch.distributed.barrier
    registry.register(FunctionContract(
        name="torch.distributed.barrier",
        qualname="torch.distributed.barrier",
        param_names=["group", "async_op", "device_ids"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
        ],
        postconditions=[
            ("synchronized", "All ranks have reached barrier"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Synchronize all ranks at barrier",
    ))


# ============================================================================
# Point-to-Point Operations
# ============================================================================

def _register_p2p(registry: ContractRegistry) -> None:
    """Register point-to-point communication contracts."""
    
    # torch.distributed.send
    registry.register(FunctionContract(
        name="torch.distributed.send",
        qualname="torch.distributed.send",
        param_names=["tensor", "dst", "group", "tag"],
        param_intervals={
            "dst": Interval(0, float('inf')),
            "tag": Interval(0, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("valid_dst", "dst must be valid rank"),
            ("not_self", "Cannot send to self"),
        ],
        postconditions=[
            ("sent", "Tensor sent to dst (blocking)"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Send tensor to dst rank (blocking)",
    ))
    
    # torch.distributed.recv
    registry.register(FunctionContract(
        name="torch.distributed.recv",
        qualname="torch.distributed.recv",
        param_names=["tensor", "src", "group", "tag"],
        param_intervals={
            "src": Interval(-1, float('inf')),  # -1 for any
            "tag": Interval(-1, float('inf')),
        },
        return_interval=Interval(0, float('inf')),  # Returns sender rank
        preconditions=[
            ("initialized", "Process group must be initialized"),
        ],
        postconditions=[
            ("received", "Tensor received from src (blocking)"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Receive tensor from src rank (blocking)",
    ))
    
    # torch.distributed.isend
    registry.register(FunctionContract(
        name="torch.distributed.isend",
        qualname="torch.distributed.isend",
        param_names=["tensor", "dst", "group", "tag"],
        param_intervals={
            "dst": Interval(0, float('inf')),
        },
        return_interval=None,  # Returns Work handle
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("valid_dst", "dst must be valid rank"),
        ],
        postconditions=[
            ("send_started", "Async send initiated"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Send tensor asynchronously",
    ))
    
    # torch.distributed.irecv
    registry.register(FunctionContract(
        name="torch.distributed.irecv",
        qualname="torch.distributed.irecv",
        param_names=["tensor", "src", "group", "tag"],
        param_intervals={},
        return_interval=None,  # Returns Work handle
        preconditions=[
            ("initialized", "Process group must be initialized"),
        ],
        postconditions=[
            ("recv_started", "Async receive initiated"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Receive tensor asynchronously",
    ))
    
    # torch.distributed.batch_isend_irecv
    registry.register(FunctionContract(
        name="torch.distributed.batch_isend_irecv",
        qualname="torch.distributed.batch_isend_irecv",
        param_names=["p2p_op_list"],
        param_intervals={},
        return_interval=None,  # Returns list of Work
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("valid_ops", "p2p_op_list contains P2POp objects"),
        ],
        postconditions=[
            ("ops_started", "All p2p ops initiated"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Batch multiple point-to-point operations",
    ))


# ============================================================================
# Object Collectives
# ============================================================================

def _register_object_collectives(registry: ContractRegistry) -> None:
    """Register object-based collective contracts."""
    
    # torch.distributed.broadcast_object_list
    registry.register(FunctionContract(
        name="torch.distributed.broadcast_object_list",
        qualname="torch.distributed.broadcast_object_list",
        param_names=["object_list", "src", "group", "device"],
        param_intervals={
            "src": Interval(0, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("valid_src", "src must be valid rank"),
            ("picklable", "Objects must be picklable"),
        ],
        postconditions=[
            ("broadcasted", "All ranks have objects from src"),
        ],
        requires_same_device=False,  # Objects serialized
        may_raise=["RuntimeError"],
        docstring="Broadcast Python objects from src",
    ))
    
    # torch.distributed.all_gather_object
    registry.register(FunctionContract(
        name="torch.distributed.all_gather_object",
        qualname="torch.distributed.all_gather_object",
        param_names=["object_list", "obj", "group"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("picklable", "obj must be picklable"),
        ],
        postconditions=[
            ("gathered", "object_list[i] = obj from rank i"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Gather Python objects from all ranks",
    ))
    
    # torch.distributed.gather_object
    registry.register(FunctionContract(
        name="torch.distributed.gather_object",
        qualname="torch.distributed.gather_object",
        param_names=["obj", "object_gather_list", "dst", "group"],
        param_intervals={
            "dst": Interval(0, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("picklable", "obj must be picklable"),
        ],
        postconditions=[
            ("gathered_to_dst", "dst has all objects"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Gather Python objects to dst",
    ))
    
    # torch.distributed.scatter_object_list
    registry.register(FunctionContract(
        name="torch.distributed.scatter_object_list",
        qualname="torch.distributed.scatter_object_list",
        param_names=["scatter_object_output_list", "scatter_object_input_list",
                    "src", "group"],
        param_intervals={
            "src": Interval(0, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
        ],
        postconditions=[
            ("scattered", "Each rank receives object from src"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Scatter Python objects from src",
    ))


# ============================================================================
# Store Operations
# ============================================================================

def _register_store(registry: ContractRegistry) -> None:
    """Register distributed store contracts."""
    
    # Store base operations
    registry.register(MethodContract(
        name="torch.distributed.Store.set",
        qualname="torch.distributed.Store.set",
        param_names=["self", "key", "value"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("value_stored", "Value stored at key"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Store value at key",
    ))
    
    registry.register(MethodContract(
        name="torch.distributed.Store.get",
        qualname="torch.distributed.Store.get",
        param_names=["self", "key"],
        param_intervals={},
        return_interval=None,  # Returns bytes
        preconditions=[
            ("key_exists", "Key must exist in store"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Get value at key",
    ))
    
    registry.register(MethodContract(
        name="torch.distributed.Store.add",
        qualname="torch.distributed.Store.add",
        param_names=["self", "key", "amount"],
        param_intervals={},
        return_interval=None,  # Returns new value
        preconditions=[],
        postconditions=[
            ("value_incremented", "Key incremented atomically"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Atomically add to value at key",
    ))
    
    registry.register(MethodContract(
        name="torch.distributed.Store.wait",
        qualname="torch.distributed.Store.wait",
        param_names=["self", "keys", "timeout"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("keys_exist", "All keys exist after wait"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Wait for keys to be set",
    ))
    
    # TCPStore
    registry.register(ModuleContract(
        name="torch.distributed.TCPStore",
        qualname="torch.distributed.TCPStore",
        init_param_names=["host_name", "port", "world_size", "is_master", "timeout",
                         "wait_for_workers", "multi_tenant"],
        init_param_intervals={
            "port": Interval(1, 65535),
            "world_size": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="TCP-based distributed store",
    ))
    
    # FileStore
    registry.register(ModuleContract(
        name="torch.distributed.FileStore",
        qualname="torch.distributed.FileStore",
        init_param_names=["file_name", "world_size"],
        init_param_intervals={
            "world_size": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("file_accessible", "File must be accessible by all ranks"),
        ],
        docstring="File-based distributed store",
    ))
    
    # HashStore
    registry.register(ModuleContract(
        name="torch.distributed.HashStore",
        qualname="torch.distributed.HashStore",
        init_param_names=[],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("in_memory", "Data stored in memory"),
        ],
        docstring="In-memory hash-based store (single process)",
    ))


# ============================================================================
# Reduce Operations
# ============================================================================

def _register_reduce_ops(registry: ContractRegistry) -> None:
    """Register reduce operation contracts."""
    
    # ReduceOp enum values documentation
    # These are used with all_reduce, reduce, etc.
    
    registry.register(FunctionContract(
        name="torch.distributed.ReduceOp.SUM",
        qualname="torch.distributed.ReduceOp.SUM",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Sum reduction operation",
    ))
    
    registry.register(FunctionContract(
        name="torch.distributed.ReduceOp.PRODUCT",
        qualname="torch.distributed.ReduceOp.PRODUCT",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Product reduction operation",
    ))
    
    registry.register(FunctionContract(
        name="torch.distributed.ReduceOp.MIN",
        qualname="torch.distributed.ReduceOp.MIN",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Minimum reduction operation",
    ))
    
    registry.register(FunctionContract(
        name="torch.distributed.ReduceOp.MAX",
        qualname="torch.distributed.ReduceOp.MAX",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Maximum reduction operation",
    ))
    
    registry.register(FunctionContract(
        name="torch.distributed.ReduceOp.BAND",
        qualname="torch.distributed.ReduceOp.BAND",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Bitwise AND reduction operation",
    ))
    
    registry.register(FunctionContract(
        name="torch.distributed.ReduceOp.BOR",
        qualname="torch.distributed.ReduceOp.BOR",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Bitwise OR reduction operation",
    ))
    
    registry.register(FunctionContract(
        name="torch.distributed.ReduceOp.BXOR",
        qualname="torch.distributed.ReduceOp.BXOR",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Bitwise XOR reduction operation",
    ))
    
    registry.register(FunctionContract(
        name="torch.distributed.ReduceOp.AVG",
        qualname="torch.distributed.ReduceOp.AVG",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Average reduction operation",
    ))


# ============================================================================
# Distributed Data Parallel Utilities
# ============================================================================

def _register_ddp_utilities(registry: ContractRegistry) -> None:
    """Register DDP utility contracts."""
    
    # torch.nn.parallel.DistributedDataParallel
    registry.register(ModuleContract(
        name="torch.nn.parallel.DistributedDataParallel",
        qualname="torch.nn.parallel.DistributedDataParallel",
        init_param_names=["module", "device_ids", "output_device", "dim",
                         "broadcast_buffers", "process_group", "bucket_cap_mb",
                         "find_unused_parameters", "check_reduction",
                         "gradient_as_bucket_view", "static_graph"],
        init_param_intervals={
            "bucket_cap_mb": Interval(0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=True,
        forward_preserves_device=True,
        state_invariants=[
            ("synced_parameters", "Parameters synchronized across ranks"),
            ("gradient_sync", "Gradients synchronized in backward"),
        ],
        docstring="Distributed data parallel wrapper for modules",
    ))
    
    # DistributedSampler
    registry.register(ModuleContract(
        name="torch.utils.data.distributed.DistributedSampler",
        qualname="torch.utils.data.distributed.DistributedSampler",
        init_param_names=["dataset", "num_replicas", "rank", "shuffle",
                         "seed", "drop_last"],
        init_param_intervals={
            "num_replicas": Interval(1, float('inf')),
            "rank": Interval(0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("disjoint_samples", "Each rank sees different samples"),
        ],
        docstring="Sampler for distributed training",
    ))


# ============================================================================
# FSDP (Fully Sharded Data Parallel)
# ============================================================================

def _register_fsdp(registry: ContractRegistry) -> None:
    """Register FSDP contracts."""
    
    registry.register(ModuleContract(
        name="torch.distributed.fsdp.FullyShardedDataParallel",
        qualname="torch.distributed.fsdp.FullyShardedDataParallel",
        init_param_names=["module", "process_group", "sharding_strategy",
                         "cpu_offload", "auto_wrap_policy", "backward_prefetch",
                         "mixed_precision", "ignored_modules", "param_init_fn",
                         "device_id", "sync_module_states", "forward_prefetch",
                         "limit_all_gathers", "use_orig_params"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=True,
        forward_preserves_device=True,
        state_invariants=[
            ("sharded_params", "Parameters sharded across ranks"),
            ("all_gather_in_forward", "Params gathered for forward"),
            ("reduce_scatter_in_backward", "Grads reduced in backward"),
        ],
        docstring="Fully sharded data parallel for large models",
    ))
    
    # FSDP.state_dict
    registry.register(MethodContract(
        name="torch.distributed.fsdp.FullyShardedDataParallel.state_dict",
        qualname="torch.distributed.fsdp.FullyShardedDataParallel.state_dict",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("state_gathered", "Full state gathered on rank 0"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Get FSDP state dict (gathered)",
    ))
    
    # FSDP.load_state_dict
    registry.register(MethodContract(
        name="torch.distributed.fsdp.FullyShardedDataParallel.load_state_dict",
        qualname="torch.distributed.fsdp.FullyShardedDataParallel.load_state_dict",
        param_names=["self", "state_dict"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_state_dict", "state_dict matches model structure"),
        ],
        postconditions=[
            ("state_loaded", "State loaded and re-sharded"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Load FSDP state dict",
    ))


# ============================================================================
# Distributed Checkpointing
# ============================================================================

def _register_checkpointing(registry: ContractRegistry) -> None:
    """Register distributed checkpoint contracts."""
    
    # torch.distributed.checkpoint.save
    registry.register(FunctionContract(
        name="torch.distributed.checkpoint.save",
        qualname="torch.distributed.checkpoint.save",
        param_names=["state_dict", "storage_writer", "planner", "process_group"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("serializable", "state_dict must be serializable"),
        ],
        postconditions=[
            ("saved", "Distributed checkpoint saved"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Save distributed checkpoint",
    ))
    
    # torch.distributed.checkpoint.load
    registry.register(FunctionContract(
        name="torch.distributed.checkpoint.load",
        qualname="torch.distributed.checkpoint.load",
        param_names=["state_dict", "storage_reader", "planner", "process_group"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
            ("checkpoint_exists", "Checkpoint must exist"),
        ],
        postconditions=[
            ("loaded", "State dict populated from checkpoint"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Load distributed checkpoint",
    ))


# ============================================================================
# Monitored Barrier
# ============================================================================

def _register_monitored_barrier(registry: ContractRegistry) -> None:
    """Register monitored barrier contract."""
    
    registry.register(FunctionContract(
        name="torch.distributed.monitored_barrier",
        qualname="torch.distributed.monitored_barrier",
        param_names=["group", "timeout", "wait_all_ranks"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("initialized", "Process group must be initialized"),
        ],
        postconditions=[
            ("synchronized", "All ranks reached barrier"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Monitored barrier with timeout and error reporting",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_distributed_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.distributed contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_initialization(registry)
    _register_collectives(registry)
    _register_p2p(registry)
    _register_object_collectives(registry)
    _register_store(registry)
    _register_reduce_ops(registry)
    _register_ddp_utilities(registry)
    _register_fsdp(registry)
    _register_checkpointing(registry)
    _register_monitored_barrier(registry)


# Export
__all__ = [
    "register_distributed_contracts",
]
