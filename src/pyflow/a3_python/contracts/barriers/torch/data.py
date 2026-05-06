"""
PyTorch Data Utilities Contracts - torch.utils.data

This module provides contracts for PyTorch's data loading utilities:
- Dataset classes
- DataLoader
- Samplers
- Collation
- Workers

Device Barrier Considerations:
- DataLoader returns CPU tensors by default
- pin_memory=True enables faster CPU→GPU transfers
- collate_fn should not move tensors to GPU (do in training loop)
- Dataset __getitem__ typically returns CPU tensors
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
# Dataset Classes
# ============================================================================

def _register_datasets(registry: ContractRegistry) -> None:
    """Register dataset contracts."""
    
    # torch.utils.data.Dataset
    registry.register(ModuleContract(
        name="torch.utils.data.Dataset",
        qualname="torch.utils.data.Dataset",
        init_param_names=[],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("getitem_defined", "__getitem__ must be defined"),
        ],
        docstring="Abstract base class for datasets",
    ))
    
    # Dataset.__len__ (optional)
    registry.register(MethodContract(
        name="torch.utils.data.Dataset.__len__",
        qualname="torch.utils.data.Dataset.__len__",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=["TypeError"],  # If not implemented
        docstring="Return dataset size",
    ))
    
    # Dataset.__getitem__
    registry.register(MethodContract(
        name="torch.utils.data.Dataset.__getitem__",
        qualname="torch.utils.data.Dataset.__getitem__",
        param_names=["self", "index"],
        param_intervals={},
        return_interval=None,  # Returns sample
        preconditions=[
            ("valid_index", "index must be within dataset range"),
        ],
        postconditions=[
            ("sample_returned", "Returns sample at index"),
        ],
        requires_same_device=False,  # Typically returns CPU data
        may_raise=["IndexError"],
        docstring="Get sample at index",
    ))
    
    # torch.utils.data.IterableDataset
    registry.register(ModuleContract(
        name="torch.utils.data.IterableDataset",
        qualname="torch.utils.data.IterableDataset",
        init_param_names=[],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("iter_defined", "__iter__ must be defined"),
        ],
        docstring="Abstract base class for iterable datasets",
    ))
    
    # IterableDataset.__iter__
    registry.register(MethodContract(
        name="torch.utils.data.IterableDataset.__iter__",
        qualname="torch.utils.data.IterableDataset.__iter__",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns iterator
        preconditions=[],
        postconditions=[
            ("iterator_returned", "Returns iterator over samples"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Return iterator over dataset",
    ))
    
    # torch.utils.data.TensorDataset
    registry.register(ModuleContract(
        name="torch.utils.data.TensorDataset",
        qualname="torch.utils.data.TensorDataset",
        init_param_names=["*tensors"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=True,  # All tensors same device
        forward_preserves_device=True,
        state_invariants=[
            ("same_first_dim", "All tensors must have same first dimension"),
        ],
        docstring="Dataset wrapping tensors",
    ))
    
    # torch.utils.data.ConcatDataset
    registry.register(ModuleContract(
        name="torch.utils.data.ConcatDataset",
        qualname="torch.utils.data.ConcatDataset",
        init_param_names=["datasets"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("contiguous_indices", "Indices span all datasets sequentially"),
        ],
        docstring="Concatenation of multiple datasets",
    ))
    
    # torch.utils.data.Subset
    registry.register(ModuleContract(
        name="torch.utils.data.Subset",
        qualname="torch.utils.data.Subset",
        init_param_names=["dataset", "indices"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("valid_indices", "All indices must be valid for dataset"),
        ],
        docstring="Subset of dataset at specified indices",
    ))
    
    # torch.utils.data.ChainDataset
    registry.register(ModuleContract(
        name="torch.utils.data.ChainDataset",
        qualname="torch.utils.data.ChainDataset",
        init_param_names=["datasets"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("iterable_datasets", "All datasets must be IterableDataset"),
        ],
        docstring="Chain multiple IterableDatasets",
    ))
    
    # torch.utils.data.StackDataset
    registry.register(ModuleContract(
        name="torch.utils.data.StackDataset",
        qualname="torch.utils.data.StackDataset",
        init_param_names=["*args", "**kwargs"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("same_length", "All datasets must have same length"),
        ],
        docstring="Stack samples from multiple datasets",
    ))


# ============================================================================
# DataLoader
# ============================================================================

def _register_dataloader(registry: ContractRegistry) -> None:
    """Register DataLoader contracts."""
    
    # torch.utils.data.DataLoader
    registry.register(ModuleContract(
        name="torch.utils.data.DataLoader",
        qualname="torch.utils.data.DataLoader",
        init_param_names=["dataset", "batch_size", "shuffle", "sampler",
                         "batch_sampler", "num_workers", "collate_fn",
                         "pin_memory", "drop_last", "timeout", "worker_init_fn",
                         "multiprocessing_context", "generator", "prefetch_factor",
                         "persistent_workers", "pin_memory_device"],
        init_param_intervals={
            "batch_size": Interval(1, float('inf')),
            "num_workers": Interval(0, float('inf')),
            "timeout": Interval(0, float('inf')),
            "prefetch_factor": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,  # Returns CPU by default
        forward_preserves_device=False,
        state_invariants=[
            ("batch_or_sampler", "batch_size or batch_sampler, not both"),
            ("shuffle_sampler", "shuffle and sampler mutually exclusive"),
        ],
        docstring="Data loader combining dataset and sampler",
    ))
    
    # DataLoader.__iter__
    registry.register(MethodContract(
        name="torch.utils.data.DataLoader.__iter__",
        qualname="torch.utils.data.DataLoader.__iter__",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns iterator
        preconditions=[],
        postconditions=[
            ("batches_yielded", "Yields batches from dataset"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],  # Worker errors
        docstring="Return iterator over batches",
    ))
    
    # DataLoader.__len__
    registry.register(MethodContract(
        name="torch.utils.data.DataLoader.__len__",
        qualname="torch.utils.data.DataLoader.__len__",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[
            ("sized_dataset", "Dataset must implement __len__"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["TypeError"],
        docstring="Return number of batches",
    ))


# ============================================================================
# Samplers
# ============================================================================

def _register_samplers(registry: ContractRegistry) -> None:
    """Register sampler contracts."""
    
    # torch.utils.data.Sampler
    registry.register(ModuleContract(
        name="torch.utils.data.Sampler",
        qualname="torch.utils.data.Sampler",
        init_param_names=["data_source"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("iter_defined", "__iter__ must be defined"),
        ],
        docstring="Abstract base class for samplers",
    ))
    
    # torch.utils.data.SequentialSampler
    registry.register(ModuleContract(
        name="torch.utils.data.SequentialSampler",
        qualname="torch.utils.data.SequentialSampler",
        init_param_names=["data_source"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("sequential", "Samples in order 0, 1, 2, ..."),
        ],
        docstring="Sample elements sequentially",
    ))
    
    # torch.utils.data.RandomSampler
    registry.register(ModuleContract(
        name="torch.utils.data.RandomSampler",
        qualname="torch.utils.data.RandomSampler",
        init_param_names=["data_source", "replacement", "num_samples", "generator"],
        init_param_intervals={
            "num_samples": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("random_order", "Samples in random order"),
        ],
        docstring="Sample elements randomly",
    ))
    
    # torch.utils.data.SubsetRandomSampler
    registry.register(ModuleContract(
        name="torch.utils.data.SubsetRandomSampler",
        qualname="torch.utils.data.SubsetRandomSampler",
        init_param_names=["indices", "generator"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("subset_random", "Randomly samples from given indices"),
        ],
        docstring="Randomly sample from subset indices",
    ))
    
    # torch.utils.data.WeightedRandomSampler
    registry.register(ModuleContract(
        name="torch.utils.data.WeightedRandomSampler",
        qualname="torch.utils.data.WeightedRandomSampler",
        init_param_names=["weights", "num_samples", "replacement", "generator"],
        init_param_intervals={
            "num_samples": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("weighted", "Samples according to weights"),
            ("non_negative_weights", "All weights must be non-negative"),
        ],
        docstring="Sample with given weights",
    ))
    
    # torch.utils.data.BatchSampler
    registry.register(ModuleContract(
        name="torch.utils.data.BatchSampler",
        qualname="torch.utils.data.BatchSampler",
        init_param_names=["sampler", "batch_size", "drop_last"],
        init_param_intervals={
            "batch_size": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("batches_indices", "Yields batches of indices"),
        ],
        docstring="Wrap sampler to yield batches of indices",
    ))


# ============================================================================
# Collation
# ============================================================================

def _register_collation(registry: ContractRegistry) -> None:
    """Register collation contracts."""
    
    # torch.utils.data.default_collate
    registry.register(FunctionContract(
        name="torch.utils.data.default_collate",
        qualname="torch.utils.data.default_collate",
        param_names=["batch"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("batch_list", "batch must be list of samples"),
            ("consistent_types", "All samples must have consistent types"),
        ],
        postconditions=[
            ("collated", "Returns batched tensors/dicts/tuples"),
        ],
        requires_same_device=True,  # All tensors same device
        may_raise=["TypeError", "RuntimeError"],
        docstring="Default collation for DataLoader",
    ))
    
    # torch.utils.data.default_convert
    registry.register(FunctionContract(
        name="torch.utils.data.default_convert",
        qualname="torch.utils.data.default_convert",
        param_names=["data"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("converted", "NumPy arrays converted to tensors"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Default conversion for batch elements",
    ))


# ============================================================================
# Worker Utilities
# ============================================================================

def _register_workers(registry: ContractRegistry) -> None:
    """Register worker utility contracts."""
    
    # torch.utils.data.get_worker_info
    registry.register(FunctionContract(
        name="torch.utils.data.get_worker_info",
        qualname="torch.utils.data.get_worker_info",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns WorkerInfo or None
        preconditions=[],
        postconditions=[
            ("info_or_none", "Returns WorkerInfo in worker, None in main"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get current worker info",
    ))
    
    # WorkerInfo attributes
    registry.register(FunctionContract(
        name="torch.utils.data.WorkerInfo.id",
        qualname="torch.utils.data.WorkerInfo.id",
        param_names=[],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Worker ID (0 to num_workers-1)",
    ))
    
    registry.register(FunctionContract(
        name="torch.utils.data.WorkerInfo.num_workers",
        qualname="torch.utils.data.WorkerInfo.num_workers",
        param_names=[],
        param_intervals={},
        return_interval=Interval(1, float('inf')),
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Total number of workers",
    ))


# ============================================================================
# Random Split
# ============================================================================

def _register_random_split(registry: ContractRegistry) -> None:
    """Register random_split contract."""
    
    registry.register(FunctionContract(
        name="torch.utils.data.random_split",
        qualname="torch.utils.data.random_split",
        param_names=["dataset", "lengths", "generator"],
        param_intervals={},
        return_interval=None,  # Returns list of Subset
        preconditions=[
            ("lengths_sum", "sum(lengths) must equal len(dataset)"),
            ("positive_lengths", "All lengths must be positive"),
        ],
        postconditions=[
            ("splits_created", "Returns list of disjoint Subset objects"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Randomly split dataset into non-overlapping subsets",
    ))


# ============================================================================
# Data Pipes (torch.utils.data.datapipes)
# ============================================================================

def _register_datapipes(registry: ContractRegistry) -> None:
    """Register DataPipe contracts."""
    
    # MapDataPipe
    registry.register(ModuleContract(
        name="torch.utils.data.MapDataPipe",
        qualname="torch.utils.data.MapDataPipe",
        init_param_names=[],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("indexable", "__getitem__ and __len__ defined"),
        ],
        docstring="Abstract base for map-style data pipes",
    ))
    
    # IterDataPipe
    registry.register(ModuleContract(
        name="torch.utils.data.IterDataPipe",
        qualname="torch.utils.data.IterDataPipe",
        init_param_names=[],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("iterable", "__iter__ defined"),
        ],
        docstring="Abstract base for iterable data pipes",
    ))
    
    # Common datapipe operations (functional style)
    registry.register(MethodContract(
        name="IterDataPipe.map",
        qualname="torch.utils.data.IterDataPipe.map",
        param_names=["self", "fn"],
        param_intervals={},
        return_interval=None,  # Returns MapperIterDataPipe
        preconditions=[
            ("callable", "fn must be callable"),
        ],
        postconditions=[
            ("mapped", "Returns datapipe applying fn to each element"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Apply function to each element",
    ))
    
    registry.register(MethodContract(
        name="IterDataPipe.filter",
        qualname="torch.utils.data.IterDataPipe.filter",
        param_names=["self", "fn"],
        param_intervals={},
        return_interval=None,  # Returns FilterIterDataPipe
        preconditions=[
            ("callable", "fn must be callable returning bool"),
        ],
        postconditions=[
            ("filtered", "Returns datapipe with elements where fn is True"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Filter elements by predicate",
    ))
    
    registry.register(MethodContract(
        name="IterDataPipe.batch",
        qualname="torch.utils.data.IterDataPipe.batch",
        param_names=["self", "batch_size", "drop_last", "wrapper_class"],
        param_intervals={
            "batch_size": Interval(1, float('inf')),
        },
        return_interval=None,  # Returns BatcherIterDataPipe
        preconditions=[],
        postconditions=[
            ("batched", "Returns datapipe yielding batches"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Batch elements",
    ))
    
    registry.register(MethodContract(
        name="IterDataPipe.shuffle",
        qualname="torch.utils.data.IterDataPipe.shuffle",
        param_names=["self", "buffer_size"],
        param_intervals={
            "buffer_size": Interval(1, float('inf')),
        },
        return_interval=None,  # Returns ShufflerIterDataPipe
        preconditions=[],
        postconditions=[
            ("shuffled", "Returns datapipe with shuffled elements"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Shuffle with buffer",
    ))
    
    registry.register(MethodContract(
        name="IterDataPipe.collate",
        qualname="torch.utils.data.IterDataPipe.collate",
        param_names=["self", "collate_fn"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("collated", "Returns datapipe with collated batches"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Apply collation function to batches",
    ))
    
    registry.register(MethodContract(
        name="IterDataPipe.sharding_filter",
        qualname="torch.utils.data.IterDataPipe.sharding_filter",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("sharded", "Returns datapipe filtered by worker/world"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Filter for multi-worker/distributed sharding",
    ))


# ============================================================================
# Communication
# ============================================================================

def _register_communication(registry: ContractRegistry) -> None:
    """Register data communication contracts."""
    
    # DataLoader2 with reading service (if available)
    registry.register(ModuleContract(
        name="torch.utils.data.DataLoader2",
        qualname="torch.utils.data.DataLoader2",
        init_param_names=["datapipe", "datapipe_adapter_fn", "reading_service"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("service_active", "Reading service manages data loading"),
        ],
        docstring="Next-gen DataLoader with reading services",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_data_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.utils.data contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_datasets(registry)
    _register_dataloader(registry)
    _register_samplers(registry)
    _register_collation(registry)
    _register_workers(registry)
    _register_random_split(registry)
    _register_datapipes(registry)
    _register_communication(registry)


# Export
__all__ = [
    "register_data_contracts",
]
