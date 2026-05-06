"""
PyTorch Sparse Tensor Contracts - torch.sparse

This module provides contracts for PyTorch's sparse tensor operations:
- Sparse tensor creation
- Sparse tensor operations
- Sparse matrix formats (COO, CSR, CSC, BSR, BSC)
- Sparse-dense conversions

Device Barrier Considerations:
- Sparse and dense tensor operations require same device
- Indices and values must be on same device
- Sparse matrix multiplications require device compatibility
"""

from typing import Dict, List, Any, Optional, Callable
from ..intervals import Interval
from ..contracts import (
    ContractRegistry,
    FunctionContract,
    MethodContract,
)


# ============================================================================
# Sparse Tensor Creation
# ============================================================================

def _register_sparse_creation(registry: ContractRegistry) -> None:
    """Register sparse tensor creation contracts."""
    
    # torch.sparse_coo_tensor
    registry.register(FunctionContract(
        name="torch.sparse_coo_tensor",
        qualname="torch.sparse_coo_tensor",
        param_names=["indices", "values", "size", "dtype", "device", "requires_grad"],
        param_intervals={},
        return_interval=None,  # Returns sparse tensor
        preconditions=[
            ("indices_2d", "indices must be 2D with shape [sparse_dim, nnz]"),
            ("values_match", "values first dim must match indices nnz"),
            ("indices_valid", "indices must be within size bounds"),
        ],
        postconditions=[
            ("sparse_created", "Returns sparse COO tensor"),
        ],
        requires_same_device=True,  # indices and values on same device
        may_raise=["RuntimeError", "IndexError"],
        docstring="Create sparse tensor in COO format",
    ))
    
    # torch.sparse_csr_tensor
    registry.register(FunctionContract(
        name="torch.sparse_csr_tensor",
        qualname="torch.sparse_csr_tensor",
        param_names=["crow_indices", "col_indices", "values", "size", 
                    "dtype", "device", "requires_grad"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("crow_valid", "crow_indices length = rows + 1"),
            ("col_valid", "col_indices length = nnz"),
            ("values_valid", "values length = nnz"),
            ("indices_sorted", "col_indices must be sorted within each row"),
        ],
        postconditions=[
            ("csr_created", "Returns sparse CSR tensor"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError", "IndexError"],
        docstring="Create sparse tensor in CSR format",
    ))
    
    # torch.sparse_csc_tensor
    registry.register(FunctionContract(
        name="torch.sparse_csc_tensor",
        qualname="torch.sparse_csc_tensor",
        param_names=["ccol_indices", "row_indices", "values", "size",
                    "dtype", "device", "requires_grad"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("ccol_valid", "ccol_indices length = cols + 1"),
            ("row_valid", "row_indices length = nnz"),
            ("values_valid", "values length = nnz"),
        ],
        postconditions=[
            ("csc_created", "Returns sparse CSC tensor"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError", "IndexError"],
        docstring="Create sparse tensor in CSC format",
    ))
    
    # torch.sparse_bsr_tensor
    registry.register(FunctionContract(
        name="torch.sparse_bsr_tensor",
        qualname="torch.sparse_bsr_tensor",
        param_names=["crow_indices", "col_indices", "values", "size",
                    "dtype", "device", "requires_grad"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("block_size_valid", "size divisible by block size"),
            ("crow_valid", "crow_indices properly formed"),
            ("values_blocks", "values contains blocks"),
        ],
        postconditions=[
            ("bsr_created", "Returns block sparse row tensor"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Create block sparse row tensor",
    ))
    
    # torch.sparse_bsc_tensor
    registry.register(FunctionContract(
        name="torch.sparse_bsc_tensor",
        qualname="torch.sparse_bsc_tensor",
        param_names=["ccol_indices", "row_indices", "values", "size",
                    "dtype", "device", "requires_grad"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("block_size_valid", "size divisible by block size"),
        ],
        postconditions=[
            ("bsc_created", "Returns block sparse column tensor"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Create block sparse column tensor",
    ))
    
    # torch.sparse.spdiags
    registry.register(FunctionContract(
        name="torch.sparse.spdiags",
        qualname="torch.sparse.spdiags",
        param_names=["diagonals", "offsets", "shape", "layout"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("diagonals_2d", "diagonals must be 2D"),
            ("offsets_match", "offsets length matches diagonals rows"),
        ],
        postconditions=[
            ("sparse_diag", "Returns sparse diagonal matrix"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Create sparse matrix from diagonals",
    ))


# ============================================================================
# Sparse Tensor Properties
# ============================================================================

def _register_sparse_properties(registry: ContractRegistry) -> None:
    """Register sparse tensor property access contracts."""
    
    # Tensor.is_sparse
    registry.register(MethodContract(
        name="torch.Tensor.is_sparse",
        qualname="torch.Tensor.is_sparse",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if tensor is sparse COO",
    ))
    
    # Tensor.is_sparse_csr
    registry.register(MethodContract(
        name="torch.Tensor.is_sparse_csr",
        qualname="torch.Tensor.is_sparse_csr",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if tensor is sparse CSR",
    ))
    
    # Tensor.sparse_dim
    registry.register(MethodContract(
        name="torch.Tensor.sparse_dim",
        qualname="torch.Tensor.sparse_dim",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[
            ("is_sparse", "Tensor must be sparse"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return number of sparse dimensions",
    ))
    
    # Tensor.dense_dim
    registry.register(MethodContract(
        name="torch.Tensor.dense_dim",
        qualname="torch.Tensor.dense_dim",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[
            ("is_sparse", "Tensor must be sparse"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return number of dense dimensions",
    ))
    
    # Tensor._nnz
    registry.register(MethodContract(
        name="torch.Tensor._nnz",
        qualname="torch.Tensor._nnz",
        param_names=["self"],
        param_intervals={},
        return_interval=Interval(0, float('inf')),
        preconditions=[
            ("is_sparse", "Tensor must be sparse"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Return number of non-zero elements",
    ))
    
    # Tensor._indices
    registry.register(MethodContract(
        name="torch.Tensor._indices",
        qualname="torch.Tensor._indices",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns indices tensor
        preconditions=[
            ("is_sparse_coo", "Tensor must be sparse COO"),
        ],
        postconditions=[
            ("same_device", "Indices on same device as tensor"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return indices of sparse COO tensor",
    ))
    
    # Tensor._values
    registry.register(MethodContract(
        name="torch.Tensor._values",
        qualname="torch.Tensor._values",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns values tensor
        preconditions=[
            ("is_sparse", "Tensor must be sparse"),
        ],
        postconditions=[
            ("same_device", "Values on same device as tensor"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return values of sparse tensor",
    ))
    
    # Tensor.crow_indices
    registry.register(MethodContract(
        name="torch.Tensor.crow_indices",
        qualname="torch.Tensor.crow_indices",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns crow indices
        preconditions=[
            ("is_sparse_csr", "Tensor must be sparse CSR/BSR"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return compressed row indices",
    ))
    
    # Tensor.col_indices
    registry.register(MethodContract(
        name="torch.Tensor.col_indices",
        qualname="torch.Tensor.col_indices",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns col indices
        preconditions=[
            ("is_sparse_csr", "Tensor must be sparse CSR/BSR"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return column indices",
    ))
    
    # Tensor.ccol_indices
    registry.register(MethodContract(
        name="torch.Tensor.ccol_indices",
        qualname="torch.Tensor.ccol_indices",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_sparse_csc", "Tensor must be sparse CSC/BSC"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return compressed column indices",
    ))
    
    # Tensor.row_indices
    registry.register(MethodContract(
        name="torch.Tensor.row_indices",
        qualname="torch.Tensor.row_indices",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_sparse_csc", "Tensor must be sparse CSC/BSC"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return row indices",
    ))
    
    # Tensor.values
    registry.register(MethodContract(
        name="torch.Tensor.values",
        qualname="torch.Tensor.values",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_sparse", "Tensor must be sparse"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Return values of sparse tensor",
    ))


# ============================================================================
# Sparse-Dense Conversion
# ============================================================================

def _register_sparse_conversion(registry: ContractRegistry) -> None:
    """Register sparse-dense conversion contracts."""
    
    # Tensor.to_sparse
    registry.register(MethodContract(
        name="torch.Tensor.to_sparse",
        qualname="torch.Tensor.to_sparse",
        param_names=["self", "sparseDims"],
        param_intervals={
            "sparseDims": Interval(0, float('inf')),
        },
        return_interval=None,  # Returns sparse tensor
        preconditions=[
            ("is_dense", "Tensor must be dense"),
        ],
        postconditions=[
            ("is_sparse", "Result is sparse COO"),
            ("same_device", "Result on same device"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert dense tensor to sparse COO",
    ))
    
    # Tensor.to_sparse_coo
    registry.register(MethodContract(
        name="torch.Tensor.to_sparse_coo",
        qualname="torch.Tensor.to_sparse_coo",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("is_coo", "Result is sparse COO"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert to sparse COO format",
    ))
    
    # Tensor.to_sparse_csr
    registry.register(MethodContract(
        name="torch.Tensor.to_sparse_csr",
        qualname="torch.Tensor.to_sparse_csr",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("2d_or_batched", "Must be 2D or batched 2D"),
        ],
        postconditions=[
            ("is_csr", "Result is sparse CSR"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert to sparse CSR format",
    ))
    
    # Tensor.to_sparse_csc
    registry.register(MethodContract(
        name="torch.Tensor.to_sparse_csc",
        qualname="torch.Tensor.to_sparse_csc",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("2d_or_batched", "Must be 2D or batched 2D"),
        ],
        postconditions=[
            ("is_csc", "Result is sparse CSC"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert to sparse CSC format",
    ))
    
    # Tensor.to_sparse_bsr
    registry.register(MethodContract(
        name="torch.Tensor.to_sparse_bsr",
        qualname="torch.Tensor.to_sparse_bsr",
        param_names=["self", "blocksize"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("2d", "Must be 2D"),
            ("divisible", "Dimensions divisible by block size"),
        ],
        postconditions=[
            ("is_bsr", "Result is block sparse row"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert to block sparse row format",
    ))
    
    # Tensor.to_sparse_bsc
    registry.register(MethodContract(
        name="torch.Tensor.to_sparse_bsc",
        qualname="torch.Tensor.to_sparse_bsc",
        param_names=["self", "blocksize"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("2d", "Must be 2D"),
            ("divisible", "Dimensions divisible by block size"),
        ],
        postconditions=[
            ("is_bsc", "Result is block sparse column"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert to block sparse column format",
    ))
    
    # Tensor.to_dense
    registry.register(MethodContract(
        name="torch.Tensor.to_dense",
        qualname="torch.Tensor.to_dense",
        param_names=["self", "dtype", "masked_grad"],
        param_intervals={},
        return_interval=None,  # Returns dense tensor
        preconditions=[
            ("is_sparse", "Tensor must be sparse"),
        ],
        postconditions=[
            ("is_dense", "Result is dense tensor"),
            ("same_device", "Result on same device"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert sparse tensor to dense",
    ))
    
    # Tensor.coalesce
    registry.register(MethodContract(
        name="torch.Tensor.coalesce",
        qualname="torch.Tensor.coalesce",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_sparse_coo", "Must be sparse COO"),
        ],
        postconditions=[
            ("is_coalesced", "Result has no duplicate indices"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Coalesce sparse tensor (combine duplicates)",
    ))
    
    # Tensor.is_coalesced
    registry.register(MethodContract(
        name="torch.Tensor.is_coalesced",
        qualname="torch.Tensor.is_coalesced",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns bool
        preconditions=[
            ("is_sparse_coo", "Must be sparse COO"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if sparse tensor is coalesced",
    ))


# ============================================================================
# Sparse Arithmetic Operations
# ============================================================================

def _register_sparse_arithmetic(registry: ContractRegistry) -> None:
    """Register sparse arithmetic operation contracts."""
    
    # torch.sparse.sum
    registry.register(FunctionContract(
        name="torch.sparse.sum",
        qualname="torch.sparse.sum",
        param_names=["input", "dim", "dtype"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_sparse", "input must be sparse"),
        ],
        postconditions=[
            ("summed", "Returns sum along dimension"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Sum sparse tensor along dimension",
    ))
    
    # torch.sparse.softmax
    registry.register(FunctionContract(
        name="torch.sparse.softmax",
        qualname="torch.sparse.softmax",
        param_names=["input", "dim", "dtype"],
        param_intervals={},
        return_interval=Interval(0.0, 1.0),  # Probabilities
        preconditions=[
            ("is_sparse_coo", "input must be sparse COO"),
        ],
        postconditions=[
            ("normalized", "Result sums to 1 along dim"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Sparse softmax",
    ))
    
    # torch.sparse.log_softmax
    registry.register(FunctionContract(
        name="torch.sparse.log_softmax",
        qualname="torch.sparse.log_softmax",
        param_names=["input", "dim", "dtype"],
        param_intervals={},
        return_interval=Interval(float('-inf'), 0.0),  # Log probabilities
        preconditions=[
            ("is_sparse_coo", "input must be sparse COO"),
        ],
        postconditions=[
            ("log_normalized", "exp(result) sums to 1"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Sparse log softmax",
    ))
    
    # torch.sparse.mm
    registry.register(FunctionContract(
        name="torch.sparse.mm",
        qualname="torch.sparse.mm",
        param_names=["input", "mat2"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("input_sparse", "input must be sparse"),
            ("mat2_dense", "mat2 must be dense"),
            ("dims_compatible", "input.shape[1] == mat2.shape[0]"),
        ],
        postconditions=[
            ("mm_computed", "Returns sparse @ dense matrix multiply"),
        ],
        requires_same_device=True,  # Must be on same device
        may_raise=["RuntimeError"],
        docstring="Sparse-dense matrix multiplication",
    ))
    
    # torch.sparse.sampled_addmm
    registry.register(FunctionContract(
        name="torch.sparse.sampled_addmm",
        qualname="torch.sparse.sampled_addmm",
        param_names=["input", "mat1", "mat2", "beta", "alpha"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("input_sparse", "input must be sparse CSR"),
            ("mats_dense", "mat1 and mat2 must be dense"),
        ],
        postconditions=[
            ("result_sparse", "Returns sparse result"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Sampled sparse-dense addmm",
    ))
    
    # torch.sparse.addmm
    registry.register(FunctionContract(
        name="torch.sparse.addmm",
        qualname="torch.sparse.addmm",
        param_names=["input", "sparse", "dense", "beta", "alpha"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("sparse_is_sparse", "sparse must be sparse"),
            ("input_dense_compatible", "input and dense must be compatible"),
        ],
        postconditions=[
            ("result_dense", "Returns dense result"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Sparse addmm: input * beta + alpha * sparse @ dense",
    ))
    
    # torch.sparse.spsolve
    registry.register(FunctionContract(
        name="torch.sparse.spsolve",
        qualname="torch.sparse.spsolve",
        param_names=["A", "B"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("A_sparse", "A must be sparse CSR"),
            ("A_square", "A must be square"),
            ("A_invertible", "A must be invertible"),
        ],
        postconditions=[
            ("solved", "Returns X where AX = B"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Sparse linear solve",
    ))
    
    # torch.smm (sparse matrix multiplication)
    registry.register(FunctionContract(
        name="torch.smm",
        qualname="torch.smm",
        param_names=["input", "mat"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("both_sparse", "Both inputs must be sparse"),
        ],
        postconditions=[
            ("result_sparse", "Returns sparse result"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Sparse-sparse matrix multiply",
    ))
    
    # torch.hspmm
    registry.register(FunctionContract(
        name="torch.hspmm",
        qualname="torch.hspmm",
        param_names=["mat1", "mat2"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("mat1_sparse", "mat1 must be sparse"),
            ("mat2_dense", "mat2 must be dense"),
        ],
        postconditions=[
            ("hybrid_result", "Returns hybrid sparse result"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Hybrid sparse matrix multiply",
    ))
    
    # torch.sspaddmm
    registry.register(FunctionContract(
        name="torch.sspaddmm",
        qualname="torch.sspaddmm",
        param_names=["input", "mat1", "mat2", "beta", "alpha"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("input_sparse", "input must be sparse"),
            ("mat1_sparse", "mat1 must be sparse"),
            ("mat2_dense", "mat2 must be dense"),
        ],
        postconditions=[
            ("result_sparse", "Returns sparse result"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Sparse matrix multiply and add",
    ))


# ============================================================================
# Sparse Semi-Structured (2:4 Sparsity)
# ============================================================================

def _register_sparse_semi_structured(registry: ContractRegistry) -> None:
    """Register 2:4 semi-structured sparsity contracts."""
    
    # torch.sparse.to_sparse_semi_structured
    registry.register(FunctionContract(
        name="torch.sparse.to_sparse_semi_structured",
        qualname="torch.sparse.to_sparse_semi_structured",
        param_names=["input"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("2d", "Input must be 2D"),
            ("divisible_by_4", "Columns must be divisible by 4"),
            ("cuda", "Must be on CUDA"),
            ("fp16_or_bf16", "Must be float16 or bfloat16"),
        ],
        postconditions=[
            ("semi_structured", "Returns 2:4 sparse tensor"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Convert to 2:4 semi-structured sparse format",
    ))


# ============================================================================
# Miscellaneous Sparse Functions
# ============================================================================

def _register_sparse_misc(registry: ContractRegistry) -> None:
    """Register miscellaneous sparse functions."""
    
    # torch.sparse_coo_tensor alias checks
    registry.register(FunctionContract(
        name="torch._sparse_coo_tensor_unsafe",
        qualname="torch._sparse_coo_tensor_unsafe",
        param_names=["indices", "values", "size", "dtype", "device", "is_coalesced"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("user_validates", "User responsible for index validation"),
        ],
        postconditions=[
            ("sparse_created", "Returns sparse COO (no validation)"),
        ],
        requires_same_device=True,
        may_raise=[],
        docstring="Create sparse tensor without validation (unsafe)",
    ))
    
    # torch.sparse_compressed_tensor
    registry.register(FunctionContract(
        name="torch.sparse_compressed_tensor",
        qualname="torch.sparse_compressed_tensor",
        param_names=["compressed_indices", "plain_indices", "values", "size",
                    "dtype", "layout", "device", "requires_grad"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_layout", "layout must be CSR, CSC, BSR, or BSC"),
        ],
        postconditions=[
            ("compressed_created", "Returns compressed sparse tensor"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Create compressed sparse tensor",
    ))
    
    # torch.sparse.as_sparse_gradcheck
    registry.register(FunctionContract(
        name="torch.sparse.as_sparse_gradcheck",
        qualname="torch.sparse.as_sparse_gradcheck",
        param_names=["tensor"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("gradcheck_compatible", "Tensor prepared for sparse gradcheck"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Prepare sparse tensor for gradcheck",
    ))


# ============================================================================
# Sparse Tensor Linear Algebra
# ============================================================================

def _register_sparse_linalg(registry: ContractRegistry) -> None:
    """Register sparse linear algebra contracts."""
    
    # torch.linalg.solve for sparse
    # Note: This may use dense solve internally, device consistency required
    
    # torch.sparse.addmv (sparse matrix-vector)
    # Included in arithmetic but document device requirements
    
    # Dense fallback operations
    registry.register(FunctionContract(
        name="torch.sparse._to_dense",
        qualname="torch.sparse._to_dense",
        param_names=["self", "dtype", "masked_grad"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_sparse", "Input must be sparse"),
        ],
        postconditions=[
            ("is_dense", "Output is dense"),
            ("same_device", "Output on same device as input"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Internal: convert sparse to dense",
    ))


# ============================================================================
# Structured Sparsity
# ============================================================================

def _register_structured_sparsity(registry: ContractRegistry) -> None:
    """Register structured sparsity patterns."""
    
    # torch.nn.utils.prune sparse patterns
    # These create structured sparsity masks
    
    # Note: Many pruning utilities work with dense masks
    # but result in effective sparsity
    
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
            ("mask_applied", "Pruning mask registered on module"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Apply random unstructured pruning",
    ))
    
    registry.register(FunctionContract(
        name="torch.nn.utils.prune.l1_unstructured",
        qualname="torch.nn.utils.prune.l1_unstructured",
        param_names=["module", "name", "amount"],
        param_intervals={
            "amount": Interval(0.0, 1.0),
        },
        return_interval=None,
        preconditions=[
            ("has_param", "module must have parameter 'name'"),
        ],
        postconditions=[
            ("mask_applied", "L1-based pruning mask applied"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Apply L1-based unstructured pruning",
    ))
    
    registry.register(FunctionContract(
        name="torch.nn.utils.prune.ln_structured",
        qualname="torch.nn.utils.prune.ln_structured",
        param_names=["module", "name", "amount", "n", "dim"],
        param_intervals={
            "amount": Interval(0.0, 1.0),
            "n": Interval(1, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("has_param", "module must have parameter 'name'"),
        ],
        postconditions=[
            ("structured_pruned", "Entire rows/cols/etc pruned"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Apply Ln-based structured pruning",
    ))
    
    registry.register(FunctionContract(
        name="torch.nn.utils.prune.remove",
        qualname="torch.nn.utils.prune.remove",
        param_names=["module", "name"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_pruned", "Parameter must have pruning applied"),
        ],
        postconditions=[
            ("mask_permanent", "Pruning becomes permanent, hooks removed"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Make pruning permanent and remove hooks",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_sparse_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.sparse contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_sparse_creation(registry)
    _register_sparse_properties(registry)
    _register_sparse_conversion(registry)
    _register_sparse_arithmetic(registry)
    _register_sparse_semi_structured(registry)
    _register_sparse_misc(registry)
    _register_sparse_linalg(registry)
    _register_structured_sparsity(registry)


# Export
__all__ = [
    "register_sparse_contracts",
]
