"""
PyTorch Linear Algebra Contracts (torch.linalg.*)

This module provides contracts for torch.linalg functions.
These are the linear algebra operations in PyTorch.

Includes:
- Matrix decompositions (SVD, QR, LU, Cholesky, etc.)
- Matrix operations (norm, det, inv, solve, etc.)
- Eigenvalue/eigenvector computations
"""

from typing import Optional, List, Dict, Any, Tuple
import math

from ..intervals import Interval
from ..contracts import (
    LibraryContract, FunctionContract, ContractRegistry,
    ContractBuilder, Precondition, Postcondition
)
from ..abstract_values import Shape, DType, Device, AbstractTensor

from .registry import bulk_register


def register_linalg_contracts(registry: ContractRegistry) -> None:
    """Register all torch.linalg contracts."""
    
    contracts = []
    
    # =========================================================================
    # MATRIX PROPERTIES
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="det",
        module="torch.linalg",
        description="Matrix determinant",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="slogdet",
        module="torch.linalg",
        description="Sign and log-abs determinant",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cond",
        module="torch.linalg",
        description="Matrix condition number",
        return_interval=Interval(1.0, float('inf')),
        guarantees_positive=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="matrix_rank",
        module="torch.linalg",
        description="Matrix rank",
        return_interval=Interval.non_negative(),
        preserves_device=True,
    ))
    
    # =========================================================================
    # NORMS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="norm",
        module="torch.linalg",
        description="Matrix or vector norm",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="vector_norm",
        module="torch.linalg",
        description="Vector norm",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="matrix_norm",
        module="torch.linalg",
        description="Matrix norm",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="diagonal",
        module="torch.linalg",
        description="Extract or create diagonal",
        preserves_device=True,
    ))
    
    # =========================================================================
    # DECOMPOSITIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="cholesky",
        module="torch.linalg",
        description="Cholesky decomposition",
        preconditions=[
            Precondition("self is positive definite", "Matrix must be positive definite")
        ],
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cholesky_ex",
        module="torch.linalg",
        description="Cholesky with error info",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="qr",
        module="torch.linalg",
        description="QR decomposition",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="lu",
        module="torch.linalg",
        description="LU decomposition with pivoting",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="lu_factor",
        module="torch.linalg",
        description="LU factorization",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="lu_factor_ex",
        module="torch.linalg",
        description="LU factorization with error info",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ldl_factor",
        module="torch.linalg",
        description="LDL factorization",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ldl_factor_ex",
        module="torch.linalg",
        description="LDL factorization with error info",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="svd",
        module="torch.linalg",
        description="Singular value decomposition",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="svdvals",
        module="torch.linalg",
        description="Singular values only",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="eig",
        module="torch.linalg",
        description="Eigenvalues and eigenvectors",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="eigvals",
        module="torch.linalg",
        description="Eigenvalues only",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="eigh",
        module="torch.linalg",
        description="Symmetric eigendecomposition",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="eigvalsh",
        module="torch.linalg",
        description="Symmetric eigenvalues only",
        preserves_device=True,
    ))
    
    # =========================================================================
    # INVERSES
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="inv",
        module="torch.linalg",
        description="Matrix inverse",
        preconditions=[
            Precondition("det(self) != 0", "Matrix must be invertible")
        ],
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="inv_ex",
        module="torch.linalg",
        description="Matrix inverse with error info",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="pinv",
        module="torch.linalg",
        description="Pseudo-inverse (Moore-Penrose)",
        preserves_device=True,
    ))
    
    # =========================================================================
    # SOLVERS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="solve",
        module="torch.linalg",
        description="Solve linear system Ax = b",
        preconditions=[
            Precondition("det(A) != 0", "Matrix A must be invertible")
        ],
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="solve_ex",
        module="torch.linalg",
        description="Solve with error info",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="solve_triangular",
        module="torch.linalg",
        description="Solve triangular system",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="lu_solve",
        module="torch.linalg",
        description="Solve using LU factorization",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ldl_solve",
        module="torch.linalg",
        description="Solve using LDL factorization",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cholesky_solve",
        module="torch.linalg",
        description="Solve using Cholesky factorization",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="lstsq",
        module="torch.linalg",
        description="Least-squares solution",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    # =========================================================================
    # MATRIX PRODUCTS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="matmul",
        module="torch.linalg",
        description="Matrix multiplication",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="multi_dot",
        module="torch.linalg",
        description="Chained matrix products",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="matrix_power",
        module="torch.linalg",
        description="Matrix power",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="matrix_exp",
        module="torch.linalg",
        description="Matrix exponential",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cross",
        module="torch.linalg",
        description="Cross product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="vecdot",
        module="torch.linalg",
        description="Vector dot product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="vander",
        module="torch.linalg",
        description="Vandermonde matrix",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="householder_product",
        module="torch.linalg",
        description="Product of Householder matrices",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="tensorinv",
        module="torch.linalg",
        description="Tensor inverse",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="tensorsolve",
        module="torch.linalg",
        description="Tensor solve",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    # Register all contracts
    bulk_register(contracts, registry)
