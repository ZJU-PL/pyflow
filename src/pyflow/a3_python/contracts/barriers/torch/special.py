"""
PyTorch Special Functions Contracts (torch.special.*)

This module provides contracts for torch.special functions.
These are special mathematical functions in PyTorch.

Includes:
- Gamma functions
- Bessel functions
- Error functions
- Other special functions
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


def register_special_contracts(registry: ContractRegistry) -> None:
    """Register all torch.special contracts."""
    
    contracts = []
    
    # =========================================================================
    # ERROR FUNCTIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="erf",
        module="torch.special",
        description="Error function",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="erfc",
        module="torch.special",
        description="Complementary error function",
        return_interval=Interval(0.0, 2.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="erfcx",
        module="torch.special",
        description="Scaled complementary error function",
        return_interval=Interval.positive(),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="erfinv",
        module="torch.special",
        description="Inverse error function",
        preconditions=[
            Precondition("-1 < x < 1", "Input must be in (-1, 1)")
        ],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="erfcinv",
        module="torch.special",
        description="Inverse complementary error function",
        preconditions=[
            Precondition("0 < x < 2", "Input must be in (0, 2)")
        ],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="ndtr",
        module="torch.special",
        description="Standard Gaussian CDF",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="ndtri",
        module="torch.special",
        description="Inverse standard Gaussian CDF",
        preconditions=[
            Precondition("0 < x < 1", "Input must be in (0, 1)")
        ],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # GAMMA FUNCTIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="gammaln",
        module="torch.special",
        description="Log of absolute gamma function",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="multigammaln",
        module="torch.special",
        description="Multivariate log-gamma",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="digamma",
        module="torch.special",
        description="Digamma (psi) function",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="psi",
        module="torch.special",
        description="Digamma function (alias)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="polygamma",
        module="torch.special",
        description="n-th derivative of digamma",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="gammainc",
        module="torch.special",
        description="Lower incomplete gamma function (regularized)",
        return_interval=Interval(0.0, 1.0),
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="gammaincc",
        module="torch.special",
        description="Upper incomplete gamma function (regularized)",
        return_interval=Interval(0.0, 1.0),
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="gammaincinv",
        module="torch.special",
        description="Inverse lower incomplete gamma",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="gammainccinv",
        module="torch.special",
        description="Inverse upper incomplete gamma",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # BESSEL FUNCTIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="i0",
        module="torch.special",
        description="Modified Bessel function I0",
        return_interval=Interval(1.0, float('inf')),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="i0e",
        module="torch.special",
        description="Exponentially scaled I0",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="i1",
        module="torch.special",
        description="Modified Bessel function I1",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="i1e",
        module="torch.special",
        description="Exponentially scaled I1",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="bessel_j0",
        module="torch.special",
        description="Bessel function J0",
        return_interval=Interval(-0.5, 1.0),  # J0(0) = 1
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="bessel_j1",
        module="torch.special",
        description="Bessel function J1",
        return_interval=Interval(-0.6, 0.6),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="spherical_bessel_j0",
        module="torch.special",
        description="Spherical Bessel j0",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # EXPONENTIAL AND LOGARITHMIC
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="exp2",
        module="torch.special",
        description="Base-2 exponential",
        return_interval=Interval.positive(),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="expm1",
        module="torch.special",
        description="exp(x) - 1",
        return_interval=Interval(-1.0, float('inf')),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="expit",
        module="torch.special",
        description="Sigmoid function (alias)",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="logit",
        module="torch.special",
        description="Logit function (inverse sigmoid)",
        preconditions=[
            Precondition("0 < x < 1", "Input must be in (0, 1)")
        ],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="log1p",
        module="torch.special",
        description="log(1 + x)",
        preconditions=[
            Precondition("x > -1", "Input must be > -1")
        ],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="log_softmax",
        module="torch.special",
        description="Log-softmax function",
        return_interval=Interval(float('-inf'), 0.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="softmax",
        module="torch.special",
        description="Softmax function",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="xlog1py",
        module="torch.special",
        description="x * log(1 + y)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="xlogy",
        module="torch.special",
        description="x * log(y)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="zeta",
        module="torch.special",
        description="Hurwitz zeta function",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # TRIGONOMETRIC SPECIAL
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="sinc",
        module="torch.special",
        description="Normalized sinc function",
        return_interval=Interval(-0.22, 1.0),  # sinc(0) = 1
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # COMBINATORICS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="entr",
        module="torch.special",
        description="Entropy function: -x*log(x)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="log_ndtr",
        module="torch.special",
        description="Log of standard Gaussian CDF",
        return_interval=Interval(float('-inf'), 0.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="round",
        module="torch.special",
        description="Round to nearest integer",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # AIRY FUNCTIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="airy_ai",
        module="torch.special",
        description="Airy function Ai",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="scaled_modified_bessel_k0",
        module="torch.special",
        description="Scaled modified Bessel K0",
        return_interval=Interval.positive(),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="scaled_modified_bessel_k1",
        module="torch.special",
        description="Scaled modified Bessel K1",
        return_interval=Interval.positive(),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="modified_bessel_i0",
        module="torch.special",
        description="Modified Bessel I0",
        return_interval=Interval(1.0, float('inf')),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="modified_bessel_i1",
        module="torch.special",
        description="Modified Bessel I1",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="modified_bessel_k0",
        module="torch.special",
        description="Modified Bessel K0",
        preconditions=[
            Precondition("x > 0", "Input must be positive")
        ],
        return_interval=Interval.positive(),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="modified_bessel_k1",
        module="torch.special",
        description="Modified Bessel K1",
        preconditions=[
            Precondition("x > 0", "Input must be positive")
        ],
        return_interval=Interval.positive(),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # LEGENDRE FUNCTIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="legendre_polynomial_p",
        module="torch.special",
        description="Legendre polynomial P_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="chebyshev_polynomial_t",
        module="torch.special",
        description="Chebyshev polynomial T_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="chebyshev_polynomial_u",
        module="torch.special",
        description="Chebyshev polynomial U_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="chebyshev_polynomial_v",
        module="torch.special",
        description="Chebyshev polynomial V_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="chebyshev_polynomial_w",
        module="torch.special",
        description="Chebyshev polynomial W_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="hermite_polynomial_h",
        module="torch.special",
        description="Physicist's Hermite polynomial H_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="hermite_polynomial_he",
        module="torch.special",
        description="Probabilist's Hermite polynomial He_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="laguerre_polynomial_l",
        module="torch.special",
        description="Laguerre polynomial L_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="shifted_chebyshev_polynomial_t",
        module="torch.special",
        description="Shifted Chebyshev polynomial T*_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="shifted_chebyshev_polynomial_u",
        module="torch.special",
        description="Shifted Chebyshev polynomial U*_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="shifted_chebyshev_polynomial_v",
        module="torch.special",
        description="Shifted Chebyshev polynomial V*_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="shifted_chebyshev_polynomial_w",
        module="torch.special",
        description="Shifted Chebyshev polynomial W*_n",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # Register all contracts
    bulk_register(contracts, registry)
