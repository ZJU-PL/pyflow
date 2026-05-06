"""
PyTorch Distributions Contracts (torch.distributions.*)

This module provides contracts for torch.distributions classes.
These are probability distribution implementations in PyTorch.

Includes:
- Continuous distributions
- Discrete distributions
- Mixture distributions
- Transformed distributions
"""

from typing import Optional, List, Dict, Any, Tuple
import math

from ..intervals import Interval
from ..contracts import (
    LibraryContract, ModuleContract, MethodContract, 
    PropertyContract, ContractRegistry, Precondition
)
from ..abstract_values import Shape, DType, Device, AbstractTensor

from .registry import bulk_register


def register_distribution_contracts(registry: ContractRegistry) -> None:
    """Register all torch.distributions contracts."""
    
    contracts = []
    
    # =========================================================================
    # BASE DISTRIBUTION
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Distribution",
        module="torch.distributions",
        description="Base distribution class",
    ))
    
    contracts.append(ModuleContract(
        name="ExponentialFamily",
        module="torch.distributions",
        description="Base class for exponential family",
    ))
    
    # =========================================================================
    # CONTINUOUS DISTRIBUTIONS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Normal",
        module="torch.distributions",
        description="Normal (Gaussian) distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MultivariateNormal",
        module="torch.distributions",
        description="Multivariate normal distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LowRankMultivariateNormal",
        module="torch.distributions",
        description="Low-rank multivariate normal",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Uniform",
        module="torch.distributions",
        description="Uniform distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Beta",
        module="torch.distributions",
        description="Beta distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Gamma",
        module="torch.distributions",
        description="Gamma distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Exponential",
        module="torch.distributions",
        description="Exponential distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Laplace",
        module="torch.distributions",
        description="Laplace distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Cauchy",
        module="torch.distributions",
        description="Cauchy distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="HalfCauchy",
        module="torch.distributions",
        description="Half-Cauchy distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="HalfNormal",
        module="torch.distributions",
        description="Half-normal distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LogNormal",
        module="torch.distributions",
        description="Log-normal distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="StudentT",
        module="torch.distributions",
        description="Student's t-distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Chi2",
        module="torch.distributions",
        description="Chi-squared distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="FisherSnedecor",
        module="torch.distributions",
        description="F-distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Weibull",
        module="torch.distributions",
        description="Weibull distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Pareto",
        module="torch.distributions",
        description="Pareto distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Gumbel",
        module="torch.distributions",
        description="Gumbel distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="VonMises",
        module="torch.distributions",
        description="Von Mises distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Dirichlet",
        module="torch.distributions",
        description="Dirichlet distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Kumaraswamy",
        module="torch.distributions",
        description="Kumaraswamy distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LKJCholesky",
        module="torch.distributions",
        description="LKJ Cholesky distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Wishart",
        module="torch.distributions",
        description="Wishart distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="InverseGamma",
        module="torch.distributions",
        description="Inverse gamma distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # DISCRETE DISTRIBUTIONS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Bernoulli",
        module="torch.distributions",
        description="Bernoulli distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Binomial",
        module="torch.distributions",
        description="Binomial distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Categorical",
        module="torch.distributions",
        description="Categorical distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="OneHotCategorical",
        module="torch.distributions",
        description="One-hot categorical distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="OneHotCategoricalStraightThrough",
        module="torch.distributions",
        description="One-hot categorical with straight-through gradient",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Geometric",
        module="torch.distributions",
        description="Geometric distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Multinomial",
        module="torch.distributions",
        description="Multinomial distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="NegativeBinomial",
        module="torch.distributions",
        description="Negative binomial distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Poisson",
        module="torch.distributions",
        description="Poisson distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # MIXTURE DISTRIBUTIONS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="MixtureSameFamily",
        module="torch.distributions",
        description="Mixture of same family distributions",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # RELAXED DISTRIBUTIONS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="RelaxedBernoulli",
        module="torch.distributions",
        description="Relaxed (continuous) Bernoulli",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="RelaxedOneHotCategorical",
        module="torch.distributions",
        description="Relaxed one-hot categorical (Gumbel-Softmax)",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ContinuousBernoulli",
        module="torch.distributions",
        description="Continuous Bernoulli distribution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # TRANSFORMED DISTRIBUTIONS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="TransformedDistribution",
        module="torch.distributions",
        description="Distribution with bijective transform",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Independent",
        module="torch.distributions",
        description="Reinterpret batch dims as event dims",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # TRANSFORMS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Transform",
        module="torch.distributions.transforms",
        description="Base transform class",
    ))
    
    contracts.append(ModuleContract(
        name="AbsTransform",
        module="torch.distributions.transforms",
        description="Absolute value transform",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="AffineTransform",
        module="torch.distributions.transforms",
        description="Affine (scale + shift) transform",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ComposeTransform",
        module="torch.distributions.transforms",
        description="Composition of transforms",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="CorrCholeskyTransform",
        module="torch.distributions.transforms",
        description="Transform to correlation Cholesky",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="CumulativeDistributionTransform",
        module="torch.distributions.transforms",
        description="CDF transform",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ExpTransform",
        module="torch.distributions.transforms",
        description="Exponential transform",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="IndependentTransform",
        module="torch.distributions.transforms",
        description="Independent transform",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LowerCholeskyTransform",
        module="torch.distributions.transforms",
        description="Transform to lower triangular",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="PositiveDefiniteTransform",
        module="torch.distributions.transforms",
        description="Transform to positive definite matrix",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="PowerTransform",
        module="torch.distributions.transforms",
        description="Power transform",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ReshapeTransform",
        module="torch.distributions.transforms",
        description="Reshape transform",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="SigmoidTransform",
        module="torch.distributions.transforms",
        description="Sigmoid transform (logistic)",
        forward_return_interval=Interval(0.0, 1.0),
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="SoftmaxTransform",
        module="torch.distributions.transforms",
        description="Softmax transform",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="SoftplusTransform",
        module="torch.distributions.transforms",
        description="Softplus transform",
        forward_return_interval=Interval.positive(),
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="StackTransform",
        module="torch.distributions.transforms",
        description="Stack multiple transforms",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="StickBreakingTransform",
        module="torch.distributions.transforms",
        description="Stick-breaking transform",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="TanhTransform",
        module="torch.distributions.transforms",
        description="Tanh transform",
        forward_return_interval=Interval(-1.0, 1.0),
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # DISTRIBUTION METHODS (common to all distributions)
    # =========================================================================
    
    contracts.append(MethodContract(
        name="sample",
        module="torch.distributions.Distribution",
        description="Draw samples from distribution",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="rsample",
        module="torch.distributions.Distribution",
        description="Draw reparameterized samples",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="log_prob",
        module="torch.distributions.Distribution",
        description="Log probability density/mass",
        return_interval=Interval(float('-inf'), 0.0),
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="entropy",
        module="torch.distributions.Distribution",
        description="Distribution entropy",
        return_interval=Interval.non_negative(),
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="cdf",
        module="torch.distributions.Distribution",
        description="Cumulative distribution function",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="icdf",
        module="torch.distributions.Distribution",
        description="Inverse CDF (quantile function)",
        preconditions=[
            Precondition("0 <= value <= 1", "Value must be in [0, 1]")
        ],
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="expand",
        module="torch.distributions.Distribution",
        description="Expand batch shape",
        preserves_device=True,
    ))
    
    contracts.append(PropertyContract(
        name="mean",
        module="torch.distributions.Distribution",
        description="Distribution mean",
    ))
    
    contracts.append(PropertyContract(
        name="mode",
        module="torch.distributions.Distribution",
        description="Distribution mode",
    ))
    
    contracts.append(PropertyContract(
        name="variance",
        module="torch.distributions.Distribution",
        description="Distribution variance",
        return_interval=Interval.non_negative(),
    ))
    
    contracts.append(PropertyContract(
        name="stddev",
        module="torch.distributions.Distribution",
        description="Distribution standard deviation",
        return_interval=Interval.non_negative(),
    ))
    
    contracts.append(PropertyContract(
        name="batch_shape",
        module="torch.distributions.Distribution",
        description="Batch dimensions shape",
    ))
    
    contracts.append(PropertyContract(
        name="event_shape",
        module="torch.distributions.Distribution",
        description="Event dimensions shape",
    ))
    
    contracts.append(PropertyContract(
        name="support",
        module="torch.distributions.Distribution",
        description="Distribution support",
    ))
    
    # Register all contracts
    bulk_register(contracts, registry)
