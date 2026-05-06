"""
PyTorch Neural Network Functional Contracts (torch.nn.functional.*)

This module provides contracts for all torch.nn.functional functions.
These are the stateless versions of neural network operations.

Includes:
- Activation functions
- Loss functions  
- Normalization functions
- Linear/bilinear operations
- Dropout
- Convolution and pooling
- Attention mechanisms
- Distance and similarity functions
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


def register_nn_functional_contracts(registry: ContractRegistry) -> None:
    """Register all torch.nn.functional.* contracts."""
    
    contracts = []
    
    # =========================================================================
    # ACTIVATION FUNCTIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="relu",
        module="torch.nn.functional",
        description="Rectified Linear Unit",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="relu_",
        module="torch.nn.functional",
        description="In-place ReLU",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="relu6",
        module="torch.nn.functional",
        description="ReLU6: min(max(0, x), 6)",
        return_interval=Interval(0.0, 6.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="leaky_relu",
        module="torch.nn.functional",
        description="Leaky ReLU",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="leaky_relu_",
        module="torch.nn.functional",
        description="In-place Leaky ReLU",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="prelu",
        module="torch.nn.functional",
        description="Parametric ReLU",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="rrelu",
        module="torch.nn.functional",
        description="Randomized Leaky ReLU",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="rrelu_",
        module="torch.nn.functional",
        description="In-place Randomized Leaky ReLU",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="elu",
        module="torch.nn.functional",
        description="Exponential Linear Unit",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="elu_",
        module="torch.nn.functional",
        description="In-place ELU",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="selu",
        module="torch.nn.functional",
        description="Scaled ELU",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="celu",
        module="torch.nn.functional",
        description="Continuously Differentiable ELU",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="gelu",
        module="torch.nn.functional",
        description="Gaussian Error Linear Unit",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="sigmoid",
        module="torch.nn.functional",
        description="Sigmoid activation",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="hardsigmoid",
        module="torch.nn.functional",
        description="Hard sigmoid",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="silu",
        module="torch.nn.functional",
        description="Sigmoid Linear Unit (Swish)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="mish",
        module="torch.nn.functional",
        description="Mish activation",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="tanh",
        module="torch.nn.functional",
        description="Hyperbolic tangent",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="hardtanh",
        module="torch.nn.functional",
        description="Hard tanh (clamped)",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="hardtanh_",
        module="torch.nn.functional",
        description="In-place hard tanh",
        return_interval=Interval(-1.0, 1.0),
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="hardswish",
        module="torch.nn.functional",
        description="Hard Swish activation",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="softplus",
        module="torch.nn.functional",
        description="Softplus activation",
        return_interval=Interval.positive(),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="softshrink",
        module="torch.nn.functional",
        description="Soft shrinkage",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="hardshrink",
        module="torch.nn.functional",
        description="Hard shrinkage",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="softsign",
        module="torch.nn.functional",
        description="Softsign activation",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="tanhshrink",
        module="torch.nn.functional",
        description="Tanh shrinkage: x - tanh(x)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="threshold",
        module="torch.nn.functional",
        description="Threshold activation",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="threshold_",
        module="torch.nn.functional",
        description="In-place threshold",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="glu",
        module="torch.nn.functional",
        description="Gated Linear Unit",
        preserves_device=True,
    ))
    
    # =========================================================================
    # SOFTMAX FAMILY
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="softmax",
        module="torch.nn.functional",
        description="Softmax (elements sum to 1)",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="softmin",
        module="torch.nn.functional",
        description="Softmin (softmax of negation)",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="log_softmax",
        module="torch.nn.functional",
        description="Log of softmax",
        return_interval=Interval(float('-inf'), 0.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="gumbel_softmax",
        module="torch.nn.functional",
        description="Gumbel-softmax (differentiable sampling)",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # NORMALIZATION
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="normalize",
        module="torch.nn.functional",
        description="L2 normalization along dimension",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="batch_norm",
        module="torch.nn.functional",
        description="Batch normalization",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="layer_norm",
        module="torch.nn.functional",
        description="Layer normalization",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="instance_norm",
        module="torch.nn.functional",
        description="Instance normalization",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="group_norm",
        module="torch.nn.functional",
        description="Group normalization",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="local_response_norm",
        module="torch.nn.functional",
        description="Local response normalization",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="rms_norm",
        module="torch.nn.functional",
        description="RMS normalization",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # LINEAR OPERATIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="linear",
        module="torch.nn.functional",
        description="Linear transformation: xW^T + b",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="bilinear",
        module="torch.nn.functional",
        description="Bilinear transformation",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    # =========================================================================
    # DROPOUT
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="dropout",
        module="torch.nn.functional",
        description="Dropout regularization",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="dropout1d",
        module="torch.nn.functional",
        description="1D dropout (channel-wise)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="dropout2d",
        module="torch.nn.functional",
        description="2D dropout (channel-wise)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="dropout3d",
        module="torch.nn.functional",
        description="3D dropout (channel-wise)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="alpha_dropout",
        module="torch.nn.functional",
        description="Alpha dropout (for SELU)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="feature_alpha_dropout",
        module="torch.nn.functional",
        description="Feature-wise alpha dropout",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # CONVOLUTION
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="conv1d",
        module="torch.nn.functional",
        description="1D convolution",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="conv2d",
        module="torch.nn.functional",
        description="2D convolution",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="conv3d",
        module="torch.nn.functional",
        description="3D convolution",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="conv_transpose1d",
        module="torch.nn.functional",
        description="1D transposed convolution",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="conv_transpose2d",
        module="torch.nn.functional",
        description="2D transposed convolution",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="conv_transpose3d",
        module="torch.nn.functional",
        description="3D transposed convolution",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="unfold",
        module="torch.nn.functional",
        description="Extract sliding blocks",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="fold",
        module="torch.nn.functional",
        description="Combine sliding blocks",
        preserves_device=True,
    ))
    
    # =========================================================================
    # POOLING
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="max_pool1d",
        module="torch.nn.functional",
        description="1D max pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="max_pool2d",
        module="torch.nn.functional",
        description="2D max pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="max_pool3d",
        module="torch.nn.functional",
        description="3D max pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="max_pool1d_with_indices",
        module="torch.nn.functional",
        description="1D max pooling with indices",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="max_pool2d_with_indices",
        module="torch.nn.functional",
        description="2D max pooling with indices",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="max_pool3d_with_indices",
        module="torch.nn.functional",
        description="3D max pooling with indices",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="max_unpool1d",
        module="torch.nn.functional",
        description="1D max unpooling",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="max_unpool2d",
        module="torch.nn.functional",
        description="2D max unpooling",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="max_unpool3d",
        module="torch.nn.functional",
        description="3D max unpooling",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="avg_pool1d",
        module="torch.nn.functional",
        description="1D average pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="avg_pool2d",
        module="torch.nn.functional",
        description="2D average pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="avg_pool3d",
        module="torch.nn.functional",
        description="3D average pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="fractional_max_pool2d",
        module="torch.nn.functional",
        description="2D fractional max pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="fractional_max_pool3d",
        module="torch.nn.functional",
        description="3D fractional max pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="fractional_max_pool2d_with_indices",
        module="torch.nn.functional",
        description="2D fractional max pooling with indices",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="fractional_max_pool3d_with_indices",
        module="torch.nn.functional",
        description="3D fractional max pooling with indices",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="lp_pool1d",
        module="torch.nn.functional",
        description="1D power-average pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="lp_pool2d",
        module="torch.nn.functional",
        description="2D power-average pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="lp_pool3d",
        module="torch.nn.functional",
        description="3D power-average pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="adaptive_max_pool1d",
        module="torch.nn.functional",
        description="1D adaptive max pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="adaptive_max_pool2d",
        module="torch.nn.functional",
        description="2D adaptive max pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="adaptive_max_pool3d",
        module="torch.nn.functional",
        description="3D adaptive max pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="adaptive_max_pool1d_with_indices",
        module="torch.nn.functional",
        description="1D adaptive max pooling with indices",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="adaptive_max_pool2d_with_indices",
        module="torch.nn.functional",
        description="2D adaptive max pooling with indices",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="adaptive_max_pool3d_with_indices",
        module="torch.nn.functional",
        description="3D adaptive max pooling with indices",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="adaptive_avg_pool1d",
        module="torch.nn.functional",
        description="1D adaptive average pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="adaptive_avg_pool2d",
        module="torch.nn.functional",
        description="2D adaptive average pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="adaptive_avg_pool3d",
        module="torch.nn.functional",
        description="3D adaptive average pooling",
        preserves_device=True,
    ))
    
    # =========================================================================
    # PADDING
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="pad",
        module="torch.nn.functional",
        description="Pad tensor",
        preserves_device=True,
    ))
    
    # =========================================================================
    # EMBEDDING
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="embedding",
        module="torch.nn.functional",
        description="Lookup embedding table",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="embedding_bag",
        module="torch.nn.functional",
        description="Embedding bag (aggregated)",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="one_hot",
        module="torch.nn.functional",
        description="One-hot encoding",
        return_interval=Interval(0.0, 1.0),
        preserves_device=True,
    ))
    
    # =========================================================================
    # DISTANCE FUNCTIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="pairwise_distance",
        module="torch.nn.functional",
        description="Pairwise distance between tensors",
        requires_same_device=True,
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cosine_similarity",
        module="torch.nn.functional",
        description="Cosine similarity between tensors",
        return_interval=Interval(-1.0, 1.0),
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="pdist",
        module="torch.nn.functional",
        description="Pairwise distance matrix",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    # =========================================================================
    # LOSS FUNCTIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="binary_cross_entropy",
        module="torch.nn.functional",
        description="Binary cross-entropy loss",
        preconditions=[
            Precondition("0 <= input <= 1", "Input must be in [0, 1]"),
            Precondition("0 <= target <= 1", "Target must be in [0, 1]"),
        ],
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="binary_cross_entropy_with_logits",
        module="torch.nn.functional",
        description="BCE with logits (numerically stable)",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cross_entropy",
        module="torch.nn.functional",
        description="Cross-entropy loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="nll_loss",
        module="torch.nn.functional",
        description="Negative log-likelihood loss",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="poisson_nll_loss",
        module="torch.nn.functional",
        description="Poisson NLL loss",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="gaussian_nll_loss",
        module="torch.nn.functional",
        description="Gaussian NLL loss",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="kl_div",
        module="torch.nn.functional",
        description="KL divergence loss",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="mse_loss",
        module="torch.nn.functional",
        description="Mean squared error loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="l1_loss",
        module="torch.nn.functional",
        description="L1 (MAE) loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="smooth_l1_loss",
        module="torch.nn.functional",
        description="Smooth L1 (Huber) loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="huber_loss",
        module="torch.nn.functional",
        description="Huber loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="hinge_embedding_loss",
        module="torch.nn.functional",
        description="Hinge embedding loss",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="margin_ranking_loss",
        module="torch.nn.functional",
        description="Margin ranking loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="multilabel_margin_loss",
        module="torch.nn.functional",
        description="Multi-label margin loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="multilabel_soft_margin_loss",
        module="torch.nn.functional",
        description="Multi-label soft margin loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="multi_margin_loss",
        module="torch.nn.functional",
        description="Multi-class hinge loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="soft_margin_loss",
        module="torch.nn.functional",
        description="Soft margin loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="triplet_margin_loss",
        module="torch.nn.functional",
        description="Triplet margin loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="triplet_margin_with_distance_loss",
        module="torch.nn.functional",
        description="Triplet loss with custom distance",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cosine_embedding_loss",
        module="torch.nn.functional",
        description="Cosine embedding loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ctc_loss",
        module="torch.nn.functional",
        description="Connectionist temporal classification loss",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    # =========================================================================
    # ATTENTION
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="scaled_dot_product_attention",
        module="torch.nn.functional",
        description="Scaled dot-product attention",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="multi_head_attention_forward",
        module="torch.nn.functional",
        description="Multi-head attention",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    # =========================================================================
    # INTERPOLATION / UPSAMPLING
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="interpolate",
        module="torch.nn.functional",
        description="Interpolate tensor",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="upsample",
        module="torch.nn.functional",
        description="Upsample tensor (deprecated)",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="upsample_nearest",
        module="torch.nn.functional",
        description="Nearest neighbor upsampling (deprecated)",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="upsample_bilinear",
        module="torch.nn.functional",
        description="Bilinear upsampling (deprecated)",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="grid_sample",
        module="torch.nn.functional",
        description="Sample with grid",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="affine_grid",
        module="torch.nn.functional",
        description="Generate affine grid",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="pixel_shuffle",
        module="torch.nn.functional",
        description="Rearrange for upscaling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="pixel_unshuffle",
        module="torch.nn.functional",
        description="Inverse pixel shuffle",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="channel_shuffle",
        module="torch.nn.functional",
        description="Shuffle channels",
        preserves_device=True,
    ))
    
    # =========================================================================
    # SPARSE
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="celu",
        module="torch.nn.functional",
        description="Continuously differentiable ELU",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # MISCELLANEOUS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="batch_norm",
        module="torch.nn.functional",
        description="Batch normalization",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="fractional_max_pool2d",
        module="torch.nn.functional",
        description="2D fractional max pooling",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="fractional_max_pool3d",
        module="torch.nn.functional",
        description="3D fractional max pooling",
        preserves_device=True,
    ))
    
    # Register all contracts
    bulk_register(contracts, registry)
