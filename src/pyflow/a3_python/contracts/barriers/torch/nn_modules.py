"""
PyTorch Neural Network Module Contracts (torch.nn.*)

This module provides contracts for torch.nn module classes.
These are the stateful building blocks for neural networks.

Includes:
- Layer modules (Linear, Conv, etc.)
- Normalization modules
- Activation modules
- Loss modules
- Container modules
"""

from typing import Optional, List, Dict, Any, Tuple
import math

from ..intervals import Interval
from ..contracts import (
    LibraryContract, ModuleContract, ContractRegistry,
    ContractBuilder, Precondition, Postcondition
)
from ..abstract_values import Shape, DType, Device, AbstractTensor

from .registry import bulk_register


def register_nn_module_contracts(registry: ContractRegistry) -> None:
    """Register all torch.nn module contracts."""
    
    contracts = []
    
    # =========================================================================
    # LINEAR LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Linear",
        module="torch.nn",
        description="Linear transformation layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Bilinear",
        module="torch.nn",
        description="Bilinear transformation layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyLinear",
        module="torch.nn",
        description="Lazy linear layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Identity",
        module="torch.nn",
        description="Identity layer (pass-through)",
        forward_preserves_device=True,
        forward_preserves_shape=True,
        forward_preserves_dtype=True,
    ))
    
    # =========================================================================
    # CONVOLUTION LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Conv1d",
        module="torch.nn",
        description="1D convolution layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Conv2d",
        module="torch.nn",
        description="2D convolution layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Conv3d",
        module="torch.nn",
        description="3D convolution layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ConvTranspose1d",
        module="torch.nn",
        description="1D transposed convolution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ConvTranspose2d",
        module="torch.nn",
        description="2D transposed convolution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ConvTranspose3d",
        module="torch.nn",
        description="3D transposed convolution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyConv1d",
        module="torch.nn",
        description="Lazy 1D convolution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyConv2d",
        module="torch.nn",
        description="Lazy 2D convolution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyConv3d",
        module="torch.nn",
        description="Lazy 3D convolution",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyConvTranspose1d",
        module="torch.nn",
        description="Lazy 1D transposed conv",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyConvTranspose2d",
        module="torch.nn",
        description="Lazy 2D transposed conv",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyConvTranspose3d",
        module="torch.nn",
        description="Lazy 3D transposed conv",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Unfold",
        module="torch.nn",
        description="Extract sliding blocks",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Fold",
        module="torch.nn",
        description="Combine sliding blocks",
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # POOLING LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="MaxPool1d",
        module="torch.nn",
        description="1D max pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MaxPool2d",
        module="torch.nn",
        description="2D max pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MaxPool3d",
        module="torch.nn",
        description="3D max pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MaxUnpool1d",
        module="torch.nn",
        description="1D max unpooling",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MaxUnpool2d",
        module="torch.nn",
        description="2D max unpooling",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MaxUnpool3d",
        module="torch.nn",
        description="3D max unpooling",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="AvgPool1d",
        module="torch.nn",
        description="1D average pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="AvgPool2d",
        module="torch.nn",
        description="2D average pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="AvgPool3d",
        module="torch.nn",
        description="3D average pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="FractionalMaxPool2d",
        module="torch.nn",
        description="2D fractional max pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="FractionalMaxPool3d",
        module="torch.nn",
        description="3D fractional max pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LPPool1d",
        module="torch.nn",
        description="1D power-average pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LPPool2d",
        module="torch.nn",
        description="2D power-average pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LPPool3d",
        module="torch.nn",
        description="3D power-average pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="AdaptiveMaxPool1d",
        module="torch.nn",
        description="1D adaptive max pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="AdaptiveMaxPool2d",
        module="torch.nn",
        description="2D adaptive max pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="AdaptiveMaxPool3d",
        module="torch.nn",
        description="3D adaptive max pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="AdaptiveAvgPool1d",
        module="torch.nn",
        description="1D adaptive average pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="AdaptiveAvgPool2d",
        module="torch.nn",
        description="2D adaptive average pooling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="AdaptiveAvgPool3d",
        module="torch.nn",
        description="3D adaptive average pooling",
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # PADDING LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="ReflectionPad1d",
        module="torch.nn",
        description="1D reflection padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ReflectionPad2d",
        module="torch.nn",
        description="2D reflection padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ReflectionPad3d",
        module="torch.nn",
        description="3D reflection padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ReplicationPad1d",
        module="torch.nn",
        description="1D replication padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ReplicationPad2d",
        module="torch.nn",
        description="2D replication padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ReplicationPad3d",
        module="torch.nn",
        description="3D replication padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ZeroPad1d",
        module="torch.nn",
        description="1D zero padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ZeroPad2d",
        module="torch.nn",
        description="2D zero padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ZeroPad3d",
        module="torch.nn",
        description="3D zero padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ConstantPad1d",
        module="torch.nn",
        description="1D constant padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ConstantPad2d",
        module="torch.nn",
        description="2D constant padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ConstantPad3d",
        module="torch.nn",
        description="3D constant padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="CircularPad1d",
        module="torch.nn",
        description="1D circular padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="CircularPad2d",
        module="torch.nn",
        description="2D circular padding",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="CircularPad3d",
        module="torch.nn",
        description="3D circular padding",
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # ACTIVATION LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="ReLU",
        module="torch.nn",
        description="ReLU activation",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="ReLU6",
        module="torch.nn",
        description="ReLU6 activation",
        forward_return_interval=Interval(0.0, 6.0),
        forward_guarantees_non_negative=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="LeakyReLU",
        module="torch.nn",
        description="Leaky ReLU activation",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="PReLU",
        module="torch.nn",
        description="Parametric ReLU",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="RReLU",
        module="torch.nn",
        description="Randomized Leaky ReLU",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="ELU",
        module="torch.nn",
        description="ELU activation",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="SELU",
        module="torch.nn",
        description="SELU activation",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="CELU",
        module="torch.nn",
        description="CELU activation",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="GELU",
        module="torch.nn",
        description="GELU activation",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Sigmoid",
        module="torch.nn",
        description="Sigmoid activation",
        forward_return_interval=Interval(0.0, 1.0),
        forward_guarantees_non_negative=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Hardsigmoid",
        module="torch.nn",
        description="Hard sigmoid",
        forward_return_interval=Interval(0.0, 1.0),
        forward_guarantees_non_negative=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="SiLU",
        module="torch.nn",
        description="SiLU (Swish) activation",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Mish",
        module="torch.nn",
        description="Mish activation",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Tanh",
        module="torch.nn",
        description="Tanh activation",
        forward_return_interval=Interval(-1.0, 1.0),
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Hardtanh",
        module="torch.nn",
        description="Hard tanh",
        forward_return_interval=Interval(-1.0, 1.0),
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Hardswish",
        module="torch.nn",
        description="Hard swish activation",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Softplus",
        module="torch.nn",
        description="Softplus activation",
        forward_return_interval=Interval.positive(),
        forward_guarantees_positive=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Softshrink",
        module="torch.nn",
        description="Soft shrinkage",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Hardshrink",
        module="torch.nn",
        description="Hard shrinkage",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Softsign",
        module="torch.nn",
        description="Softsign activation",
        forward_return_interval=Interval(-1.0, 1.0),
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Tanhshrink",
        module="torch.nn",
        description="Tanh shrinkage",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Threshold",
        module="torch.nn",
        description="Threshold activation",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="GLU",
        module="torch.nn",
        description="Gated Linear Unit",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Softmax",
        module="torch.nn",
        description="Softmax activation",
        forward_return_interval=Interval(0.0, 1.0),
        forward_guarantees_non_negative=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Softmax2d",
        module="torch.nn",
        description="2D Softmax",
        forward_return_interval=Interval(0.0, 1.0),
        forward_guarantees_non_negative=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Softmin",
        module="torch.nn",
        description="Softmin activation",
        forward_return_interval=Interval(0.0, 1.0),
        forward_guarantees_non_negative=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="LogSoftmax",
        module="torch.nn",
        description="Log softmax",
        forward_return_interval=Interval(float('-inf'), 0.0),
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    # =========================================================================
    # NORMALIZATION LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="BatchNorm1d",
        module="torch.nn",
        description="1D batch normalization",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="BatchNorm2d",
        module="torch.nn",
        description="2D batch normalization",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="BatchNorm3d",
        module="torch.nn",
        description="3D batch normalization",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyBatchNorm1d",
        module="torch.nn",
        description="Lazy 1D batch norm",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyBatchNorm2d",
        module="torch.nn",
        description="Lazy 2D batch norm",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyBatchNorm3d",
        module="torch.nn",
        description="Lazy 3D batch norm",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="SyncBatchNorm",
        module="torch.nn",
        description="Synchronized batch norm",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="InstanceNorm1d",
        module="torch.nn",
        description="1D instance normalization",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="InstanceNorm2d",
        module="torch.nn",
        description="2D instance normalization",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="InstanceNorm3d",
        module="torch.nn",
        description="3D instance normalization",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyInstanceNorm1d",
        module="torch.nn",
        description="Lazy 1D instance norm",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyInstanceNorm2d",
        module="torch.nn",
        description="Lazy 2D instance norm",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="LazyInstanceNorm3d",
        module="torch.nn",
        description="Lazy 3D instance norm",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="LayerNorm",
        module="torch.nn",
        description="Layer normalization",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="GroupNorm",
        module="torch.nn",
        description="Group normalization",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="RMSNorm",
        module="torch.nn",
        description="RMS normalization",
        forward_requires_same_device=True,
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="LocalResponseNorm",
        module="torch.nn",
        description="Local response normalization",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    # =========================================================================
    # DROPOUT LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Dropout",
        module="torch.nn",
        description="Dropout regularization",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Dropout1d",
        module="torch.nn",
        description="1D channel dropout",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Dropout2d",
        module="torch.nn",
        description="2D channel dropout",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Dropout3d",
        module="torch.nn",
        description="3D channel dropout",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="AlphaDropout",
        module="torch.nn",
        description="Alpha dropout (for SELU)",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="FeatureAlphaDropout",
        module="torch.nn",
        description="Feature-wise alpha dropout",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    # =========================================================================
    # EMBEDDING LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Embedding",
        module="torch.nn",
        description="Embedding lookup table",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="EmbeddingBag",
        module="torch.nn",
        description="Embedding bag (aggregated)",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # RECURRENT LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="RNN",
        module="torch.nn",
        description="RNN layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="RNNCell",
        module="torch.nn",
        description="RNN cell",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LSTM",
        module="torch.nn",
        description="LSTM layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="LSTMCell",
        module="torch.nn",
        description="LSTM cell",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="GRU",
        module="torch.nn",
        description="GRU layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="GRUCell",
        module="torch.nn",
        description="GRU cell",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # TRANSFORMER LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Transformer",
        module="torch.nn",
        description="Transformer model",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="TransformerEncoder",
        module="torch.nn",
        description="Transformer encoder",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="TransformerDecoder",
        module="torch.nn",
        description="Transformer decoder",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="TransformerEncoderLayer",
        module="torch.nn",
        description="Transformer encoder layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="TransformerDecoderLayer",
        module="torch.nn",
        description="Transformer decoder layer",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MultiheadAttention",
        module="torch.nn",
        description="Multi-head attention",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # LOSS MODULES
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="L1Loss",
        module="torch.nn",
        description="L1 (MAE) loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MSELoss",
        module="torch.nn",
        description="Mean squared error loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="CrossEntropyLoss",
        module="torch.nn",
        description="Cross-entropy loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="NLLLoss",
        module="torch.nn",
        description="Negative log-likelihood loss",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="PoissonNLLLoss",
        module="torch.nn",
        description="Poisson NLL loss",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="GaussianNLLLoss",
        module="torch.nn",
        description="Gaussian NLL loss",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="KLDivLoss",
        module="torch.nn",
        description="KL divergence loss",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="BCELoss",
        module="torch.nn",
        description="Binary cross-entropy loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="BCEWithLogitsLoss",
        module="torch.nn",
        description="BCE with logits",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="SmoothL1Loss",
        module="torch.nn",
        description="Smooth L1 (Huber) loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="HuberLoss",
        module="torch.nn",
        description="Huber loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="HingeEmbeddingLoss",
        module="torch.nn",
        description="Hinge embedding loss",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MarginRankingLoss",
        module="torch.nn",
        description="Margin ranking loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MultiLabelMarginLoss",
        module="torch.nn",
        description="Multi-label margin loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MultiLabelSoftMarginLoss",
        module="torch.nn",
        description="Multi-label soft margin loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="MultiMarginLoss",
        module="torch.nn",
        description="Multi-class margin loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="SoftMarginLoss",
        module="torch.nn",
        description="Soft margin loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="TripletMarginLoss",
        module="torch.nn",
        description="Triplet margin loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="TripletMarginWithDistanceLoss",
        module="torch.nn",
        description="Triplet with custom distance",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="CosineEmbeddingLoss",
        module="torch.nn",
        description="Cosine embedding loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="CTCLoss",
        module="torch.nn",
        description="CTC loss",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # DISTANCE MODULES
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="PairwiseDistance",
        module="torch.nn",
        description="Pairwise distance",
        forward_return_interval=Interval.non_negative(),
        forward_guarantees_non_negative=True,
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="CosineSimilarity",
        module="torch.nn",
        description="Cosine similarity",
        forward_return_interval=Interval(-1.0, 1.0),
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    # =========================================================================
    # CONTAINER MODULES
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Sequential",
        module="torch.nn",
        description="Sequential container",
        forward_requires_same_device=True,
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ModuleList",
        module="torch.nn",
        description="Module list container",
    ))
    
    contracts.append(ModuleContract(
        name="ModuleDict",
        module="torch.nn",
        description="Module dict container",
    ))
    
    contracts.append(ModuleContract(
        name="ParameterList",
        module="torch.nn",
        description="Parameter list",
    ))
    
    contracts.append(ModuleContract(
        name="ParameterDict",
        module="torch.nn",
        description="Parameter dict",
    ))
    
    # =========================================================================
    # UTILITY LAYERS
    # =========================================================================
    
    contracts.append(ModuleContract(
        name="Flatten",
        module="torch.nn",
        description="Flatten dimensions",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="Unflatten",
        module="torch.nn",
        description="Unflatten dimension",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="PixelShuffle",
        module="torch.nn",
        description="Pixel shuffle for upscaling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="PixelUnshuffle",
        module="torch.nn",
        description="Inverse pixel shuffle",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="ChannelShuffle",
        module="torch.nn",
        description="Channel shuffle",
        forward_preserves_device=True,
        forward_preserves_shape=True,
    ))
    
    contracts.append(ModuleContract(
        name="Upsample",
        module="torch.nn",
        description="Upsample layer",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="UpsamplingNearest2d",
        module="torch.nn",
        description="Nearest neighbor upsampling",
        forward_preserves_device=True,
    ))
    
    contracts.append(ModuleContract(
        name="UpsamplingBilinear2d",
        module="torch.nn",
        description="Bilinear upsampling",
        forward_preserves_device=True,
    ))
    
    # Register all contracts
    bulk_register(contracts, registry)
