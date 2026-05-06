"""
PyTorch FFT Contracts (torch.fft.*)

This module provides contracts for torch.fft functions.
These are the Fourier transform operations in PyTorch.

Includes:
- 1D, 2D, and ND FFTs
- Real and complex FFTs
- Inverse FFTs
- Frequency utilities
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


def register_fft_contracts(registry: ContractRegistry) -> None:
    """Register all torch.fft contracts."""
    
    contracts = []
    
    # =========================================================================
    # 1D FFT
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="fft",
        module="torch.fft",
        description="1D FFT (complex-to-complex)",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ifft",
        module="torch.fft",
        description="1D inverse FFT",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="rfft",
        module="torch.fft",
        description="1D FFT of real input",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="irfft",
        module="torch.fft",
        description="Inverse of rfft",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="hfft",
        module="torch.fft",
        description="1D FFT of Hermitian signal",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ihfft",
        module="torch.fft",
        description="Inverse of hfft",
        preserves_device=True,
    ))
    
    # =========================================================================
    # 2D FFT
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="fft2",
        module="torch.fft",
        description="2D FFT (complex-to-complex)",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ifft2",
        module="torch.fft",
        description="2D inverse FFT",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="rfft2",
        module="torch.fft",
        description="2D FFT of real input",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="irfft2",
        module="torch.fft",
        description="Inverse of rfft2",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="hfft2",
        module="torch.fft",
        description="2D FFT of Hermitian signal",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ihfft2",
        module="torch.fft",
        description="Inverse of hfft2",
        preserves_device=True,
    ))
    
    # =========================================================================
    # ND FFT
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="fftn",
        module="torch.fft",
        description="N-dimensional FFT",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ifftn",
        module="torch.fft",
        description="N-dimensional inverse FFT",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="rfftn",
        module="torch.fft",
        description="N-dimensional FFT of real input",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="irfftn",
        module="torch.fft",
        description="Inverse of rfftn",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="hfftn",
        module="torch.fft",
        description="N-dimensional FFT of Hermitian signal",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ihfftn",
        module="torch.fft",
        description="Inverse of hfftn",
        preserves_device=True,
    ))
    
    # =========================================================================
    # FREQUENCY UTILITIES
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="fftfreq",
        module="torch.fft",
        description="DFT sample frequencies",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="rfftfreq",
        module="torch.fft",
        description="Sample frequencies for rfft",
        return_interval=Interval.non_negative(),
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="fftshift",
        module="torch.fft",
        description="Shift zero-frequency to center",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="ifftshift",
        module="torch.fft",
        description="Inverse of fftshift",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # Register all contracts
    bulk_register(contracts, registry)
