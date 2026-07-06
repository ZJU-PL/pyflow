"""
PyTorch Optimizer Contracts - torch.optim

This module provides contracts for PyTorch optimizers including:
- SGD, Adam, AdamW, RMSprop, Adagrad, etc.
- Learning rate schedulers
- Optimizer state management

Device Barrier Considerations:
- Optimizer parameters must match model parameter devices
- State tensors are created on the same device as parameters
- Moving model to different device requires optimizer recreation or state transfer
"""

from typing import Dict, List, Any, Optional, Callable
from ..intervals import Interval
from ..contracts import (
    ContractRegistry,
    ModuleContract,
    MethodContract,
    PropertyContract,
)


# ============================================================================
# Optimizer Base Contracts
# ============================================================================

def _register_optimizer_base(registry: ContractRegistry) -> None:
    """Register base Optimizer class contracts."""
    
    # Optimizer.__init__
    registry.register(MethodContract(
        name="torch.optim.Optimizer.__init__",
        qualname="torch.optim.Optimizer.__init__",
        param_names=["self", "params", "defaults"],
        param_intervals={
            # defaults is a dict, params is iterable of parameters
        },
        return_interval=None,
        preconditions=[
            ("params_iterable", "params must be iterable of parameters or param groups"),
        ],
        postconditions=[],
        requires_same_device=False,  # Parameters can be on different devices
        may_raise=["ValueError", "TypeError"],
        docstring="Initialize optimizer with parameters and default hyperparameters",
    ))
    
    # Optimizer.zero_grad
    registry.register(MethodContract(
        name="torch.optim.Optimizer.zero_grad",
        qualname="torch.optim.Optimizer.zero_grad",
        param_names=["self", "set_to_none"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("gradients_zeroed", "All parameter gradients are zeroed or set to None"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Zero out gradients of all parameters",
    ))
    
    # Optimizer.step
    registry.register(MethodContract(
        name="torch.optim.Optimizer.step",
        qualname="torch.optim.Optimizer.step",
        param_names=["self", "closure"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("gradients_computed", "backward() should be called before step()"),
        ],
        postconditions=[
            ("parameters_updated", "All parameters are updated based on gradients"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],  # If gradients not computed
        docstring="Perform a single optimization step",
    ))
    
    # Optimizer.state_dict
    registry.register(MethodContract(
        name="torch.optim.Optimizer.state_dict",
        qualname="torch.optim.Optimizer.state_dict",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns dict
        preconditions=[],
        postconditions=[
            ("state_captured", "Returns complete optimizer state"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Return optimizer state as a dictionary",
    ))
    
    # Optimizer.load_state_dict
    registry.register(MethodContract(
        name="torch.optim.Optimizer.load_state_dict",
        qualname="torch.optim.Optimizer.load_state_dict",
        param_names=["self", "state_dict"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_state_dict", "state_dict must match optimizer structure"),
        ],
        postconditions=[
            ("state_restored", "Optimizer state is restored from dict"),
        ],
        requires_same_device=True,  # State tensors must be on correct device
        may_raise=["ValueError", "KeyError"],
        docstring="Load optimizer state from dictionary",
    ))
    
    # Optimizer.add_param_group
    registry.register(MethodContract(
        name="torch.optim.Optimizer.add_param_group",
        qualname="torch.optim.Optimizer.add_param_group",
        param_names=["self", "param_group"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_param_group", "param_group must be dict with 'params' key"),
        ],
        postconditions=[
            ("group_added", "Parameter group is added to optimizer"),
        ],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Add a parameter group to optimizer",
    ))


# ============================================================================
# SGD Optimizer
# ============================================================================

def _register_sgd(registry: ContractRegistry) -> None:
    """Register SGD optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.SGD",
        qualname="torch.optim.SGD",
        init_param_names=["params", "lr", "momentum", "dampening", "weight_decay", "nesterov"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),  # Learning rate > 0
            "momentum": Interval(0.0, 1.0),
            "dampening": Interval(0.0, float('inf')),
            "weight_decay": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,  # step() returns None
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("momentum_buffer_same_device", "Momentum buffers on same device as params"),
        ],
        docstring="Stochastic Gradient Descent optimizer with momentum",
    ))
    
    # SGD.step with custom behavior
    registry.register(MethodContract(
        name="torch.optim.SGD.step",
        qualname="torch.optim.SGD.step",
        param_names=["self", "closure"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("gradients_exist", "Parameters should have gradients"),
        ],
        postconditions=[
            ("parameters_updated", "p = p - lr * (grad + weight_decay * p + momentum * buf)"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Perform SGD update step",
    ))


# ============================================================================
# Adam Optimizer
# ============================================================================

def _register_adam(registry: ContractRegistry) -> None:
    """Register Adam optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.Adam",
        qualname="torch.optim.Adam",
        init_param_names=["params", "lr", "betas", "eps", "weight_decay", "amsgrad"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "eps": Interval(1e-10, float('inf')),  # Must be > 0
            "weight_decay": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("exp_avg_same_device", "Exponential averages on same device as params"),
            ("exp_avg_sq_same_device", "Squared exp averages on same device as params"),
        ],
        docstring="Adam optimizer with adaptive learning rates",
    ))
    
    # betas validation
    registry.register(MethodContract(
        name="torch.optim.Adam.__init__",
        qualname="torch.optim.Adam.__init__",
        param_names=["self", "params", "lr", "betas", "eps", "weight_decay", "amsgrad"],
        param_intervals={
            "lr": Interval(0.0, float('inf')),
            "eps": Interval(1e-10, float('inf')),
            "weight_decay": Interval(0.0, float('inf')),
        },
        return_interval=None,
        preconditions=[
            ("valid_betas", "betas must be tuple of (beta1, beta2) in [0, 1)"),
            ("positive_lr", "lr must be positive"),
            ("positive_eps", "eps must be positive"),
        ],
        postconditions=[],
        requires_same_device=False,
        may_raise=["ValueError"],
        docstring="Initialize Adam optimizer",
    ))


# ============================================================================
# AdamW Optimizer
# ============================================================================

def _register_adamw(registry: ContractRegistry) -> None:
    """Register AdamW optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.AdamW",
        qualname="torch.optim.AdamW",
        init_param_names=["params", "lr", "betas", "eps", "weight_decay", "amsgrad"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "eps": Interval(1e-10, float('inf')),
            "weight_decay": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("decoupled_weight_decay", "Weight decay is applied separately from gradient"),
        ],
        docstring="AdamW optimizer with decoupled weight decay",
    ))


# ============================================================================
# RMSprop Optimizer
# ============================================================================

def _register_rmsprop(registry: ContractRegistry) -> None:
    """Register RMSprop optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.RMSprop",
        qualname="torch.optim.RMSprop",
        init_param_names=["params", "lr", "alpha", "eps", "weight_decay", "momentum", "centered"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "alpha": Interval(0.0, 1.0),
            "eps": Interval(1e-10, float('inf')),
            "weight_decay": Interval(0.0, float('inf')),
            "momentum": Interval(0.0, 1.0),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("square_avg_same_device", "Square averages on same device as params"),
        ],
        docstring="RMSprop optimizer with adaptive learning rate",
    ))


# ============================================================================
# Adagrad Optimizer
# ============================================================================

def _register_adagrad(registry: ContractRegistry) -> None:
    """Register Adagrad optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.Adagrad",
        qualname="torch.optim.Adagrad",
        init_param_names=["params", "lr", "lr_decay", "weight_decay", "initial_accumulator_value", "eps"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "lr_decay": Interval(0.0, 1.0),
            "weight_decay": Interval(0.0, float('inf')),
            "initial_accumulator_value": Interval(0.0, float('inf')),
            "eps": Interval(1e-10, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("sum_same_device", "Gradient sum squares on same device as params"),
        ],
        docstring="Adagrad optimizer with per-parameter learning rates",
    ))


# ============================================================================
# Adadelta Optimizer
# ============================================================================

def _register_adadelta(registry: ContractRegistry) -> None:
    """Register Adadelta optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.Adadelta",
        qualname="torch.optim.Adadelta",
        init_param_names=["params", "lr", "rho", "eps", "weight_decay"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "rho": Interval(0.0, 1.0),
            "eps": Interval(1e-10, float('inf')),
            "weight_decay": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("acc_delta_same_device", "Accumulated deltas on same device as params"),
        ],
        docstring="Adadelta optimizer",
    ))


# ============================================================================
# Adamax Optimizer
# ============================================================================

def _register_adamax(registry: ContractRegistry) -> None:
    """Register Adamax optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.Adamax",
        qualname="torch.optim.Adamax",
        init_param_names=["params", "lr", "betas", "eps", "weight_decay"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "eps": Interval(1e-10, float('inf')),
            "weight_decay": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[],
        docstring="Adamax optimizer (Adam with infinity norm)",
    ))


# ============================================================================
# ASGD Optimizer
# ============================================================================

def _register_asgd(registry: ContractRegistry) -> None:
    """Register Averaged SGD optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.ASGD",
        qualname="torch.optim.ASGD",
        init_param_names=["params", "lr", "lambd", "alpha", "t0", "weight_decay"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "lambd": Interval(0.0, float('inf')),
            "alpha": Interval(0.0, 1.0),
            "t0": Interval(0.0, float('inf')),
            "weight_decay": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("ax_same_device", "Averaged parameters on same device"),
        ],
        docstring="Averaged Stochastic Gradient Descent",
    ))


# ============================================================================
# LBFGS Optimizer
# ============================================================================

def _register_lbfgs(registry: ContractRegistry) -> None:
    """Register L-BFGS optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.LBFGS",
        qualname="torch.optim.LBFGS",
        init_param_names=["params", "lr", "max_iter", "max_eval", "tolerance_grad", 
                         "tolerance_change", "history_size", "line_search_fn"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "max_iter": Interval(1, float('inf')),
            "tolerance_grad": Interval(0.0, float('inf')),
            "tolerance_change": Interval(0.0, float('inf')),
            "history_size": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=True,  # All params must be on same device
        forward_preserves_device=True,
        state_invariants=[
            ("single_param_group", "L-BFGS only supports single parameter group"),
        ],
        docstring="L-BFGS quasi-Newton optimizer",
    ))
    
    # L-BFGS step requires closure
    registry.register(MethodContract(
        name="torch.optim.LBFGS.step",
        qualname="torch.optim.LBFGS.step",
        param_names=["self", "closure"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("closure_required", "closure is required for L-BFGS"),
            ("closure_callable", "closure must be callable returning loss"),
        ],
        postconditions=[
            ("line_search_performed", "Line search is performed for step size"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Perform L-BFGS optimization step",
    ))


# ============================================================================
# RAdam Optimizer
# ============================================================================

def _register_radam(registry: ContractRegistry) -> None:
    """Register Rectified Adam optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.RAdam",
        qualname="torch.optim.RAdam",
        init_param_names=["params", "lr", "betas", "eps", "weight_decay"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "eps": Interval(1e-10, float('inf')),
            "weight_decay": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("variance_rectification", "Variance is rectified for stable early training"),
        ],
        docstring="Rectified Adam with variance rectification",
    ))


# ============================================================================
# NAdam Optimizer
# ============================================================================

def _register_nadam(registry: ContractRegistry) -> None:
    """Register Nesterov Adam optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.NAdam",
        qualname="torch.optim.NAdam",
        init_param_names=["params", "lr", "betas", "eps", "weight_decay", "momentum_decay"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "eps": Interval(1e-10, float('inf')),
            "weight_decay": Interval(0.0, float('inf')),
            "momentum_decay": Interval(0.0, 1.0),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[],
        docstring="Nesterov-accelerated Adam",
    ))


# ============================================================================
# SparseAdam Optimizer
# ============================================================================

def _register_sparse_adam(registry: ContractRegistry) -> None:
    """Register SparseAdam optimizer contracts."""
    
    registry.register(ModuleContract(
        name="torch.optim.SparseAdam",
        qualname="torch.optim.SparseAdam",
        init_param_names=["params", "lr", "betas", "eps"],
        init_param_intervals={
            "lr": Interval(0.0, float('inf')),
            "eps": Interval(1e-10, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("sparse_gradients", "Only updates parameters with sparse gradients"),
        ],
        docstring="Adam variant for sparse gradients (embeddings)",
    ))


# ============================================================================
# Learning Rate Schedulers
# ============================================================================

def _register_lr_schedulers(registry: ContractRegistry) -> None:
    """Register learning rate scheduler contracts."""
    
    # Base LRScheduler
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.LRScheduler",
        qualname="torch.optim.lr_scheduler.LRScheduler",
        init_param_names=["optimizer", "last_epoch", "verbose"],
        init_param_intervals={
            "last_epoch": Interval(-1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[],
        docstring="Base class for learning rate schedulers",
    ))
    
    # LRScheduler.step
    registry.register(MethodContract(
        name="torch.optim.lr_scheduler.LRScheduler.step",
        qualname="torch.optim.lr_scheduler.LRScheduler.step",
        param_names=["self", "epoch"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("lr_updated", "Learning rate is updated for next epoch"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Update learning rate based on schedule",
    ))
    
    # StepLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.StepLR",
        qualname="torch.optim.lr_scheduler.StepLR",
        init_param_names=["optimizer", "step_size", "gamma", "last_epoch", "verbose"],
        init_param_intervals={
            "step_size": Interval(1, float('inf')),
            "gamma": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("lr_decay", "lr = lr * gamma every step_size epochs"),
        ],
        docstring="Step learning rate decay",
    ))
    
    # MultiStepLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.MultiStepLR",
        qualname="torch.optim.lr_scheduler.MultiStepLR",
        init_param_names=["optimizer", "milestones", "gamma", "last_epoch", "verbose"],
        init_param_intervals={
            "gamma": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("milestone_decay", "lr = lr * gamma at each milestone"),
        ],
        docstring="Multi-milestone learning rate decay",
    ))
    
    # ExponentialLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.ExponentialLR",
        qualname="torch.optim.lr_scheduler.ExponentialLR",
        init_param_names=["optimizer", "gamma", "last_epoch", "verbose"],
        init_param_intervals={
            "gamma": Interval(0.0, 1.0),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("exponential_decay", "lr = lr * gamma every epoch"),
        ],
        docstring="Exponential learning rate decay",
    ))
    
    # CosineAnnealingLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.CosineAnnealingLR",
        qualname="torch.optim.lr_scheduler.CosineAnnealingLR",
        init_param_names=["optimizer", "T_max", "eta_min", "last_epoch", "verbose"],
        init_param_intervals={
            "T_max": Interval(1, float('inf')),
            "eta_min": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("cosine_schedule", "lr follows cosine annealing to eta_min"),
        ],
        docstring="Cosine annealing learning rate schedule",
    ))
    
    # CosineAnnealingWarmRestarts
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.CosineAnnealingWarmRestarts",
        qualname="torch.optim.lr_scheduler.CosineAnnealingWarmRestarts",
        init_param_names=["optimizer", "T_0", "T_mult", "eta_min", "last_epoch", "verbose"],
        init_param_intervals={
            "T_0": Interval(1, float('inf')),
            "T_mult": Interval(1, float('inf')),
            "eta_min": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("warm_restarts", "lr restarts at T_0, T_0*T_mult, ... epochs"),
        ],
        docstring="Cosine annealing with warm restarts",
    ))
    
    # ReduceLROnPlateau
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.ReduceLROnPlateau",
        qualname="torch.optim.lr_scheduler.ReduceLROnPlateau",
        init_param_names=["optimizer", "mode", "factor", "patience", "threshold",
                         "threshold_mode", "cooldown", "min_lr", "eps", "verbose"],
        init_param_intervals={
            "factor": Interval(0.0, 1.0),
            "patience": Interval(0, float('inf')),
            "threshold": Interval(0.0, float('inf')),
            "cooldown": Interval(0, float('inf')),
            "min_lr": Interval(0.0, float('inf')),
            "eps": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("metric_based", "lr reduced when metric plateaus"),
        ],
        docstring="Reduce LR when metric stops improving",
    ))
    
    # ReduceLROnPlateau.step requires metrics
    registry.register(MethodContract(
        name="torch.optim.lr_scheduler.ReduceLROnPlateau.step",
        qualname="torch.optim.lr_scheduler.ReduceLROnPlateau.step",
        param_names=["self", "metrics", "epoch"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("metrics_required", "metrics value is required"),
        ],
        postconditions=[
            ("lr_maybe_reduced", "lr reduced if metric plateaus for patience epochs"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Update LR based on metric value",
    ))
    
    # CyclicLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.CyclicLR",
        qualname="torch.optim.lr_scheduler.CyclicLR",
        init_param_names=["optimizer", "base_lr", "max_lr", "step_size_up", "step_size_down",
                         "mode", "gamma", "scale_fn", "scale_mode", "cycle_momentum",
                         "base_momentum", "max_momentum", "last_epoch", "verbose"],
        init_param_intervals={
            "step_size_up": Interval(1, float('inf')),
            "gamma": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("cyclic_lr", "lr cycles between base_lr and max_lr"),
        ],
        docstring="Cyclic learning rate schedule",
    ))
    
    # OneCycleLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.OneCycleLR",
        qualname="torch.optim.lr_scheduler.OneCycleLR",
        init_param_names=["optimizer", "max_lr", "total_steps", "epochs", "steps_per_epoch",
                         "pct_start", "anneal_strategy", "cycle_momentum", "base_momentum",
                         "max_momentum", "div_factor", "final_div_factor", "three_phase",
                         "last_epoch", "verbose"],
        init_param_intervals={
            "pct_start": Interval(0.0, 1.0),
            "div_factor": Interval(1.0, float('inf')),
            "final_div_factor": Interval(1.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("one_cycle", "lr follows one-cycle policy with warm-up and decay"),
        ],
        docstring="One-cycle learning rate policy",
    ))
    
    # LinearLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.LinearLR",
        qualname="torch.optim.lr_scheduler.LinearLR",
        init_param_names=["optimizer", "start_factor", "end_factor", "total_iters",
                         "last_epoch", "verbose"],
        init_param_intervals={
            "start_factor": Interval(0.0, 1.0),
            "end_factor": Interval(0.0, 1.0),
            "total_iters": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("linear_schedule", "lr linearly changes from start to end factor"),
        ],
        docstring="Linear learning rate schedule",
    ))
    
    # PolynomialLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.PolynomialLR",
        qualname="torch.optim.lr_scheduler.PolynomialLR",
        init_param_names=["optimizer", "total_iters", "power", "last_epoch", "verbose"],
        init_param_intervals={
            "total_iters": Interval(1, float('inf')),
            "power": Interval(0.0, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("polynomial_decay", "lr decays polynomially"),
        ],
        docstring="Polynomial learning rate decay",
    ))
    
    # ConstantLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.ConstantLR",
        qualname="torch.optim.lr_scheduler.ConstantLR",
        init_param_names=["optimizer", "factor", "total_iters", "last_epoch", "verbose"],
        init_param_intervals={
            "factor": Interval(0.0, 1.0),
            "total_iters": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("constant_factor", "lr = base_lr * factor for total_iters"),
        ],
        docstring="Constant learning rate with warmup",
    ))
    
    # SequentialLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.SequentialLR",
        qualname="torch.optim.lr_scheduler.SequentialLR",
        init_param_names=["optimizer", "schedulers", "milestones", "last_epoch", "verbose"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("sequential_schedulers", "Different schedulers at each milestone"),
        ],
        docstring="Sequential composition of schedulers",
    ))
    
    # ChainedScheduler
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.ChainedScheduler",
        qualname="torch.optim.lr_scheduler.ChainedScheduler",
        init_param_names=["schedulers"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("chained_schedulers", "All schedulers stepped together"),
        ],
        docstring="Chained composition of schedulers",
    ))
    
    # LambdaLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.LambdaLR",
        qualname="torch.optim.lr_scheduler.LambdaLR",
        init_param_names=["optimizer", "lr_lambda", "last_epoch", "verbose"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("custom_lambda", "lr = base_lr * lr_lambda(epoch)"),
        ],
        docstring="Custom learning rate lambda function",
    ))
    
    # MultiplicativeLR
    registry.register(ModuleContract(
        name="torch.optim.lr_scheduler.MultiplicativeLR",
        qualname="torch.optim.lr_scheduler.MultiplicativeLR",
        init_param_names=["optimizer", "lr_lambda", "last_epoch", "verbose"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=True,
        state_invariants=[
            ("multiplicative_lambda", "lr = lr * lr_lambda(epoch)"),
        ],
        docstring="Multiplicative learning rate lambda",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_optim_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.optim contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_optimizer_base(registry)
    _register_sgd(registry)
    _register_adam(registry)
    _register_adamw(registry)
    _register_rmsprop(registry)
    _register_adagrad(registry)
    _register_adadelta(registry)
    _register_adamax(registry)
    _register_asgd(registry)
    _register_lbfgs(registry)
    _register_radam(registry)
    _register_nadam(registry)
    _register_sparse_adam(registry)
    _register_lr_schedulers(registry)


# Export
__all__ = [
    "register_optim_contracts",
]
