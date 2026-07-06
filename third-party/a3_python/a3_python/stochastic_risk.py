"""
Stochastic risk bounds for precondition violations (Prajna et al., TAC 2007).

This module provides lightweight, *non-proof* probabilistic bounds for
precondition-based bugs. The intent is orthogonal to worst-case reasoning:
- Worst-case: does a counterexample exist? (reachability in PTS_R)
- Stochastic: how likely is a violation under an assumed distribution?

These bounds are metadata only; they do not affect BUG/SAFE/UNKNOWN semantics.
"""

from __future__ import annotations

from typing import Optional

from .confidence_interval import RiskInterval
from .semantics.crash_summaries import Precondition, PreconditionType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .semantics.interprocedural_bugs import ValueState


def risk_interval_for_precondition(
    precond: Precondition,
    value_state: Optional["ValueState"] = None,
    *,
    default_support: int = 9,
) -> Optional[RiskInterval]:
    """
    Estimate a conservative stochastic risk bound for violating a precondition.

    This uses a simple discrete-uniform assumption over a bounded support
    when bounds are available, otherwise falls back to a conservative prior.

    Returns:
        RiskInterval or None if no reasonable estimate is available.
    """
    cond = precond.condition_type
    evidence: list[str] = [f"precond={cond.name}"]

    # Use value-state bounds if available.
    if value_state and value_state.has_upper_bound and value_state.upper_bound is not None:
        ub = max(0, int(value_state.upper_bound))
    else:
        ub = default_support
        if value_state is None:
            evidence.append("value_state=unknown")
        else:
            evidence.append("value_state=no_bound")

    # Risk estimates for discrete integer-like values.
    if cond == PreconditionType.NOT_ZERO:
        # P(x == 0) under uniform in [-ub, ub] or [0, ub] if non-negative.
        support = (ub + 1) if (value_state and not value_state.may_be_negative) else (2 * ub + 1)
        p = 1.0 / float(max(1, support))
        evidence.append(f"support={support}")
        return RiskInterval(risk_lb=0.0, risk_ub=min(1.0, p), threat_model_id="stochastic_precond_v1", evidence=evidence)

    if cond == PreconditionType.NOT_NONE:
        # Prior: assume None occurs with small probability.
        return RiskInterval(risk_lb=0.0, risk_ub=0.05, threat_model_id="stochastic_precond_v1", evidence=evidence)

    if cond == PreconditionType.POSITIVE:
        # P(x <= 0)
        return RiskInterval(risk_lb=0.0, risk_ub=0.2, threat_model_id="stochastic_precond_v1", evidence=evidence)

    if cond == PreconditionType.NON_NEGATIVE:
        return RiskInterval(risk_lb=0.0, risk_ub=0.15, threat_model_id="stochastic_precond_v1", evidence=evidence)

    if cond == PreconditionType.IN_BOUNDS:
        return RiskInterval(risk_lb=0.0, risk_ub=0.25, threat_model_id="stochastic_precond_v1", evidence=evidence)

    if cond == PreconditionType.VALID_TYPE:
        return RiskInterval(risk_lb=0.0, risk_ub=0.2, threat_model_id="stochastic_precond_v1", evidence=evidence)

    if cond == PreconditionType.NOT_EMPTY:
        return RiskInterval(risk_lb=0.0, risk_ub=0.2, threat_model_id="stochastic_precond_v1", evidence=evidence)

    if cond == PreconditionType.FINITE:
        return RiskInterval(risk_lb=0.0, risk_ub=0.02, threat_model_id="stochastic_precond_v1", evidence=evidence)

    if cond == PreconditionType.VALID_RANGE:
        return RiskInterval(risk_lb=0.0, risk_ub=0.25, threat_model_id="stochastic_precond_v1", evidence=evidence)

    if cond == PreconditionType.SANITIZED:
        return RiskInterval(risk_lb=0.0, risk_ub=0.3, threat_model_id="stochastic_precond_v1", evidence=evidence)

    if cond == PreconditionType.TRUSTED:
        return RiskInterval(risk_lb=0.0, risk_ub=0.35, threat_model_id="stochastic_precond_v1", evidence=evidence)

    return None
