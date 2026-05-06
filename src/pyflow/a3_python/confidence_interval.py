"""
Confidence / risk interval data model (barrier-compatible).

This module defines *reporting* structures that sit on top of the core semantics
defined in python-barrier-certificate-theory.md:

- Unsafe region U ⊆ S and reachability Bug(U) ⇔ Reach ∩ U ≠ ∅
- Contracted transition system PTS_R with unknown calls modeled by relations R_f
- Concrete execution evidence (concolic/DSE) as witness-only, never proof of absence

These structures are intentionally lightweight and optional: they must not
change BUG/SAFE/UNKNOWN semantics, only attach provenance and quantitative
metadata for ranking/triage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Literal


IntervalKind = Literal["reachability_pts", "risk"]
WitnessKind = Literal["symbolic_pts", "concrete_sem_prog", "none"]


@dataclass(frozen=True)
class Interval:
    """A closed interval [low, high] with evidence."""

    low: float
    high: float
    kind: IntervalKind
    evidence: List[str] = field(default_factory=list)

    def clamp01(self) -> "Interval":
        return Interval(
            low=max(0.0, min(1.0, self.low)),
            high=max(0.0, min(1.0, self.high)),
            kind=self.kind,
            evidence=self.evidence.copy(),
        )


@dataclass(frozen=True)
class ReachabilityIntervalPTS:
    """
    Interval for reachability of U in the *contracted* transition system PTS_R.

    This is intentionally discrete today:
    - [1,1] once we have a satisfiable symbolic witness in PTS_R
    - [0,0] only with a barrier proof of Safe(U) for PTS_R (under stated contracts)
    - [0,1] otherwise
    """

    reachable_lb: int  # 0 or 1
    reachable_ub: int  # 0 or 1
    evidence: List[str] = field(default_factory=list)

    @staticmethod
    def unknown(evidence: Optional[Sequence[str]] = None) -> "ReachabilityIntervalPTS":
        return ReachabilityIntervalPTS(0, 1, list(evidence or []))

    @staticmethod
    def reachable(evidence: Optional[Sequence[str]] = None) -> "ReachabilityIntervalPTS":
        return ReachabilityIntervalPTS(1, 1, list(evidence or []))

    @staticmethod
    def unreachable(evidence: Optional[Sequence[str]] = None) -> "ReachabilityIntervalPTS":
        return ReachabilityIntervalPTS(0, 0, list(evidence or []))


@dataclass(frozen=True)
class RiskInterval:
    """
    Optional risk bounds under a stated threat model / input distribution.

    Interpreted as bounds on the measure of executions that reach U, not as a
    semantic reachability fact.
    """

    risk_lb: float
    risk_ub: float
    threat_model_id: str = "default"
    evidence: List[str] = field(default_factory=list)

    def clamp01(self) -> "RiskInterval":
        return RiskInterval(
            risk_lb=max(0.0, min(1.0, self.risk_lb)),
            risk_ub=max(0.0, min(1.0, self.risk_ub)),
            threat_model_id=self.threat_model_id,
            evidence=self.evidence.copy(),
        )


@dataclass(frozen=True)
class ConcreteWitnessEvidence:
    """Concrete witness in Sem_prog (CPython + real libraries)."""

    present: bool
    input_config_id: Optional[str] = None
    trace_id: Optional[str] = None
    evidence: List[str] = field(default_factory=list)


def derived_scalar_confidence(
    reachability: Optional[ReachabilityIntervalPTS],
    risk: Optional[RiskInterval],
    legacy_confidence: float,
) -> float:
    """
    Produce a backward-compatible scalar confidence for UI filtering.

    Policy (conservative):
    - If risk bounds exist, use risk_ub (upper bound on risk).
    - Else fall back to legacy_confidence (the current heuristic score).
    """

    if risk is not None:
        return float(max(0.0, min(1.0, risk.risk_ub)))
    return float(max(0.0, min(1.0, legacy_confidence)))

