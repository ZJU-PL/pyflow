"""
Multi-factor confidence scoring for bug detection.

Implements barrier-theoretic confidence estimation combining:
1. Source presence and quality (τ, σ validation)
2. Call chain complexity and depth
3. Semantic context (guards, exception handling, framework patterns)
4. Sanitization analysis (κ coverage)

Reference: python-barrier-certificate-theory.md §13 (Confidence Metrics)
"""

from dataclasses import dataclass
from typing import Set, Optional, List, FrozenSet
from enum import IntEnum

from .z3model.taint_lattice import TaintLabel, SourceType, SinkType, SanitizerType


class ConfidenceFactor(IntEnum):
    """Individual confidence factors (0-100 scale)."""
    DEFINITE = 95       # Provable by Z3
    VERY_HIGH = 85      # Strong evidence
    HIGH = 75           # Multiple indicators
    MODERATE = 60       # Some evidence
    LOW = 40            # Weak signal
    VERY_LOW = 20       # Speculative


@dataclass
class ConfidenceBreakdown:
    """
    Detailed breakdown of confidence calculation.
    
    Each component is scored 0.0-1.0, then combined with weights.
    """
    # Component scores (0.0-1.0)
    source_score: float = 0.0      # Quality of taint sources
    sink_score: float = 0.0        # Sink reachability/certainty  
    sanitization_score: float = 0.0  # Confidence in unsanitized state
    semantic_score: float = 0.0    # Guards, exception handling, patterns
    chain_score: float = 0.0       # Call chain complexity penalty
    
    # Component weights (must sum to 1.0)
    source_weight: float = 0.30
    sink_weight: float = 0.25
    sanitization_weight: float = 0.20
    semantic_weight: float = 0.15
    chain_weight: float = 0.10
    
    # Evidence tracking
    evidence: List[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
    
    def combined_score(self) -> float:
        """Compute weighted average confidence score."""
        return (
            self.source_score * self.source_weight +
            self.sink_score * self.sink_weight +
            self.sanitization_score * self.sanitization_weight +
            self.semantic_score * self.semantic_weight +
            self.chain_score * self.chain_weight
        )
    
    def __str__(self) -> str:
        """Human-readable breakdown."""
        total = self.combined_score()
        lines = [
            f"Confidence: {total:.2f}",
            f"  Source:       {self.source_score:.2f} (weight {self.source_weight})",
            f"  Sink:         {self.sink_score:.2f} (weight {self.sink_weight})",
            f"  Sanitization: {self.sanitization_score:.2f} (weight {self.sanitization_weight})",
            f"  Semantic:     {self.semantic_score:.2f} (weight {self.semantic_weight})",
            f"  Chain:        {self.chain_score:.2f} (weight {self.chain_weight})",
        ]
        if self.evidence:
            lines.append("  Evidence:")
            for e in self.evidence:
                lines.append(f"    - {e}")
        return "\n".join(lines)


class ConfidenceScorer:
    """
    Multi-factor confidence scoring for security and error bugs.
    
    Produces ConfidenceBreakdown with justification for each score.
    """
    
    # ========================================================================
    # Security Bug Scoring (Taint-based)
    # ========================================================================
    
    def score_security_bug(
        self,
        label: TaintLabel,
        sink_type: SinkType,
        is_guarded: bool = False,
        call_chain_length: int = 1,
        has_exception_handler: bool = False,
        in_framework_context: bool = False,
        taint_sources: Optional[Set[str]] = None,
    ) -> ConfidenceBreakdown:
        """
        Score a security bug (taint-based).
        
        Args:
            label: Taint label at sink
            sink_type: Type of sink being reached
            is_guarded: Whether guards protect this path
            call_chain_length: Number of functions in call chain
            has_exception_handler: Whether exceptions are handled
            in_framework_context: Whether in recognized framework pattern
            taint_sources: Specific taint source identifiers
        
        Returns:
            ConfidenceBreakdown with component scores
        """
        breakdown = ConfidenceBreakdown()
        
        # 1. Source score: Quality and quantity of taint sources
        breakdown.source_score = self._score_taint_sources(label, taint_sources, breakdown.evidence)
        
        # EARLY EXIT: If no sources, this is a false positive (no bug to report)
        if breakdown.source_score == 0.0:
            # Set all other scores to 0 to enforce 0.0 final score
            breakdown.sink_score = 0.0
            breakdown.sanitization_score = 0.0
            breakdown.semantic_score = 0.0
            breakdown.chain_score = 0.0
            return breakdown
        
        # 2. Sink score: Certainty of reaching sink
        breakdown.sink_score = self._score_sink_reachability(
            sink_type, call_chain_length, breakdown.evidence
        )
        
        # 3. Sanitization score: Confidence in unsanitized state
        breakdown.sanitization_score = self._score_sanitization_state(
            label, sink_type, breakdown.evidence
        )
        
        # EARLY EXIT: If value is safe for sink, this is not a bug
        if breakdown.sanitization_score == 0.0:
            # Set all scores to 0 to enforce 0.0 final score
            breakdown.source_score = 0.0
            breakdown.sink_score = 0.0
            breakdown.semantic_score = 0.0
            breakdown.chain_score = 0.0
            return breakdown
        
        # 4. Semantic score: Guards, handlers, framework context
        breakdown.semantic_score = self._score_semantic_context(
            is_guarded, has_exception_handler, in_framework_context, breakdown.evidence
        )
        
        # 5. Chain score: Penalty for complex call chains
        breakdown.chain_score = self._score_call_chain(call_chain_length, breakdown.evidence)
        
        return breakdown
    
    def _score_taint_sources(
        self,
        label: TaintLabel,
        source_ids: Optional[Set[str]],
        evidence: List[str],
    ) -> float:
        """
        Score based on taint source presence and quality.
        
        High confidence: Multiple high-risk sources (HTTP_PARAM, USER_INPUT)
        Low confidence: Single low-risk source or unknown provenance
        """
        # Check basic taint presence (requirement from iter 427)
        has_untrusted = label.has_untrusted_taint()
        has_sensitive = label.has_sensitivity()
        
        if not has_untrusted and not has_sensitive:
            evidence.append("No taint sources (τ=0, σ=0) - SHOULD NOT REPORT")
            return 0.0
        
        # Analyze source types
        untrusted_sources = label.get_untrusted_sources()
        sensitive_sources = label.get_sensitivity_sources()
        
        score = 0.0
        
        # Untrusted taint scoring
        if untrusted_sources:
            high_risk_sources = {
                SourceType.HTTP_PARAM,
                SourceType.USER_INPUT,
                SourceType.NETWORK_RECV,
                SourceType.COOKIE,
            }
            medium_risk_sources = {
                SourceType.FILE_CONTENT,
                SourceType.ENVIRONMENT,
                SourceType.ARGV,
                SourceType.HEADER,
            }
            
            high_count = len(untrusted_sources & high_risk_sources)
            medium_count = len(untrusted_sources & medium_risk_sources)
            other_count = len(untrusted_sources) - high_count - medium_count
            
            if high_count >= 2:
                score = 0.95
                evidence.append(f"Multiple high-risk sources: {high_count}")
            elif high_count == 1:
                score = 0.85
                evidence.append(f"High-risk source: {list(untrusted_sources & high_risk_sources)[0].name}")
            elif medium_count >= 1:
                score = 0.70
                evidence.append(f"Medium-risk sources: {medium_count}")
            else:
                score = 0.50
                evidence.append(f"Low-risk sources: {other_count}")
        
        # Sensitivity taint scoring (slightly higher risk)
        if sensitive_sources:
            sens_score = 0.90 if len(sensitive_sources) >= 2 else 0.85
            score = max(score, sens_score)
            evidence.append(f"Sensitive data: {len(sensitive_sources)} types")
        
        # Provenance bonus: if we have specific source IDs
        if source_ids and len(source_ids) > 0:
            score = min(1.0, score + 0.05)
            evidence.append(f"Provenance tracked: {len(source_ids)} sources")
        
        return score
    
    def _score_sink_reachability(
        self,
        sink_type: SinkType,
        chain_length: int,
        evidence: List[str],
    ) -> float:
        """
        Score based on sink reachability certainty.
        
        Direct sinks (chain_length=1) are high confidence.
        Deep call chains reduce confidence due to analysis imprecision.
        """
        # Critical sinks have higher certainty requirements
        critical_sinks = {
            SinkType.SQL_EXECUTE,
            SinkType.COMMAND_SHELL,
            SinkType.CODE_EVAL,
            SinkType.DESERIALIZE,
        }
        
        is_critical = sink_type in critical_sinks
        
        if chain_length == 1:
            score = 0.95
            evidence.append("Direct sink (no intermediaries)")
        elif chain_length == 2:
            score = 0.85
            evidence.append("Single function call to sink")
        elif chain_length <= 4:
            score = 0.70
            evidence.append(f"Moderate call chain ({chain_length} functions)")
        else:
            score = 0.50
            evidence.append(f"Deep call chain ({chain_length} functions)")
        
        if is_critical:
            evidence.append(f"Critical sink: {sink_type.name}")
        
        return score
    
    def _score_sanitization_state(
        self,
        label: TaintLabel,
        sink_type: SinkType,
        evidence: List[str],
    ) -> float:
        """
        Score based on confidence in unsanitized state.
        
        High confidence: κ provably excludes sink
        Low confidence: κ may include sink (imprecise tracking)
        """
        is_safe = label.is_safe_for_sink(sink_type)
        
        if is_safe:
            # Should not report - this is safe
            evidence.append(f"Value IS SAFE for {sink_type.name} (k ∈ κ)")
            return 0.0
        
        # Not safe - how confident are we?
        kappa_size = bin(label.kappa).count('1')
        
        if kappa_size == 0:
            # No sanitization at all
            score = 0.95
            evidence.append("No sanitization applied (κ = ∅)")
        elif kappa_size <= 3:
            # Some sanitization, but not for this sink
            score = 0.85
            evidence.append(f"Partial sanitization (|κ| = {kappa_size}, excludes {sink_type.name})")
        else:
            # Heavy sanitization, but still not safe for this sink
            score = 0.70
            evidence.append(f"Heavy sanitization (|κ| = {kappa_size}), but not for {sink_type.name}")
        
        return score
    
    def _score_semantic_context(
        self,
        is_guarded: bool,
        has_exception_handler: bool,
        in_framework_context: bool,
        evidence: List[str],
    ) -> float:
        """
        Score based on semantic context (guards, handlers, frameworks).
        
        Guards and handlers reduce confidence (may protect against bug).
        Framework context may increase confidence (known patterns).
        """
        score = 0.80  # Baseline: moderate semantic confidence
        
        if is_guarded:
            score -= 0.40
            evidence.append("Guard detected (may protect)")
        
        if has_exception_handler:
            score -= 0.20
            evidence.append("Exception handler present (may catch)")
        
        if in_framework_context:
            score += 0.10
            evidence.append("Framework context (known pattern)")
        
        # Clamp to [0, 1]
        score = max(0.0, min(1.0, score))
        
        return score
    
    def _score_call_chain(
        self,
        chain_length: int,
        evidence: List[str],
    ) -> float:
        """
        Score call chain quality (inverse penalty for complexity).
        
        Short chains: high confidence
        Long chains: analysis imprecision accumulates
        """
        if chain_length == 1:
            score = 1.0
            evidence.append("Intraprocedural (single function)")
        elif chain_length == 2:
            score = 0.90
        elif chain_length <= 4:
            score = 0.75
        elif chain_length <= 8:
            score = 0.60
        else:
            score = 0.40
            evidence.append(f"Long chain ({chain_length}) - precision loss")
        
        return score
    
    # ========================================================================
    # Error Bug Scoring (Non-taint)
    # ========================================================================
    
    def score_error_bug(
        self,
        bug_type: str,
        certainty: str,  # 'DEFINITE', 'LIKELY', 'POSSIBLE', 'UNKNOWN'
        is_guarded: bool = False,
        call_chain_length: int = 1,
        has_exception_handler: bool = False,
        param_sources: Optional[FrozenSet[int]] = None,
    ) -> ConfidenceBreakdown:
        """
        Score an error bug (DIV_ZERO, NULL_PTR, BOUNDS, etc.).
        
        Args:
            bug_type: Type of error bug
            certainty: Abstract certainty level
            is_guarded: Whether guards protect
            call_chain_length: Call chain depth
            has_exception_handler: Exception handling present
            param_sources: Parameter indices involved
        
        Returns:
            ConfidenceBreakdown with component scores
        """
        breakdown = ConfidenceBreakdown()
        
        # For error bugs, use different weight distribution
        breakdown.source_weight = 0.40   # "source" = certainty of error state
        breakdown.sink_weight = 0.0      # Not applicable
        breakdown.sanitization_weight = 0.0  # Not applicable
        breakdown.semantic_weight = 0.40  # Guards/handlers
        breakdown.chain_weight = 0.20    # Call chain quality
        
        # 1. Certainty score (maps to "source" weight)
        breakdown.source_score = self._score_error_certainty(
            bug_type, certainty, param_sources, breakdown.evidence
        )
        
        # 2. Semantic score
        breakdown.semantic_score = self._score_semantic_context(
            is_guarded, has_exception_handler, False, breakdown.evidence
        )
        
        # 3. Chain score
        breakdown.chain_score = self._score_call_chain(call_chain_length, breakdown.evidence)
        
        return breakdown
    
    def _score_error_certainty(
        self,
        bug_type: str,
        certainty: str,
        param_sources: Optional[FrozenSet[int]],
        evidence: List[str],
    ) -> float:
        """Score error bug certainty."""
        certainty_map = {
            'DEFINITE': 0.95,
            'LIKELY': 0.80,
            'POSSIBLE': 0.60,
            'UNKNOWN': 0.40,
        }
        
        score = certainty_map.get(certainty, 0.50)
        evidence.append(f"{bug_type} certainty: {certainty} → {score:.2f}")
        
        # Bonus for param tracking
        if param_sources and len(param_sources) > 0:
            score = min(1.0, score + 0.05)
            evidence.append(f"Param sources tracked: {len(param_sources)}")
        
        return score


# ============================================================================
# Convenience Functions
# ============================================================================

def compute_security_confidence(
    label: TaintLabel,
    sink_type: SinkType,
    **kwargs,
) -> float:
    """Compute security bug confidence (returns 0.0-1.0)."""
    scorer = ConfidenceScorer()
    breakdown = scorer.score_security_bug(label, sink_type, **kwargs)
    return breakdown.combined_score()


def compute_error_confidence(
    bug_type: str,
    certainty: str,
    **kwargs,
) -> float:
    """Compute error bug confidence (returns 0.0-1.0)."""
    scorer = ConfidenceScorer()
    breakdown = scorer.score_error_bug(bug_type, certainty, **kwargs)
    return breakdown.combined_score()
