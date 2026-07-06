"""
Bayesian Confidence Scoring: Combine multiple weak signals probabilistically.

Goes beyond regex by treating each check as a probabilistic signal and
combining them using Bayesian inference. This is more nuanced because:
1. No single signal is definitive
2. Multiple weak signals compound evidence
3. Contradictory signals reduce confidence
4. Prior probabilities based on historical data

Example: 
- Variable name "count" suggests int (P=0.7)
- Assigned from len() suggests >= 0 (P=0.95)  
- Used in division suggests validated (P=0.6)
- Bayesian posterior: P(safe) = 0.98 → FP
"""

from dataclasses import dataclass
from typing import List, Tuple
from ..semantics.crash_summaries import CrashSummary
import math


@dataclass
class Signal:
    """A weak probabilistic signal about safety."""
    name: str
    strength: float  # P(signal | safe) - how likely this signal if code is safe
    inverse_strength: float  # P(signal | unsafe) - how likely if unsafe
    
    def likelihood_ratio(self) -> float:
        """Bayes factor: how much this signal favors safe vs unsafe."""
        if self.inverse_strength == 0:
            return float('inf')
        return self.strength / self.inverse_strength


@dataclass
class BayesianConfidenceScorer:
    """
    Combine multiple weak signals using Bayes' theorem.
    
    Strategy: Each potential FP indicator is a signal with associated
    likelihood ratios. Combine them to get posterior probability.
    
    Formula:
        P(safe|signals) = P(safe) * ∏ LR(signal_i)
    
    where LR = P(signal|safe) / P(signal|unsafe)
    """
    
    # Prior probabilities (from historical data)
    prior_fp_rate: float = 0.60  # 60% of reported bugs are FPs
    
    def collect_signals(
        self,
        bug_type: str,
        bug_variable: str,
        summary: CrashSummary
    ) -> List[Signal]:
        """
        Collect all weak signals that might indicate FP.
        
        Signals include:
        - Variable naming conventions
        - Code patterns
        - Function context (test, CLI, etc.)
        - Guard presence
        - Type hints
        - Historical patterns
        """
        signals = []
        
        # SIGNAL 1: Variable name suggests type
        if bug_type == 'DIV_ZERO' and bug_variable:
            if any(word in bug_variable.lower() for word in ['count', 'num', 'size', 'len']):
                # These names suggest positive integers
                # P(name="count"|safe) = 0.8 (counts are usually validated)
                # P(name="count"|unsafe) = 0.3 (sometimes counts can be 0)
                signals.append(Signal('suggestive_name', 0.8, 0.3))
        
        # SIGNAL 2: Function name suggests safe context
        func_name = summary.function_name.lower()
        if any(word in func_name for word in ['test_', '_test', 'mock_', 'debug_']):
            # Test code often has intentional edge cases
            # P(test_func|safe) = 0.4 (tests explore unsafe paths)
            # P(test_func|unsafe) = 0.7 (but tests also find real bugs)
            signals.append(Signal('test_context', 0.4, 0.7))
        
        # SIGNAL 3: Has nearby guards
        if hasattr(summary, 'guarded_bugs') and bug_type in summary.guarded_bugs:
            # Presence of guard suggests programmer was aware
            # P(guard|safe) = 0.9 (guards usually make code safe)
            # P(guard|unsafe) = 0.2 (but guards can be incomplete)
            signals.append(Signal('has_guard', 0.9, 0.2))
        
        # SIGNAL 4: Parameter position (param_0 often 'self')
        if bug_type == 'NULL_PTR' and bug_variable == 'param_0':
            if '.' in summary.function_name:  # Method
                # param_0 in methods is 'self', never None
                # P(param_0_in_method|safe) = 0.99
                # P(param_0_in_method|unsafe) = 0.01
                signals.append(Signal('param_0_is_self', 0.99, 0.01))
        
        # SIGNAL 5: Common safe pattern detected
        if hasattr(summary, 'instructions'):
            has_max_pattern = any('max' in str(instr.argval) for instr in summary.instructions)
            if has_max_pattern and bug_type == 'DIV_ZERO':
                # max(x, eps) pattern suggests safety
                # P(max_pattern|safe) = 0.85
                # P(max_pattern|unsafe) = 0.15
                signals.append(Signal('max_pattern', 0.85, 0.15))
        
        # SIGNAL 6: Library function with known contracts
        if hasattr(summary, 'called_functions'):
            safe_funcs = {'len', 'abs', 'max', 'min'}
            if any(func in safe_funcs for func in summary.called_functions):
                # Calling known-safe functions
                # P(safe_lib|safe) = 0.75
                # P(safe_lib|unsafe) = 0.40
                signals.append(Signal('safe_library_call', 0.75, 0.40))
        
        return signals
    
    def compute_posterior_safe_probability(
        self,
        signals: List[Signal]
    ) -> float:
        """
        Compute P(safe | all signals) using Bayes' theorem.
        
        Uses log-space to avoid numerical underflow.
        
        Returns:
            Probability that code is actually safe (0.0 to 1.0)
        """
        # Start with prior odds
        # odds(safe) = P(safe) / P(unsafe) = P(safe) / (1 - P(safe))
        prior_safe_prob = self.prior_fp_rate  # FPs are "safe"
        prior_odds = prior_safe_prob / (1 - prior_safe_prob)
        
        # Convert to log-odds for numerical stability
        log_odds = math.log(prior_odds)
        
        # Multiply by likelihood ratios (add in log-space)
        for signal in signals:
            lr = signal.likelihood_ratio()
            if math.isfinite(lr) and lr > 0:
                log_odds += math.log(lr)
        
        # Convert back to probability
        # P(safe|signals) = odds / (1 + odds)
        odds = math.exp(log_odds)
        posterior_prob = odds / (1 + odds)
        
        return posterior_prob
    
    def is_likely_false_positive(
        self,
        bug_type: str,
        bug_variable: str,
        summary: CrashSummary,
        threshold: float = 0.80
    ) -> Tuple[bool, float, List[Signal]]:
        """
        Determine if bug is likely a FP using Bayesian analysis.
        
        Args:
            bug_type: Type of bug
            bug_variable: Variable involved
            summary: Function summary
            threshold: Minimum posterior probability to classify as FP
        
        Returns:
            (is_fp, confidence, signals_used)
        """
        signals = self.collect_signals(bug_type, bug_variable, summary)
        
        if not signals:
            # No signals → use prior
            return False, self.prior_fp_rate, []
        
        posterior = self.compute_posterior_safe_probability(signals)
        
        is_fp = posterior >= threshold
        
        return is_fp, posterior, signals
    
    def explain_decision(
        self,
        signals: List[Signal],
        posterior: float
    ) -> str:
        """Generate human-readable explanation of the decision."""
        lines = [f"Bayesian Analysis: P(safe) = {posterior:.1%}"]
        lines.append(f"Prior: P(FP) = {self.prior_fp_rate:.1%}")
        lines.append("Signals:")
        
        for signal in signals:
            lr = signal.likelihood_ratio()
            impact = "strong" if lr > 3.0 else "moderate" if lr > 1.5 else "weak"
            lines.append(f"  - {signal.name}: LR={lr:.2f} ({impact} evidence for safe)")
        
        return "\n".join(lines)
