"""
Learned Invariant Detection: Learn safety patterns from the codebase itself.

Goes beyond regex by analyzing statistical patterns across the entire codebase:
1. What guards typically protect which operations?
2. What initialization patterns always result in safe values?
3. What function return types are never None in practice?
4. What parameter combinations are validated together?

This is "wisdom of the codebase" - if 95% of similar code validates X before Y,
then Y probably needs X validation even if we don't have explicit rules for it.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional
from collections import Counter, defaultdict
from ..semantics.crash_summaries import CrashSummary


@dataclass
class InvariantPattern:
    """A learned safety pattern from the codebase."""
    pattern_type: str  # 'guard_before_op', 'return_never_null', 'param_always_validated'
    confidence: float  # 0.0-1.0, based on frequency in codebase
    support: int  # Number of times seen
    evidence: List[str]  # Function names where this pattern appears
    

@dataclass
class CodebaseInvariantLearner:
    """
    Learn safety invariants from the codebase itself.
    
    Strategy: Analyze ALL functions to find common patterns, then use those
    patterns to identify when violations are likely FPs vs TPs.
    
    Example insights:
    - "99% of dict.get() calls are followed by null checks" 
      → dict.get() without check is suspicious (TP)
    - "100% of tensor.size() results are used as divisors without checks"
      → tensor.size() division without check is normal (FP)
    """
    
    # Pattern databases (learned from codebase)
    operations_always_validated: Dict[str, InvariantPattern] = field(default_factory=dict)
    operations_never_validated: Dict[str, InvariantPattern] = field(default_factory=dict)
    return_types_never_null: Dict[str, InvariantPattern] = field(default_factory=dict)
    parameter_validation_patterns: Dict[Tuple[str, str], InvariantPattern] = field(default_factory=dict)
    
    # Raw statistics
    _op_to_guard_count: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    _func_return_null_count: Dict[str, int] = field(default_factory=Counter)
    _func_return_total_count: Dict[str, int] = field(default_factory=Counter)
    
    def learn_from_summaries(self, summaries: Dict[str, CrashSummary]) -> None:
        """
        Learn safety patterns by analyzing all function summaries.
        
        Collects statistics on:
        1. Which operations are guarded vs unguarded
        2. Which functions return None vs never return None
        3. Which parameters are validated together
        4. Which operations are consistently safe/unsafe
        """
        for func_name, summary in summaries.items():
            self._analyze_guard_patterns(summary)
            self._analyze_return_patterns(summary)
            self._analyze_parameter_validation(summary)
        
        # Convert statistics to learned patterns
        self._extract_invariants()
    
    def _analyze_guard_patterns(self, summary: CrashSummary) -> None:
        """
        Analyze which operations are guarded in this function.
        
        Pattern: If operation X is guarded 95% of the time, then unguarded X is suspicious.
                 If operation Y is never guarded, then guarded Y is probably over-cautious.
        """
        if not hasattr(summary, 'instructions'):
            return
        
        # Look for guarded operations
        for i, instr in enumerate(summary.instructions):
            # Detect operations like BINARY_TRUE_DIVIDE, BINARY_SUBSCR, etc.
            if instr.opname in ['BINARY_TRUE_DIVIDE', 'BINARY_FLOOR_DIVIDE']:
                op_key = 'division'
                # Check if there's a guard nearby (within 10 instructions before)
                has_guard = self._has_nearby_guard(summary.instructions, i, guard_distance=10)
                self._op_to_guard_count[op_key]['guarded' if has_guard else 'unguarded'] += 1
            
            elif instr.opname == 'BINARY_SUBSCR':
                op_key = 'subscript'
                has_guard = self._has_nearby_guard(summary.instructions, i, guard_distance=10)
                self._op_to_guard_count[op_key]['guarded' if has_guard else 'unguarded'] += 1
            
            elif instr.opname in ['LOAD_ATTR', 'LOAD_METHOD']:
                op_key = f'attr_access:{instr.argval}'
                has_guard = self._has_nearby_guard(summary.instructions, i, guard_distance=10)
                self._op_to_guard_count[op_key]['guarded' if has_guard else 'unguarded'] += 1
    
    def _has_nearby_guard(self, instructions: List, idx: int, guard_distance: int = 10) -> bool:
        """Check if there's a guard (comparison, null check) before this instruction."""
        start = max(0, idx - guard_distance)
        for instr in instructions[start:idx]:
            # Guards: POP_JUMP_IF_FALSE, POP_JUMP_IF_TRUE, COMPARE_OP
            if instr.opname in ['POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE', 'COMPARE_OP']:
                return True
            # Null checks: IS_OP (is None), IS_NOT (is not None)
            if instr.opname == 'IS_OP':
                return True
        return False
    
    def _analyze_return_patterns(self, summary: CrashSummary) -> None:
        """
        Track which functions return None vs never return None.
        
        Pattern: If a function NEVER returns None across all call sites,
                 then null checks after calling it are likely FPs.
        """
        func_name = summary.function_name
        self._func_return_total_count[func_name] += 1
        
        # Check if function can return None
        if hasattr(summary, 'may_return_none') and summary.may_return_none:
            self._func_return_null_count[func_name] += 1
    
    def _analyze_parameter_validation(self, summary: CrashSummary) -> None:
        """
        Track which parameters are validated together.
        
        Pattern: If param X is ALWAYS validated when param Y is used,
                 then lack of X validation is suspicious.
        """
        # This would require deeper analysis of guard facts and parameter usage
        # For now, just track preconditions
        if hasattr(summary, 'preconditions'):
            for precond in summary.preconditions:
                param_name = f"param_{precond.param_index}"
                # Track that this parameter has validation
                validation_key = (summary.function_name, param_name)
                # Would track co-occurrence patterns here
    
    def _extract_invariants(self) -> None:
        """
        Convert raw statistics into learned invariant patterns.
        
        Uses statistical thresholds:
        - 95%+ occurrence → "ALWAYS" pattern (high confidence)
        - 80-95% → "USUALLY" pattern (medium confidence)
        - 5-20% → "RARELY" pattern (low confidence)
        - <5% → "NEVER" pattern (high confidence for negation)
        """
        # Extract operation guard patterns
        for op_key, counts in self._op_to_guard_count.items():
            total = counts['guarded'] + counts['unguarded']
            if total < 5:  # Need at least 5 samples
                continue
            
            guarded_pct = counts['guarded'] / total
            
            if guarded_pct >= 0.95:
                # This operation is ALWAYS guarded → unguarded instance is suspicious (TP)
                self.operations_always_validated[op_key] = InvariantPattern(
                    pattern_type='always_guarded',
                    confidence=guarded_pct,
                    support=total,
                    evidence=[]  # Would collect function names
                )
            elif guarded_pct <= 0.05:
                # This operation is NEVER guarded → guarded instance is over-cautious (FP)
                self.operations_never_validated[op_key] = InvariantPattern(
                    pattern_type='never_guarded',
                    confidence=1.0 - guarded_pct,
                    support=total,
                    evidence=[]
                )
        
        # Extract return null patterns
        for func_name, null_count in self._func_return_null_count.items():
            total = self._func_return_total_count[func_name]
            null_pct = null_count / total
            
            if null_pct <= 0.01 and total >= 10:
                # Function NEVER returns None (< 1% of time)
                self.return_types_never_null[func_name] = InvariantPattern(
                    pattern_type='never_returns_null',
                    confidence=1.0 - null_pct,
                    support=total,
                    evidence=[func_name]
                )
    
    def is_likely_false_positive(
        self,
        bug_type: str,
        bug_variable: str,
        operation: str,
        summary: CrashSummary
    ) -> Tuple[bool, float]:
        """
        Use learned invariants to determine if this bug is likely a FP.
        
        Returns:
            (is_fp, confidence) where confidence is 0.0-1.0
        
        Logic:
        - If operation is NEVER guarded in codebase but is here → likely over-reporting (FP)
        - If operation is ALWAYS guarded but not here → likely real bug (TP)
        - If function return is NEVER null but we report NULL_PTR → FP
        """
        if bug_type == 'DIV_ZERO':
            # Check if division operations are typically guarded
            if 'division' in self.operations_never_validated:
                pattern = self.operations_never_validated['division']
                if pattern.confidence > 0.90:
                    # Division is almost never guarded in this codebase
                    # Reporting unguarded division is likely FP
                    return True, pattern.confidence
        
        elif bug_type == 'NULL_PTR':
            # Check if the function being called never returns None
            if hasattr(summary, 'called_functions'):
                for called_func in summary.called_functions:
                    if called_func in self.return_types_never_null:
                        pattern = self.return_types_never_null[called_func]
                        if pattern.confidence > 0.95:
                            # Function never returns None → NULL_PTR check is FP
                            return True, pattern.confidence
        
        return False, 0.0
    
    def get_learned_invariants_summary(self) -> str:
        """Return human-readable summary of learned invariants."""
        lines = ["Learned Invariants from Codebase:"]
        lines.append(f"\nOperations always guarded ({len(self.operations_always_validated)}):")
        for op, pattern in list(self.operations_always_validated.items())[:5]:
            lines.append(f"  - {op}: {pattern.confidence:.1%} guarded (n={pattern.support})")
        
        lines.append(f"\nOperations never guarded ({len(self.operations_never_validated)}):")
        for op, pattern in list(self.operations_never_validated.items())[:5]:
            lines.append(f"  - {op}: {pattern.confidence:.1%} unguarded (n={pattern.support})")
        
        lines.append(f"\nFunctions never returning None ({len(self.return_types_never_null)}):")
        for func, pattern in list(self.return_types_never_null.items())[:5]:
            lines.append(f"  - {func}: {pattern.confidence:.1%} non-null (n={pattern.support})")
        
        return '\n'.join(lines)
