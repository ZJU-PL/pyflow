"""
Tests for STACK_OVERFLOW unsafe region.

Tests both BUG cases (recursion depth exceeds limit) and NON-BUG cases
(bounded recursion within limits).

STACK_OVERFLOW is detected when len(frame_stack) > recursion_limit.
This corresponds to RecursionError in Python.

Note: Since function call opcodes are not yet implemented, we test the
unsafe predicate directly by creating states with varying frame depths.
This is the correct semantic approach: testing the predicate U_STACK_OVERFLOW(σ)
independent of the specific execution paths that could reach such states.
"""

import pytest
import sys
from a3_python.semantics.state import MachineState, Frame
from a3_python.unsafe.stack_overflow import is_unsafe_stack_overflow, extract_counterexample


def create_state_with_depth(depth: int) -> MachineState:
    """
    Helper: Create a machine state with a specific frame stack depth.
    
    This simulates the state that would result from recursive function calls.
    """
    state = MachineState()
    # Create dummy frames
    for i in range(depth):
        frame = Frame(code=None)
        state.frame_stack.append(frame)
    return state


def test_exceeds_default_limit_bug():
    """
    BUG: Frame stack depth exceeds default recursion limit.
    
    Python's default limit is sys.getrecursionlimit() (typically 1000).
    """
    limit = sys.getrecursionlimit()
    # Create state with depth exceeding limit
    state = create_state_with_depth(limit + 1)
    
    assert is_unsafe_stack_overflow(state), \
        f"Should detect STACK_OVERFLOW when depth={limit+1} > limit={limit}"
    
    # Extract counterexample
    trace = [f"frame_{i}" for i in range(min(5, limit+1))]  # Sample trace
    cex = extract_counterexample(state, trace)
    
    assert cex['bug_type'] == 'STACK_OVERFLOW'
    assert cex['final_state']['recursion_depth'] == limit + 1
    assert cex['final_state']['recursion_limit'] == limit
    assert cex['final_state']['depth_exceeded_by'] == 1


def test_barely_exceeds_limit_bug():
    """
    BUG: Frame stack depth exactly exceeds limit by 1.
    
    Edge case: limit + 1 should be unsafe.
    """
    limit = 100  # Use smaller limit for test
    state = create_state_with_depth(limit + 1)
    
    assert is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Should detect overflow at limit + 1"


def test_deeply_exceeds_limit_bug():
    """
    BUG: Frame stack depth far exceeds limit.
    
    Testing with depth >> limit to ensure it's not an off-by-one issue.
    """
    limit = 100
    state = create_state_with_depth(limit + 50)
    
    assert is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Should detect overflow when depth >> limit"
    
    cex = extract_counterexample(state, [], recursion_limit=limit)
    assert cex['final_state']['depth_exceeded_by'] == 50


def test_custom_high_limit_bug():
    """
    BUG: Exceeds a custom higher recursion limit.
    
    Tests that the predicate respects custom limits.
    """
    custom_limit = 5000
    state = create_state_with_depth(custom_limit + 1)
    
    assert is_unsafe_stack_overflow(state, recursion_limit=custom_limit), \
        "Should detect overflow with custom limit"


def test_at_limit_not_bug():
    """
    NON-BUG: Frame stack depth exactly at limit (not exceeding).
    
    Being AT the limit is allowed; only EXCEEDING is unsafe.
    """
    limit = 100
    state = create_state_with_depth(limit)
    
    assert not is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Should NOT detect overflow when depth == limit (only > limit is unsafe)"


def test_below_limit_not_bug():
    """
    NON-BUG: Frame stack depth well below limit.
    
    Normal recursion within bounds should not trigger STACK_OVERFLOW.
    """
    limit = 100
    state = create_state_with_depth(limit - 50)
    
    assert not is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Should not detect overflow when depth < limit"


def test_shallow_stack_not_bug():
    """
    NON-BUG: Shallow recursion (depth = 5) is safe.
    """
    state = create_state_with_depth(5)
    
    assert not is_unsafe_stack_overflow(state), \
        "Shallow stack should not be unsafe"


def test_single_frame_not_bug():
    """
    NON-BUG: Single frame (top-level execution).
    
    A single frame is the minimum and should never be unsafe.
    """
    state = create_state_with_depth(1)
    
    assert not is_unsafe_stack_overflow(state), \
        "Single frame should not trigger STACK_OVERFLOW"


def test_empty_stack_not_bug():
    """
    NON-BUG: Empty frame stack (no active execution).
    
    Edge case: empty stack should not be considered overflow.
    """
    state = create_state_with_depth(0)
    
    assert not is_unsafe_stack_overflow(state), \
        "Empty stack should not be unsafe"


def test_one_below_limit_not_bug():
    """
    NON-BUG: Frame stack depth exactly one below limit.
    
    Edge case testing the boundary.
    """
    limit = 100
    state = create_state_with_depth(limit - 1)
    
    assert not is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Should not detect overflow at limit - 1"


def test_counterexample_structure():
    """
    BUG: Verify counterexample structure is correct.
    
    Tests that the extracted counterexample contains all required fields.
    """
    limit = 50
    depth = 75
    state = create_state_with_depth(depth)
    trace = ["call_foo", "call_bar", "call_baz"]
    
    cex = extract_counterexample(state, trace, recursion_limit=limit)
    
    # Verify structure
    assert 'bug_type' in cex
    assert 'trace' in cex
    assert 'final_state' in cex
    assert 'path_condition' in cex
    
    # Verify values
    assert cex['bug_type'] == 'STACK_OVERFLOW'
    assert cex['trace'] == trace
    assert cex['final_state']['recursion_depth'] == depth
    assert cex['final_state']['recursion_limit'] == limit
    assert cex['final_state']['depth_exceeded_by'] == depth - limit


# ============================================================================
# Additional NON-BUG tests
# ============================================================================

def test_medium_depth_not_bug():
    """NON-BUG: Medium recursion depth (50 frames) is safe."""
    state = create_state_with_depth(50)
    
    assert not is_unsafe_stack_overflow(state), \
        "Medium depth should not be unsafe"


def test_two_frames_not_bug():
    """NON-BUG: Two frames (one function call) is safe."""
    state = create_state_with_depth(2)
    
    assert not is_unsafe_stack_overflow(state), \
        "Two frames should not trigger STACK_OVERFLOW"


def test_ten_frames_not_bug():
    """NON-BUG: Ten frames is safe."""
    state = create_state_with_depth(10)
    
    assert not is_unsafe_stack_overflow(state), \
        "Ten frames should be safe"


def test_half_limit_not_bug():
    """NON-BUG: Half of recursion limit is safe."""
    limit = 200
    state = create_state_with_depth(limit // 2)
    
    assert not is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Half of limit should be safe"


def test_exceeds_by_ten_bug():
    """BUG: Frame stack exceeds limit by 10."""
    limit = 100
    state = create_state_with_depth(limit + 10)
    
    assert is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Should detect overflow when exceeding by 10"


def test_exceeds_by_hundred_bug():
    """BUG: Frame stack exceeds limit by 100."""
    limit = 100
    state = create_state_with_depth(limit + 100)
    
    assert is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Should detect overflow when exceeding by 100"


def test_small_limit_exceeded_bug():
    """BUG: Exceeding very small custom limit."""
    limit = 10
    state = create_state_with_depth(limit + 1)
    
    assert is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Should detect overflow with small limit"


def test_large_limit_exceeded_bug():
    """BUG: Exceeding large custom limit."""
    limit = 10000
    state = create_state_with_depth(limit + 1)
    
    assert is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Should detect overflow with large limit"


def test_multiple_frames_over_limit_bug():
    """BUG: Many frames over the limit."""
    limit = 50
    state = create_state_with_depth(limit + 25)
    
    assert is_unsafe_stack_overflow(state, recursion_limit=limit), \
        "Should detect overflow when depth = limit + 25"
