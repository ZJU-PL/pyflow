"""
Test that NULL_PTR and BOUNDS bugs get appropriate confidence scores.

These bug types have higher false positive rates due to path infeasibility
and unmodeled invariants, so they should get lower confidence than other
bug types like DIV_ZERO or ASSERT_FAIL.
"""

import pytest
from a3_python.semantics.interprocedural_bugs import InterproceduralBugTracker
from a3_python.cfg.call_graph import build_call_graph_from_directory
from pathlib import Path
import tempfile
import shutil


def test_null_ptr_gets_lower_confidence_than_div_zero():
    """Test that NULL_PTR bugs get lower confidence than DIV_ZERO bugs."""
    
    # Create temporary directory with test code
    tmpdir = tempfile.mkdtemp()
    try:
        test_file = Path(tmpdir) / "test.py"
        test_file.write_text("""
def null_ptr_bug(x):
    # May raise AttributeError if x is None
    return x.value

def div_zero_bug(y):
    # May raise ZeroDivisionError if y is 0
    return 10 / y

def entry():
    null_ptr_bug(None)
    div_zero_bug(0)
""")
        
        # Build tracker and run interprocedural analysis
        tracker = InterproceduralBugTracker.from_project(Path(tmpdir))
        bugs = tracker.find_all_bugs()
        
        # Find NULL_PTR and DIV_ZERO bugs
        null_ptr_bugs = [b for b in bugs if b.bug_type == 'NULL_PTR']
        div_zero_bugs = [b for b in bugs if b.bug_type == 'DIV_ZERO']
        
        # Both should be found
        assert len(null_ptr_bugs) >= 1, "Should detect NULL_PTR bug"
        assert len(div_zero_bugs) >= 1, "Should detect DIV_ZERO bug"
        
        # NULL_PTR should have lower confidence
        null_confidence = null_ptr_bugs[0].confidence
        div_confidence = div_zero_bugs[0].confidence
        
        assert null_confidence < div_confidence, \
            f"NULL_PTR confidence ({null_confidence:.2f}) should be lower than DIV_ZERO ({div_confidence:.2f})"
        
        # Verify confidence values are in expected range
        # NULL_PTR with POSSIBLE certainty: 0.60 * 0.40 + 0.80 * 0.40 + 1.0 * 0.20 = 0.76
        assert 0.70 <= null_confidence <= 0.80, \
            f"NULL_PTR confidence should be ~0.76, got {null_confidence:.2f}"
        # DIV_ZERO with LIKELY certainty: 0.80 * 0.40 + 0.80 * 0.40 + 1.0 * 0.20 = 0.84
        assert 0.80 <= div_confidence <= 0.90, \
            f"DIV_ZERO confidence should be ~0.84, got {div_confidence:.2f}"
    
    finally:
        shutil.rmtree(tmpdir)


def test_bounds_gets_lower_confidence_than_div_zero():
    """Test that BOUNDS bugs get lower confidence than DIV_ZERO bugs."""
    
    # Create temporary directory with test code
    tmpdir = tempfile.mkdtemp()
    try:
        test_file = Path(tmpdir) / "test.py"
        test_file.write_text("""
def bounds_bug(lst, idx):
    # May raise IndexError if idx out of bounds
    return lst[idx]

def div_zero_bug(y):
    # May raise ZeroDivisionError if y is 0
    return 10 / y

def entry():
    bounds_bug([1, 2, 3], 10)
    div_zero_bug(0)
""")
        
        # Build tracker and run interprocedural analysis
        tracker = InterproceduralBugTracker.from_project(Path(tmpdir))
        bugs = tracker.find_all_bugs()
        
        # Find BOUNDS and DIV_ZERO bugs
        bounds_bugs = [b for b in bugs if b.bug_type == 'BOUNDS']
        div_zero_bugs = [b for b in bugs if b.bug_type == 'DIV_ZERO']
        
        # Both should be found
        assert len(bounds_bugs) >= 1, "Should detect BOUNDS bug"
        assert len(div_zero_bugs) >= 1, "Should detect DIV_ZERO bug"
        
        # BOUNDS should have lower confidence
        bounds_confidence = bounds_bugs[0].confidence
        div_confidence = div_zero_bugs[0].confidence
        
        assert bounds_confidence < div_confidence, \
            f"BOUNDS confidence ({bounds_confidence:.2f}) should be lower than DIV_ZERO ({div_confidence:.2f})"
        
        # Verify confidence values are in expected range
        # BOUNDS with POSSIBLE certainty: 0.60 * 0.40 + 0.80 * 0.40 + 1.0 * 0.20 = 0.76
        assert 0.70 <= bounds_confidence <= 0.80, \
            f"BOUNDS confidence should be ~0.76, got {bounds_confidence:.2f}"
        # DIV_ZERO with LIKELY certainty: 0.80 * 0.40 + 0.80 * 0.40 + 1.0 * 0.20 = 0.84
        assert 0.80 <= div_confidence <= 0.90, \
            f"DIV_ZERO confidence should be ~0.84, got {div_confidence:.2f}"
    
    finally:
        shutil.rmtree(tmpdir)


def test_null_ptr_and_bounds_have_similar_confidence():
    """Test that NULL_PTR and BOUNDS have similar confidence (both are may-analysis)."""
    
    # Create temporary directory with test code
    tmpdir = tempfile.mkdtemp()
    try:
        test_file = Path(tmpdir) / "test.py"
        test_file.write_text("""
def null_ptr_bug(x):
    return x.value

def bounds_bug(lst, idx):
    return lst[idx]

def entry():
    null_ptr_bug(None)
    bounds_bug([1, 2], 5)
""")
        
        # Build tracker and run interprocedural analysis
        tracker = InterproceduralBugTracker.from_project(Path(tmpdir))
        bugs = tracker.find_all_bugs()
        
        # Find NULL_PTR and BOUNDS bugs
        null_ptr_bugs = [b for b in bugs if b.bug_type == 'NULL_PTR']
        bounds_bugs = [b for b in bugs if b.bug_type == 'BOUNDS']
        
        # Both should be found
        assert len(null_ptr_bugs) >= 1, "Should detect NULL_PTR bug"
        assert len(bounds_bugs) >= 1, "Should detect BOUNDS bug"
        
        # Confidence should be similar (within 0.1)
        null_confidence = null_ptr_bugs[0].confidence
        bounds_confidence = bounds_bugs[0].confidence
        
        assert abs(null_confidence - bounds_confidence) < 0.1, \
            f"NULL_PTR ({null_confidence:.2f}) and BOUNDS ({bounds_confidence:.2f}) should have similar confidence"
    
    finally:
        shutil.rmtree(tmpdir)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
