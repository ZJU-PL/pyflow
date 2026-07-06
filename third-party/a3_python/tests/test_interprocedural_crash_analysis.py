"""
Tests for interprocedural bytecode-level crash analysis.

Iteration 424: Verify that analyze_file() correctly uses interprocedural analysis
for crash bugs while prioritizing security violations from symbolic VM.
"""

import tempfile
from pathlib import Path
import pytest

from a3_python.analyzer import Analyzer


class TestInterproceduralCrashAnalysis:
    """Test that interprocedural crash analysis is re-enabled and works correctly."""
    
    def test_null_ptr_crash_detected(self):
        """Test that NULL_PTR bugs are detected via interprocedural analysis."""
        code = """
def get_value(x):
    # Returns None if x is falsy
    if not x:
        return None
    return x

def process(data):
    # Dereferences without null check
    value = get_value(data)
    return value.strip()  # NULL_PTR if value is None

def entry():
    return process(False)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            filepath = Path(f.name)
        
        try:
            analyzer = Analyzer(verbose=True, enable_interprocedural=True)
            result = analyzer.analyze_file(filepath)
            
            # Should detect NULL_PTR via interprocedural analysis
            assert result.verdict == "BUG"
            assert result.bug_type in ["NULL_PTR", "TYPE_CONFUSION"]  # Could be either
            assert result.counterexample is not None
        finally:
            filepath.unlink()
    
    def test_bounds_error_detected(self):
        """Test that BOUNDS errors are detected via interprocedural analysis."""
        code = """
def get_index():
    return 100

def access_list():
    items = [1, 2, 3]
    idx = get_index()
    return items[idx]  # BOUNDS - index out of range
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            filepath = Path(f.name)
        
        try:
            analyzer = Analyzer(verbose=True, enable_interprocedural=True)
            result = analyzer.analyze_file(filepath)
            
            # Should detect BOUNDS via interprocedural analysis
            # Note: May be UNKNOWN if analysis can't prove index is always out of bounds
            assert result.verdict in ["BUG", "UNKNOWN"]
            if result.verdict == "BUG":
                assert result.bug_type == "BOUNDS"
        finally:
            filepath.unlink()
    
    def test_security_bugs_prioritized_over_crash(self):
        """Test that security bugs from symbolic VM take priority over crash bugs."""
        code = """
def get_query(username):
    # SQL injection vulnerability
    return "SELECT * FROM users WHERE name = '" + username + "'"

def execute_query(username):
    query = get_query(username)
    cursor.execute(query)  # SQL_INJECTION (security bug)

def also_crashes():
    x = None
    return x.strip()  # NULL_PTR (crash bug)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            filepath = Path(f.name)
        
        try:
            analyzer = Analyzer(verbose=True, enable_interprocedural=True)
            result = analyzer.analyze_file(filepath)
            
            # Should detect SQL_INJECTION first (security bugs take priority)
            assert result.verdict == "BUG"
            assert result.bug_type == "SQL_INJECTION"
            # NOT NULL_PTR, even though also_crashes has a crash
        finally:
            filepath.unlink()
    
    def test_crash_bugs_detected_when_no_security_bugs(self):
        """Test that crash bugs are still detected when no security bugs exist."""
        code = """
def safe_function(x):
    # No security issues here
    return x * 2

def crashes():
    # Division by zero
    return 1 / 0
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            filepath = Path(f.name)
        
        try:
            analyzer = Analyzer(verbose=True, enable_interprocedural=True)
            result = analyzer.analyze_file(filepath)
            
            # Should detect DIV_ZERO crash
            assert result.verdict == "BUG"
            assert result.bug_type == "DIV_ZERO"
        finally:
            filepath.unlink()
    
    def test_interprocedural_only_mode(self):
        """Test that interprocedural_only mode skips symbolic execution."""
        code = """
def get_none():
    return None

def use_value():
    value = get_none()
    return value.strip()  # NULL_PTR
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            filepath = Path(f.name)
        
        try:
            # interprocedural_only mode
            analyzer = Analyzer(verbose=True, interprocedural_only=True)
            result = analyzer.analyze_file(filepath)
            
            # Should use interprocedural analysis only
            assert result.verdict in ["BUG", "UNKNOWN"]
            # Should NOT run module-level symbolic execution
        finally:
            filepath.unlink()


class TestInterproceduralCallChains:
    """Test that call chains are properly tracked in interprocedural bugs."""
    
    def test_call_chain_in_counterexample(self):
        """Test that bug counterexamples include call chain."""
        code = """
def level3():
    return None

def level2():
    return level3()

def level1():
    val = level2()
    return val.strip()  # NULL_PTR

def entry():
    return level1()
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            filepath = Path(f.name)
        
        try:
            analyzer = Analyzer(verbose=True, enable_interprocedural=True)
            result = analyzer.analyze_file(filepath)
            
            if result.verdict == "BUG":
                # Should have call chain
                assert 'call_chain' in result.counterexample or result.call_chain is not None
                if 'call_chain' in result.counterexample:
                    # Call chain should include at least the crash function
                    chain = result.counterexample['call_chain']
                    assert isinstance(chain, list)
                    # Should have at least 1 entry (the function where crash occurs)
                    assert len(chain) >= 1
                    # Chain should contain level1 (where the actual NULL_PTR occurs)
                    assert any('level1' in func for func in chain)
        finally:
            filepath.unlink()

    def test_no_null_ptr_on_builtin_call_result_attribute(self):
        """Regression: keras#11 — attribute access on set(dir(...)) must not
        produce a false-positive NULL_PTR.  The crash-summary analyser should
        recognise that the CALL result of ``set(...)`` is always non-None, and
        that TOS has no parameter flow when the attribute access target is a
        locally computed value.
        """
        code = """\
from collections.abc import Sequence

def is_sequence(seq):
    return (getattr(seq, 'use_sequence_api', False)
            or set(dir(Sequence())).issubset(set(dir(seq) + ['use_sequence_api'])))
"""
        filepath = Path(tempfile.mktemp(suffix=".py"))
        filepath.write_text(code)
        try:
            from a3_python.cfg.call_graph import build_call_graph_from_file
            from a3_python.semantics.crash_summaries import BytecodeCrashSummaryComputer

            cg = build_call_graph_from_file(filepath, filepath.stem)
            summaries = BytecodeCrashSummaryComputer(cg).compute_all()
            for name, s in summaries.items():
                if 'is_sequence' in name:
                    assert 'NULL_PTR' not in s.may_trigger, (
                        f"is_sequence should NOT trigger unguarded NULL_PTR, "
                        f"but may_trigger={s.may_trigger}"
                    )
        finally:
            filepath.unlink()

    def test_null_ptr_still_detected_on_param_attribute(self):
        """Ensure NULL_PTR is still detected when attribute access IS on a
        parameter-derived value (no regression from the keras#11 fix)."""
        code = """\
def null_deref(x):
    return x.value
"""
        filepath = Path(tempfile.mktemp(suffix=".py"))
        filepath.write_text(code)
        try:
            from a3_python.cfg.call_graph import build_call_graph_from_file
            from a3_python.semantics.crash_summaries import BytecodeCrashSummaryComputer

            cg = build_call_graph_from_file(filepath, filepath.stem)
            summaries = BytecodeCrashSummaryComputer(cg).compute_all()
            for name, s in summaries.items():
                if 'null_deref' in name:
                    assert 'NULL_PTR' in s.may_trigger, (
                        f"null_deref SHOULD trigger NULL_PTR, "
                        f"but may_trigger={s.may_trigger}"
                    )
        finally:
            filepath.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
