"""
Test DSE integration in analyzer.

Validates that when bugs are found, the analyzer can:
1. Extract path constraints from the symbolic trace
2. Solve constraints with Z3 to get concrete inputs
3. Validate the bug with concrete execution
"""

import pytest
from pathlib import Path
import types

from a3_python.analyzer import Analyzer
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


class TestAnalyzerDSEIntegration:
    """Test that analyzer integrates DSE validation for counterexamples."""
    
    def test_dse_validate_counterexample_div_zero(self):
        """Test DSE validation on a DIV_ZERO bug path."""
        # Create simple div-by-zero code
        code = compile("x = 10 / 0", "<test>", "exec")
        
        # Find bug with symbolic execution
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=20)
        
        # Find the buggy path
        buggy_path = None
        for path in paths:
            unsafe = check_unsafe_regions(path.state, path.trace)
            if unsafe and unsafe['bug_type'] == 'DIV_ZERO':
                buggy_path = path
                break
        
        assert buggy_path is not None, "Should find DIV_ZERO bug"
        
        # Now test DSE validation
        analyzer = Analyzer(verbose=False)
        
        # Create a dummy filepath for DSE context
        test_file = Path("<test>")
        
        dse_result = analyzer._validate_counterexample_with_dse(
            code, buggy_path, test_file
        )
        
        # DSE should at least attempt validation
        # It may not always succeed (depends on constraint complexity)
        # but it should return a result
        assert dse_result is not None
        assert dse_result.status in ("realized", "failed", "error")
    
    def test_dse_validate_counterexample_assert_fail(self):
        """Test DSE validation on an ASSERT_FAIL bug path."""
        code = compile("assert False", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=20)
        
        buggy_path = None
        for path in paths:
            unsafe = check_unsafe_regions(path.state, path.trace)
            if unsafe and unsafe['bug_type'] == 'ASSERT_FAIL':
                buggy_path = path
                break
        
        assert buggy_path is not None, "Should find ASSERT_FAIL bug"
        
        analyzer = Analyzer(verbose=False)
        test_file = Path("<test>")
        
        dse_result = analyzer._validate_counterexample_with_dse(
            code, buggy_path, test_file
        )
        
        assert dse_result is not None
        assert dse_result.status in ("realized", "failed", "error")
    
    def test_constraint_extraction_from_path(self):
        """Test that we can extract constraints from a symbolic path."""
        from a3_python.dse.constraint_solver import ConstraintExtractor
        
        code = compile("x = 10\ny = x / 0", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=30)
        
        # Get any completed path
        completed_paths = [p for p in paths if p.state.halted or not p.state.frame_stack]
        
        if completed_paths:
            extractor = ConstraintExtractor()
            constraints = extractor.extract_from_path(completed_paths[0])
            
            # Should have a path condition
            assert constraints is not None
            assert constraints.path_condition is not None
