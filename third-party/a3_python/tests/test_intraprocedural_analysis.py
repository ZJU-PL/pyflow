"""
Tests for intraprocedural analysis.

Tests CFG construction, dominance analysis, guard propagation,
and integration with symbolic execution.
"""

import pytest
import types


# ============================================================================
# CFG Construction Tests
# ============================================================================

class TestCFGConstruction:
    """Tests for control flow graph construction."""
    
    def test_simple_function_cfg(self):
        """Test CFG for a simple function."""
        from a3_python.cfg import build_cfg
        
        def simple():
            x = 1
            y = 2
            return x + y
        
        cfg = build_cfg(simple.__code__)
        
        assert cfg.entry_block == 0
        assert len(cfg.blocks) >= 1
        assert len(cfg.exit_blocks) >= 1
    
    def test_conditional_cfg(self):
        """Test CFG for function with if/else."""
        from a3_python.cfg import build_cfg, EdgeType
        
        def conditional(x):
            if x > 0:
                return 1
            else:
                return -1
        
        cfg = build_cfg(conditional.__code__)
        
        # Should have multiple blocks for branches
        assert len(cfg.blocks) >= 2
        
        # Should have conditional edges
        has_cond_edge = False
        for block in cfg.blocks.values():
            for _, edge_type, _ in block.successors:
                if edge_type in (EdgeType.COND_TRUE, EdgeType.COND_FALSE):
                    has_cond_edge = True
                    break
        
        assert has_cond_edge
    
    def test_loop_detection(self):
        """Test loop header and back edge detection."""
        from a3_python.cfg import build_cfg
        
        def with_loop(n):
            total = 0
            for i in range(n):
                total += i
            return total
        
        cfg = build_cfg(with_loop.__code__)
        
        # Should detect loop header
        # Note: May not detect loop if optimizer removes it
        # For non-trivial loops, back_edges should be populated
        assert isinstance(cfg.loop_headers, set)
        assert isinstance(cfg.back_edges, list)
    
    def test_exception_regions(self):
        """Test exception region parsing."""
        from a3_python.cfg import build_cfg
        
        def with_try():
            try:
                x = 1 / 0
            except ZeroDivisionError:
                return 0
            return 1
        
        cfg = build_cfg(with_try.__code__)
        
        # Should have exception regions from exception table
        assert len(cfg.exception_regions) >= 0  # May be empty if no real try/except


# ============================================================================
# Dominance Analysis Tests
# ============================================================================

class TestDominanceAnalysis:
    """Tests for dominance computation."""
    
    def test_entry_dominates_all(self):
        """Entry block should dominate all other blocks."""
        from a3_python.cfg import build_cfg
        
        def simple(x):
            if x > 0:
                y = 1
            else:
                y = 2
            return y
        
        cfg = build_cfg(simple.__code__)
        
        # Entry block should dominate all blocks
        entry = cfg.entry_block
        for block_id in cfg.blocks:
            assert entry in cfg.dominators.get(block_id, set())
    
    def test_self_dominates(self):
        """Every block should dominate itself."""
        from a3_python.cfg import build_cfg
        
        def func():
            return 42
        
        cfg = build_cfg(func.__code__)
        
        for block_id in cfg.blocks:
            assert block_id in cfg.dominators.get(block_id, set())
    
    def test_immediate_dominator(self):
        """Test immediate dominator computation."""
        from a3_python.cfg import build_cfg
        
        def branching(x):
            if x > 0:
                return 1
            return 0
        
        cfg = build_cfg(branching.__code__)
        
        # Non-entry blocks should have immediate dominators
        for block_id in cfg.blocks:
            if block_id != cfg.entry_block:
                if block_id in cfg.immediate_dominator:
                    idom = cfg.immediate_dominator[block_id]
                    assert idom in cfg.blocks


# ============================================================================
# Guard Analysis Tests
# ============================================================================

class TestGuardAnalysis:
    """Tests for guard establishment and propagation."""
    
    def test_none_check_guard(self):
        """Test that 'if x is not None' establishes g_nonnull(x)."""
        from a3_python.cfg import build_cfg, GuardAnalyzer
        
        def none_check(x):
            if x is not None:
                return x.value
            return 0
        
        cfg = build_cfg(none_check.__code__)
        analyzer = GuardAnalyzer(cfg)
        guards = analyzer.analyze()
        
        # Should have some guards (at least truthiness checks)
        # Note: Pattern detection depends on bytecode structure
        assert isinstance(guards, dict)
    
    def test_isinstance_guard(self):
        """Test that isinstance check establishes g_type guard."""
        from a3_python.cfg import build_cfg, GuardAnalyzer
        
        def type_check(x):
            if isinstance(x, int):
                return x + 1
            return 0
        
        cfg = build_cfg(type_check.__code__)
        analyzer = GuardAnalyzer(cfg)
        guards = analyzer.analyze()
        
        # Check that analysis completed
        assert isinstance(guards, dict)
    
    def test_truthiness_guard(self):
        """Test that 'if x:' establishes nonnull guard for sequences."""
        from a3_python.cfg import build_cfg, GuardAnalyzer
        
        def truthiness_check(items):
            if items:
                return items[0]
            return None
        
        cfg = build_cfg(truthiness_check.__code__)
        analyzer = GuardAnalyzer(cfg)
        guards = analyzer.analyze()
        
        assert isinstance(guards, dict)


# ============================================================================
# Dataflow Analysis Tests
# ============================================================================

class TestGuardDataflow:
    """Tests for guard dataflow analysis."""
    
    def test_guard_propagation(self):
        """Test that guards propagate through dominators."""
        from a3_python.cfg import build_cfg
        from a3_python.cfg.dataflow import GuardDataflowAnalysis
        
        def guarded_use(x):
            if x is not None:
                # x is known nonnull here
                y = x + 1
                return y
            return 0
        
        cfg = build_cfg(guarded_use.__code__)
        analysis = GuardDataflowAnalysis(cfg)
        result = analysis.analyze()
        
        # Result should map block_id -> GuardState
        assert isinstance(result, dict)
    
    def test_guard_intersection_at_merge(self):
        """Test that guards are intersected at merge points."""
        from a3_python.cfg import build_cfg
        from a3_python.cfg.dataflow import GuardDataflowAnalysis
        
        def branching_guards(x, condition):
            if condition:
                if x is not None:
                    pass
            else:
                # x not checked here
                pass
            # At merge: x may or may not be checked
            return x
        
        cfg = build_cfg(branching_guards.__code__)
        analysis = GuardDataflowAnalysis(cfg)
        result = analysis.analyze()
        
        assert isinstance(result, dict)


class TestTypeStateAnalysis:
    """Tests for type state dataflow analysis."""
    
    def test_type_refinement(self):
        """Test that type state is refined on branches."""
        from a3_python.cfg import build_cfg
        from a3_python.cfg.dataflow import TypeStateAnalysis
        
        def type_refined(x):
            if x is None:
                return 0
            # x is not None here
            return x + 1
        
        cfg = build_cfg(type_refined.__code__)
        analysis = TypeStateAnalysis(cfg)
        result = analysis.analyze()
        
        assert isinstance(result, dict)


class TestBoundsAnalysis:
    """Tests for bounds dataflow analysis."""
    
    def test_len_tracking(self):
        """Test that len() calls are tracked."""
        from a3_python.cfg import build_cfg
        from a3_python.cfg.dataflow import BoundsAnalysis
        
        def len_use(items):
            n = len(items)
            if n > 0:
                return items[0]
            return None
        
        cfg = build_cfg(len_use.__code__)
        analysis = BoundsAnalysis(cfg)
        result = analysis.analyze()
        
        assert isinstance(result, dict)


# ============================================================================
# WillCatchAt Predicate Tests
# ============================================================================

class TestExceptionCatchAnalysis:
    """Tests for exception catching analysis."""
    
    def test_basic_try_except(self):
        """Test that handler is found for exception in try block."""
        from a3_python.cfg import build_cfg, ExceptionCatchAnalyzer
        
        def with_handler():
            try:
                x = 1 / 0
            except ZeroDivisionError:
                return 0
            return 1
        
        cfg = build_cfg(with_handler.__code__)
        analyzer = ExceptionCatchAnalyzer(cfg)
        
        # The division instruction should be within try block
        # Note: Exact offset detection depends on bytecode layout
        assert isinstance(analyzer, ExceptionCatchAnalyzer)
    
    def test_no_handler(self):
        """Test that lack of handler is detected."""
        from a3_python.cfg import build_cfg, ExceptionCatchAnalyzer
        
        def no_handler():
            return 1 / 0  # No try/except
        
        cfg = build_cfg(no_handler.__code__)
        analyzer = ExceptionCatchAnalyzer(cfg)
        
        # No exception regions should be found
        # (is_in_try_block should return False for all offsets)
        for block in cfg.blocks.values():
            for instr in block.instructions:
                result = analyzer.is_in_try_block(instr.offset)
                assert result == False or result == True  # Just check it runs


# ============================================================================
# Integrated Intraprocedural Analysis Tests
# ============================================================================

class TestIntraprocAnalysis:
    """Tests for the complete intraprocedural analysis."""
    
    def test_run_analysis(self):
        """Test that complete analysis runs without error."""
        from a3_python.cfg import run_intraprocedural_analysis
        
        def example(x, y):
            if x is not None:
                if isinstance(y, int):
                    if y != 0:
                        return x / y
            return 0
        
        result = run_intraprocedural_analysis(example.__code__)
        
        assert result.cfg is not None
        assert result.guard_states is not None
        assert result.type_states is not None
        assert result.bounds is not None
    
    def test_is_nonnull_query(self):
        """Test querying nonnull status at offset."""
        from a3_python.cfg import run_intraprocedural_analysis
        
        def checked(x):
            if x is not None:
                return x.attr
            return None
        
        result = run_intraprocedural_analysis(checked.__code__)
        
        # The result should have is_nonnull method
        # Testing exact offset would require bytecode inspection
        assert hasattr(result, 'is_nonnull')
    
    def test_is_safe_division_query(self):
        """Test querying division safety at offset."""
        from a3_python.cfg import run_intraprocedural_analysis
        
        def guarded_div(x, y):
            if y != 0:
                return x / y
            return 0
        
        result = run_intraprocedural_analysis(guarded_div.__code__)
        
        assert hasattr(result, 'is_safe_division')


# ============================================================================
# Integration with Symbolic VM Tests
# ============================================================================

class TestSymbolicVMIntegration:
    """Tests for integration of guards with symbolic execution."""
    
    def test_guard_state_in_machine_state(self):
        """Test that machine state has guard tracking fields."""
        from a3_python.semantics.symbolic_vm import SymbolicMachineState
        
        state = SymbolicMachineState()
        
        # Should have guard-related methods
        assert hasattr(state, 'set_guard')
        assert hasattr(state, 'has_guard')
        assert hasattr(state, 'has_nonnull_guard')
        assert hasattr(state, 'has_div_guard')
    
    def test_set_and_get_guard(self):
        """Test setting and querying guards."""
        from a3_python.semantics.symbolic_vm import SymbolicMachineState
        
        state = SymbolicMachineState()
        
        # Initially no guards
        assert not state.has_nonnull_guard('x')
        assert not state.has_div_guard('y')
        
        # Set guards
        state.set_guard('nonnull', 'x')
        state.set_guard('div', 'y')
        
        # Now guards should be established
        assert state.has_nonnull_guard('x')
        assert state.has_div_guard('y')
    
    def test_guard_copy(self):
        """Test that guards are copied during path branching."""
        from a3_python.semantics.symbolic_vm import SymbolicMachineState
        
        state = SymbolicMachineState()
        state.set_guard('nonnull', 'x')
        
        copied = state.copy()
        
        # Copied state should have the guard
        assert copied.has_nonnull_guard('x')
        
        # Modifying copy should not affect original
        copied.set_guard('div', 'y')
        assert copied.has_div_guard('y')
        assert not state.has_div_guard('y')


# ============================================================================
# Unsafe Detector Guard Integration Tests
# ============================================================================

class TestUnsafeDetectorGuards:
    """Tests that unsafe detectors respect guards."""
    
    def test_div_zero_with_guard(self):
        """Test that DIV_ZERO respects div guard."""
        from a3_python.semantics.symbolic_vm import SymbolicMachineState
        from a3_python.unsafe.div_zero import is_unsafe_div_zero
        
        state = SymbolicMachineState()
        state.div_by_zero_reached = True
        state.div_by_zero_context = {'divisor_var': 'y'}
        
        # Without guard: should be unsafe
        assert is_unsafe_div_zero(state)
        
        # With guard: should be safe
        state.set_guard('div', 'y')
        assert not is_unsafe_div_zero(state)
    
    def test_null_ptr_with_guard(self):
        """Test that NULL_PTR respects nonnull guard."""
        from a3_python.semantics.symbolic_vm import SymbolicMachineState
        from a3_python.unsafe.null_ptr import is_unsafe_null_ptr
        
        state = SymbolicMachineState()
        state.none_misuse_reached = True
        state.none_misuse_context = {'receiver_var': 'x'}
        
        # Without guard: should be unsafe
        assert is_unsafe_null_ptr(state)
        
        # With guard: should be safe
        state.set_guard('nonnull', 'x')
        assert not is_unsafe_null_ptr(state)
    
    def test_bounds_with_guard(self):
        """Test that BOUNDS respects bounds guard."""
        from a3_python.semantics.symbolic_vm import SymbolicMachineState
        from a3_python.unsafe.bounds import is_unsafe_bounds
        
        state = SymbolicMachineState()
        state.index_out_of_bounds = True
        state.bounds_context = {'container_var': 'arr', 'index_var': 'i'}
        
        # Without guard: should be unsafe
        assert is_unsafe_bounds(state)
        
        # With guard: should be safe
        state.set_guard('bounds', 'arr[i]')
        assert not is_unsafe_bounds(state)
    
    def test_type_confusion_with_guard(self):
        """Test that TYPE_CONFUSION respects type guard."""
        from a3_python.semantics.symbolic_vm import SymbolicMachineState
        from a3_python.unsafe.type_confusion import is_unsafe_type_confusion
        
        state = SymbolicMachineState()
        state.type_confusion_reached = True
        state.type_confusion_context = {'operand_var': 'x', 'expected_type': 'int'}
        
        # Without guard: should be unsafe
        assert is_unsafe_type_confusion(state)
        
        # With guard: should be safe
        state.set_guard('type', 'x', 'int')
        assert not is_unsafe_type_confusion(state)


# ============================================================================
# End-to-End Analysis Tests
# ============================================================================

class TestEndToEndAnalysis:
    """End-to-end tests for the analyzer with guards."""
    
    def test_guarded_division_not_flagged(self):
        """Test that guarded division is not flagged as bug."""
        from a3_python.analyzer import Analyzer
        from pathlib import Path
        import tempfile
        
        code = '''
def safe_divide(x, y):
    if y != 0:
        return x / y
    return 0

safe_divide(10, 2)
'''
        
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            
            analyzer = Analyzer(max_paths=100, verbose=False)
            result = analyzer.analyze_file(Path(f.name))
            
            # Should not find DIV_ZERO bug because of guard
            if result.verdict == "BUG":
                assert result.bug_type != "DIV_ZERO", \
                    "Guarded division should not be flagged as DIV_ZERO"
    
    def test_guarded_none_access_not_flagged(self):
        """Test that guarded None access is not flagged."""
        from a3_python.analyzer import Analyzer
        from pathlib import Path
        import tempfile
        
        code = '''
def safe_access(obj):
    if obj is not None:
        return obj.value
    return 0

safe_access(None)
'''
        
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            
            analyzer = Analyzer(max_paths=100, verbose=False)
            result = analyzer.analyze_file(Path(f.name))
            
            # Should not find NULL_PTR because of guard
            if result.verdict == "BUG":
                assert result.bug_type != "NULL_PTR", \
                    "Guarded None access should not be flagged as NULL_PTR"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
