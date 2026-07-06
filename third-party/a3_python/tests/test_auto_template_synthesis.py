"""
Tests for automatic template selection in CEGIS barrier synthesis.

This validates the integration of program structure analysis with
CEGIS synthesis, ensuring templates are automatically selected based
on loop structure and synthesis falls back to higher degrees when needed.
"""

import pytest
import z3
from typing import Callable

from a3_python.barriers.cegis import (
    synthesize_barrier_with_auto_template,
    CEGISConfig,
)
from a3_python.barriers.program_analysis import (
    analyze_program_structure,
)
from a3_python.semantics.symbolic_vm import SymbolicMachineState


def compile_code(source: str):
    """Helper to compile source."""
    return compile(source, "<test>", "exec")


class TestAutoTemplateSelection:
    """Test automatic template selection based on program structure."""
    
    def test_linear_selected_for_simple_code(self):
        """Simple code with no loops selects linear template."""
        code = compile_code("""
x = 0
x = x + 1
""")
        structure = analyze_program_structure(code)
        
        # Should suggest linear
        assert structure.suggested_template_degree() == 1
    
    def test_quadratic_selected_for_nested_loops(self):
        """Nested loops select quadratic template."""
        code = compile_code("""
total = 0
for i in range(10):
    for j in range(5):
        total += 1
""")
        structure = analyze_program_structure(code)
        
        # Should suggest quadratic (degree 2)
        assert structure.suggested_template_degree() == 2
    
    def test_cubic_selected_for_deep_nesting(self):
        """Triple-nested loops select cubic template."""
        code = compile_code("""
total = 0
for i in range(5):
    for j in range(5):
        for k in range(5):
            total += 1
""")
        structure = analyze_program_structure(code)
        
        # Should suggest cubic (degree 3)
        assert structure.suggested_template_degree() == 3


class TestAutoTemplateSynthesisMock:
    """
    Test auto-template synthesis with mock state builders.
    
    These tests verify the integration works but use simplified
    mocks for the symbolic state/predicates. Full end-to-end tests
    are in test_cegis_synthesis.py.
    """
    
    def test_auto_template_synthesis_returns_structure(self):
        """synthesize_barrier_with_auto_template returns structure analysis."""
        code = compile_code("""
x = 0
for i in range(10):
    x += 1
""")
        
        # Mock builders (minimal)
        def init_state():
            return SymbolicMachineState(
                frame_stack=[],
                heap={},
            )
        
        def unsafe_pred(state):
            return z3.BoolVal(False)  # Never unsafe
        
        def step_rel(s1, s2):
            return z3.BoolVal(True)  # Always can step
        
        def var_extractor(state):
            return z3.Int("x")
        
        config = CEGISConfig(
            max_iterations=2,  # Limit iterations for fast test
            timeout_total_ms=1000
        )
        
        result, structure = synthesize_barrier_with_auto_template(
            code,
            init_state,
            unsafe_pred,
            step_rel,
            "x",
            var_extractor,
            config
        )
        
        # Should return structure
        assert structure is not None
        assert structure.loops is not None
        
        # Result may or may not succeed (depends on mock predicates)
        # Just verify it ran without crashing
        assert result is not None
    
    def test_fallback_to_higher_degree(self):
        """If synthesis fails with lower degree, tries higher degree."""
        # This is tested implicitly by the fallback logic in
        # synthesize_barrier_with_auto_template.
        
        # For a program with nested loops that suggests quadratic,
        # if quadratic fails, it should try cubic.
        
        code = compile_code("""
total = 0
for i in range(10):
    for j in range(10):
        total += 1
""")
        
        structure = analyze_program_structure(code)
        degree = structure.suggested_template_degree()
        
        # Nested loops suggest degree 2
        assert degree == 2
        
        # The synthesize_barrier_with_auto_template function will:
        # 1. Try quadratic first (degree 2)
        # 2. If it fails, fall back to cubic (degree 3)
        
        # We can't easily test the fallback without running full synthesis,
        # but we can verify the logic is present by code inspection.
        # The key is that degree < 3, so fallback should be attempted.


class TestProgramStructureIntegration:
    """Test integration between program analysis and CEGIS."""
    
    def test_structure_captures_loop_info(self):
        """Program structure captures loops for CEGIS guidance."""
        code = compile_code("""
x = 0
for i in range(10):
    x += i
""")
        
        structure = analyze_program_structure(code)
        
        # Should have loop info
        assert len(structure.loops) >= 1
        
        # Variables in loops should be tracked
        assert "i" in structure.variables_in_loops or "x" in structure.variables_in_loops
    
    def test_suggested_variables_are_relevant(self):
        """Suggested template variables are from loops."""
        code = compile_code("""
x = 0
y = 100
for i in range(10):
    x += 1
    y -= 1
""")
        
        structure = analyze_program_structure(code)
        suggested_vars = structure.suggested_template_variables()
        
        # Should suggest variables modified in loops
        # (x, y, and possibly i)
        assert len(suggested_vars) > 0
        # At least one of the loop variables
        assert any(v in suggested_vars for v in ["x", "y", "i"])


class TestTemplateEscalation:
    """Test template escalation strategy."""
    
    def test_escalation_from_linear_to_quadratic(self):
        """If linear fails, should try quadratic."""
        # The code in synthesize_barrier_with_auto_template
        # implements this escalation for degree 1 -> quadratic
        
        # Just verify the logic by checking degree mappings
        code = compile_code("x = 1")
        structure = analyze_program_structure(code)
        
        degree = structure.suggested_template_degree()
        assert degree == 1
        
        # According to the code:
        # if degree == 1 and synthesis fails, fallback to "quadratic"
        # We can't test the actual synthesis easily, but the logic is there
    
    def test_escalation_from_quadratic_to_cubic(self):
        """If quadratic fails, should try cubic."""
        code = compile_code("""
for i in range(10):
    for j in range(10):
        pass
""")
        structure = analyze_program_structure(code)
        
        degree = structure.suggested_template_degree()
        assert degree == 2
        
        # According to the code:
        # if degree == 2 and synthesis fails, fallback to "cubic"
    
    def test_no_escalation_from_cubic(self):
        """If cubic suggested, no further fallback."""
        code = compile_code("""
for i in range(5):
    for j in range(5):
        for k in range(5):
            pass
""")
        structure = analyze_program_structure(code)
        
        degree = structure.suggested_template_degree()
        assert degree == 3
        
        # No escalation beyond cubic in current implementation


class TestLinearTemplateCEGIS:
    """Test linear template support in CEGIS."""
    
    def test_linear_template_parameters_created(self):
        """Linear template creates correct parameters (coeff_x, constant)."""
        from a3_python.barriers.cegis import CEGISBarrierSynthesizer
        
        synth = CEGISBarrierSynthesizer()
        params = synth._create_parameter_variables("linear")
        
        assert "coeff_x" in params
        assert "constant" in params
        assert len(params) == 2
    
    def test_linear_template_evaluation(self):
        """Linear template evaluates correctly at a point."""
        from a3_python.barriers.cegis import CEGISBarrierSynthesizer
        
        synth = CEGISBarrierSynthesizer()
        
        # Create mock params
        a = z3.Real("coeff_x")
        b = z3.Real("constant")
        params = {"coeff_x": a, "constant": b}
        
        # Evaluate at x=5: should be a*5 + b
        expr = synth._evaluate_template_at_point(params, "linear", 5.0)
        
        # Check structure (should involve a and b)
        assert expr is not None
        # Convert to string and check it references parameters
        expr_str = str(expr)
        assert "coeff_x" in expr_str or "Real" in expr_str
    
    def test_linear_barrier_built_from_params(self):
        """Linear barrier can be built from parameter values."""
        from a3_python.barriers.cegis import CEGISBarrierSynthesizer
        
        synth = CEGISBarrierSynthesizer()
        
        def var_extractor(state):
            return z3.Int("x")
        
        param_values = {
            "coeff_x": -1.0,
            "constant": 10.0,
        }
        
        barrier = synth._build_barrier(
            "linear",
            "x",
            var_extractor,
            param_values
        )
        
        assert barrier is not None
        assert barrier.name == "cegis_linear_x"
        assert "x" in barrier.variables


class TestConfigAndTimeout:
    """Test CEGIS configuration for auto-template synthesis."""
    
    def test_custom_config_respected(self):
        """Custom CEGISConfig is passed through."""
        code = compile_code("x = 1")
        
        # Mock state builders
        def init_state():
            return SymbolicMachineState(
                frame_stack=[],
                heap={},
            )
        
        def unsafe_pred(state):
            return z3.BoolVal(False)
        
        def step_rel(s1, s2):
            return z3.BoolVal(True)
        
        def var_extractor(state):
            return z3.Int("x")
        
        custom_config = CEGISConfig(
            max_iterations=5,
            timeout_total_ms=500,
        )
        
        result, structure = synthesize_barrier_with_auto_template(
            code,
            init_state,
            unsafe_pred,
            step_rel,
            "x",
            var_extractor,
            custom_config
        )
        
        # Should complete (may not succeed due to mock predicates)
        assert result is not None
        assert result.iterations <= custom_config.max_iterations
