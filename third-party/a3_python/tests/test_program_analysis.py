"""
Tests for program structure analysis and automatic template selection.

This validates that loop detection, nesting analysis, and template
inference work correctly for various program structures.
"""

import pytest
import dis
import types

from a3_python.barriers.program_analysis import (
    analyze_program_structure,
    suggest_template_for_program,
    print_program_analysis,
    LoopInfo,
    ProgramStructure,
)


def compile_code(source: str) -> types.CodeType:
    """Helper to compile source code."""
    return compile(source, "<test>", "exec")


class TestLoopDetection:
    """Test loop detection in bytecode."""
    
    def test_no_loops(self):
        """Simple linear code has no loops."""
        code = compile_code("""
x = 1
y = 2
z = x + y
""")
        structure = analyze_program_structure(code)
        
        assert len(structure.loops) == 0
        assert structure.max_nesting_depth == 0
        assert structure.suggested_template_degree() == 1
    
    def test_simple_for_loop(self):
        """Single for loop detected."""
        code = compile_code("""
x = 0
for i in range(10):
    x += 1
""")
        structure = analyze_program_structure(code)
        
        assert len(structure.loops) >= 1
        assert structure.max_nesting_depth >= 1
        # Simple single loop -> linear or quadratic
        assert structure.suggested_template_degree() in [1, 2]
    
    def test_nested_for_loops(self):
        """Nested loops detected with correct nesting level."""
        code = compile_code("""
total = 0
for i in range(10):
    for j in range(5):
        total += i * j
""")
        structure = analyze_program_structure(code)
        
        # Should detect nested loops
        assert len(structure.loops) >= 2
        assert structure.max_nesting_depth >= 2
        # Nested loops -> quadratic
        assert structure.suggested_template_degree() == 2
    
    def test_triple_nested_loops(self):
        """Deeply nested loops (3 levels) detected."""
        code = compile_code("""
total = 0
for i in range(5):
    for j in range(5):
        for k in range(5):
            total += i * j * k
""")
        structure = analyze_program_structure(code)
        
        # Should detect deep nesting
        assert structure.max_nesting_depth >= 3
        # Deep nesting -> cubic
        assert structure.suggested_template_degree() == 3
    
    def test_sequential_loops(self):
        """Multiple sequential loops (not nested)."""
        code = compile_code("""
x = 0
for i in range(10):
    x += 1

y = 0
for j in range(5):
    y += 2
""")
        structure = analyze_program_structure(code)
        
        # Should detect multiple loops
        assert len(structure.loops) >= 2
        # But nesting is still 1 (sequential, not nested)
        assert structure.max_nesting_depth == 1
        # Multiple sequential -> quadratic
        assert structure.suggested_template_degree() == 2
    
    def test_while_loop(self):
        """While loops also use JUMP_BACKWARD."""
        code = compile_code("""
x = 0
while x < 10:
    x += 1
""")
        structure = analyze_program_structure(code)
        
        # Should detect the loop
        assert len(structure.loops) >= 1
        assert structure.max_nesting_depth >= 1


class TestVariableAnalysis:
    """Test variable tracking in loops."""
    
    def test_variables_in_loop(self):
        """Variables modified in loop are tracked."""
        code = compile_code("""
x = 0
y = 100
for i in range(10):
    x += 1
    y -= 1
""")
        structure = analyze_program_structure(code)
        
        # x and y are modified in loop
        assert "x" in structure.variables_in_loops or "i" in structure.variables_in_loops
        # Total variables includes all varnames
        assert len(structure.total_variables) >= 3  # x, y, i
    
    def test_loop_counter_identified(self):
        """Loop counter variable is in total variables."""
        code = compile_code("""
for i in range(5):
    pass
""")
        structure = analyze_program_structure(code)
        
        # 'i' should be in varnames
        assert "i" in structure.total_variables


class TestConditionals:
    """Test conditional detection."""
    
    def test_simple_if(self):
        """Simple if statement detected."""
        code = compile_code("""
x = 5
if x > 3:
    y = 10
""")
        structure = analyze_program_structure(code)
        
        assert structure.has_conditionals
    
    def test_if_in_loop(self):
        """Conditionals in loops may need disjunctive templates."""
        code = compile_code("""
x = 0
for i in range(10):
    if i % 2 == 0:
        x += 1
    else:
        x += 2
""")
        structure = analyze_program_structure(code)
        
        assert structure.has_conditionals
        # May suggest disjunctive templates
        # (depends on implementation heuristics)


class TestTemplateSelection:
    """Test automatic template selection."""
    
    def test_linear_for_no_loops(self):
        """No loops → linear template."""
        code = compile_code("""
x = 1
y = x + 2
""")
        
        # Mock variable extractor
        def var_extractor(state):
            return state
        
        template = suggest_template_for_program(code, "x", var_extractor)
        assert template == "linear"
    
    def test_quadratic_for_nested_loops(self):
        """Nested loops → quadratic template."""
        code = compile_code("""
total = 0
for i in range(10):
    for j in range(10):
        total += 1
""")
        
        def var_extractor(state):
            return state
        
        template = suggest_template_for_program(code, "total", var_extractor)
        assert template in ["quadratic", "polynomial_2"]
    
    def test_cubic_for_deep_nesting(self):
        """Triple nesting → cubic template."""
        code = compile_code("""
total = 0
for i in range(5):
    for j in range(5):
        for k in range(5):
            total += 1
""")
        
        def var_extractor(state):
            return state
        
        template = suggest_template_for_program(code, "total", var_extractor)
        assert template in ["polynomial_3", "cubic"]


class TestProgramComplexity:
    """Test complexity scoring."""
    
    def test_complexity_increases_with_loops(self):
        """More loops → higher complexity."""
        simple_code = compile_code("x = 1")
        loop_code = compile_code("for i in range(10): pass")
        
        simple_struct = analyze_program_structure(simple_code)
        loop_struct = analyze_program_structure(loop_code)
        
        assert loop_struct.complexity_score > simple_struct.complexity_score
    
    def test_complexity_increases_with_nesting(self):
        """Deeper nesting → higher complexity."""
        single_loop = compile_code("""
for i in range(10):
    pass
""")
        nested_loop = compile_code("""
for i in range(10):
    for j in range(10):
        pass
""")
        
        single_struct = analyze_program_structure(single_loop)
        nested_struct = analyze_program_structure(nested_loop)
        
        assert nested_struct.complexity_score > single_struct.complexity_score


class TestDisjunctiveTemplates:
    """Test disjunctive template suggestions."""
    
    def test_no_disjunction_for_simple_code(self):
        """Simple code doesn't need disjunctions."""
        code = compile_code("x = 1")
        structure = analyze_program_structure(code)
        
        assert not structure.needs_disjunctive_template()
    
    def test_disjunction_for_branching_loops(self):
        """Loops with conditionals may need disjunctions."""
        code = compile_code("""
x = 0
for i in range(10):
    if i % 2 == 0:
        x += 1
    else:
        x -= 1
""")
        structure = analyze_program_structure(code)
        
        # Should suggest disjunctions due to conditionals in loops
        # (May depend on heuristics)
        if structure.has_conditionals and structure.max_nesting_depth > 0:
            assert structure.needs_disjunctive_template()


class TestSummaryAndPrinting:
    """Test human-readable output."""
    
    def test_summary_generation(self):
        """Summary is generated without errors."""
        code = compile_code("""
total = 0
for i in range(10):
    for j in range(5):
        total += i + j
""")
        structure = analyze_program_structure(code)
        
        summary = structure.summary()
        assert "Program Structure Analysis" in summary
        assert "Loops:" in summary
        assert "Template Suggestions:" in summary
        assert "Degree:" in summary
    
    def test_print_analysis_no_crash(self):
        """Print analysis runs without errors."""
        code = compile_code("""
for i in range(10):
    pass
""")
        
        # Should not raise
        try:
            print_program_analysis(code)
        except Exception as e:
            pytest.fail(f"print_program_analysis raised: {e}")


class TestEdgeCases:
    """Test edge cases and unusual bytecode patterns."""
    
    def test_empty_function(self):
        """Empty function analyzed without error."""
        code = compile_code("pass")
        structure = analyze_program_structure(code)
        
        assert len(structure.loops) == 0
        assert structure.max_nesting_depth == 0
    
    def test_loop_with_break(self):
        """Loop with break statement."""
        code = compile_code("""
for i in range(100):
    if i > 10:
        break
""")
        structure = analyze_program_structure(code)
        
        # Should detect the loop (break detection is bonus)
        assert len(structure.loops) >= 1
    
    def test_loop_with_continue(self):
        """Loop with continue statement."""
        code = compile_code("""
for i in range(10):
    if i % 2 == 0:
        continue
    x = i
""")
        structure = analyze_program_structure(code)
        
        # Should detect the loop
        assert len(structure.loops) >= 1
    
    def test_comprehension(self):
        """List comprehension (internal loop)."""
        code = compile_code("""
squares = [x**2 for x in range(10)]
""")
        structure = analyze_program_structure(code)
        
        # Comprehensions may or may not appear as loops in main code object
        # (they're often compiled to separate code objects)
        # Just ensure no crash
        assert structure is not None
