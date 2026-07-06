"""
Program structure analysis for barrier template selection.

Analyzes Python bytecode to infer appropriate barrier template complexity:
- Loop nesting depth → polynomial degree
- Number of variables → template dimensionality
- Control flow complexity → disjunctive templates

This is used to guide CEGIS by selecting starting templates that match
the program's structure, improving synthesis efficiency.
"""

from dataclasses import dataclass
from typing import Set, Dict, List, Optional
import dis
import types


@dataclass
class LoopInfo:
    """
    Information about a loop in the bytecode.
    
    Attributes:
        start_offset: Bytecode offset where loop starts (target of JUMP_BACKWARD)
        end_offset: Bytecode offset of JUMP_BACKWARD instruction
        nesting_level: How deeply nested this loop is (1 = outermost)
        variables_modified: Set of variable names modified in loop body
        has_break: Whether loop contains break statement
        has_continue: Whether loop contains continue statement
    """
    start_offset: int
    end_offset: int
    nesting_level: int
    variables_modified: Set[str]
    has_break: bool = False
    has_continue: bool = False
    
    @property
    def body_size(self) -> int:
        """Size of loop body in bytecode offsets."""
        return self.end_offset - self.start_offset


@dataclass
class ProgramStructure:
    """
    Analysis of program structure for template selection.
    
    Attributes:
        loops: List of detected loops
        max_nesting_depth: Maximum loop nesting depth
        total_variables: Total number of variables in program
        variables_in_loops: Variables used in any loop
        has_recursion: Whether program contains recursive calls
        has_conditionals: Whether program has if/else branches
        complexity_score: Overall complexity (heuristic)
    """
    loops: List[LoopInfo]
    max_nesting_depth: int
    total_variables: Set[str]
    variables_in_loops: Set[str]
    has_recursion: bool
    has_conditionals: bool
    complexity_score: float
    
    def suggested_template_degree(self) -> int:
        """
        Suggest polynomial degree based on loop nesting.
        
        Returns:
            1: Linear (no loops or simple single loop)
            2: Quadratic (nested loops or complex single loop)
            3: Cubic (deeply nested or multiple interacting loops)
        """
        if self.max_nesting_depth == 0:
            return 1  # No loops, linear sufficient
        elif self.max_nesting_depth == 1:
            # Single-level loops
            if len(self.loops) == 1:
                return 1  # Simple single loop
            else:
                return 2  # Multiple sequential loops
        elif self.max_nesting_depth == 2:
            return 2  # Nested loops
        else:
            return 3  # Deeply nested
    
    def suggested_template_variables(self) -> Set[str]:
        """
        Suggest which variables to include in barrier template.
        
        Prioritizes:
        - Variables modified in loops
        - Loop counters
        - Variables involved in conditionals within loops
        
        Returns:
            Set of variable names to track
        """
        # Start with variables in loops
        candidates = self.variables_in_loops.copy()
        
        # If too many, prioritize variables in innermost loops
        if len(candidates) > 5:
            # In a real implementation, would analyze variable usage patterns
            # For now, just return the set
            pass
        
        return candidates
    
    def needs_disjunctive_template(self) -> bool:
        """
        Whether to use disjunctive (OR) barrier templates.
        
        Disjunctive templates help when different execution paths need
        different invariants.
        
        Returns:
            True if program has complex branching requiring disjunctions
        """
        # Use disjunctions if we have conditionals inside loops
        has_loops = self.max_nesting_depth > 0
        has_branches = self.has_conditionals
        
        # Also useful if multiple loops with different variables
        multiple_loops = len(self.loops) > 1
        different_vars = len(self.variables_in_loops) > 2
        
        return has_loops and (has_branches or (multiple_loops and different_vars))
    
    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"Program Structure Analysis:",
            f"  Loops: {len(self.loops)} (max nesting: {self.max_nesting_depth})",
            f"  Variables: {len(self.total_variables)} total, {len(self.variables_in_loops)} in loops",
            f"  Recursion: {self.has_recursion}",
            f"  Conditionals: {self.has_conditionals}",
            f"  Complexity: {self.complexity_score:.2f}",
            f"",
            f"Template Suggestions:",
            f"  Degree: {self.suggested_template_degree()}",
            f"  Variables: {self.suggested_template_variables()}",
            f"  Disjunctive: {self.needs_disjunctive_template()}",
        ]
        return "\n".join(lines)


def analyze_program_structure(code: types.CodeType) -> ProgramStructure:
    """
    Analyze bytecode to extract program structure.
    
    Args:
        code: Python code object to analyze
    
    Returns:
        ProgramStructure with loop info and complexity metrics
    """
    loops = []
    jump_targets: Dict[int, List[int]] = {}  # target -> list of sources
    variables: Set[str] = set()
    variables_in_loops: Set[str] = set()
    has_conditionals = False
    has_recursion = False
    
    # First pass: collect jump targets and identify backward jumps (loops)
    instructions = list(dis.get_instructions(code))
    offset_to_instr = {instr.offset: instr for instr in instructions}
    
    # Collect all variable names from co_varnames and co_names
    # co_varnames: local variables (in functions)
    # co_names: global names referenced (in module-level code)
    variables.update(code.co_varnames)
    variables.update(code.co_names)
    
    # Track which offsets are in loops
    loop_ranges: List[tuple[int, int]] = []
    
    for instr in instructions:
        # Check for backward jumps (loops)
        if instr.opname == 'JUMP_BACKWARD':
            # In Python 3.11+, JUMP_BACKWARD has absolute target
            target = instr.argval
            if target < instr.offset:
                loop_start = target
                loop_end = instr.offset
                loop_ranges.append((loop_start, loop_end))
        
        # Check for conditional jumps
        if instr.opname in ('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
                            'POP_JUMP_FORWARD_IF_FALSE', 'POP_JUMP_FORWARD_IF_TRUE'):
            has_conditionals = True
        
        # Check for recursive calls (CALL with same function)
        if instr.opname in ('CALL', 'CALL_FUNCTION', 'CALL_KW'):
            # Detecting recursion requires runtime info; for now mark uncertain
            # A more sophisticated analysis would track function references
            pass
    
    # Second pass: analyze each loop
    for loop_start, loop_end in sorted(loop_ranges):
        nesting = _compute_nesting_level(loop_start, loop_end, loop_ranges)
        modified_vars = _find_modified_variables(
            instructions, loop_start, loop_end, offset_to_instr
        )
        has_break, has_continue = _check_loop_controls(
            instructions, loop_start, loop_end, offset_to_instr
        )
        
        loop_info = LoopInfo(
            start_offset=loop_start,
            end_offset=loop_end,
            nesting_level=nesting,
            variables_modified=modified_vars,
            has_break=has_break,
            has_continue=has_continue,
        )
        loops.append(loop_info)
        variables_in_loops.update(modified_vars)
    
    # Compute metrics
    max_nesting = max((loop.nesting_level for loop in loops), default=0)
    
    # Complexity score (heuristic)
    complexity = (
        len(loops) * 1.0 +
        max_nesting * 2.0 +
        len(variables_in_loops) * 0.5 +
        (1.0 if has_conditionals else 0.0) +
        (2.0 if has_recursion else 0.0)
    )
    
    return ProgramStructure(
        loops=loops,
        max_nesting_depth=max_nesting,
        total_variables=variables,
        variables_in_loops=variables_in_loops,
        has_recursion=has_recursion,
        has_conditionals=has_conditionals,
        complexity_score=complexity,
    )


def _compute_nesting_level(
    start: int,
    end: int,
    all_loops: List[tuple[int, int]]
) -> int:
    """
    Compute nesting level of a loop.
    
    A loop is nested inside another if its range is strictly contained.
    """
    nesting = 1
    for other_start, other_end in all_loops:
        if other_start < start and other_end > end:
            # This loop is inside another
            nesting += 1
    return nesting


def _find_modified_variables(
    instructions: List[dis.Instruction],
    start: int,
    end: int,
    offset_map: Dict[int, dis.Instruction]
) -> Set[str]:
    """
    Find variables modified within loop body.
    
    Looks for STORE_* instructions in the loop range.
    """
    modified = set()
    
    for instr in instructions:
        if start <= instr.offset < end:
            # Check for store operations
            if instr.opname in ('STORE_FAST', 'STORE_NAME', 'STORE_GLOBAL',
                               'STORE_DEREF', 'STORE_ATTR', 'STORE_SUBSCR'):
                if instr.argval and isinstance(instr.argval, str):
                    modified.add(instr.argval)
    
    return modified


def _check_loop_controls(
    instructions: List[dis.Instruction],
    start: int,
    end: int,
    offset_map: Dict[int, dis.Instruction]
) -> tuple[bool, bool]:
    """
    Check if loop contains break or continue statements.
    
    Break: jump target is beyond loop end
    Continue: jump target is at loop start
    
    Returns:
        (has_break, has_continue)
    """
    has_break = False
    has_continue = False
    
    for instr in instructions:
        if start <= instr.offset < end:
            if instr.opname in ('JUMP_FORWARD', 'POP_JUMP_IF_TRUE', 
                               'POP_JUMP_IF_FALSE', 'JUMP_ABSOLUTE'):
                if instr.argval:
                    target = instr.argval
                    # Break: jumps beyond loop end
                    if target >= end:
                        has_break = True
                    # Continue: jumps to loop start
                    if target == start:
                        has_continue = True
    
    return has_break, has_continue


def suggest_template_for_program(
    code: types.CodeType,
    variable_name: str,
    variable_extractor
) -> str:
    """
    Suggest best barrier template based on program structure.
    
    Args:
        code: Code object to analyze
        variable_name: Name of variable to bound
        variable_extractor: Function to extract variable from state
    
    Returns:
        Template name: 'linear', 'quadratic', 'polynomial_3', etc.
    """
    structure = analyze_program_structure(code)
    degree = structure.suggested_template_degree()
    
    if degree == 1:
        return 'linear'
    elif degree == 2:
        return 'quadratic'
    else:
        return f'polynomial_{degree}'


def print_program_analysis(code: types.CodeType) -> None:
    """
    Print detailed analysis of program structure (for debugging).
    
    Args:
        code: Code object to analyze
    """
    structure = analyze_program_structure(code)
    print(structure.summary())
    
    if structure.loops:
        print("\nDetailed Loop Information:")
        for i, loop in enumerate(structure.loops, 1):
            print(f"\n  Loop {i}:")
            print(f"    Offsets: {loop.start_offset} -> {loop.end_offset}")
            print(f"    Nesting: {loop.nesting_level}")
            print(f"    Body size: {loop.body_size}")
            print(f"    Modified vars: {loop.variables_modified}")
            print(f"    Break: {loop.has_break}, Continue: {loop.has_continue}")
