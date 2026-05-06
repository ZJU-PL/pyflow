"""
Loop analysis for termination checking.

Extracts loop structure information including:
- Loop headers and back-edges (from CFG)
- Loop variables (modified within loop body)
- Loop bounds (if identifiable)

This information feeds into ranking function synthesis for automatic
termination checking (barrier-certificate-theory.tex §8).
"""

import dis
from dataclasses import dataclass
from typing import Set, List, Optional, Tuple
from .control_flow import ControlFlowGraph, build_cfg


@dataclass
class LoopInfo:
    """
    Information about a loop in the bytecode.
    
    Attributes:
        header_offset: Bytecode offset of loop header (target of back-edge)
        back_edge_offsets: List of offsets that jump back to header
        body_offsets: Set of bytecode offsets in loop body
        modified_variables: Variables that are modified in the loop
        compared_variables: Variables used in loop condition
    """
    header_offset: int
    back_edge_offsets: List[int]
    body_offsets: Set[int]
    modified_variables: Set[str]
    compared_variables: Set[str]
    
    @property
    def loop_variables(self) -> Set[str]:
        """
        Combined set of loop-relevant variables.
        
        For ranking function synthesis, we prioritize:
        1. Variables modified in loop (loop counters)
        2. Variables in loop condition (bounds)
        """
        return self.modified_variables | self.compared_variables


def extract_loops(code_obj, *, cfg: Optional[ControlFlowGraph] = None) -> List[LoopInfo]:
    """
    Extract loop information from bytecode.
    
    Args:
        code_obj: Python code object
    
    Returns:
        List of LoopInfo for each loop in the code
    """
    if cfg is None:
        cfg = build_cfg(code_obj)
    
    loops = []
    
    # For each loop header (detected via back-edges)
    for header_block_id in cfg.loop_headers:
        # Find all back-edges to this header
        back_edges = [(src, tgt) for src, tgt in cfg.back_edges if tgt == header_block_id]
        
        if not back_edges:
            continue
        
        # Get the header block
        header_block = cfg.blocks.get(header_block_id)
        if not header_block:
            continue
        
        # Extract header offset (first instruction in block)
        header_offset = header_block.instructions[0].offset if header_block.instructions else 0
        
        # Extract back-edge source offsets
        back_edge_offsets = []
        for src_id, _ in back_edges:
            src_block = cfg.blocks.get(src_id)
            if src_block and src_block.instructions:
                # Last instruction in source block is the jump back
                back_edge_offsets.append(src_block.instructions[-1].offset)
        
        # Extract loop body offsets (all blocks dominated by header that can reach back-edge)
        body_offsets = _extract_loop_body_offsets(cfg, header_block_id, back_edges)

        # Heuristic variable extraction for termination:
        # - Compare variables: prefer the loop header block (condition)
        # - Modified variables: prefer back-edge source block(s) (counter updates)
        header_offsets = {instr.offset for instr in header_block.instructions}
        back_edge_body_offsets: Set[int] = set()
        for src_id, _ in back_edges:
            src_block = cfg.blocks.get(src_id)
            if not src_block:
                continue
            for instr in src_block.instructions:
                back_edge_body_offsets.add(instr.offset)
        if not back_edge_body_offsets:
            back_edge_body_offsets = body_offsets
        
        # Extract modified and compared variables.
        # First try narrow scan (back-edge source blocks) for counter detection;
        # if nothing is found, widen to the full loop body.
        modified_vars, compared_vars = _extract_loop_variables(
            code_obj,
            modified_offsets=back_edge_body_offsets,
            compared_offsets=header_offsets
        )
        if not modified_vars and body_offsets != back_edge_body_offsets:
            modified_vars, compared_vars2 = _extract_loop_variables(
                code_obj,
                modified_offsets=body_offsets,
                compared_offsets=header_offsets
            )
            compared_vars |= compared_vars2
        
        loops.append(LoopInfo(
            header_offset=header_offset,
            back_edge_offsets=back_edge_offsets,
            body_offsets=body_offsets,
            modified_variables=modified_vars,
            compared_variables=compared_vars
        ))
    
    return loops


def _extract_loop_body_offsets(
    cfg: ControlFlowGraph,
    header_id: int,
    back_edges: List[Tuple[int, int]]
) -> Set[int]:
    """
    Extract bytecode offsets in the loop body.
    
    Loop body consists of blocks that:
    1. Are dominated by the header, AND
    2. Can reach a back-edge source
    """
    body_offsets = set()
    back_edge_sources = {src for src, _ in back_edges}
    
    # Find all blocks that can reach a back-edge source
    reachable_to_back_edge = set()
    
    def find_reachable(block_id: int, visited: Set[int]):
        """DFS to find blocks that reach back-edge sources."""
        if block_id in visited:
            return
        visited.add(block_id)
        
        if block_id in back_edge_sources:
            reachable_to_back_edge.add(block_id)
            return
        
        block = cfg.blocks.get(block_id)
        if not block:
            return
        
        for succ_id, _, _ in block.successors:
            find_reachable(succ_id, visited)
            if succ_id in reachable_to_back_edge:
                reachable_to_back_edge.add(block_id)
    
    # Start from header
    find_reachable(header_id, set())
    
    # Collect offsets from blocks in loop body
    for block_id in reachable_to_back_edge:
        if cfg.is_dominated_by(block_id, header_id):
            block = cfg.blocks.get(block_id)
            if block:
                for instr in block.instructions:
                    body_offsets.add(instr.offset)
    
    return body_offsets


def _extract_loop_variables(
    code_obj,
    *,
    modified_offsets: Set[int],
    compared_offsets: Set[int],
) -> Tuple[Set[str], Set[str]]:
    """
    Extract loop variables from bytecode.
    
    Returns:
        (modified_variables, compared_variables)
    """
    modified_vars = set()
    compared_vars = set()
    
    instructions = list(dis.get_instructions(code_obj))

    # Modified variables: prefer STORE_* in/near the back-edge source block(s).
    for instr in instructions:
        if instr.offset not in modified_offsets:
            continue
        if instr.opname in ('STORE_FAST', 'STORE_NAME', 'STORE_GLOBAL'):
            if instr.argval:
                modified_vars.add(str(instr.argval))

    # Compared variables: prefer LOAD_* in the loop header that feed a COMPARE_OP.
    load_opnames = (
        'LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME', 'LOAD_GLOBAL',
        'LOAD_DEREF', 'LOAD_CLOSURE',
        # CPython superinstructions (3.13+): load 2 locals at once
        'LOAD_FAST_LOAD_FAST',
        'LOAD_FAST_BORROW_LOAD_FAST_BORROW',
        'LOAD_FAST_BORROW_LOAD_FAST',
        'LOAD_FAST_LOAD_FAST_BORROW',
    )
    for i, instr in enumerate(instructions):
        if instr.offset not in compared_offsets:
            continue
        if instr.opname not in load_opnames:
            continue
        if not instr.argval:
            continue

        # Look ahead a few instructions for a COMPARE_OP (e.g., i < n).
        # This avoids treating every LOAD_FAST in the loop body as a bound variable.
        for j in range(i + 1, min(i + 5, len(instructions))):
            if instructions[j].opname == 'COMPARE_OP':
                # Superinstructions may carry multiple names in a tuple.
                if isinstance(instr.argval, tuple):
                    for name in instr.argval:
                        if name:
                            compared_vars.add(str(name))
                else:
                    compared_vars.add(str(instr.argval))
                break
    
    return modified_vars, compared_vars


def identify_loop_pattern(loop: LoopInfo) -> str:
    """
    Identify common loop patterns for ranking synthesis hints.
    
    Returns:
        Pattern hint: "simple_counter", "bounded_counter", "nested", "complex"
    """
    num_modified = len(loop.modified_variables)
    num_compared = len(loop.compared_variables)
    
    if num_modified == 1 and num_compared <= 2:
        # Simple counter: one variable modified, checked against bound
        # while i > 0: i -= 1
        # while i < n: i += 1
        return "simple_counter"
    
    if num_modified == 1 and num_compared > 2:
        # Bounded counter with complex condition
        return "bounded_counter"
    
    if num_modified >= 2:
        # Nested loops or multi-variable iteration
        return "nested"
    
    return "complex"
