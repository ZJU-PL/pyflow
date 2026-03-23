"""
Shared CFG/SSA traversal helpers for query modules.
"""

from collections import deque
from typing import Any, Iterable, List


def iter_cfg_blocks(cfg_or_ssa) -> List[Any]:
    """Return CFG blocks in breadth-first order from the entry terminal."""
    entry = getattr(cfg_or_ssa, "entryTerminal", None)
    if entry is None:
        return []

    blocks: List[Any] = []
    visited = set()
    queue = deque([entry])

    while queue:
        block = queue.popleft()
        if block in visited:
            continue
        visited.add(block)
        blocks.append(block)

        for target in iter_successors(block):
            if target is not None and target not in visited:
                queue.append(target)

    return blocks


def iter_successors(block) -> Iterable[Any]:
    """Yield CFG successor blocks for a block."""
    nxt = getattr(block, "next", None)
    if isinstance(nxt, dict):
        return nxt.values()
    if nxt is None:
        return ()
    return (nxt,)


def get_block_statements(block) -> List[Any]:
    """Return the statement-like payload attached to a CFG block."""
    if hasattr(block, "statements"):
        return block.statements
    if hasattr(block, "ops"):
        return block.ops
    if hasattr(block, "body"):
        return block.body
    if hasattr(block, "operations"):
        return block.operations
    return []
