"""Emit C3 method-resolution order computation using core MIR instructions.

This module constructs a CFG; it does not calculate a Python MRO while lowering
or call Python's ``type.mro`` at analysis/runtime.  Both the direct bases and
their existing MROs can be computed values in the input program.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .builder import Builder, field
from .model import Alloc, Binary, Length, ListExpr, Literal, LValue, Not, Var

if TYPE_CHECKING:
    from .runtime import Runtime


def _increment(b: Builder, index: Var) -> None:
    b.emit(Alloc(index.name, Binary("+", index, Literal(1))))


def _append(b: Builder, sequence: Var, value: LValue) -> None:
    item = b.alloc(ListExpr((value,)), "mro_item")
    b.emit(Alloc(sequence.name, Binary("+", sequence, item)))


def _inside(sequence: LValue, index: LValue):
    """MIR lists are one-based, so a head remains valid through len(sequence)."""
    return Not(Binary("<", Length(sequence), index))


def emit_mro(b: Builder, runtime: Runtime, cls: LValue, bases: LValue) -> LValue:
    """Emit ``[cls] + merge(mro(base_1), ..., mro(base_n), bases)``.

    ``bases`` and the returned value are raw MIR lists of class references.
    Parent ``__mro__`` lists are never modified: each merge sequence has a
    separate one-based head index.  Duplicate direct bases, a cycle through
    ``cls``, malformed base MROs, and inconsistent precedence order set the
    runtime's ``TypeError`` state and return from the enclosing CFG.
    """
    result = b.alloc(ListExpr((cls,)), "mro_result")
    sequences = b.alloc(ListExpr(()), "mro_sequences")
    heads = b.alloc(ListExpr(()), "mro_heads")

    # Build the C3 merge inputs from the runtime bases, checking the invariants
    # expected of previously constructed class objects along the way.
    base_index = b.alloc(Literal(1), "mro_base_index")
    init_head, init_done = b.node(), b.node()
    b.jump(init_head)
    b.use({init_head})
    inside, outside = b.branch(_inside(bases, base_index))
    b.use(outside)
    b.jump(init_done)
    b.use(inside)
    base = b.bind(field(bases, base_index), "mro_base")
    class_base, nonclass = b.branch(Binary("in", Literal("$class"), base))
    b.use(nonclass)
    runtime.error(b, "TypeError")
    b.use(class_base)
    has_mro, no_mro = b.branch(Binary("in", Literal("__mro__"), base))
    b.use(no_mro)
    runtime.error(b, "TypeError")
    b.use(has_mro)
    sequence = b.bind(field(base, "__mro__"), "mro_parent")
    empty, nonempty = b.branch(Binary("=", Length(sequence), Literal(0)))
    b.use(empty)
    runtime.error(b, "TypeError")
    b.use(nonempty)
    valid_start, invalid_start = b.branch(Binary("=", field(sequence, 1), base))
    b.use(invalid_start)
    runtime.error(b, "TypeError")
    b.use(valid_start)

    previous = b.alloc(Literal(1), "mro_previous")
    previous_head, previous_done = b.node(), b.node()
    b.jump(previous_head)
    b.use({previous_head})
    check_previous, previous_finished = b.branch(Binary("<", previous, base_index))
    b.use(previous_finished)
    b.jump(previous_done)
    b.use(check_previous)
    duplicate, distinct = b.branch(Binary("=", field(bases, previous), base))
    b.use(duplicate)
    runtime.error(b, "TypeError")
    b.use(distinct)
    _increment(b, previous)
    b.jump(previous_head)
    b.use({previous_done})

    ancestor_index = b.alloc(Literal(1), "mro_ancestor_index")
    ancestor_head, ancestor_done = b.node(), b.node()
    b.jump(ancestor_head)
    b.use({ancestor_head})
    check_ancestor, ancestors_finished = b.branch(_inside(sequence, ancestor_index))
    b.use(ancestors_finished)
    b.jump(ancestor_done)
    b.use(check_ancestor)
    cycle, acyclic = b.branch(Binary("=", field(sequence, ancestor_index), cls))
    b.use(cycle)
    runtime.error(b, "TypeError")
    b.use(acyclic)
    _increment(b, ancestor_index)
    b.jump(ancestor_head)
    b.use({ancestor_done})

    _append(b, sequences, sequence)
    _append(b, heads, b.alloc(Literal(1), "mro_head_index"))
    _increment(b, base_index)
    b.jump(init_head)
    b.use({init_done})
    _append(b, sequences, bases)
    _append(b, heads, b.alloc(Literal(1), "mro_head_index"))

    # C3 accepts the first sequence head that appears in no sequence's tail.
    # An unsuccessful scan with no nonempty sequences completes the merge;
    # an unsuccessful scan with remaining heads is an inconsistent hierarchy.
    merge_head, merge_done = b.node(), b.node()
    accept, reject = b.node(), b.node()
    b.jump(merge_head)
    b.use({merge_head})
    remaining = b.alloc(Literal(False), "mro_remaining")
    candidate_index = b.alloc(Literal(1), "mro_candidate_index")
    candidates_head = b.node()
    b.jump(candidates_head)
    b.use({candidates_head})
    candidates_left, candidates_finished = b.branch(_inside(sequences, candidate_index))
    b.use(candidates_finished)
    inconsistent, complete = b.branch(remaining)
    b.use(inconsistent)
    runtime.error(b, "TypeError")
    b.use(complete)
    b.jump(merge_done)
    b.use(candidates_left)
    candidate_sequence = b.bind(field(sequences, candidate_index), "mro_candidate_sequence")
    candidate_position = b.bind(field(heads, candidate_index), "mro_candidate_position")
    nonempty, exhausted = b.branch(_inside(candidate_sequence, candidate_position))
    b.use(exhausted)
    b.jump(reject)
    b.use(nonempty)
    b.emit(Alloc(remaining.name, Literal(True)))
    candidate = b.bind(field(candidate_sequence, candidate_position), "mro_candidate")

    tail_sequence_index = b.alloc(Literal(1), "mro_tail_sequence_index")
    tails_head = b.node()
    b.jump(tails_head)
    b.use({tails_head})
    tails_left, tails_finished = b.branch(_inside(sequences, tail_sequence_index))
    b.use(tails_finished)
    b.jump(accept)
    b.use(tails_left)
    tail_sequence = b.bind(field(sequences, tail_sequence_index), "mro_tail_sequence")
    tail_index = b.alloc(
        Binary("+", field(heads, tail_sequence_index), Literal(1)), "mro_tail_index"
    )
    tail_head, tail_done = b.node(), b.node()
    b.jump(tail_head)
    b.use({tail_head})
    tail_left, tail_finished = b.branch(_inside(tail_sequence, tail_index))
    b.use(tail_finished)
    b.jump(tail_done)
    b.use(tail_left)
    appears_in_tail, absent_from_tail = b.branch(
        Binary("=", field(tail_sequence, tail_index), candidate)
    )
    b.use(appears_in_tail)
    b.jump(reject)
    b.use(absent_from_tail)
    _increment(b, tail_index)
    b.jump(tail_head)
    b.use({tail_done})
    _increment(b, tail_sequence_index)
    b.jump(tails_head)

    b.use({reject})
    _increment(b, candidate_index)
    b.jump(candidates_head)

    # Append an accepted head once, then advance every sequence that starts
    # with that exact class.  Rebinding a head slot cannot mutate a base MRO.
    b.use({accept})
    _append(b, result, candidate)
    advance_index = b.alloc(Literal(1), "mro_advance_index")
    advance_head = b.node()
    b.jump(advance_head)
    b.use({advance_head})
    advance_left, advance_finished = b.branch(_inside(sequences, advance_index))
    b.use(advance_finished)
    b.jump(merge_head)
    b.use(advance_left)
    advance_sequence = b.bind(field(sequences, advance_index), "mro_advance_sequence")
    position = b.bind(field(heads, advance_index), "mro_position")
    active, exhausted = b.branch(_inside(advance_sequence, position))
    b.use(active)
    matches, different = b.branch(Binary("=", field(advance_sequence, position), candidate))
    b.use(matches)
    new_position = b.alloc(Binary("+", position, Literal(1)), "mro_next_position")
    b.assign(field(heads, advance_index), new_position)
    b.join(b.tails, different, exhausted)
    _increment(b, advance_index)
    b.jump(advance_head)
    b.use({merge_done})
    return result


__all__ = ["emit_mro"]
