from __future__ import annotations

from itertools import product

from pyflow.checker.ast_dataflow.domain import (
    AbstractString,
    AnalysisUncertainty,
    PrecisionLevel,
    SelectorKind,
    TaintLocation,
    TaintOrigin,
    TaintState,
)

ORIGIN = TaintOrigin("user_input", "sample.py", 1, 0, "input")
X = TaintLocation("x")
Y = TaintLocation("y")


def _states():
    bottom = TaintState.bottom()
    empty = TaintState()
    x = empty.introduce(X, {"html"}, ORIGIN)
    y = empty.introduce(Y, {"shell"}, ORIGIN)
    both = x.join(y)
    uncertain = both.with_uncertainty(
        AnalysisUncertainty(
            "unknown-call",
            "Call target cannot be resolved",
            PrecisionLevel.CONSERVATIVE,
        )
    )
    return bottom, empty, x, y, both, uncertain


def test_taint_state_join_satisfies_semilattice_laws():
    states = _states()
    for state in states:
        assert state.join(state) == state
        assert TaintState.bottom().join(state) == state
        assert state.leq(state)
    for left, right in product(states, repeat=2):
        assert left.join(right) == right.join(left)
        assert left.leq(left.join(right))
        assert right.leq(left.join(right))
    for first, second, third in product(states, repeat=3):
        assert first.join(second).join(third) == first.join(second.join(third))


def test_strong_write_kills_old_descendants_and_weak_write_preserves_them():
    field = X.attribute("value")
    old = TaintState().introduce(field, {"html"}, ORIGIN)
    safe_strong = old.write(field, (), strong=True)
    safe_weak = old.write(field, (), strong=False)

    assert not safe_strong.is_tainted(field)
    assert safe_weak.is_tainted(field)


def test_wildcard_taint_contaminates_precise_child():
    wildcard = X.wildcard()
    precise = X.key("command")
    state = TaintState().introduce(wildcard, {"shell"}, ORIGIN)

    assert state.is_tainted(precise, {"shell"})
    assert wildcard.selectors[0].kind is SelectorKind.WILDCARD


def test_copy_preserves_nested_access_path_shape():
    source_field = X.key("payload").attribute("command")
    destination = Y
    state = TaintState().introduce(source_field, {"shell"}, ORIGIN)

    copied = state.copy(X, destination, strong=True)

    assert copied.is_tainted(Y.key("payload").attribute("command"), {"shell"})
    assert not copied.is_tainted(Y.key("other"), {"shell"})


def test_strong_child_write_masks_coarse_ancestor_taint_for_that_child():
    state = TaintState().introduce(X, {"shell"}, ORIGIN)

    cleaned = state.write(X.key("command"), (), strong=True)

    assert not cleaned.is_tainted(X.key("command"), {"shell"})
    assert cleaned.is_tainted(X.key("other"), {"shell"})


def test_sanitizer_removes_only_configured_kinds_and_records_guarantee():
    state = TaintState().introduce(X, {"html", "shell"}, ORIGIN)
    sanitized = state.sanitize(X, Y, {"html"}, sanitizer="escape_html")

    assert not sanitized.is_tainted(Y, {"html"})
    assert sanitized.is_tainted(Y, {"shell"})
    assert (Y, "html") in sanitized.guarantees


def test_must_sanitization_guarantees_join_by_intersection():
    tainted = TaintState().introduce(X, {"html"}, ORIGIN)
    cleaned = tainted.sanitize(X, Y, {"html"})
    untouched = TaintState()

    assert (Y, "html") not in cleaned.join(untouched).guarantees


def test_abstract_string_widens_constants_to_prefix_then_top():
    prefixed = AbstractString.from_constants(
        ["request.user", "request.command", "request.page"], max_constants=2
    )
    unrelated = prefixed.join(AbstractString.constant("other", max_constants=2))

    assert prefixed.may_contain("request.token")
    assert not prefixed.may_contain("response.token")
    assert unrelated.may_contain("anything")


def test_recursive_shape_growth_widens_to_a_finite_wildcard_path():
    state = TaintState(max_access_path=3).introduce(X, {"shell"}, ORIGIN)

    for _ in range(12):
        previous = state
        state = state.copy(X, X.attribute("next"), strong=False)
        if state == previous:
            break
    else:
        raise AssertionError("bounded access paths did not stabilize")

    assert state == previous
    assert all(len(fact.location.selectors) <= 3 for fact in state.facts)
    assert any(
        selector.kind is SelectorKind.WILDCARD
        for fact in state.facts
        for selector in fact.location.selectors
    )


def test_provenance_overflow_uses_an_explicit_top_element():
    source = TaintState(max_provenance_edges=1).introduce(X, {"shell"}, ORIGIN)
    first = source.copy(X, Y, strong=True)
    overflowed = first.copy(X, TaintLocation("z"), strong=True)

    assert overflowed.provenance_is_top
    assert not overflowed.provenance
    assert any(
        item.code == "provenance-budget-exceeded" for item in overflowed.uncertainties
    )
    assert overflowed.join(first).provenance_is_top
