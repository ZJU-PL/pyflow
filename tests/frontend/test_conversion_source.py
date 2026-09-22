"""Caching behavior tests for pyflow.frontend.conversion.source.

The correctness of the lookup helpers is exercised indirectly by the
frontend/function-extractor suites; these tests focus on the caching
contracts: equal-valued strings share span entries, and repeated callable
lookups against one source set scan at most once.
"""

import textwrap
from unittest.mock import patch

from pyflow.frontend.conversion import source as source_module
from pyflow.frontend.conversion.source import (
    _SPAN_CACHE,
    _SOURCE_LOOKUP_CACHE,
    _cached_spans,
    best_source_for_callable,
)


def _clear_caches():
    _SPAN_CACHE.clear()
    _SOURCE_LOOKUP_CACHE.clear()


def test_cached_spans_shares_entries_between_original_and_dedented_copy():
    """A dedent-ed copy with equal content must reuse the cached spans."""
    _clear_caches()
    original = "def f():\n    return 1\n"
    # textwrap.dedent of an already-unindented module returns the same object,
    # so build a distinct-but-equal copy the way functions.py does: dedent an
    # indented variant.
    indented = "    def f():\n        return 1\n"
    dedented = textwrap.dedent(indented)
    assert dedented == original
    assert dedented is not original

    with patch.object(
        source_module.ast, "parse", wraps=source_module.ast.parse
    ) as parse:
        first = _cached_spans(original)
        second = _cached_spans(dedented)

    assert first == second
    assert first is second
    assert parse.call_count == 1


def test_cached_spans_parses_distinct_content_separately():
    """Different module content must not share span entries."""
    _clear_caches()
    with patch.object(
        source_module.ast, "parse", wraps=source_module.ast.parse
    ) as parse:
        _cached_spans("def a():\n    return 1\n")
        _cached_spans("def b():\n    return 2\n")
    assert parse.call_count == 2


def _external_func():
    return 1


def test_best_source_for_callable_scans_missing_filename_once():
    """Repeated lookups for an external callable must scan the sources once."""
    _clear_caches()
    sources = {"pkg/mod.py": "def other():\n    return 2\n"}
    with patch.object(
        source_module,
        "find_function_source_segment",
        wraps=source_module.find_function_source_segment,
    ) as spy:
        assert best_source_for_callable(_external_func, sources) is None
        first = spy.call_count
        assert first == 1
        assert best_source_for_callable(_external_func, sources) is None
        assert spy.call_count == first


def test_best_source_for_callable_memoizes_exact_hit():
    """A callable whose filename is in the map is resolved once per source set."""
    _clear_caches()
    namespace = {}
    exec(compile("def helper():\n    return 1\n", "pkg/mod.py", "exec"), namespace)
    helper = namespace["helper"]
    sources = {"pkg/mod.py": "def helper():\n    return 1\n"}
    with patch.object(
        source_module,
        "find_function_source_segment",
        wraps=source_module.find_function_source_segment,
    ) as spy:
        first = best_source_for_callable(helper, sources)
        second = best_source_for_callable(helper, sources)
    assert first == "def helper():\n    return 1"
    assert second == first
    assert spy.call_count == 1


def test_best_source_for_callable_invalidates_on_new_source_set():
    """A rebuilt source set must start a fresh memo bucket."""
    _clear_caches()
    namespace = {}
    exec(compile("def helper():\n    return 1\n", "pkg/mod.py", "exec"), namespace)
    helper = namespace["helper"]
    sources_a = {"pkg/mod.py": "def helper():\n    return 1\n"}
    sources_b = {"pkg/mod.py": "def helper():\n    return 1\n"}
    with patch.object(
        source_module,
        "find_function_source_segment",
        wraps=source_module.find_function_source_segment,
    ) as spy:
        best_source_for_callable(helper, sources_a)
        best_source_for_callable(helper, sources_b)
    assert spy.call_count == 2
