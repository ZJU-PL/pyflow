"""Tests for optimization/clone.py."""

from types import SimpleNamespace
from unittest.mock import patch

from pyflow.optimization.clone import rewriteProgram


class _NoRewriteCloner:
    def __init__(self, live_functions):
        self.liveFunctions = live_functions
        self.provenance_seeds = []

    def clonedNumGroups(self):
        return 1

    def originalNumGroups(self):
        return 1

    def rewriteProgram(self, _compiler, _prgm):
        raise AssertionError("rewriteProgram should not be called when groups do not grow")


def test_rewrite_program_reports_changed_when_live_code_set_changes_without_cloning():
    old_code = object()
    new_code = object()
    prgm = SimpleNamespace(liveCode={old_code})
    cloner = _NoRewriteCloner({new_code})

    with patch("pyflow.optimization.clone.rebuild_program_ir") as rebuild:
        changed = rewriteProgram(None, prgm, cloner)

    assert changed is True
    assert prgm.liveCode == {new_code}
    rebuild.assert_called_once_with(prgm, provenance_seeds=[])


def test_rewrite_program_reports_unchanged_when_live_code_set_is_identical():
    code = object()
    prgm = SimpleNamespace(liveCode={code})
    cloner = _NoRewriteCloner({code})

    changed = rewriteProgram(None, prgm, cloner)

    assert changed is False
    assert prgm.liveCode == {code}
