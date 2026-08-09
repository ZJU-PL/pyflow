"""Regression tests for the responsibility-based concolic package layout."""

from __future__ import annotations

import importlib.util

import pyflow.concolic as concolic


def test_public_api_is_implemented_by_responsibility_subpackages():
    assert concolic.explore_file.__module__ == "pyflow.concolic.exploration.engine"
    assert concolic.scan_project.__module__ == "pyflow.concolic.project.scan"
    assert concolic.replay_runs.__module__ == "pyflow.concolic.artifacts.replay"
    assert concolic.generate_pytest.__module__ == "pyflow.concolic.artifacts.pytestgen"


def test_removed_root_modules_have_no_compatibility_shims():
    removed = (
        "engine",
        "runtime",
        "module_loader",
        "search",
        "contracts",
        "catalog",
        "inputgen",
        "project_scan",
        "worker",
        "corpus",
        "replay",
        "pytestgen",
    )

    for module in removed:
        assert importlib.util.find_spec(f"pyflow.concolic.{module}") is None
