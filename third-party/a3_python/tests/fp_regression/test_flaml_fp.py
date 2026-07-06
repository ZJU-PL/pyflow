"""
Regression test for false-positive reduction on a local FLAML checkout.
"""

from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FLAML_PATH = REPO_ROOT / "external_tools" / "FLAML"


@pytest.mark.skipif(not FLAML_PATH.exists(), reason="FLAML checkout not available")
def test_flaml_fp_reduction_does_not_increase_findings() -> None:
    InterproceduralBugTracker = pytest.importorskip(
        "a3_python.semantics.interprocedural_bugs",
        reason="a3 interprocedural analysis dependencies not available",
    ).InterproceduralBugTracker

    tracker = InterproceduralBugTracker.from_project(FLAML_PATH)
    bugs_raw = tracker.find_all_bugs(apply_fp_reduction=False)
    raw_types = Counter(bug.bug_type for bug in bugs_raw)

    tracker_filtered = InterproceduralBugTracker.from_project(FLAML_PATH)
    bugs_filtered = tracker_filtered.find_all_bugs(apply_fp_reduction=True)
    filtered_types = Counter(bug.bug_type for bug in bugs_filtered)

    assert len(bugs_filtered) <= len(bugs_raw)
    for bug_type, filtered_count in filtered_types.items():
        assert filtered_count <= raw_types[bug_type]
