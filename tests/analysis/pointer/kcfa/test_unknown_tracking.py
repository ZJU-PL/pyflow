from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.unknown_tracker import (
    UnknownKind,
    UnknownTracker,
)


def test_unknown_tracker_records_summary_counts():
    tracker = UnknownTracker()

    tracker.record(UnknownKind.CALLEE_EMPTY, "loc1", "empty")
    tracker.record(UnknownKind.CALLEE_NON_CALLABLE, "loc2", "non-callable", context="ctx")

    assert tracker.get_summary() == {
        "total_unknowns": 2,
        "unknown_callee_empty": 1,
        "unknown_callee_non_callable": 1,
    }


def test_unknown_tracker_detailed_report():
    tracker = UnknownTracker()

    tracker.record(UnknownKind.IMPORT_NOT_FOUND, "module", "missing import")

    assert tracker.get_detailed_report() == [
        {
            "kind": "import_not_found",
            "location": "module",
            "message": "missing import",
            "context": None,
        }
    ]
