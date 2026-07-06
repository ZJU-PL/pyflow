"""Tests for the collection-desync detector (black#22 pattern)."""

import pytest
from pathlib import Path
from a3_python.semantics.collection_desync_detector import (
    scan_file_for_collection_desync_bugs,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestCollectionDesyncDetector:
    """Test the AST + Z3 collection desync detector."""

    def test_buggy_version_detected(self):
        """Buggy version: self.leaves.pop() without updating self.comments → BUG."""
        bugs = scan_file_for_collection_desync_bugs(
            FIXTURES / "black_bug22_buggy.py"
        )
        assert len(bugs) >= 1
        bug = bugs[0]
        assert bug.pattern in ("collection_pop_without_sync", "id_key_instability")
        assert "leaves" in bug.reason
        assert "comments" in bug.reason
        assert "pop" in bug.reason
        assert bug.confidence >= 0.6
        assert "leaves" in (bug.variable or "")

    def test_fixed_version_clean(self):
        """Fixed version: remove_trailing_comma() syncs both collections → SAFE."""
        bugs = scan_file_for_collection_desync_bugs(
            FIXTURES / "black_bug22_fixed.py"
        )
        assert len(bugs) == 0

    def test_analyzer_buggy_reports_bug(self):
        """End-to-end: Analyzer.analyze_file reports BUG on buggy fixture."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "black_bug22_buggy.py")
        assert result.verdict == "BUG"
        assert result.bug_type == "COLLECTION_DESYNC"
        assert "collection_pop_without_sync" in result.counterexample.get("pattern", "") or \
               "id_key_instability" in result.counterexample.get("pattern", "")

    def test_analyzer_fixed_no_bug(self):
        """End-to-end: Analyzer.analyze_file reports no COLLECTION_DESYNC on fixed."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "black_bug22_fixed.py")
        if result.verdict == "BUG":
            assert result.bug_type != "COLLECTION_DESYNC" or \
                "collection_pop_without_sync" not in result.counterexample.get("pattern", "")

    def test_safe_pattern_not_flagged(self):
        """Class with two collections where mutations properly sync both → no bug."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            class DataStore:
                def __init__(self):
                    self.items = []
                    self.index = {}

                def add(self, item):
                    self.items.append(item)
                    self.index[item.id] = len(self.items) - 1

                def remove_last(self):
                    item = self.items.pop()
                    del self.index[item.id]
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_collection_desync_bugs(Path(f.name))
        assert len(bugs) == 0

    def test_single_collection_not_flagged(self):
        """Class with only one collection attribute → no bug possible."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            class SimpleList:
                def __init__(self):
                    self.items = []

                def remove_last(self):
                    self.items.pop()
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_collection_desync_bugs(Path(f.name))
        assert len(bugs) == 0

    def test_unrelated_collections_not_flagged(self):
        """Class with two collections that are never cross-referenced → no bug."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            class TwoLists:
                def __init__(self):
                    self.names = []
                    self.scores = []

                def remove_name(self):
                    self.names.pop()

                def get_name(self):
                    return self.names[0] if self.names else None

                def get_score(self):
                    return self.scores[0] if self.scores else None
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_collection_desync_bugs(Path(f.name))
        assert len(bugs) == 0
