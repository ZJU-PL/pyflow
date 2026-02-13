"""
Adapter manager for semantic checker to work with common formatters.

Makes the semantic checker compatible with the pattern checker's manager
interface so it can use the shared formatters (text, JSON, SARIF).
"""

from __future__ import annotations

from typing import List, Optional
from pathlib import Path

from ...pattern.core import constants as b_constants
from ...pattern.core.metrics import Metrics
from .runner import StaticBugFinder, BugFinderConfig
from .issue import Issue


class SemanticManager:
    """Adapter manager that makes semantic checker compatible with formatters."""

    scope = []

    def __init__(
        self,
        config: Optional[BugFinderConfig] = None,
        debug: bool = False,
        verbose: bool = False,
        quiet: bool = False,
    ):
        """
        Initialize the semantic checker manager adapter.

        Args:
            config: Bug finder configuration
            debug: Enable debug output
            verbose: Enable verbose output
            quiet: Quiet mode (minimal output)
        """
        self.debug = debug
        self.verbose = verbose
        self.quiet = quiet
        self.finder = StaticBugFinder(config or BugFinderConfig(verbose=verbose))
        self.results: List[Issue] = []
        self.skipped: List[tuple] = []
        self.baseline: List[Issue] = []
        self.metrics = Metrics()
        self.agg_type = "file"  # Default aggregation type for formatters

    def get_skipped(self):
        """Get list of skipped files."""
        return self.skipped

    def get_issue_list(
        self, sev_level=b_constants.LOW, conf_level=b_constants.LOW
    ) -> List[Issue]:
        """Get filtered list of issues."""
        return self.filter_results(sev_level, conf_level)

    def filter_results(self, sev_filter, conf_filter):
        """Filter results by severity and confidence thresholds."""
        results = [i for i in self.results if i.filter(sev_filter, conf_filter)]
        return results

    def results_count(self, sev_filter=b_constants.LOW, conf_filter=b_constants.LOW):
        """Return the count of results."""
        return len(self.get_issue_list(sev_filter, conf_filter))

    def analyze(self, paths: list[str | Path]) -> List[Issue]:
        """
        Run analysis on the specified paths and store results.

        Args:
            paths: List of file or directory paths to analyze

        Returns:
            List of Issue objects found
        """
        self.results = self.finder.analyze(paths)

        # Count lines of code from analyzed files
        total_lines = 0
        for path in paths:
            path_obj = Path(path) if isinstance(path, str) else path
            if path_obj.is_file():
                try:
                    with open(path_obj, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    total_lines += len(lines)
                    self.metrics.files += 1
                except (IOError, OSError):
                    pass
            elif path_obj.is_dir():
                for py_file in path_obj.rglob("*.py"):
                    try:
                        with open(py_file, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                        total_lines += len(lines)
                        self.metrics.files += 1
                    except (IOError, OSError):
                        pass

        self.metrics.lines = total_lines
        self.metrics.data["_totals"]["loc"] = total_lines
        self.metrics.data["_totals"]["files"] = self.metrics.files

        # Update metrics
        for issue in self.results:
            self.metrics.issues += 1
            if issue.severity in self.metrics.issues_by_severity:
                self.metrics.issues_by_severity[issue.severity] += 1
            if issue.confidence in self.metrics.issues_by_confidence:
                self.metrics.issues_by_confidence[issue.confidence] += 1

        # Update metrics data property
        self.metrics.data = self._build_metrics_data(self.metrics)

        return self.results

    def _build_metrics_data(self, metrics: Metrics):
        """Build metrics data dictionary in format expected by formatters."""
        data = {
            "_totals": {
                "loc": metrics.lines,
                "nosec": metrics.nosec,
                "skipped_tests": metrics.skipped,
                "SEVERITY.UNDEFINED": 0,
                "SEVERITY.LOW": metrics.issues_by_severity.get("LOW", 0),
                "SEVERITY.MEDIUM": metrics.issues_by_severity.get("MEDIUM", 0),
                "SEVERITY.HIGH": metrics.issues_by_severity.get("HIGH", 0),
                "CONFIDENCE.UNDEFINED": 0,
                "CONFIDENCE.LOW": metrics.issues_by_confidence.get("LOW", 0),
                "CONFIDENCE.MEDIUM": metrics.issues_by_confidence.get("MEDIUM", 0),
                "CONFIDENCE.HIGH": metrics.issues_by_confidence.get("HIGH", 0),
            }
        }
        return data

    @property
    def metrics(self) -> Metrics:
        """Get the metrics object."""
        return self._metrics

    @metrics.setter
    def metrics(self, value: Metrics):
        """Set the metrics object."""
        self._metrics = value
        # Add data property to metrics if it doesn't exist
        if not hasattr(value, "data"):
            value.data = self._build_metrics_data(value)
