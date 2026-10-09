"""
Adapter manager for the AST dataflow checker to work with common formatters.

Makes the AST dataflow checker compatible with the pattern checker's manager
interface so it can use the shared formatters (text, JSON, SARIF).
"""

from __future__ import annotations

from typing import List, Optional
from pathlib import Path

from ...common import constants as b_constants
from ...common.metrics import Metrics
from .runner import StaticBugFinder, BugFinderConfig
from ...common.issue import Issue
from .context import AnalysisSession


class ASTDataflowManager:
    """Adapter exposing AST dataflow results to shared formatters."""

    def __init__(
        self,
        config: Optional[BugFinderConfig] = None,
        debug: bool = False,
        verbose: bool = False,
        quiet: bool = False,
    ):
        """
        Initialize the AST dataflow checker manager adapter.

        Args:
            config: Bug finder configuration
            debug: Enable debug output
            verbose: Enable verbose output
            quiet: Quiet mode (minimal output)
        """
        self.scope = []
        self.debug = debug
        self.verbose = verbose
        self.quiet = quiet
        self.finder = StaticBugFinder(config or BugFinderConfig(verbose=verbose))
        self.results: List[Issue] = []
        self.analysis_result = None
        self.skipped: List[tuple] = []
        self.baseline: List[Issue] = []
        self.metrics = Metrics()
        self.agg_type = "file"  # Default aggregation type for formatters

    def get_skipped(self):
        """Get list of skipped files."""
        return self.skipped

    def get_issue_list(self, sev_level=b_constants.LOW, conf_level=b_constants.LOW) -> List[Issue]:
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
        self.metrics = Metrics()
        self.results = self.finder.analyze(paths)
        self.analysis_result = self.finder.last_result

        config = self.finder.config
        for path_obj in AnalysisSession._collect_files(
            paths, config.recursive, tuple(config.include), tuple(config.exclude)
        ):
            try:
                with open(path_obj, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                self.metrics.begin(str(path_obj))
                self.metrics.count_locs(lines)
            except (IOError, OSError):
                pass

        self.metrics.data["_totals"]["files"] = self.metrics.files
        self.metrics.count_findings(self.results)

        return self.results
