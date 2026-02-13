"""Detector base and runner for the semantic bug finder."""

from __future__ import annotations

from typing import List

from .issue import Issue
from .context import AnalysisSession


class Detector:
    """Base class for all semantic detectors."""

    name: str = "base-detector"
    description: str = ""

    def run(self, session: AnalysisSession) -> List[Issue]:
        raise NotImplementedError


def run_detectors(session: AnalysisSession, detectors) -> List[Issue]:
    """Run all detectors on the session and collect issues."""
    reports: List[Issue] = []
    for detector in detectors:
        reports.extend(detector.run(session))
    return reports
