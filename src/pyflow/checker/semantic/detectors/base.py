"""Detector interfaces for the bug finder."""

from __future__ import annotations

from typing import List

from ..issue import BugInstance
from ..context import AnalysisSession


class Detector:
    """Base class for all detectors."""

    name: str = "base-detector"
    description: str = ""

    def run(self, session: AnalysisSession) -> List[BugInstance]:
        raise NotImplementedError


def run_detectors(session: AnalysisSession, detectors) -> List[BugInstance]:
    reports: List[BugInstance] = []
    for detector in detectors:
        reports.extend(detector.run(session))
    return reports
