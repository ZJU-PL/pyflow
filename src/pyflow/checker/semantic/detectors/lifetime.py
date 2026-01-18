"""Lifetime/escape-driven detectors leveraging PyFlow lifetime analysis."""

from __future__ import annotations

from typing import List, Optional

from ..context import AnalysisSession
from ..issue import BugInstance, Severity
from .base import Detector


class LifetimeEscapeDetector(Detector):
    name = "lifetime-escape"
    description = "Flags locally-allocated objects that escape their defining scope."

    def run(self, session: AnalysisSession) -> List[BugInstance]:
        la = session.lifetime
        if la is None:
            return []

        reports: List[BugInstance] = []

        escapes = getattr(la, "escapes", None)
        objects = getattr(la, "objects", None)
        if not escapes or not objects:
            return []

        for obj, info in objects.items():
            if obj not in escapes:
                continue
            # Skip externally visible / existing objects
            if getattr(info, "globallyVisible", False) or getattr(info, "externallyVisible", False):
                continue

            # Try to tie back to defining code object
            code_owner: Optional[str] = None
            for code in getattr(info, "localReference", []):
                if hasattr(code, "codeName"):
                    code_owner = code.codeName()
                    break

            reports.append(
                BugInstance(
                    rule="escaping-object",
                    message="Locally allocated object escapes its defining scope; review for leaks or unintended aliasing.",
                    severity=Severity.MEDIUM,
                    function=code_owner,
                )
            )
        return reports
