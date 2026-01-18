"""High-level entry point for the analysis-backed bug finder."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Union

from .context import AnalysisSession
from .detectors.base import run_detectors
from .detectors.misuse import MisuseDetector
from .detectors.taint import TaintDetector
from .detectors.lifetime import LifetimeEscapeDetector
from .issue import BugInstance


@dataclass
class BugFinderConfig:
    use_pass_manager: bool = True
    verbose: bool = False
    recursive: bool = False
    include: Iterable[str] = field(default_factory=lambda: ("*.py",))
    exclude: Iterable[str] = field(default_factory=tuple)


class StaticBugFinder:
    """Orchestrates running PyFlow analyses and detectors."""

    def __init__(self, config: Optional[BugFinderConfig] = None):
        self.config = config or BugFinderConfig()
        self.detectors = [
            TaintDetector(),
            MisuseDetector(),
            LifetimeEscapeDetector(),
        ]

    def analyze(self, paths: Sequence[Union[str, Path]]) -> List[BugInstance]:
        session = AnalysisSession.from_paths(
            paths,
            use_pass_manager=self.config.use_pass_manager,
            verbose=self.config.verbose,
            recursive=self.config.recursive,
            include=self.config.include,
            exclude=self.config.exclude,
        )
        return run_detectors(session, self.detectors)
