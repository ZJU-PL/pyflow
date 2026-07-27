"""High-level entry point for the analysis-backed bug finder."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Union

from .context import AnalysisSession
from ..detectors.taint import ASTDataflowTaintDetector
from .issue import Issue


@dataclass
class BugFinderConfig:
    use_pass_manager: bool = True
    verbose: bool = False
    recursive: bool = False
    include: Iterable[str] = field(default_factory=lambda: ("*.py",))
    exclude: Iterable[str] = field(default_factory=tuple)
    sources: Iterable[str] = field(default_factory=tuple)
    sinks: Iterable[str] = field(default_factory=tuple)
    sanitizers: Iterable[str] = field(default_factory=tuple)
    frameworks: Optional[Iterable[str]] = None
    registry_paths: Iterable[str | Path] = field(default_factory=tuple)


class StaticBugFinder:
    """Orchestrates running PyFlow analyses and detectors."""

    def __init__(self, config: Optional[BugFinderConfig] = None):
        self.config = config or BugFinderConfig()
        self.detectors = self._create_detectors()
        self.last_result = None

    def _create_detectors(self) -> List:
        sources = set(self.config.sources or ())
        sinks = set(self.config.sinks or ())
        sanitizers = set(self.config.sanitizers or ())
        return [
            ASTDataflowTaintDetector(
                sources=sources or None,
                sinks=sinks or None,
                sanitizers=sanitizers or None,
                frameworks=(
                    None
                    if self.config.frameworks is None
                    else tuple(self.config.frameworks)
                ),
                registry_paths=tuple(self.config.registry_paths),
            )
        ]

    def analyze(self, paths: Sequence[Union[str, Path]]) -> List[Issue]:
        session = AnalysisSession.from_paths(
            paths,
            use_pass_manager=self.config.use_pass_manager,
            verbose=self.config.verbose,
            recursive=self.config.recursive,
            include=self.config.include,
            exclude=self.config.exclude,
        )
        detector = self.detectors[0]
        self.last_result = detector.analyze(session)
        return detector.issues_from_result(self.last_result)
