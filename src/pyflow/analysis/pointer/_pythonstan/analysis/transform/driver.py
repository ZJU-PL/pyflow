from typing import Dict, Type, Any

from pyflow.analysis.pointer._pythonstan.ir import IRScope
from ..analysis import Analysis, AnalysisConfig, AnalysisDriver
from .transform import Transform


class TransformDriver(AnalysisDriver):
    transform: Type[Transform]
    results: Any

    def __init__(self, config):
        self.config = config
        self.transform = Transform.get_analysis(config.id)
        self.results = {}

    def analyze(self, scope: IRScope, prev_results):
        analyzer = self.transform(self.config)
        for prev in self.config.prev_analysis:
            if prev in prev_results:
                analyzer.set_input(prev, prev_results[prev][scope])
        analyzer.transform(scope)
        if hasattr(analyzer, "results"):
            self.results[scope] = analyzer.results
        else:
            self.results[scope] = None
