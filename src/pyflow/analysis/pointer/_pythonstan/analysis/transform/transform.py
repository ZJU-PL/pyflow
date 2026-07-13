import copy
from typing import Dict, Any
from abc import abstractmethod

from pyflow.analysis.pointer._pythonstan.ir import IRScope
from ..analysis import Analysis, AnalysisConfig


class Transform(Analysis):
    module: IRScope
    inputs: Dict[str, Any]
    results: Any

    @abstractmethod
    def __init__(self, config: AnalysisConfig):
        super().__init__(config)
        self.inputs = {}

    def set_input(self, key, value):
        self.inputs[key] = value

    def get_input(self, key):
        return self.inputs[key]

    @abstractmethod
    def transform(self, module: IRScope):
        ...
