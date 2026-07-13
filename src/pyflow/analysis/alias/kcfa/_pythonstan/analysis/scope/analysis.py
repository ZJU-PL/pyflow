from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Optional

from pyflow.analysis.alias.kcfa._pythonstan.ir import *
from ..analysis import Analysis, AnalysisConfig

Fact = TypeVar('Fact')


class ScopeAnalysis(Generic[Fact], Analysis):
    @abstractmethod
    def __init__(self, config: AnalysisConfig):
        super(Analysis, self.__class__).__init__(config)
    
    @abstractmethod
    def analyze_function(self, fn: IRFunc,fact: Optional[Fact] = None) -> Fact:
        pass

    @abstractmethod
    def analyze_class(self, cls: IRClass, fact: Optional[Fact] = None) -> Fact:
        pass

    @abstractmethod
    def analyze_module(self, mod: IRModule, fact: Optional[Fact] = None) -> Fact:
        pass

    @abstractmethod
    def init_function(self, fn: IRFunc) -> Fact:
        pass

    @abstractmethod
    def init_class(self, cls: IRClass) -> Fact:
        pass

    @abstractmethod
    def init_module(self, mod: IRModule) -> Fact:
        pass
