from abc import ABC, abstractmethod
from typing import Dict, Any, Type, Literal, List

from pyflow.analysis.alias.kcfa._pythonstan.ir import IRScope


class AnalysisConfig:
    name: str
    id: str
    description: str
    type: Literal['dataflow analysis', 'transform', 'pointer analysis']
    inter_procedure: bool
    prev_analysis: List[str]  # previous analysis name
    options: Dict[str, Any]

    def __init__(self, name, id, description="", prev_analysis=None, inter_procedure=False, options=None):
        if options.get("type") is None:
            print(name, id, description, prev_analysis, inter_procedure, options)
            print(options)
            raise ValueError("type is required")
        self.name = name
        self.id = id
        self.description = description
        self.type = options["type"]
        self.inter_procedure = inter_procedure
        if options is None:
            self.options = {}
        else:
            self.options = options
        if prev_analysis is None:
            self.prev_analysis = []
        else:
            self.prev_analysis = prev_analysis
    
    def __str__(self):
        return f'''
AnalysisConfig(
    name={self.name},
    id={self.id},
    description={self.description},
    type={self.type},
    inter_procedure={self.inter_procedure},
    prev_analysis={self.prev_analysis},
    options={self.options}
)
'''
    
    def __repr__(self):
        return self.__str__()


class Analysis(ABC):
    analysis_dict: 'Dict[str, Type[Analysis]]' = {}
    config: AnalysisConfig

    @abstractmethod
    def __init__(self, config: AnalysisConfig):
        self.config = config
        self.valid_id()

    def __init_subclass__(cls):
        cls.analysis_dict[cls.__name__] = cls

    @classmethod
    def get_analysis(cls, id):
        return cls.analysis_dict[id]

    def get_id(self):
        return self.config.id

    def valid_id(self):
        cls_name = self.__class__.__name__
        assert cls_name == self.get_id(), "Invalid id for current Analysis"


class AnalysisDriver(ABC):
    config: AnalysisConfig
    results: Any

    @abstractmethod
    def __init__(self, config):
        self.config = config

    @abstractmethod
    def analyze(self, scope: IRScope, prev_results: Dict[str, Any]):
        pass
