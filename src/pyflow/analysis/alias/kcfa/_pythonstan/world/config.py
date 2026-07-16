from typing import Set, Dict, List
from queue import Queue
import json as _json

try:
    import yaml as _yaml
except ImportError:
    _yaml = None  # type: ignore[assignment]

from pyflow.analysis.alias.kcfa._pythonstan.analysis import AnalysisConfig
from pyflow.analysis.alias.kcfa._pythonstan.utils.common import topo_sort

__all__ = ["Config"]


class Config:
    filename: str
    project_path: str
    library_paths: List[str]
    analysis: Dict[str, AnalysisConfig]
    succ_analysis: Dict[str, Set[str]]
    lazy_ir_construction: bool
    import_level: int
    time_count: bool
    mock_libs: bool
    prefer_mock_libs: bool

    def __init__(self, filename, project_path,
                 lazy_ir_construction: bool = False,
                 import_level: int = -1,
                 time_count: bool = False,
                 mock_libs: bool = True,
                 prefer_mock_libs: bool = False):
        self.filename = filename
        self.project_path = project_path
        self.library_paths = []
        self.succ_analysis = {}
        self.analysis = {}
        self.lazy_ir_construction = lazy_ir_construction
        self.import_level = import_level
        self.time_count = time_count
        self.mock_libs = mock_libs
        self.prefer_mock_libs = prefer_mock_libs
        
    @classmethod
    def from_dict(cls, info: Dict):
        lazy_ir = info.get('lazy_ir_construction', False)
        mock_libs = info.get('mock_libs', True)
        prefer_mock_libs = info.get('prefer_mock_libs', False)
        conf = cls(
            info['filename'],
            info['project_path'],
            lazy_ir_construction=lazy_ir,
            mock_libs=mock_libs,
            prefer_mock_libs=prefer_mock_libs,
        )
        for anal_info in info['analysis']:
            inter_procedure = anal_info.get('inter_procedure', False)
            anal_cfg = AnalysisConfig(
                anal_info['name'], anal_info['id'], anal_info['description'],
                anal_info['prev_analysis'], inter_procedure, anal_info['options'])
            conf.add_analysis(anal_cfg)
        for library_path in info['library_paths']:
            conf.add_library_path(library_path)
        conf.import_level = info.get('import_level', -1)
        conf.time_count = info.get('time_count', False)
        return conf

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'r') as f:
            if filename.endswith('.json'):
                info = _json.load(f)
            elif _yaml is not None:
                info = _yaml.safe_load(f)
            else:
                info = _json.load(f)
        return cls.from_dict(info)

    def add_analysis(self, cfg: AnalysisConfig):
        self.analysis[cfg.name] = cfg
        self.succ_analysis[cfg.name] = {*()}
        for prev_name in cfg.prev_analysis:
            if prev_name not in self.succ_analysis:
                self.succ_analysis[prev_name] = {*()}
            self.succ_analysis[prev_name].add(cfg.name)

    def add_library_path(self, path: str):
        self.library_paths.append(path)

    def get_analysis_list(self):
        analysis_id_list = topo_sort(self.succ_analysis)
        return [self.analysis[anal_id] for anal_id in analysis_id_list if anal_id in self.analysis]
