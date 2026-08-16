"""Build modules, run lowering passes, and schedule configured analyses.

The pipeline is the orchestration boundary used by PyFlow's public k-CFA
bridge. It constructs the import graph, lowers reachable modules through the
required IR and CFG passes, and dispatches analysis drivers in dependency order.
"""

from pyflow.analysis.alias.kcfa._pythonstan.ir import IRModule
from pyflow.analysis.alias.kcfa._pythonstan.analysis import AnalysisConfig, AnalysisDriver
from .namespace import Namespace
from .world import World
from .config import Config
from .scope_manager import ModuleGraph
from .analysis_manager import AnalysisManager

from typing import List, Tuple, Generator
from queue import Queue
import logging

logger = logging.getLogger(__name__)

class Pipeline:
    """Coordinate project discovery, lowering, and analysis execution."""

    config: Config
    analysis_manager: AnalysisManager

    def __init__(self, config=None, filename=None):
        """Create a pipeline from a configuration mapping or config file.

        Construction initializes the shared :class:`World` and builds the
        module graph rooted at the configured entry file.
        """
        if config is not None:
            self.config = Config.from_dict(config)
        elif filename is not None:
            self.config = Config.from_file(filename)
        else:
            raise ValueError("No proper configuration for pipeline!")
        self.world = World.fresh()
        self.world.setup()
        self.world.build(self.config)
        self.analysis_manager = AnalysisManager()
        self.analysis_manager.build(self.config.get_analysis_list())
        self.analysis_manager.set_time_count(self.config.time_count)
        self.world.analysis_manager = self.analysis_manager
        self.build_scope_graph(self.config.filename)

    def get_world(self):
        """Return the shared world populated by this pipeline."""
        return self.world

    def build_scope_graph(self, entry_path: str):
        """Discover modules and run prerequisite lowering passes.

        Lazy mode lowers only the entry module. Otherwise imports are followed
        transitively up to the configured import depth.
        """
        entry_ns = World().namespace_manager.set_entry_module(entry_path, self.config.project_path)
        entry_mod = World().scope_manager.add_module(entry_ns, entry_path)
        World().entry_module = entry_mod
        q: List[Tuple[Namespace, IRModule, int]] = [(entry_ns, entry_mod, 0)]
        g = ModuleGraph()
        g.add_node(entry_mod)
        visited_ns = set()
        
        # Lazy IR construction: only process entry module, skip imports
        if self.config.lazy_ir_construction:
            # Only process the entry module
            ns, mod, _ = q.pop()
            visited_ns.add(ns)
            # Run transformations only on entry module
            self.analysis_manager.analysis("three address", mod)
            self.analysis_manager.analysis("ir", mod)
            self.analysis_manager.analysis("block cfg", mod)
            self.analysis_manager.analysis("cfg", mod)
            self.analysis_manager.analysis("closure", mod)
            # Skip import traversal - imports are registered but not processed
            imports = World().scope_manager.get_ir(mod, "imports")
            for stmt in imports:
                get_import = World().namespace_manager.get_import(ns, stmt)
                if get_import is not None:
                    mod_ns, mod_path = get_import
                    new_mod = World().scope_manager.add_module(mod_ns, mod_path)
                    if new_mod is not None and mod_ns not in visited_ns:
                        g.add_edge(mod, stmt, new_mod)
                        World().import_manager.set_import(mod, stmt, new_mod)
                        
        else:
            # Original behavior: process all imports transitively
            while len(q) > 0:
                ns, mod, level = q.pop()
                
                if mod.get_qualname() in visited_ns:
                    continue                
                visited_ns.add(mod.get_qualname())
                
                # Preprocess module
                # TODO to be completed
                self.analysis_manager.analysis("three address", mod)
                self.analysis_manager.analysis("ir", mod)
                self.analysis_manager.analysis("block cfg", mod)
                self.analysis_manager.analysis("cfg", mod)
                self.analysis_manager.analysis("closure", mod)
                # self.analysis_manager.analysis("ssa", mod)
                imports = World().scope_manager.get_ir(mod, "imports")

                for stmt in imports:
                    get_import = World().namespace_manager.get_import(ns, stmt)
                    if get_import is not None:
                        mod_ns, mod_path = get_import

                        new_mod = World().scope_manager.add_module(mod_ns, mod_path)
                        if new_mod is None:
                            continue
                        
                        g.add_edge(mod, stmt, new_mod)
                        if self.config.import_level < 0 or level < self.config.import_level:
                            q.append((mod_ns, new_mod, level + 1))                 
                        World().import_manager.set_import(mod, stmt, new_mod)
        World().scope_manager.set_module_graph(g)

    def analyse_intra_procedure(self, analyzer):
        """Run ``analyzer`` independently on every reachable module."""
        module_graph = World().scope_manager.get_module_graph()
        q = Queue()
        for entry in module_graph.get_entries():
            q.put(entry)
        visited = {*()}
        while not q.empty():
            cur_module = q.get()
            self.analysis_manager.do_analysis(analyzer, cur_module)
            visited.add(cur_module)
            for succ in module_graph.succs_of(cur_module):
                if not succ in visited:
                    q.put(succ)

    def analyse_inter_procedure(self, analyzer: AnalysisDriver):
        """Run an interprocedural analyzer from the entry module."""
        entry_mod = World().get_entry_module()
        self.analysis_manager.do_analysis(analyzer, entry_mod)

    def do_transform(self, analyzer):
        """Apply a transform to modules in import-graph order."""
        module_graph = World().scope_manager.get_module_graph()
        q = Queue()
        for entry in module_graph.get_entries():
            q.put(entry)
        visited = {*()}
        while not q.empty():
            cur_module = q.get()
            self.analysis_manager.do_analysis(analyzer, cur_module)
            visited.add(cur_module)
            for succ in module_graph.succs_of(cur_module):
                if not succ in visited:
                    q.put(succ)

    def do_analysis(self, analyzer_generator: Generator[AnalysisDriver, None, None]):
        """Dispatch configured drivers according to their analysis type."""
        for analyzer in analyzer_generator:
            if analyzer.config.type == "dataflow analysis":
                if analyzer.config.inter_procedure:
                    self.analyse_inter_procedure(analyzer)
                else:
                    self.analyse_intra_procedure(analyzer)
            elif analyzer.config.type == 'transform':
                self.do_transform(analyzer)
            elif analyzer.config.type == 'inter-procedure':
                self.analyse_inter_procedure(analyzer)
            elif analyzer.config.type == 'pointer analysis':
                # Pointer analysis is typically inter-procedural
                self.analyse_inter_procedure(analyzer)
            elif analyzer.config.type == 'ai analysis':
                self.analyse_inter_procedure(analyzer)

    def run(self):
        """Execute configured analyses in dependency order."""
        World.set_current(self.world)
        analyzer_generator = self.analysis_manager.generator()
        self.do_analysis(analyzer_generator)
