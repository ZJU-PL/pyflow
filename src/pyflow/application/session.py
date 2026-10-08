"""Ownership and lifecycle of one program's analysis state."""

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisOptions:
    """Immutable options for an analysis run; no process-global switches."""

    cpa_path_length: int = 3
    enable_caching: bool = True
    dump_reports: bool = False
    mask_dump_errors: bool = False
    dump_stats: bool = False

    def __post_init__(self):
        if self.cpa_path_length < 0:
            raise ValueError("cpa_path_length must be nonnegative")


class AnalysisResults(Mapping):
    """Solver objects pinned to the catalog and IR revision that produced them."""

    def __init__(self, session):
        self.session = session
        self._entries = {}
        self.generation = 0

    def _token(self):
        program = self.session.program
        return (program.ir, program.ir.revision, self.session.options)

    def __getitem__(self, key):
        token, result = self._entries[key]
        if token != self._token():
            raise KeyError(key)
        return result

    def __iter__(self):
        token = self._token()
        return (key for key, (version, _) in self._entries.items() if version == token)

    def __len__(self):
        return sum(1 for _ in self)

    def record(self, key, result):
        self._entries[key] = (self._token(), result)

    def invalidate(self, keys):
        for key in keys:
            self._entries.pop(key, None)
        self.generation += 1

    def retain(self, keys):
        token = self._token()
        self._entries = {
            key: (token, result) for key, (_, result) in self._entries.items() if key in keys
        }
        self.generation += 1


class AnalysisSession:
    """Owns options, solver results, scheduling, and invalidation.

    Program owns the source/IR model and its identity catalog. A session owns
    the analysis of that model, including the lifetime of published facts.
    CompilerContext supplies extraction and console services to each pass.
    """

    ANALYSIS_KEYS = {
        "ipa_refresh": "ipa",
        "ipa_after_simplify": "ipa",
        "cpa_path_sensitive": "cpa",
        "cpa_after_simplify": "cpa",
        "lifetime_refresh": "lifetime",
        "lifetime_after_simplify": "lifetime",
    }

    def __init__(self, program, *, options=None):
        self.program = program
        self._options = options if options is not None else AnalysisOptions()
        self.results = AnalysisResults(self)
        self._pass_manager = None

    @property
    def options(self):
        return self._options

    @property
    def pass_manager(self):
        if self._pass_manager is None:
            from .passes.manager import PassManager
            from .passes.registry import register_standard_passes

            manager = PassManager(enable_caching=self.options.enable_caching)
            register_standard_passes(manager)
            self._pass_manager = manager
        return self._pass_manager

    def configure(self, options: AnalysisOptions):
        """Replace run options and retire results from the previous configuration."""
        if options == self.options:
            return
        self._options = options
        self.results.retain(set())
        self.program.ir.facts.clear()
        self._pass_manager = None

    def analysis_key(self, name):
        return self.ANALYSIS_KEYS.get(name, name)

    def record_result(self, name, result):
        self.results.record(self.analysis_key(name), result)

    def get_result(self, name):
        return self.results.get(self.analysis_key(name))

    def invalidate_results(self, names):
        keys = {self.analysis_key(name) for name in names}
        self.results.invalidate(keys)
        self.program.ir.facts.invalidate_producers(keys)

    def mark_changed(self, *, preserved=()):
        """Advance the IR and retire every fact/result not explicitly preserved."""
        keys = {self.analysis_key(name) for name in preserved}
        current_keys = set(self.results)
        catalog = self.program.ir
        catalog.facts.retain_producers(keys)
        catalog.commit_revision(preserved_capabilities=catalog.facts.capabilities())
        catalog.semantics.invalidate()
        self.results.retain(keys & current_keys)
