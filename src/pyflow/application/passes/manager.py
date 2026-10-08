"""Pass scheduling, dependency resolution, and invalidation."""

import time
from typing import Any, Dict, List, Optional, Set

from .base import ExecutionRecord, Pass, PassInfo, PassKind, PassResult, PipelineResult
from .cache import AnalysisAvailability, PassCache


class PassManager:
    """LLVM-inspired pass manager for PyFlow."""

    def __init__(self, enable_caching: bool = True, *, max_analysis_refreshes: int = 32):
        if max_analysis_refreshes < 1:
            raise ValueError("max_analysis_refreshes must be positive")
        self.max_analysis_refreshes = max_analysis_refreshes
        self.analysis_availability = AnalysisAvailability()
        self._run_id = 0
        self.passes: Dict[str, Pass] = {}
        self.pass_aliases: Dict[str, str] = {}
        self.pass_order: List[str] = []
        self.cache = PassCache() if enable_caching else None
        self.execution_log: List[Dict[str, Any]] = []

    def register_pass(self, pass_instance: Pass) -> None:
        """Register a pass instance.

        CRITICAL FIX #2: Validate that optimization passes declare invalidation metadata.
        Passes that transform the program must explicitly declare what they invalidate
        or preserve to ensure cache correctness.

        Note: Validation is deferred until _resolve_dependencies() to allow metadata
        to be set after registration.
        """
        if pass_instance.name in self.passes or pass_instance.name in self.pass_aliases:
            raise ValueError(f"Pass '{pass_instance.name}' already registered")

        self.passes[pass_instance.name] = pass_instance
        self.pass_order.append(pass_instance.name)

        # Recompute pass ordering based on dependencies
        self._resolve_dependencies()

    def register_alias(self, alias: str, target: str) -> None:
        """Register an alternate pass name."""
        if alias in self.passes or alias in self.pass_aliases:
            raise ValueError(f"Pass alias '{alias}' already registered")
        if target not in self.passes:
            raise ValueError(f"Cannot alias unknown pass '{target}'")
        self.pass_aliases[alias] = target

    def resolve_pass_name(self, pass_name: str) -> str:
        """Resolve canonical pass names and aliases."""
        if pass_name in self.passes:
            return pass_name
        if pass_name in self.pass_aliases:
            return self.pass_aliases[pass_name]
        raise ValueError(f"Unknown pass '{pass_name}'")

    def unregister_pass(self, pass_name: str) -> None:
        """Unregister a pass."""
        canonical = self.resolve_pass_name(pass_name)
        del self.passes[canonical]
        self.pass_order = [p for p in self.pass_order if p != canonical]
        self.pass_aliases = {
            alias: target for alias, target in self.pass_aliases.items() if target != canonical
        }
        self._resolve_dependencies()

    def _resolve_dependencies(self) -> None:
        """Resolve pass execution order based on dependencies."""
        # Simple topological sort based on dependencies
        visited = set()
        temp_visited = set()
        order = []

        def visit(pass_name: str):
            if pass_name in temp_visited:
                raise ValueError(f"Circular dependency detected involving '{pass_name}'")
            if pass_name not in visited and pass_name in self.passes:
                temp_visited.add(pass_name)

                # Visit dependencies first
                for dep in self._iter_prerequisites(pass_name):
                    if dep in self.passes:
                        visit(dep)

                temp_visited.remove(pass_name)
                visited.add(pass_name)
                order.append(pass_name)

        # Visit all passes
        for pass_name in list(self.pass_order):
            if pass_name not in visited:
                visit(pass_name)

        self.pass_order = order

    def validate_optimization_metadata(self) -> None:
        """Validate that optimization passes declare invalidation metadata.

        CRITICAL FIX #2: This should be called after all passes are registered
        and their metadata is configured.
        """
        for pass_name, pass_obj in self.passes.items():
            if pass_obj.kind == PassKind.OPTIMIZATION:
                if not pass_obj.info.invalidates and not pass_obj.info.preserves:
                    raise ValueError(
                        f"Optimization pass '{pass_name}' must declare either "
                        f"'invalidates' or 'preserves' metadata. Transforming passes must "
                        f"explicitly specify which analysis results they invalidate or preserve "
                        f"to ensure cache correctness. If the pass invalidates all analyses, "
                        f"add them to 'invalidates'. If it preserves specific analyses, "
                        f"add them to 'preserves'."
                    )

    def _iter_prerequisites(self, pass_name: str, *, validate: bool = False) -> List[str]:
        """Return prerequisite pass names for a pass.

        Dependencies and analysis requirements are treated as scheduling
        prerequisites. Validation is deferred until pipeline construction so
        callers can register passes in any order.
        """
        pass_obj = self.passes[pass_name]
        prerequisites: Set[str] = set(pass_obj.info.dependencies)
        prerequisites.update(pass_obj.info.requirements)

        def prereq_sort_key(prereq: str) -> tuple[int, str]:
            # "first_pass_*" utility anchors encode a strict stage ordering.
            # Prefer prior anchors before real stage passes so dependency-only
            # pipeline requests preserve the configured first-pass sequence.
            if pass_name.startswith("first_pass_") or pass_name == "cpa_path_sensitive":
                return (0 if prereq.startswith("first_pass_") else 1, prereq)
            return (0, prereq)

        resolved: List[str] = []
        for prereq in sorted(prerequisites, key=prereq_sort_key):
            try:
                canonical = self.resolve_pass_name(prereq)
            except ValueError:
                if validate:
                    raise ValueError(
                        f"Pass '{pass_name}' depends on unknown pass '{prereq}'"
                    ) from None
                continue
            if (
                prereq in pass_obj.info.requirements
                and self.passes[canonical].kind != PassKind.ANALYSIS
            ):
                raise ValueError(f"Pass '{pass_name}' requires non-analysis pass '{prereq}'")
            resolved.append(canonical)
        return resolved

    def build_pipeline(self, pass_names: List[str]) -> "PassPipeline":
        """Build a pipeline from a list of pass names.

        Automatically inserts required dependencies for each requested pass
        while preserving the caller's explicit ordering. Pass names may be
        repeated to request distinct invocations, and aliases are
        resolved to their canonical registered names.
        """
        ordered: List[str] = []
        available: Set[str] = set()
        resolving: Set[str] = set()

        def emit(name: str, *, explicit=False):
            canonical = self.resolve_pass_name(name)
            if canonical in resolving:
                raise ValueError(f"Circular dependency detected involving '{canonical}'")
            if canonical in available and not explicit:
                return
            resolving.add(canonical)
            for dep in self._iter_prerequisites(canonical, validate=True):
                emit(dep)
            resolving.remove(canonical)
            ordered.append(canonical)
            available.add(canonical)

        for name in pass_names:
            emit(name, explicit=True)
        return PassPipeline(self, ordered)

    def run_pipeline(self, compiler, program, pipeline: "PassPipeline") -> PipelineResult:
        """Refresh stale analysis prerequisites immediately before each invocation."""
        self._run_id += 1
        run_id = self._run_id
        records = []
        completed = set()
        resolving = []
        # Local stamps also support program objects unsuitable as persistent cache keys.
        local_available = {}
        availability = self.analysis_availability

        def revision():
            return getattr(getattr(program, "ir", None), "revision", None)

        def valid(name):
            token = availability.version_token(program)
            return local_available.get(name) == token or availability.is_valid(program, name)

        def retire_failed_state():
            session = getattr(program, "session", None)
            if session is not None:
                session.mark_changed()
            local_available.clear()
            availability.invalidate(program)
            if self.cache:
                self.cache.invalidate(program)

        def record(name, result, before, *, cached=False, automatic=False, requested_by=None):
            item = ExecutionRecord(
                run_id=run_id,
                sequence=len(records) + 1,
                stage_name=name,
                pass_name=name,
                success=result.success,
                changed=result.changed,
                time=0.0 if cached else result.time or 0.0,
                cached=cached,
                revision_before=before,
                revision_after=revision(),
                result=result,
                timestamp=time.time(),
                error=result.error,
                exception_type=result.exception_type,
                automatic=automatic,
                requested_by=requested_by,
            )
            records.append(item)
            self.execution_log.append(item.as_dict())

        def execute(name, *, automatic=False, requested_by=None):
            canonical = self.resolve_pass_name(name)
            if canonical in resolving:
                raise ValueError(f"Circular dependency detected involving '{canonical}'")
            resolving.append(canonical)
            try:
                prerequisites = self._iter_prerequisites(canonical, validate=True)
                # Ordering-only prerequisites run once, even when later IR edits retire caches.
                for prerequisite in prerequisites:
                    if (
                        self.passes[prerequisite].kind != PassKind.ANALYSIS
                        and prerequisite not in completed
                    ):
                        if not execute(prerequisite, automatic=True, requested_by=canonical):
                            return False
                required = [
                    name for name in prerequisites if self.passes[name].kind == PassKind.ANALYSIS
                ]
                refreshes = {}
                # Refreshing one analysis can retire another; re-check the entire required set.
                while True:
                    missing = [name for name in required if not valid(name)]
                    if not missing:
                        break
                    prerequisite = missing[0]
                    refreshes[prerequisite] = refreshes.get(prerequisite, 0) + 1
                    if refreshes[prerequisite] > self.max_analysis_refreshes:
                        error = RuntimeError(
                            f"Analysis requirements for '{canonical}' did not stabilize: "
                            f"'{prerequisite}' remains invalid after "
                            f"{self.max_analysis_refreshes} refreshes"
                        )
                        before = revision()
                        result = PassResult.from_exception(error, execution_time=0.0)
                        retire_failed_state()
                        record(
                            canonical,
                            result,
                            before,
                            automatic=automatic,
                            requested_by=requested_by,
                        )
                        return False
                    if not execute(prerequisite, automatic=True, requested_by=canonical):
                        return False

                pass_obj = self.passes[canonical]
                before = revision()
                cached = self.cache.get(program, canonical) if self.cache else None
                if cached is not None:
                    if pass_obj.kind == PassKind.ANALYSIS:
                        availability.mark_valid(program, canonical)
                        local_available[canonical] = availability.version_token(program)
                    completed.add(canonical)
                    record(
                        canonical,
                        cached,
                        before,
                        cached=True,
                        automatic=automatic,
                        requested_by=requested_by,
                    )
                    return True

                before_cache = self.cache.version_token(program) if self.cache else None
                before_available = availability.version_token(program)
                result = self._run_pass(pass_obj, compiler, program)
                if not result.success:
                    retire_failed_state()
                elif result.changed:
                    preserved = self._invalidate_dependent_passes(
                        program, canonical, before_cache, before_available
                    )
                    after_available = availability.version_token(program)
                    local_available.update(
                        {
                            name: after_available
                            for name, token in list(local_available.items())
                            if name in preserved and token == before_available
                        }
                    )
                    for name in set(local_available) - preserved:
                        local_available.pop(name)
                else:
                    if pass_obj.kind == PassKind.ANALYSIS:
                        before_retirement = availability.version_token(program)
                        retired = self._retire_analysis_dependents(
                            program, canonical, local_available
                        )
                        after_retirement = availability.version_token(program)
                        for name, token in list(local_available.items()):
                            if name in retired:
                                local_available.pop(name)
                            elif token == before_retirement:
                                local_available[name] = after_retirement
                        availability.mark_valid(program, canonical)
                        local_available[canonical] = availability.version_token(program)
                    if self.cache:
                        self.cache.put(program, canonical, result)
                record(canonical, result, before, automatic=automatic, requested_by=requested_by)
                if result.success:
                    completed.add(canonical)
                return result.success
            finally:
                resolving.pop()

        for name in pipeline.passes:
            if not execute(name):
                break
        return PipelineResult(records)

    def run_passes(self, compiler, program, pass_names: List[str]) -> PipelineResult:
        """Run a specific set of passes."""
        pipeline = self.build_pipeline(pass_names)
        return self.run_pipeline(compiler, program, pipeline)

    def run_all_passes(self, compiler, program) -> PipelineResult:
        """Run all registered passes in dependency order."""
        return self.run_passes(compiler, program, self.pass_order)

    def _run_pass(self, pass_obj: Pass, compiler, program) -> PassResult:
        """Run a pass body; scheduling records are emitted after lifecycle handling."""
        start_time = time.perf_counter()
        try:
            result = pass_obj.run(compiler, program)
            if not isinstance(result, PassResult):
                raise TypeError(f"Pass '{pass_obj.name}' must return a PassResult")
            result.time = time.perf_counter() - start_time
            return result
        except Exception as error:
            return PassResult.from_exception(error, execution_time=time.perf_counter() - start_time)

    def _invalidate_dependent_passes(self, program, pass_name: str, before_token, before_available):
        """Commit a mutation and keep only explicitly preserved analysis state."""
        info = self.passes[pass_name].info
        preserved = {
            self.resolve_pass_name(name)
            for name in info.preserves
            if name in self.passes or name in self.pass_aliases
        }
        invalidated = {
            self.resolve_pass_name(name)
            for name in info.invalidates
            if name in self.passes or name in self.pass_aliases
        }
        preserved -= invalidated
        session = getattr(program, "session", None)
        if session is not None:
            invalidated_keys = {session.analysis_key(name) for name in invalidated}
            preserved = {
                name for name in preserved if session.analysis_key(name) not in invalidated_keys
            }
            session.mark_changed(preserved=preserved)
        for name in self.analysis_availability.pass_names(program):
            if name in preserved:
                self.analysis_availability.rebase(program, name, before_available)
            else:
                self.analysis_availability.invalidate(program, name)
        if self.cache:
            for name in self.cache.pass_names(program):
                cached_pass = self.passes.get(name)
                if (
                    name in preserved
                    and cached_pass is not None
                    and cached_pass.kind in (PassKind.ANALYSIS, PassKind.UTILITY)
                ):
                    self.cache.rebase(program, name, before_token)
                else:
                    self.cache.invalidate(program, name)
        return preserved

    def _retire_analysis_dependents(self, program, producer, local_available):
        """A newly computed input retires dependent results even at the same IR revision."""
        session = getattr(program, "session", None)
        key = session.analysis_key if session is not None else lambda name: name
        input_keys = {key(producer)}
        retired = set()
        while True:
            added = False
            for name, pass_obj in self.passes.items():
                if name in retired or key(name) == key(producer):
                    continue
                analysis_inputs = {
                    key(dependency)
                    for dependency in self._iter_prerequisites(name)
                    if self.passes[dependency].kind == PassKind.ANALYSIS
                }
                if analysis_inputs & input_keys:
                    retired.add(name)
                    if pass_obj.kind == PassKind.ANALYSIS:
                        input_keys.add(key(name))
                    added = True
            if not added:
                break
        if self.cache:
            for name in retired:
                self.cache.invalidate(program, name)
        analyses = {name for name in retired if self.passes[name].kind == PassKind.ANALYSIS}
        availability = self.analysis_availability
        before = availability.version_token(program)
        active = any(
            local_available.get(name) == before or availability.is_valid(program, name)
            for name in analyses
        )
        if session is not None:
            active = active or any(key(name) in session.results for name in analyses)
        if active and session is not None:
            session.invalidate_results(analyses)
        for name in availability.pass_names(program):
            if name in analyses:
                availability.invalidate(program, name)
            else:
                availability.rebase(program, name, before)
        return retired

    def get_pass_info(self, pass_name: str) -> Optional[PassInfo]:
        """Get metadata for a registered pass."""
        try:
            canonical = self.resolve_pass_name(pass_name)
        except ValueError:
            return None
        return self.passes[canonical].info

    def list_passes(self) -> List[str]:
        """List all registered passes."""
        return list(self.pass_order)

    def get_execution_log(self) -> List[Dict[str, Any]]:
        """Get the execution log."""
        return self.execution_log.copy()

    def clear_cache(self) -> None:
        """Clear the pass cache."""
        if self.cache:
            self.cache.clear()


class PassPipeline:
    """Represents a specific sequence of passes to run."""

    def __init__(self, manager: PassManager, passes: List[str]):
        self.manager = manager
        self.passes = passes.copy()

    def add_pass(self, pass_name: str) -> None:
        """Add a pass to the pipeline."""
        if pass_name not in self.manager.passes:
            raise ValueError(f"Unknown pass '{pass_name}'")
        self.passes.append(pass_name)

    def remove_pass(self, pass_name: str) -> None:
        """Remove a pass from the pipeline."""
        if pass_name in self.passes:
            self.passes.remove(pass_name)

    def run(self, compiler, program) -> PipelineResult:
        """Run this pipeline."""
        return self.manager.run_pipeline(compiler, program, self)
