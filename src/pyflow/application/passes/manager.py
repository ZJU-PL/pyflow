"""Pass scheduling, dependency resolution, and invalidation."""

import time
from typing import Any, Dict, List, Optional, Set

from .base import Pass, PassInfo, PassKind, PassResult
from .cache import PassCache


class PassManager:
    """LLVM-inspired pass manager for PyFlow."""

    def __init__(self, enable_caching: bool = True):
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
            # pipeline requests preserve the legacy first-pass sequence.
            if pass_name.startswith("first_pass_") or pass_name == "cpa_path_sensitive":
                return (0 if prereq.startswith("first_pass_") else 1, prereq)
            return (0, prereq)

        resolved: List[str] = []
        for prereq in sorted(prerequisites, key=prereq_sort_key):
            try:
                resolved.append(self.resolve_pass_name(prereq))
            except ValueError:
                if validate:
                    raise ValueError(
                        f"Pass '{pass_name}' depends on unknown pass '{prereq}'"
                    ) from None
        return resolved

    def build_pipeline(self, pass_names: List[str]) -> "PassPipeline":
        """Build a pipeline from a list of pass names.

        Automatically inserts required dependencies for each requested pass
        while preserving the caller's explicit ordering. Pass names may be
        repeated to force re-analysis after transformations, and aliases are
        resolved to their canonical registered names.
        """
        ordered: List[str] = []
        available: Set[str] = set()
        resolving: Set[str] = set()

        def emit(name: str):
            canonical = self.resolve_pass_name(name)
            if canonical in resolving:
                raise ValueError(f"Circular dependency detected involving '{canonical}'")

            if canonical in available:
                return

            resolving.add(canonical)
            for dep in self._iter_prerequisites(canonical, validate=True):
                emit(dep)
            resolving.remove(canonical)

            ordered.append(canonical)
            available.add(canonical)

        for name in pass_names:
            canonical = self.resolve_pass_name(name)
            emit(canonical)
            ordered.append(canonical)

        # Remove redundant consecutive duplicates introduced by explicit
        # dependencies already requested immediately beforehand.
        compacted: List[str] = []
        for pass_name in ordered:
            if compacted and compacted[-1] == pass_name:
                continue
            compacted.append(pass_name)

        return PassPipeline(self, compacted)

    def run_pipeline(self, compiler, program, pipeline: "PassPipeline") -> Dict[str, PassResult]:
        """Run a pipeline of passes."""
        results = {}

        for pass_name in pipeline.passes:
            canonical = self.resolve_pass_name(pass_name)

            # Check if we can skip this pass (caching)
            if self.cache:
                cached = self.cache.get(program, canonical)
                if cached is not None:
                    results[canonical] = cached
                    continue

            # Run the pass
            pass_obj = self.passes[canonical]
            before_token = self.cache.version_token(program) if self.cache else None
            result = self._run_pass(pass_obj, compiler, program)

            results[canonical] = result

            # Cache the result
            if self.cache and result.success:
                self.cache.put(program, canonical, result)

            if not result.success:
                # A failed pass may have partially mutated the IR or published facts.
                session = getattr(program, "session", None)
                if session is not None:
                    session.mark_changed()
                if self.cache:
                    self.cache.invalidate(program)
                break

            # Invalidate dependent passes if this pass changed something
            if result.changed:
                self._invalidate_dependent_passes(program, canonical, before_token)

        return results

    def run_passes(self, compiler, program, pass_names: List[str]) -> Dict[str, PassResult]:
        """Run a specific set of passes."""
        pipeline = self.build_pipeline(pass_names)
        return self.run_pipeline(compiler, program, pipeline)

    def run_all_passes(self, compiler, program) -> Dict[str, PassResult]:
        """Run all registered passes in dependency order."""
        return self.run_passes(compiler, program, self.pass_order)

    def _run_pass(self, pass_obj: Pass, compiler, program) -> PassResult:
        """Run a single pass and log the execution."""
        start_time = time.time()

        try:
            result = pass_obj.run(compiler, program)

            execution_time = time.time() - start_time
            result.time = execution_time
            self.execution_log.append(
                {
                    "pass": pass_obj.name,
                    "success": result.success,
                    "changed": result.changed,
                    "time": execution_time,
                    "error": result.error,
                    "exception_type": result.exception_type,
                    "timestamp": result.timestamp,
                }
            )

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            error_result = PassResult.from_exception(e, execution_time=execution_time)

            self.execution_log.append(
                {
                    "pass": pass_obj.name,
                    "success": False,
                    "changed": False,
                    "time": execution_time,
                    "error": error_result.error,
                    "exception_type": error_result.exception_type,
                    "timestamp": error_result.timestamp,
                }
            )

            return error_result

    def _invalidate_dependent_passes(self, program, pass_name: str, before_token) -> None:
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

    def run(self, compiler, program) -> Dict[str, PassResult]:
        """Run this pipeline."""
        return self.manager.run_pipeline(compiler, program, self)
