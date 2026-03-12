"""
Pass Manager system for PyFlow static analysis.

This module provides a LLVM-inspired pass manager system that allows for:
- Pass registration with metadata and dependencies
- Automatic dependency resolution and ordering (topological sort)
- Pipeline construction and execution
- Caching and invalidation of pass results
- Standardized pass interfaces for analysis and optimization

**Key Concepts:**

1. **Pass Types:**
   - AnalysisPass: Information-gathering passes (IPA, CPA, Lifetime)
   - OptimizationPass: Code transformation passes (Simplify, Clone, etc.)
   - TransformationPass: General transformation passes

2. **Dependency Management:**
   - Passes declare dependencies on other passes
   - Pass manager automatically resolves execution order
   - Circular dependencies are detected and reported

3. **Caching:**
   - Pass results can be cached based on program state
   - Invalidates dependent passes when a pass modifies the program
   - Reduces redundant computation

4. **Pipeline Execution:**
   - Builds pipelines from pass names
   - Executes passes in dependency order
   - Tracks execution time and results

**Usage:**
```python
from pyflow.application import PassManager, CompilerContext
from pyflow.application.passes import register_standard_passes

manager = PassManager()
register_standard_passes(manager)

pipeline = manager.build_pipeline(["ipa", "cpa", "simplify"])
results = manager.run_pipeline(compiler, program, pipeline)
```

The pass manager system enables flexible composition of analysis passes
while maintaining correctness and efficiency.
"""

import time
import weakref
from typing import Dict, List, Set, Optional, Any, Callable, Type
from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass, field


class PassKind(Enum):
    """Types of passes in the system."""

    ANALYSIS = "analysis"
    OPTIMIZATION = "optimization"
    TRANSFORMATION = "transformation"
    UTILITY = "utility"


class PassResult:
    """Result of running a pass."""

    def __init__(
        self,
        success: bool = True,
        changed: bool = False,
        data: Any = None,
        error: Optional[str] = None,
        execution_time: Optional[float] = None,
        exception_type: Optional[str] = None,
    ):
        self.success = success
        self.changed = changed
        self.data = data
        self.error = error
        self.time = execution_time
        self.exception_type = exception_type
        self.timestamp = time.time()

    def __bool__(self):
        return self.success

    @classmethod
    def from_exception(
        cls, exc: Exception, *, execution_time: Optional[float] = None
    ) -> "PassResult":
        """Create a failed result that preserves exception type information."""
        exc_type = type(exc).__name__
        return cls(
            success=False,
            error=f"{exc_type}: {exc}",
            execution_time=execution_time,
            exception_type=exc_type,
        )


@dataclass
class PassInfo:
    """Metadata for a registered pass."""

    name: str
    kind: PassKind
    description: str = ""
    dependencies: Set[str] = field(default_factory=set)
    requirements: Set[str] = field(
        default_factory=set
    )  # What analyses must be run first
    invalidates: Set[str] = field(default_factory=set)  # What analyses this invalidates
    preserves: Set[str] = field(default_factory=set)  # What analyses this preserves

    def __post_init__(self):
        # Convert string sets to actual sets if needed
        if isinstance(self.dependencies, list):
            self.dependencies = set(self.dependencies)
        if isinstance(self.requirements, list):
            self.requirements = set(self.requirements)
        if isinstance(self.invalidates, list):
            self.invalidates = set(self.invalidates)
        if isinstance(self.preserves, list):
            self.preserves = set(self.preserves)


class Pass(ABC):
    """Base class for all passes in the pass manager system."""

    def __init__(self, name: str, kind: PassKind, description: str = ""):
        self.name = name
        self.kind = kind
        self.description = description
        self.info = PassInfo(name, kind, description)

    @abstractmethod
    def run(self, compiler, program) -> PassResult:
        """Run the pass on the given program.

        Args:
            compiler: The PyFlow compiler instance
            program: The Program object to analyze/transform

        Returns:
            PassResult indicating success/failure and whether the program changed
        """
        pass

    def requires_analysis(self, analysis_name: str) -> bool:
        """Check if this pass requires a specific analysis to be run first."""
        return analysis_name in self.info.requirements

    def invalidates_analysis(self, analysis_name: str) -> bool:
        """Check if this pass invalidates a specific analysis."""
        return analysis_name in self.info.invalidates

    def preserves_analysis(self, analysis_name: str) -> bool:
        """Check if this pass preserves a specific analysis."""
        return analysis_name in self.info.preserves

    def depends_on(self, other_pass: str) -> bool:
        """Check if this pass depends on another pass."""
        return other_pass in self.info.dependencies

    def __repr__(self):
        return f"{self.__class__.__name__}({self.name})"


class AnalysisPass(Pass):
    """Base class for analysis passes."""

    def __init__(self, name: str, description: str = ""):
        super().__init__(name, PassKind.ANALYSIS, description)

    @abstractmethod
    def run(self, compiler, program) -> PassResult:
        """Run the analysis pass."""
        pass


class OptimizationPass(Pass):
    """Base class for optimization passes."""

    def __init__(self, name: str, description: str = ""):
        super().__init__(name, PassKind.OPTIMIZATION, description)

    @abstractmethod
    def run(self, compiler, program) -> PassResult:
        """Run the optimization pass."""
        pass


class TransformationPass(Pass):
    """Base class for transformation passes."""

    def __init__(self, name: str, description: str = ""):
        super().__init__(name, PassKind.TRANSFORMATION, description)

    @abstractmethod
    def run(self, compiler, program) -> PassResult:
        """Run the transformation pass."""
        pass


class PassCache:
    """Simple cache for pass results based on program state."""

    def __init__(self):
        self._cache: "weakref.WeakKeyDictionary[Any, Dict[str, PassResult]]" = (
            weakref.WeakKeyDictionary()
        )
        # Fallback for objects that do not support weak references.
        # Use object keys directly (when hashable) to avoid id-reuse collisions.
        self._fallback_cache: Dict[Any, Dict[str, PassResult]] = {}

    def _supports_weakrefs(self, program) -> bool:
        try:
            weakref.ref(program)
        except TypeError:
            return False
        return True

    def _is_hashable(self, program) -> bool:
        try:
            hash(program)
        except TypeError:
            return False
        return True

    def get(self, program, pass_name: str) -> Optional[PassResult]:
        """Get cached result for a pass on a program."""
        if self._supports_weakrefs(program):
            return self._cache.get(program, {}).get(pass_name)
        if not self._is_hashable(program):
            return None
        return self._fallback_cache.get(program, {}).get(pass_name)

    def put(self, program, pass_name: str, result: PassResult) -> None:
        """Cache a pass result for a program."""
        if self._supports_weakrefs(program):
            if program not in self._cache:
                self._cache[program] = {}
            self._cache[program][pass_name] = result
            return
        if not self._is_hashable(program):
            return
        if program not in self._fallback_cache:
            self._fallback_cache[program] = {}
        self._fallback_cache[program][pass_name] = result

    def invalidate(self, program, pass_name: Optional[str] = None) -> None:
        """Invalidate cached results for a program or specific pass."""
        if self._supports_weakrefs(program):
            if program in self._cache:
                if pass_name is None:
                    del self._cache[program]
                else:
                    self._cache[program].pop(pass_name, None)
            return
        if not self._is_hashable(program):
            return
        if program in self._fallback_cache:
            if pass_name is None:
                del self._fallback_cache[program]
            else:
                self._fallback_cache[program].pop(pass_name, None)

    def pass_names(self, program) -> Set[str]:
        """Return cached pass names for a program."""
        if self._supports_weakrefs(program):
            return set(self._cache.get(program, ()))
        if not self._is_hashable(program):
            return set()
        return set(self._fallback_cache.get(program, ()))

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache.clear()
        self._fallback_cache.clear()


class PassManager:
    """LLVM-inspired pass manager for PyFlow."""

    def __init__(self, enable_caching: bool = True):
        self.passes: Dict[str, Pass] = {}
        self.pass_aliases: Dict[str, str] = {}
        self.pass_order: List[str] = []
        self.cache = PassCache() if enable_caching else None
        self.execution_log: List[Dict[str, Any]] = []

    def register_pass(self, pass_instance: Pass) -> None:
        """Register a pass instance."""
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
            alias: target
            for alias, target in self.pass_aliases.items()
            if target != canonical
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
                raise ValueError(
                    f"Circular dependency detected involving '{pass_name}'"
                )
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

    def _iter_prerequisites(
        self, pass_name: str, *, validate: bool = False
    ) -> List[str]:
        """Return prerequisite pass names for a pass.

        Dependencies and analysis requirements are treated as scheduling
        prerequisites. Validation is deferred until pipeline construction so
        callers can register passes in any order.
        """
        pass_obj = self.passes[pass_name]
        prerequisites: Set[str] = set(pass_obj.info.dependencies)
        prerequisites.update(pass_obj.info.requirements)

        resolved: List[str] = []
        for prereq in sorted(prerequisites):
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
                raise ValueError(
                    f"Circular dependency detected involving '{canonical}'"
                )

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

            # Transforming passes may invalidate all prior analyses; keep the
            # builder conservative so later requested analyses are re-emitted.
            if self.passes[canonical].kind in (
                PassKind.OPTIMIZATION,
                PassKind.TRANSFORMATION,
            ):
                available = {
                    pass_name
                    for pass_name in available
                    if self.passes[pass_name].kind
                    not in (PassKind.ANALYSIS, PassKind.UTILITY)
                }

        # Remove redundant consecutive duplicates introduced by explicit
        # dependencies already requested immediately beforehand.
        compacted: List[str] = []
        for pass_name in ordered:
            if compacted and compacted[-1] == pass_name:
                continue
            compacted.append(pass_name)

        return PassPipeline(self, compacted)

    def run_pipeline(
        self, compiler, program, pipeline: "PassPipeline"
    ) -> Dict[str, PassResult]:
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
            result = self._run_pass(pass_obj, compiler, program)

            results[canonical] = result

            # Cache the result
            if self.cache and result.success:
                self.cache.put(program, canonical, result)

            if not result.success:
                break

            # Invalidate dependent passes if this pass changed something
            if result.changed:
                self._invalidate_dependent_passes(program, canonical)

        return results

    def run_passes(
        self, compiler, program, pass_names: List[str]
    ) -> Dict[str, PassResult]:
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

    def _invalidate_dependent_passes(self, program, pass_name: str) -> None:
        """Invalidate passes that depend on the given pass or are invalidated by it."""
        if not self.cache:
            return
        pass_obj = self.passes[pass_name]

        if not pass_obj.info.invalidates and not pass_obj.info.preserves:
            # Program objects are mutated in place, so a changed pass invalidates every
            # cached result associated with that program unless the manager grows a real
            # versioned cache key. Keep the behavior conservative and correct.
            self.cache.invalidate(program)
            return

        cached_names = self.cache.pass_names(program)
        preserved = {
            self.resolve_pass_name(name)
            for name in pass_obj.info.preserves
            if name in self.passes or name in self.pass_aliases
        }
        invalidated = {
            self.resolve_pass_name(name)
            for name in pass_obj.info.invalidates
            if name in self.passes or name in self.pass_aliases
        }

        for cached_name in cached_names:
            cached_pass = self.passes.get(cached_name)
            if cached_pass is None:
                self.cache.invalidate(program, cached_name)
                continue

            if cached_name == pass_name:
                self.cache.invalidate(program, cached_name)
                continue

            if cached_pass.kind in (PassKind.OPTIMIZATION, PassKind.TRANSFORMATION):
                self.cache.invalidate(program, cached_name)
                continue

            if cached_name in invalidated:
                self.cache.invalidate(program, cached_name)
                continue

            if (
                cached_pass.kind in (PassKind.ANALYSIS, PassKind.UTILITY)
                and cached_name not in preserved
            ):
                self.cache.invalidate(program, cached_name)

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


# Convenience functions for creating common pass types
def create_analysis_pass(
    name: str, run_func: Callable, description: str = ""
) -> AnalysisPass:
    """Create an analysis pass from a function."""

    class FunctionAnalysisPass(AnalysisPass):
        def __init__(self):
            super().__init__(name, description)
            self._run_func = run_func

        def run(self, compiler, program) -> PassResult:
            try:
                # Assume the function returns (changed, data)
                result = self._run_func(compiler, program)
                if isinstance(result, tuple):
                    changed, data = result
                    return PassResult(success=True, changed=changed, data=data)
                else:
                    return PassResult(success=True, changed=result, data=result)
            except Exception as e:
                return PassResult.from_exception(e)

    return FunctionAnalysisPass()


def create_optimization_pass(
    name: str, run_func: Callable, description: str = ""
) -> OptimizationPass:
    """Create an optimization pass from a function."""

    class FunctionOptimizationPass(OptimizationPass):
        def __init__(self):
            super().__init__(name, description)
            self._run_func = run_func

        def run(self, compiler, program) -> PassResult:
            try:
                result = self._run_func(compiler, program)
                if isinstance(result, tuple):
                    changed, data = result
                    return PassResult(success=True, changed=changed, data=data)
                else:
                    return PassResult(success=True, changed=result, data=result)
            except Exception as e:
                return PassResult.from_exception(e)

    return FunctionOptimizationPass()
