"""Pass interfaces and execution metadata."""

import time
from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Set


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
    requirements: Set[str] = field(default_factory=set)  # What analyses must be run first
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


class UtilityPass(Pass):
    """Base class for utility/no-op passes used for pipeline structure."""

    def __init__(self, name: str, description: str = ""):
        super().__init__(name, PassKind.UTILITY, description)

    @abstractmethod
    def run(self, compiler, program) -> PassResult:
        """Run the utility pass."""
        pass


# Convenience functions for creating common pass types
def create_analysis_pass(name: str, run_func: Callable, description: str = "") -> AnalysisPass:
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
